#!/usr/bin/python3

import os
import typing
from typing import Any

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from datetime import datetime
from pathlib import Path

import tempfile
from ansible import constants as C
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.play_context import PlayContext
from ansible.playbook.task import Task
from ansible.plugins.connection import ConnectionBase
from ansible.template import Templar
from ansible.errors import (
    AnsibleError,
    AnsibleConnectionFailure,
    AnsibleActionSkip,
    AnsibleActionFail,
    AnsibleAuthenticationFailure,
)
from ansible.module_utils.common.text.converters import to_bytes, to_text, to_native
import itertools
from ansible.template import generate_ansible_template_vars
import collections
from ansible.module_utils.basic import AnsibleModule
from ansible.parsing import dataloader as _dataloader

DOCUMENTATION = r"""

"""


class ActionModule(ActionBase):
    def __init__(
        self,
        task: Task,
        connection: ConnectionBase,
        play_context: PlayContext,
        loader: DataLoader,
        templar: Templar,
        shared_loader_obj=None,
    ):
        super(ActionModule, self).__init__(
            task, connection, play_context, loader, templar, shared_loader_obj
        )
        # Init is called for each task and for each host in that task.
        # So a playbook with two hosts and two identical task calls gets 4x inits and 4x runs

    def run(self, tmp=None, task_vars=None):
        ret = super(ActionModule, self).run(tmp, task_vars)
        ret["tree"] = {}

        # source = self._task.args.get('src', None)
        source = "files"

        try:
            source_path = self._find_needle("templates", source)
        except AnsibleError as e:
            raise AnsibleActionFail(to_text(e))

        if not source_path.exists() or not source_path.is_dir():
            raise AnsibleActionFail(f"{source_path} is not a directory")

        # From the template action, we want to set up the jinja2's search paths for includes
        # That's all out original search paths, plus their template directories
        # We don't want to search into our filedrop tree, those are for dropping not including
        base_searchpaths = [
            Path(d)
            for d in (
                *task_vars.get("ansible_search_path", []),
                self._loader._basedir,
                source_path.resolve().parent,
            )
        ]
        template_searchpath = [
            str(d / extra) for d in set(base_searchpaths) for extra in ("", "templates")
        ]

        for root, dirs, files in source_path.walk(top_down=True, follow_symlinks=True):
            base = "/" / root.relative_to(source_path)  # The remote representation
            for dirname in dirs:
                ret["tree"][str(base / dirname)] = self.process_dir(
                    base / dirname, source_path
                )
            for filename in files:
                p = base / filename
                if p.suffix == ".j2":
                    ret["tree"][str(p)] = self.process_template(
                        p, source_path, template_searchpath
                    )
                else:
                    ret["tree"][str(p)] = self.process_file(p, source_path)
                # TODO: Add .keep and _keep files, make it a customisable parameter
                # TODO: Figure out how symlinks work, especially symlinks out of the tree

        # TODO: Check for failed status and Stop immediately on first error - exception?
        # Still want to provide ret return for completed files

        ret["changed"] = any([r.get("changed") for r in ret["tree"].values()])

        return ret

    def process_dir(self, path: Path, local_root: Path) -> dict[str, str | int | bool]:
        Display().vvv(f"Processing directory {local_root} {path}")
        # TODO: Want a way to set permissions
        # TODO: Can optimize by sending bulk requests?  Do I need by own module for the other side?
        file_return = self._execute_module(
            module_name="ansible.legacy.file",
            # module_args mode: for permissions, and owner and group
            module_args={"path": str(path), "state": "directory"},
            task_vars={"ansible_facts": {}},
        )

        return {
            k: file_return.get(k)
            for k in ("path", "changed", "uid", "gid", "owner", "group", "mode")
        }

    def process_template(
        self, path: Path, local_root: Path, searchpath: list[str]
    ) -> dict[str, str | int | bool]:
        Display().vvv(f"Processing template {local_root} {path}")

        fullpath = local_root / path.relative_to("/")

        # Template process is based on the standard template action
        # Basic process is to read the file, render the template, write to a temporary file, and transfer

        temp_vars = generate_ansible_template_vars(
            path, fullpath=fullpath, dest_path=path
        )

        data_templar = self._templar.copy_with_new_env(
            searchpath=searchpath, available_variables=temp_vars
        )
        # Future/dev ansible version use trust_as_template instead of read
        # Should probably figure out (and test) a range of verions in the future
        # template_data = trust_as_template(self._loader.get_text_file_contents(source))
        template_data = fullpath.read_text()
        resultant = data_templar.template(template_data, escape_backslashes=False)

        local_tempdir = Path(tempfile.mkdtemp(dir=C.DEFAULT_LOCAL_TMP))

        try:
            result_file = local_tempdir / path.name
            result_file.write_text(resultant)

            copy_return = self.copy_action(result_file, path.with_suffix(""))
        finally:
            Path(result_file).unlink()
            local_tempdir.rmdir()

        return copy_return

    def process_file(self, path: Path, local_root: Path) -> dict[str, str | int | bool]:
        Display().vvv(f"Processing file {local_root} {path}")

        fullpath = local_root / path.relative_to("/")

        return self.copy_action(fullpath, path)

    def copy_action(
        self, source_file: Path, dest_file: Path
    ) -> dict[str, str | int | bool]:
        # call with ansible.legacy prefix to eliminate collisions with collections while still allowing local override
        copy_task = Task()
        # copy_task = self._task.copy()
        copy_task.args = {
            "src": str(source_file),
            "dest": str(dest_file),
            "follow": True,
        }
        # TODO: Pass through checkmode?
        # TODO: Pass through async?
        copy_action = self._shared_loader_obj.action_loader.get(
            "ansible.legacy.copy",
            task=copy_task,
            connection=self._connection,
            play_context=self._play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj,
        )
        copy_return = copy_action.run(task_vars={"ansible_facts": {}})

        # Trim back result to the bits we actually care about
        return {
            k: copy_return.get(k)
            for k in (
                "path",
                "changed",
                "uid",
                "gid",
                "owner",
                "group",
                "mode",
                "size",
                "checksum",
            )
        }

    def _find_needle(self, dirname: str, needle: str) -> Path:
        """
        find a needle in haystack of paths, optionally using 'dirname' as a subdir.
        This will build the ordered list of paths to search and pass them to dwim
        to get back the first existing file found.
        """

        # dwim already deals with playbook basedirs
        path_stack = self._task.get_search_path()

        # raises AnsibleFileNotFound if no match
        match = self._loader.path_dwim_relative_stack(path_stack, dirname, needle)
        return Path(match)
