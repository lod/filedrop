#!/usr/bin/python3

import re
import os
import stat
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
---
module: filedrop
short_description: Drop a directory tree of files onto the remote system
description:
    - Bob
    - Smith

File permissions are ...
1. The executable bit is taken from the file, this bit is maintained by git, this is the only permission information retained by git. The executable bit is set whenever the read bit is set.
2. The permissions are all taken from the parent directory.
3. The regex dictionary parameters owner_re, group_re and mode_re are matched against the full file path.  This allows broad matches.
4. The exact dictionary parameters owner_exact, group_exact and mode_exact are matched against the full file path. This allows precise matches.

TODO: Can I combine owner_re, group_re and mode_re?  permission_re and then a dict with owner/group/mode.  Or a composite like owner:group:mode ?





options:
    owner_re:
        description:
        - Set file ownership using file regular expressions.
        - This is passed a dictionary, the key is a regular expression, the value is the owner name or id.
        - Any path which matches the regular expression (using re.search()) has the owner set as specified.
        - Later expressions can overwrite earlier ones, this is also overwritten by owner_exact.
        - The ansible.builtin.copy rules also apply, numeric owners are user IDs and not specifying an owner means that the current user is used or existing owner if running as root.
    owner_exact:
        description:
        - Set the file ownership using exact full path matches.
        - This is passed as a dictionary, the key is the file path, the value is the owner name or id.
        - The ansible.builtin.copy rules also apply, numeric owners are user IDs and not specifying an owner means that the current user is used or existing owner if running as root.
        - It is recommended that you use this sparingly, using owner_re will typically result in cleaner code. Extensive use also defeats the flexibility that this module is designed to provide.
    group_re:
        description:
        - Set file group ownership using file regular expressions.
        - This is passed a dictionary, the key is a regular expression, the value is the group name or id.
        - Any path which matches the regular expression (using re.search()) has the group set as specified.
        - Later expressions can overwrite earlier ones, this is also overwritten by group_exact.
        - The ansible.builtin.copy rules also apply, numeric groups are user IDs and not specifying a group means that the current user default group is used or existing group if running as root.
    group_exact:
        description:
        - Set the file group ownership using exact full path matches.
        - This is passed as a dictionary, the key is the file path, the value is the file group name or id.
        - The ansible.builtin.copy rules also apply, numeric groups are user IDs and not specifying a groups means that the current user default group is used or existing group if running as root.
        - It is recommended that you use this sparingly, using group_re will typically result in cleaner code. Extensive use also defeats the flexibility that this module is designed to provide.
    ignore_file:
        description:
        - File name to ignore. This is mostly useful for creating empty directories without git cleaning them up.
        - By default both .keep and _keep are ignored. This allows for a hidden or visible file based on your preferences.
        - Setting this to "" will prevent any files from being ignored.


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

        self._task_vars = task_vars if task_vars is not None else {}
        if "ansible_facts" not in self._task_vars:
            self._task_vars["ansible_facts"] = {}

        # configure the module to perform the interpreter discovery and same in _task_vars
        # otherwise it is done on every copy operation things get really slow
        #self._configure_module("ansible.legacy.stat", self._task.args, self._task_vars)

        ret = super(ActionModule, self).run(tmp, task_vars)
        ret["tree"] = {}

        # source = self._task.args.get('src', None)
        source = "files"
        permissions_exact = self._task.args.get('permissions_exact', {})
        permissions_re = { re.compile(k):v for k,v in self._task.args.get('permissions_re', {}).items()}
        ignore_file = self._task.args.get('ignore_file', None)


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

        # Add the root, mostly so we have the permissions recorded
        ret["tree"]["/"] = self.process_dir(Path("/"), source_path)
        for root, dirs, files in source_path.walk(top_down=True, follow_symlinks=True):
            remote_base = "/" / root.relative_to(source_path)
            directory_perms = ret["tree"][str(remote_base)]
            for dirname in dirs:
                ret["tree"][str(remote_base / dirname)] = self.process_dir(
                    remote_base / dirname, source_path
                )
            for filename in files:
                p = remote_base / filename
                if ignore_file == filename or (ignore_file is None and filename in ["_keep", ".keep"]):
                    # TODO: Test specifying ignore_file and setting it to ""
                    continue
                local_path = root / filename
                if filename[-3:] == ".j2":
                    remote_path = (remote_base / filename).with_suffix("")
                    permissions = self.build_permissions(local_path, remote_path, directory_perms, permissions_re, permissions_exact)
                    ret["tree"][str(p)] = self.process_template(
                        p, source_path, template_searchpath, permissions
                    )
                else:
                    remote_path = remote_base / filename
                    permissions = self.build_permissions(local_path, remote_path, directory_perms, permissions_re, permissions_exact)
                    ret["tree"][str(p)] = self.process_file(p, source_path, permissions)
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
            task_vars=self._task_vars,
        )

        return {
            k: file_return.get(k)
            for k in ("path", "changed", "uid", "gid", "owner", "group", "mode")
        }

    def process_template(
            self, path: Path, local_root: Path, searchpath: list[str], permissions: dict[str,str]
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

            copy_return = self.copy_action(result_file, path.with_suffix(""), permissions)
        finally:
            Path(result_file).unlink()
            local_tempdir.rmdir()

        return copy_return

    def process_file(self, path: Path, local_root: Path, permissions: dict[str,str]) -> dict[str, str | int | bool]:
        Display().vvv(f"Processing file {local_root} {path}")

        fullpath = local_root / path.relative_to("/")

        return self.copy_action(fullpath, path, permissions)

    def copy_action(
            self, source_file: Path, dest_file: Path, permissions: dict[str,str] = {}
    ) -> dict[str, str | int | bool]:
        # call with ansible.legacy prefix to eliminate collisions with collections while still allowing local override
        copy_task = Task()
        # copy_task = self._task.copy()
        copy_task.args = {
            "src": str(source_file),
            "dest": str(dest_file),
            "follow": True,
        }
        if "owner" in permissions:
            copy_task.args["owner"] = permissions["owner"]
        if "group" in permissions:
            copy_task.args["group"] = permissions["group"]
        if "mode" in permissions:
            copy_task.args["mode"] = permissions["mode"]

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
        #Display().vvv(f"TASKVAR {self._task_vars}")
        copy_return = copy_action.run(task_vars=self._task_vars)

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

    @staticmethod
    def build_permissions(local_path: Path, remote_path: Path, directory_perms: dict[str,str|int], re_matches: dict[re.Pattern, str], exact_matches: dict[str,str]) -> dict[str,str]:
        # In increasing priority:
        #   1. Directory
        #   2. Regex
        #   3. Exact
        #
        # Matches can be partial, mode, owner and group can come from three different levels
        # Executable bit comes from the file itself (host side)
        # Later matches of the same priority overwrite earlier matches (dicts are ordered)

        # TODO: Handle files not being found some some reason - shouldn't happen
        # TODO: Handle templates, want no j2 for exact but j2 for exec bit

        # TODO: Ensure and test that dicts are ordered

        level1 = directory_perms

        level2 = {}  # default
        for reg, potential in re_matches.items():
            if reg.search(str(remote_path)) is not None:
                level2 = potential

        level3 = {}  # default
        for exact, potential in exact_matches.items():
            if exact == str(remote_path):
                level3 = potential

        blend = {**level1, **level2, **level3}

        # Update the mode executable bit, based on the owner bit of the file
        exec_bit = local_path.stat().st_mode & stat.S_IXUSR > 0
        mode_d = int(blend["mode"],8)
        # Read bits are always two higher than the executable bit
        new_mode_d = mode_d | (mode_d >> 2 & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        blend["mode"] = "0" + oct(new_mode_d)[2:]  # Drop the 0o, but want a leading 0

        # TODO: Test directory perms, requires setting directory perms
        # TODO: Test executable bits

        return {k:blend[k] for k in ("owner", "group", "mode")}

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
