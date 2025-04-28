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
from ansible.parsing.utils.yaml import from_yaml

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

Directory permissions follow the same pattern as files but are a little more complex.  We have a fundametal problem that when looking at the existing directory /var/spool/postfix it is unclear which directory we should be controlling the permissions and ownership for, overwriting the permissions of /var/ by accident would be undesirable. The conservative option, only controlling permissions on directory creation, is also undesirable. We balance this by requiring users to be explicit about which directories are controlled.

The following process is used to determine if a folder should be managed.

1. Folders in the filedrop tree may contain a file, one of .permissions, _permissions, .permissions.yml, _permissions.yml (this is the default set, it is configurable via the directory_permission_file option).  If this file exists then the directory is controlled. This is the recommended pattern to use.
2. If a permissions_re expression contains a / then it is considered a directory targetting regular expression.  For matching all directories end in a / so they can be differentiated, for example /etc/. If a directory targetting regular expression matches the directory then it is managed.  This does not have to match at the end, for example "/etc/" will match /etc/ and all folders within /etc/, more specific regex such as "/etc/$" can be used if this is underisable.  (NOTE: Would contains / be better?)
3. If a permissions_exact key ends in / then it is considered a directory targetting key, any match will be considered managed.
4. If the folder does not yet exist on the remote system it will be treated as managed for the creation.  Once created it will not be managed.

A managed folder follows similar permission rules to files.

1. The permissions are all taken from the parent directory.
2. The permissions_re regex keys are matched against the path.  Note all keys are matched, not just ones that end in /.
3. The directory_permission_file may contain yaml definitions of the owner, group or mode.
4. Keys from permission_exact are matched against the path.

# TODO: It looks like directory_permission_file can also be json, from https://github.com/ansible/ansible/blob/aab732cb826db93265b03ca6f6f9eb1a03746975/lib/ansible/parsing/utils/yaml.py#L22


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

# TODO: Check mode
# TODO: There's a diff mode now too?
# TODO: Test async, somebody might be silly enough to try it

# TODO: List unmanaged files in managed directory
# TODO: Option - delete unmanaged files in managed directory


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
        # self._configure_module("ansible.legacy.stat", self._task.args, self._task_vars)

        ret = super(ActionModule, self).run(tmp, task_vars)
        ret["tree"] = {}

        source = self._task.args.get("src", "files")
        self.permissions_exact = self._task.args.get("permissions_exact", {})
        self.permissions_re = {
            re.compile(k): v
            for k, v in self._task.args.get("permissions_re", {}).items()
        }
        ignore_files = self._task.args.get("ignore_file", ["_keep", ".keep"])
        permission_files = self._task.args.get(
            "directory_permission_file",
            [
                ".permissions",
                "_permissions",
                ".permissions.yml",
                "_permissions.yml",
            ],
        )

        # task arg is list, dict, or ansible.parsing.yaml.objects.AnsibleUnicode
        # We support single or multimember options for directory_permission_files and ignore_file
        self.ignore_files = (
            ignore_files if type(ignore_files) is list else [ignore_files]
        )
        self.permission_files = (
            permission_files if type(permission_files) is list else [permission_files]
        )

        try:
            # TODO: is templates correct, should we be looking inside templates directories?
            source_path = self._find_needle("templates", source)
        except AnsibleError as e:
            raise AnsibleActionFail(to_text(e))

        if not source_path.exists() or not source_path.is_dir():
            raise AnsibleActionFail(f"{source_path} is not a directory")

        # From the template action, we want to set up the jinja2's search paths for includes
        # That's all out original search paths, plus their template directories
        # We don't want to search into our filedrop tree, those are for dropping not including
        base_searchpaths = [
            *task_vars.get("ansible_search_path", []),
            self._loader._basedir,
            source_path.resolve().parent,
        ]
        template_searchpath = [
            str(Path(d) / extra)
            for d in set(base_searchpaths)
            for extra in ("", "templates")
        ]

        # Add the root, mostly so we have the permissions recorded
        ret["tree"]["/"] = self.process_dir(Path("/"), source_path, {})
        for root, dirs, files in source_path.walk(top_down=True, follow_symlinks=True):
            remote_base = "/" / root.relative_to(source_path)
            directory_perms = ret["tree"][str(remote_base)]
            for dirname in dirs:
                local_path = root / dirname
                remote_path = remote_base / dirname
                Display().vvv(f"Processing directory {remote_path}")
                if self.is_managed_directory(
                    local_path,
                    remote_path,
                    directory_perms,
                ):
                    permissions = self.build_permissions(
                        local_path,
                        remote_path,
                        directory_perms,
                    )
                else:
                    permissions = {}  # We don't manage the permissions
                ret["tree"][str(remote_path)] = self.process_dir(
                    remote_path, source_path, permissions
                )
            for filename in files:
                if filename in [*self.ignore_files, *self.permission_files]:
                    # TODO: Test specifying ignore_file and setting it to ""
                    continue
                local_path = root / filename
                if filename[-3:] == ".j2":
                    remote_path = (remote_base / filename).with_suffix("")
                    permissions = self.build_permissions(
                        local_path,
                        remote_path,
                        directory_perms,
                    )
                    ret["tree"][str(remote_path)] = self.process_template(
                        local_path, remote_path, template_searchpath, permissions
                    )
                else:
                    remote_path = remote_base / filename
                    permissions = self.build_permissions(
                        local_path,
                        remote_path,
                        directory_perms,
                    )
                    ret["tree"][str(remote_path)] = self.process_file(
                        local_path, remote_path, permissions
                    )
                # TODO: Figure out how symlinks work, especially symlinks out of the tree

        # TODO: Check for failed status and Stop immediately on first error - exception?
        # Still want to provide ret return for completed files

        ret["changed"] = any([r.get("changed") for r in ret["tree"].values()])

        return ret

    def process_dir(
        self, path: Path, local_root: Path, permissions: dict[str, str]
    ) -> dict[str, str | int | bool]:
        # TODO: Can optimize by sending bulk requests?  Do I need by own module for the other side?
        module_args = {"path": str(path), "state": "directory"}
        if "owner" in permissions:
            module_args["owner"] = permissions["owner"]
        if "group" in permissions:
            module_args["group"] = permissions["group"]
        if "mode" in permissions:
            module_args["mode"] = permissions["mode"]

        file_return = self._execute_module(
            module_name="ansible.legacy.file",
            module_args=module_args,
            task_vars=self._task_vars,
        )

        return {
            k: file_return.get(k)
            for k in ("path", "changed", "uid", "gid", "owner", "group", "mode")
        }

    def process_template(
        self,
        local_path: Path,
        remote_path: Path,
        searchpath: list[str],
        permissions: dict[str, str],
    ) -> dict[str, str | int | bool]:
        # remote_path doesn't include the .j2, local_path does

        Display().vvv(f"Processing template {remote_path}")

        # Template process is based on the standard template action
        # Basic process is to read the file, render the template, write to a temporary file, and transfer

        temp_vars = generate_ansible_template_vars(
            remote_path, fullpath=local_path, dest_path=remote_path
        )

        data_templar = self._templar.copy_with_new_env(
            searchpath=searchpath, available_variables=temp_vars
        )
        template_data = local_path.read_text()
        resultant = data_templar.template(template_data, escape_backslashes=False)

        local_tempdir = Path(tempfile.mkdtemp(dir=C.DEFAULT_LOCAL_TMP))

        # TODO: catch/handle the failure cases -- or do they propogate up?
        try:
            result_file = local_tempdir / remote_path.name
            result_file.write_text(resultant)

            copy_return = self.copy_action(result_file, remote_path, permissions)
        finally:
            Path(result_file).unlink()
            local_tempdir.rmdir()

        return copy_return

    def process_file(
        self, local_path: Path, remote_path: Path, permissions: dict[str, str]
    ) -> dict[str, str | int | bool]:
        Display().vvv(f"Processing file {remote_path}")

        return self.copy_action(local_path, remote_path, permissions)

    def copy_action(
        self, source_file: Path, dest_file: Path, permissions: dict[str, str] = {}
    ) -> dict[str, str | int | bool]:
        copy_task = Task()
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
        # Display().vvv(f"TASKVAR {self._task_vars}")
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

    def build_permissions(
        self,
        local_path: Path,
        remote_path: Path,
        directory_perms: dict[str, str | int],
    ) -> dict[str, str]:
        # In increasing priority:
        #   1. Directory
        #   2. Regex
        #   3. For directories only - directory_permission_file
        #   4. Exact
        #
        # Matches can be partial, mode, owner and group can come from three different levels
        # Executable bit comes from the file itself (host side)
        # Later matches of the same priority overwrite earlier matches (dicts are ordered)

        # TODO: Handle files not being found some some reason - shouldn't happen

        # We make directories end in a / for clearer match differentiation
        remote_path_str = str(remote_path) + "/" * local_path.is_dir()

        level1 = directory_perms

        level2 = {}
        for reg, potential in self.permissions_re.items():
            if reg.search(remote_path_str) is not None:
                level2 = potential

        level3 = {}
        if local_path.is_dir():
            for child in local_path.iterdir():
                if child.name in self.permission_files and child.is_file():
                    from_permfile = from_yaml(child.read_text())
                    # Empty files return None
                    level3 = from_permfile if from_permfile is not None else {}

        level4 = {}
        for exact, potential in self.permissions_exact.items():
            if exact == remote_path_str:
                level4 = potential

        blend = {**level1, **level2, **level3, **level4}

        # Set the mode executable bits, based on the owner bit of the file
        want_exec = local_path.stat().st_mode & stat.S_IXUSR > 0
        exec_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        mode_d = int(blend["mode"], 8)
        # Read bits are always two higher than the executable bit
        new_mode_d = mode_d & ~exec_bits | (mode_d >> 2 & exec_bits * want_exec)
        blend["mode"] = "0" + oct(new_mode_d)[2:]  # Drop the 0o, but want a leading 0

        Display().vvv(
            f"Permission construction {blend} from {level1} {level2} {level3} {level4} exec={want_exec}"
        )
        return {k: blend[k] for k in ("owner", "group", "mode")}

    def is_managed_directory(
        self,
        local_path: Path,
        remote_path: Path,
        parent_directory_perms: dict[str, str | int],
    ) -> bool:
        # 1. If we have a directory_permission_file
        for child in local_path.iterdir():
            if child.name in self.permission_files and child.is_file():
                Display().vvv(f"Managed folder: {child.name} exists")
                return True

        # 2. If directory expression matches, directory expressions contain a /
        for reg, _perms in self.permissions_re.items():
            Display().vvv(
                f"folder testing regex {reg.pattern} - {'/' in reg.pattern} {str(remote_path) + '/'} {reg.search(str(remote_path) + '/')}"
            )
            if "/" in reg.pattern and reg.search(str(remote_path) + "/") is not None:
                Display().vvv(f"Managed folder: regex {reg.pattern} matches")
                return True

        # 3. If exact directory expression matches
        for exact, _perms in self.permissions_exact.items():
            if "/" in exact and exact == str(remote_path) + "/":
                Display().vvv(f"Managed folder: {exact} matches")
                return True

        # 4. If the remote folder doesn't exist
        # We need to test for this, otherwise we don't know if we should pass permission options
        # Do this test last because it's slow
        return not self._execute_remote_stat(
            str(remote_path), self._task_vars, follow=True
        )["exists"]

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
