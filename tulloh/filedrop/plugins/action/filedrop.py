import dataclasses
import re
import stat
import tempfile
from collections import ChainMap
from pathlib import Path
from typing import Any, cast

from ansible import constants as C
from ansible.errors import (
    AnsibleActionFail,
    AnsibleError,
)
from ansible.module_utils.common.text.converters import to_text
from ansible.parsing.dataloader import DataLoader
from ansible.parsing.utils.yaml import from_yaml
from ansible.playbook.play_context import PlayContext
from ansible.playbook.task import Task
from ansible.plugins.action import ActionBase
from ansible.plugins.connection import ConnectionBase
from ansible.template import Templar, generate_ansible_template_vars
from ansible.utils.display import Display

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

Directory permissions follow the same pattern as files but are a little more complex.  We have a fundamental problem that when looking at the existing directory /var/spool/postfix it is unclear which directory we should be controlling the permissions and ownership for, overwriting the permissions of /var/ by accident would be undesirable. The conservative option, only controlling permissions on directory creation, is also undesirable. We balance this by requiring users to be explicit about which directories are controlled.

The following process is used to determine if a folder should be managed.

1. If a parent folder is managed then all folders within it are also managed.
2. Folders in the filedrop tree may contain a file, one of .permissions, _permissions, .permissions.yml, _permissions.yml (this is the default set, it is configurable via the directory_management_file option).  If this file exists then the directory is controlled. This is the recommended pattern to use.
3. If a permissions_re expression contains a / then it is considered a directory targeting regular expression.  For matching all directories end in a / so they can be differentiated, for example /etc/. If a directory targeting regular expression matches the directory then it is managed.  This does not have to match at the end, for example "/etc/" will match /etc/ and all folders within /etc/, more specific regex such as "/etc/$" can be used if this is undesirable.  (NOTE: Would contains / be better?)
4. If the folder does not yet exist on the remote system it will be treated as managed for the creation.  Once created it will not be managed.

A managed folder follows similar permission rules to files.

1. The permissions are all taken from the parent directory.
2. The permissions_re regex keys are matched against the path.  Note all keys are matched, not just ones that end in /.
3. The directory_management_file may contain yaml definitions of the owner, group or mode.



options:
    permissions_re:
        description:
        - Set file permissions using file regular expressions.
        - This is a two level dictionary, the first level key is a regular expression.
        - Any path which matches the regular expression (using re.search()) has the permissions set as specified.
        - Directories end in / for match reasons, this allows differentiation between files or directories.
        - The value is a dictionary containing one or more of owner, group or mode.
        - Partial applications also work, for example if only owner is specified then the group and mode are unchanged.
        - The ansible.builtin.copy rules also apply, numeric owners are user IDs and not specifying an owner means that the current user is used or existing owner if running as root.
    ignore_file:
        description:
        - File name to ignore. This is mostly useful for creating empty directories without git cleaning them up.
        - This can be either a filename string or a list of filename strings.
        - By default both .keep and _keep are ignored. This allows for a hidden or visible file based on your preferences.
        - Setting this to blank will prevent any files from being ignored.
    directory_management_file:
        description:
        - File name which specifies that the containing directory is managed.
        - The file may specify the owner, group, or mode permissions in the contents.  This can be either a yaml or json format.
        - This can be either a filename string or a list of filename strings.
        - Setting this to blank will prevent the directory_management_file functionality.

Note that in the event of a failure processing will continue with the rest of the tree.
The final status will be failure and the msg will reference all the failed elements.

"""


@dataclasses.dataclass(kw_only=True, slots=True)
class Permissions:
    owner: str | None = None
    group: str | None = None
    mode: str | None = None

    def asdict(self) -> dict[str, str]:
        return {k: v for k, v in dataclasses.asdict(self).items() if v is not None}


# TODO: List unmanaged files in managed directory
# TODO: Option - delete unmanaged files in managed directory

# TODO: The whole notify thing
#       We need to output the list of handlers to run in result_item['_ansible_notify']

# TODO: Do a side effect scenario, apply role, local changes, apply role

# TODO: Can mode not be numbers?  Should we support that?


class ActionModule(ActionBase):
    _supports_async = False  # Make the default explicit
    # It would be nice to support async but I'm not sure how to do it
    # all the examples seem to be single commands, we need to present
    # a single ansible_job_id in the output, unsure how to combine them.
    # The copy action doesn't support async, so it's probably not a huge benefit.
    # The magic file seems to be modules/async_wrapper.py

    def __init__(
        self,
        task: Task,
        connection: ConnectionBase,
        play_context: PlayContext,
        loader: DataLoader,
        templar: Templar,
        shared_loader_obj: None = None,
    ) -> None:
        super().__init__(
            task,
            connection,
            play_context,
            loader,
            templar,
            shared_loader_obj,
        )

        # Init is called for each task and for each host in that task.
        # So a playbook with two hosts and two identical task calls gets 4x inits and 4x runs

    def run(
        self,
        tmp: Any = None,
        task_vars: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._task_vars = task_vars if task_vars is not None else {}
        if "ansible_facts" not in self._task_vars:
            self._task_vars["ansible_facts"] = {}

        # configure the module to perform the interpreter discovery and same in _task_vars
        # otherwise it is done on every copy operation things get really slow

        ret = super().run(tmp, self._task_vars)

        source: str = self._task.args.get("src", "files")
        self.permissions_re = {
            re.compile(k): Permissions(**v)
            for k, v in self._task.args.get("permissions_re", {}).items()
        }
        ignore_files: str | list[str] = self._task.args.get(
            "ignore_file",
            ["_keep", ".keep"],
        )
        permission_files: str | list[str] = self._task.args.get(
            "directory_management_file",
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
            ignore_files if isinstance(ignore_files, list) else [ignore_files]
        )
        self.permission_files = (
            permission_files
            if isinstance(permission_files, list)
            else [permission_files]
        )

        try:
            path_stack = self._task.get_search_path()
            # raises AnsibleFileNotFound if no match
            match = self._loader.path_dwim_relative_stack(path_stack, "", source)
            source_path = Path(match)
        except AnsibleError as e:
            raise AnsibleActionFail(to_text(e))

        if not source_path.exists() or not source_path.is_dir():
            raise AnsibleActionFail(f"{source_path} is not a directory")

        # From the template action, we want to set up the jinja2's search paths for includes
        # That's all out original search paths, plus their template directories
        # We don't want to search into our filedrop tree, those are for dropping not including
        base_searchpaths = [
            *self._task_vars.get("ansible_search_path", []),
            self._loader._basedir,
            source_path.resolve().parent,
        ]
        template_searchpath = [
            str(Path(d) / extra)
            for d in set(base_searchpaths)
            for extra in ("", "templates")
        ]

        # Add the root, mostly so we have the permissions recorded
        tree: dict[Path, dict[str, Any]] = {}
        tree[Path("/")] = self.process_dir(Path("/"), source_path, None)
        for root, dirs, files in source_path.walk(top_down=True, follow_symlinks=True):
            remote_base = "/" / root.relative_to(source_path)
            directory_perms = Permissions(
                **{k: tree[remote_base][k] for k in ("owner", "group", "mode")},
            )
            for dirname in dirs:
                local_path = root / dirname
                remote_path = remote_base / dirname
                Display().vvv(f"Processing directory {remote_path}")
                if self.is_managed_directory(
                    local_path,
                    remote_path,
                    tree
                ):
                    permissions = self.build_permissions(
                        local_path,
                        remote_path,
                        directory_perms,
                    )
                else:
                    permissions = None  # We don't manage the permissions
                tree[remote_path] = self.process_dir(
                    remote_path,
                    source_path,
                    permissions,
                )
                tree[remote_path]["managed"] = permissions is not None
            for filename in files:
                if filename in [*self.ignore_files, *self.permission_files]:
                    Display().vvv(f"Ignoring file {remote_base / filename}")
                    continue
                Display().vvv(f"Processing file {remote_base / filename}")
                local_path = root / filename
                if filename[-3:] == ".j2":
                    remote_path = (remote_base / filename).with_suffix("")
                    permissions = self.build_permissions(
                        local_path,
                        remote_path,
                        directory_perms,
                    )
                    tree[remote_path] = self.process_template(
                        local_path,
                        remote_path,
                        template_searchpath,
                        permissions,
                    )
                else:
                    remote_path = remote_base / filename
                    permissions = self.build_permissions(
                        local_path,
                        remote_path,
                        directory_perms,
                    )
                    tree[remote_path] = self.process_file(
                        local_path,
                        remote_path,
                        permissions,
                    )
                # TODO: Figure out how symlinks work, especially symlinks out of the tree

        Display().vvv(f"Raw output tree {tree}")
        # Process all the return details to build out return tree
        tree_elements = [
            "path",
            "changed",
            "failed",
            "uid",
            "gid",
            "owner",
            "group",
            "mode",
            "size",
            "checksum",
            "managed",
        ]
        ret.update(
            {
                "changed": any(r.get("changed") for r in tree.values()),
                "failed": any(r.get("failed") for r in tree.values()),
                "diff": (
                    {str(p): v.get("diff", []) for p, v in tree.items()}
                    if self._task.diff
                    else {}
                ),
                "tree": {
                    str(p): {e: v.get(e) for e in tree_elements}
                    for p, v in tree.items()
                },
            },
        )
        if ret["failed"]:
            ret["msg"] = {str(p): r["msg"] for p, r in tree.items() if "msg" in r}

        return ret

    def process_dir(
        self,
        path: Path,
        local_root: Path,
        permissions: Permissions | None,
    ) -> dict[str, str | int | bool]:
        # TODO: Can optimize by sending bulk requests?  Do I need by own module for the other side?
        perm_dict = permissions.asdict() if permissions is not None else {}
        module_args = {"path": str(path), "state": "directory", **perm_dict}

        file_return = cast(
            dict[str, Any],
            self._execute_module(
                module_name="ansible.legacy.file",
                module_args=module_args,
                task_vars=self._task_vars,
            ),
        )
        Display().vvv(f"INDIR {module_args} {file_return}")

        # In check mode we don't create the directory, and it may not already exist
        # In this case so many return parameters aren't set, such as the permission elements
        # This is problematic, we rely on them as we build out the tree
        # It's reasonable to assume they will be set as instructed
        if self._task.check_mode and file_return["changed"]:
            file_return.update(perm_dict)

        return file_return

    def process_template(
        self,
        local_path: Path,
        remote_path: Path,
        searchpath: list[str],
        permissions: Permissions,
    ) -> dict[str, str | int | bool]:
        # remote_path doesn't include the .j2, local_path does

        # Template process is based on the standard template action
        # Basic process is to read the file, render the template, write to a temporary file, and transfer

        data_templar = self._templar.copy_with_new_env(
            searchpath=searchpath,
            available_variables={
                **self._task_vars,
                **generate_ansible_template_vars(
                    remote_path,
                    fullpath=local_path,
                    dest_path=remote_path,
                ),
            },
        )
        template_data = local_path.read_text()
        resultant = data_templar.template(template_data, escape_backslashes=False)

        local_tempdir = Path(tempfile.mkdtemp(dir=C.DEFAULT_LOCAL_TMP))  # type: ignore

        # TODO: catch/handle the failure cases -- or do they propagate up?
        result_file = local_tempdir / remote_path.name
        try:
            result_file.write_text(resultant)
            copy_return = self.copy_action(result_file, remote_path, permissions)
        finally:
            Path(result_file).unlink()
            local_tempdir.rmdir()

        return copy_return

    def process_file(
        self,
        local_path: Path,
        remote_path: Path,
        permissions: Permissions,
    ) -> dict[str, str | int | bool]:
        return self.copy_action(local_path, remote_path, permissions)

    def copy_action(
        self,
        source_file: Path,
        dest_file: Path,
        permissions: Permissions,
    ) -> dict[str, str | int | bool]:
        copy_task = self._task.copy()  # copy across check_mode, diff etc.
        copy_task.args = {
            "src": str(source_file),
            "dest": str(dest_file),
            "follow": True,
            **permissions.asdict(),
        }
        copy_task.async_val = False  # Not supported

        copy_action = self._shared_loader_obj.action_loader.get(
            "ansible.legacy.copy",
            task=copy_task,
            connection=self._connection,
            play_context=self._play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj,
        )
        copy_return = cast(dict[str, Any], copy_action.run(task_vars=self._task_vars))

        # copy could transfer directories, so the diff can be a list
        # it seems like if the file already exists it's a dict, list if it doesn't
        # we only ever transfer one file, so flatten it
        # this simplifies things, makes them consistent and matches directories
        if isinstance(copy_return["diff"], list):
            copy_return["diff"] = next(iter(copy_return["diff"]), {})

        return copy_return

    def build_permissions(
        self,
        local_path: Path,
        remote_path: Path,
        directory_perms: Permissions,
    ) -> Permissions:
        # In increasing priority:
        #   1. Directory
        #   2. Regex
        #   3. For directories only - directory_management_file
        #
        # Matches can be partial, pieces can come from multiple elements in the same or different level
        # Later matches of the same priority overwrite earlier matches (dicts are ordered)
        # The executable bit comes from the file itself (host side)

        # TODO: Handle files not being found some some reason - shouldn't happen

        # We make directories end in a / for clearer match differentiation
        remote_path_str = str(remote_path) + "/" * local_path.is_dir()

        perm_layers = ChainMap(directory_perms.asdict())  # Note, combines backwards

        for reg, potential in self.permissions_re.items():
            if reg.search(remote_path_str) is not None:
                perm_layers.maps.insert(0, potential.asdict())

        if local_path.is_dir():
            for child in local_path.iterdir():
                if child.name in self.permission_files and child.is_file():
                    # TODO: Test bad/rubbish files, ensure we fail gracefully
                    # Note: The from_yaml call actually loads both yaml and json data
                    from_permfile = from_yaml(child.read_text())
                    # Empty files return None
                    if from_permfile is not None:
                        perm_layers.maps.insert(0, from_permfile)

        blend = Permissions(**dict(perm_layers))

        # Set the mode executable bits, based on the owner bit of the file
        want_exec = local_path.stat().st_mode & stat.S_IXUSR > 0
        exec_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        mode_d = int(str(blend.mode), 8)
        # Read bits are always two higher than the executable bit
        new_mode_d = mode_d & ~exec_bits | (mode_d >> 2 & exec_bits * want_exec)
        blend.mode = "0" + oct(new_mode_d)[2:]  # Drop the 0o, but want a leading 0

        Display().vvv(
            f"Permission construction {blend} from {perm_layers} exec={want_exec}",
        )
        return blend

    def is_managed_directory(
        self,
        local_path: Path,
        remote_path: Path,
        tree: dict[Path, dict[str, Any]]
    ) -> bool:
        # 1. If the directory ancenstor is managed
        # This doesn't have to be an exhaustive search, we just need to check one level up
        # That level will have inherited from above, and we always work down
        if tree.get(remote_path.parent,{}).get("managed"):
            Display().vvv(f"Managed folder: {remote_path.parent} is managed")
            return True

        # 2. If we have a directory_management_file
        for child in local_path.iterdir():
            if child.name in self.permission_files and child.is_file():
                Display().vvv(f"Managed folder: {child.name} exists")
                return True

        # 3. If directory expression matches, directory expressions contain a /
        for reg in self.permissions_re:
            Display().vvv(
                f"folder testing regex {reg.pattern} - {'/' in reg.pattern} {str(remote_path) + '/'} {reg.search(str(remote_path) + '/')}",
            )
            if "/" in reg.pattern and reg.search(str(remote_path) + "/") is not None:
                Display().vvv(f"Managed folder: regex {reg.pattern} matches")
                return True

        # 4. If the remote folder doesn't exist
        # We need to test for this, otherwise we don't know if we should pass permission options
        # Do this test last because it's slow
        # return not cast(
        #    dict[str, Any],
        #    self._execute_remote_stat(str(remote_path), self._task_vars, follow=True),
        # )["exists"]
        rem_stat = cast(
            dict[str, Any],
            self._execute_remote_stat(str(remote_path), self._task_vars, follow=True),
        )
        if not rem_stat["exists"]:
            Display().vvv(f"Managed folder: {remote_path} doesn't yet exist")

        return not rem_stat["exists"]
