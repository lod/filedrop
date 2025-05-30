# Documentation for this action is in plugins/modules/filedrop.py

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


@dataclasses.dataclass(kw_only=True, slots=True)
class Options:
    owner: str | None = None
    group: str | None = None
    mode: str | None = None
    notify: set[str] = dataclasses.field(default_factory=set)
    delete_unmanaged: bool | None = (
        None  # Tristate yes/no/unset (unset is inherit/global)
    )

    # JSON friendly dict
    def asdict(self) -> dict[str, str]:
        return {
            k: (v if not isinstance(v, set) else list(v))
            for k, v in dataclasses.asdict(self).items()
            if v is not None
        }

    def permission_dict(self) -> dict[str, str]:
        return {
            k: v
            for k, v in dataclasses.asdict(self).items()
            if v is not None and k in ["owner", "group", "mode"]
        }

    def __post_init__(self):
        if isinstance(self.notify, str):
            self.notify = {self.notify}  # Allow dodgy string initialisation
        else:
            self.notify = set(self.notify)  # Convert lists, interables, etc.


# TODO: Do a side effect scenario, apply role, local changes, apply role
# TODO: I think copy supports "0644" and 0644, should test for us


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
        # Why have both?
        #
        # We don't have task_vars yet, no real setup is possible

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
        self.path_re = {
            re.compile(k): Options(**v)
            for k, v in self._task.args.get("path_re", {}).items()
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
                ".permissions.json",
                "_permissions.json",
            ],
        )

        self.delete_unmanaged: bool = self._task.args.get("delete_unmanaged", False)

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
            Display().vvv(f"TT {tree[remote_base]}")
            directory_entry = tree[remote_base]
            directory_perms = Options(
                **{k: directory_entry[k] for k in ("owner", "group", "mode")}
            )
            for dirname in dirs:
                local_path = root / dirname
                remote_path = remote_base / dirname
                Display().vvv(f"Processing directory {remote_path}")
                if self.is_managed_directory(local_path, remote_path, directory_entry):
                    options = self.build_options(
                        local_path,
                        remote_path,
                        directory_perms,
                    )
                else:
                    options = None  # We don't manage the path
                tree[remote_path] = self.process_dir(
                    remote_path,
                    source_path,
                    options,
                )
                tree[remote_path]["managed"] = options is not None
            for filename in files:
                # contents
                if filename in [*self.ignore_files, *self.permission_files]:
                    Display().vvv(f"Ignoring file {remote_base / filename}")
                    continue
                Display().vvv(f"Processing file {remote_base / filename}")
                local_path = root / filename
                if filename[-3:] == ".j2":
                    remote_path = (remote_base / filename).with_suffix("")
                    options = self.build_options(
                        local_path,
                        remote_path,
                        directory_perms,
                    )
                    tree[remote_path] = self.process_template(
                        local_path,
                        remote_path,
                        template_searchpath,
                        options,
                    )
                else:
                    remote_path = remote_base / filename
                    options = self.build_options(
                        local_path,
                        remote_path,
                        directory_perms,
                    )
                    tree[remote_path] = self.process_file(
                        local_path,
                        remote_path,
                        options,
                    )

            unmanaged_paths = set(
                directory_entry.get("remote_contents_path", [])
            ) - set(tree.keys())
            directory_entry["unmanaged_contents"] = [p.name for p in unmanaged_paths]
            if self.delete_unmanaged:
                # TODO: check and changed flags, and notify triggers based on the directory
                for p in unmanaged_paths:
                    self.delete_action(p)

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
            "delete_unmanaged",
            "notify",
            "unmanaged_contents",
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
                "notify": list(
                    {n for p, v in tree.items() for n in v.get("notify", [])}
                ),
                "_ansible_notify": list(
                    {n for p, v in tree.items() for n in v.get("notify", [])}
                ),
            },
        )
        if ret["failed"]:
            ret["msg"] = {str(p): r["msg"] for p, r in tree.items() if "msg" in r}

        return ret

    def process_dir(
        self,
        path: Path,
        local_root: Path,
        options: Options | None,
    ) -> dict[str, str | int | bool]:
        perm_dict = options.permission_dict() if options is not None else {}
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

        # Ansible handles notify at the task level, so we need to do it
        if file_return.get("changed"):
            file_return["notify"] = list(options.notify)

        # If the directory is managed we want to get the contents
        file_return["managed"] = options is not None
        if options is not None:
            find_return = cast(
                dict[str, Any],
                self._execute_module(
                    module_name="ansible.legacy.find",
                    module_args={
                        "paths": str(path),
                        "hidden": True,
                        "file_type": "any",
                    },
                    task_vars=self._task_vars,
                ),
            )
            Display().vvv(f"FIND DIR  {find_return}")
            file_return["remote_contents_path"] = [
                Path(f["path"]) for f in find_return["files"]
            ]

        file_return["delete_unmanaged"] = (
            self.delete_unmanaged
            if options is None or options.delete_unmanaged is None
            else options.delete_unmanaged
        )

        return file_return

    def process_template(
        self,
        local_path: Path,
        remote_path: Path,
        searchpath: list[str],
        options: Options,
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
            copy_return = self.copy_action(result_file, remote_path, options)
        finally:
            Path(result_file).unlink()
            local_tempdir.rmdir()

        return copy_return

    def process_file(
        self,
        local_path: Path,
        remote_path: Path,
        options: Options,
    ) -> dict[str, str | int | bool]:
        return self.copy_action(local_path, remote_path, options)

    def copy_action(
        self,
        source_file: Path,
        dest_file: Path,
        options: Options,
    ) -> dict[str, str | int | bool]:
        copy_task = self._task.copy()  # copy across check_mode, diff etc.
        copy_task.args = {
            "src": str(source_file),
            "dest": str(dest_file),
            "follow": True,
            **options.permission_dict(),
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

        # Ansible handles notify at the task level, so we need to do it
        if copy_return.get("changed"):
            copy_return["notify"] = list(options.notify)

        return copy_return

    def delete_action(self, remote_path: Path) -> None:
        # ansible.builtin.file:
        # state: absent
        # path: /home/mydata/web/

        del_return = cast(
            dict[str, Any],
            self._execute_module(
                module_name="ansible.legacy.file",
                module_args={"path": str(remote_path), "state": "absent"},
                task_vars=self._task_vars,
            ),
        )
        Display().vvv(f"DEL {del_return}")

        # TODO: Check return to ensure that it worked

    def build_options(
        self,
        local_path: Path,
        remote_path: Path,
        directory_perms: Options,
    ) -> Options:
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

        for reg, potential in self.path_re.items():
            if reg.search(remote_path_str) is not None:
                perm_layers.maps.insert(0, potential.asdict())

        if local_path.is_dir():
            for child in sorted(
                [
                    c
                    for c in local_path.iterdir()
                    if c.name in self.permission_files and c.is_file()
                ]
            ):
                # TODO: Test bad/rubbish files, ensure we fail gracefully
                # TODO: Test sorting
                # Note: The from_yaml call actually loads both yaml and json data
                from_permfile = from_yaml(child.read_text())
                # Empty files return None
                if from_permfile is not None:
                    perm_layers.maps.insert(0, Options(**from_permfile).asdict())

        blend = Options(**dict(perm_layers))

        # Notifications combine, are not replaced by higher layers
        blend.notify = {
            n for layer in perm_layers.maps for n in layer.get("notify", [])
        }

        # Set the mode executable bits, based on the owner bit of the file
        want_exec = local_path.stat().st_mode & stat.S_IXUSR > 0
        exec_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        try:
            mode_d = int(str(blend.mode), 8)
        except ValueError:
            # The provide mode wasn't numeric, like "u=rw,g=,o="
            raise Exception("mode must be numeric") from None
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
        parent_directory_details: dict[str, Any],
    ) -> bool:
        # 1. If the directory ancenstor is managed
        # This doesn't have to be an exhaustive search, we just need to check one level up
        # That level will have inherited from above, and we always work down
        if parent_directory_details.get("managed"):
            Display().vvv(f"Managed folder: {remote_path.parent} is managed")
            return True

        # 2. If we have a directory_management_file
        for child in local_path.iterdir():
            if child.name in self.permission_files and child.is_file():
                Display().vvv(f"Managed folder: {child.name} exists")
                return True

        # 3. If directory expression matches, directory expressions contain a /
        for reg in self.path_re:
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
