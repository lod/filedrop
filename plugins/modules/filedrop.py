# This is an action module, but antsibull-docs doesn't scan actions
# This is just documentation.
#
# Weird but it is how ansible has chosen to do it.
# The builtin fail module is documented in the same way.

DOCUMENTATION = r"""
module: filedrop
short_description: Drop a tree of files onto the remote system
version_added: '1.0.0'
author: David Tulloh (@lod)
description:
  - Transfers a structured directory tree of files including directory creation, permission management and fine control handler notifications.
  - This action is designed for complex implementations, it excels at simplifying roles that touch multiple service configurations.
  - The action follows the principle of keeping the simple things simplex and the complex things possible.  Much of the documentation is focused on the complex, most implementations should rarely require specific configuration.
  - Performance matches running M(ansible.builtin.copy) as this action plugin orchestrates the builtin copy and file operations.  The use of pipelining is strongly recommended as this significantly increases the speed. There is significant scope to improve the performance by shifting some of the logic to the remote system and parallelising some operations, this may be tackled in the future if there is a need.

options:
    src:
      description:
        - A directory tree that should be transferred.
        - The tree should be structured as it will reside on the remote system.  <src>/etc/ssh/ssh_config.d/10-myhost.conf will be placed at /etc/ssh/ssh_config.d/10-myhost.conf
        - Files which end in .j2 will be rendered as templates and transferred to the host without the .j2 extension.
        - Special files, as set by the O(ignore_file) and O(directory_management_file) options, allows configuration to reside in the tree.
        - Symlinks are treated as normal files, so a symlink from <src>/linked to <src>/target will result in two normal files on the remote host /linked and /target. These files will have the same contents but will not be linked together. Symlinks may also exit the <src> tree, so a symlink to /etc/passwd will result in the contents of that file being transferred to the remote host. All symlink behaviour is subject to change as the use cases become clearer.
        - The same search pattern as M(ansible.builtin.copy) and M(ansible.builtin.template) is used to find the requested directory in the current role or parent roles.
      default: files
      type: path
    ignore_file:
      description:
        - File name to ignore. This is mostly useful for creating empty directories without git cleaning them up.
        - This can be either a filename string or a list of filename strings.
        - Setting this to V("") will prevent any files from being ignored.
      default: [".keep", "_keep"]
    directory_management_file:
      description:
        - Filename for files which specify that the containing directory is managed.
        - The file may provide an options set in either the yaml or json format. These options are applied to the directory and its contents.
        - This option can be either a filename string or a list of filename strings.
        - Setting this to V("") will prevent the directory_management_file functionality.
        - If multiple files are in the tree then all are used in alphabetical order.
        - Like O(ignore_file), these files will not be transferred to the remote system.
      default: [".permissions","_permissions",".permissions.yml","_permissions.yml",".permissions.json","_permissions.json"]
    meta options:
      description:
        - This is not an explicit field, it documents the options as used by O(directory_management_file) and O(path_re).
        - Options do not all need to be set, the desired keys can be set and unset elements will be handled as described in O(meta option tiers).
      suboptions:
        owner:
          description:
            - Sets the file or directory owner as in M(ansible.builtin.copy).
          type: string
        group:
          description:
            - Sets the file or directory group as in M(ansible.builtin.copy).
          type: string
        mode:
          description:
            - Sets the file or directory mode as in M(ansible.builtin.copy).
            - Unlike M(ansible.builtin.copy) we only support octal strings such as "0644".
            - The executable portion of the mode always comes from the source, specifically the owner portion of the source.  Unlike other permission elements this bit is preserved by git.  Directories are always considered to be executable.
            - If the file or directory is deemed to be executable then the executable bit follows the read bit, any owner/group/all read bits set will have the corresponding executable bit set.
          type: string
        notify:
          description:
            - Specifies an ansible handler to notify if the file has changed.
            - This works just like the ansible task notify option, but is more specific.  Only the changed portions of the filedrop tree will trigger a notification. This allows two different services to be configured and without both handlers always being run.
            - This option may either be a string or a list of strings.
        delete_unmanaged:
          type: bool
          description:
            - If set on a directory then all unknown files within that directory on the remote system will be deleted.
            - This is designed to ensure that ansible absolutely manages the configuration, that no additional unknown files have been added.
            - See also O(delete_unmanaged).
    meta option tiers:
      description:
        - This is not an explicit field, it documents the layering of options as specified by O(meta options).
        - Options are derived from multiple levels, each subsequent level overrides the previous one.
        - Each option is optional, so the final options will typically be a mix of multiple levels.
      suboptions:
        level 1:
          description:
            - Options inherited from the parent directory.
        level 2:
          description:
            - Options set by O(path_re).
        level 3:
          description:
            - For directories only, options specified by a O(directory_management_file) in that directory.
        level 4:
          description:
            - The executable bit from the source file. This overwrites the specified mode option.
            - If the executable is set it will pair with the desired read bits, so "0604" becomes "0705".
            - This also works in reverse, if the executable bit is not set on the source file it will not be set on the remote host, even if the desired mode includes an executable portion.

    meta managed directories:
      description:
        - This is not an explicit field, it documents the concept of managed directories.
        - Given /var/log/my_thing/ we need a way to manage the directory permissions of the final my_thing directory without changing the parent directories. Doing this and managing all the possible interactions is complex, we use the following rules.
        - 1. If the directory ancestor is managed then the directory is managed.
        - 2. If the directory includes a O(directory_management_file)
        - 3. If a key from O(path_re) matches and includes a / character.
        - 4. If a directory does not exist on the remote system it is managed only for the creation.

    path_re:
      description:
        - Set options of paths that match regular expressions.
        - This is a two level dictionary, the first level key is a regular expression.
        - The second level is a set of options as specified in O(meta options).
        - Any path which matches the regular expression (using re.search()) has the options set as specified.
        - Directories end in / for match reasons, this allows differentiation between files or directories.
      type: dict
    delete_unmanaged:
      description:
        - Deletes unmanaged (unknown) files and directories inside managed directories.
        - This option sets the state for all managed directories, it can be overridden by setting the delete_unmanaged option on a directory.
        - See O(meta managed directories) for details on when this option applies.
      type: bool
      default: false

notes:
  - In the event of a failure processing will continue with the rest of the tree. The final status will be failure and the failure msg will reference all the failed elements.
  - WARNING - Using the standard task based notification system on this task will overwrite the custom notifications returned by this task.  They cannot both be used together.
"""

# TODO:
#   Document that symlinks are created as normal files
#   Could optimize by sending bulk requests, requires custom client side module
#   Add examples and return details


EXAMPLES = r"""
- name: Transfer from files to remote host
  lod.filedrop:

- name: Transfer from files and restart ssh if required
  lod.filedrop:
    path_re:
      ssh:
        notify: Restart sshd


"""

RETURN = r"""
"""
