# Ansible Collection - lod.filedrop

This collection contains a single action, filedrop, that transfers a structured tree of files to a remote host.

This action coordinates directory creation, file copying, rendering templates, permissions management and fine grained handler notification all in one. It can be configured through in-tree directory management files or via the `path_re` task argument.

It is designed to significantly simplify more complex roles with lots of files and directories, it works for simpler roles but scales trivially to larger ones.  In particular when a role touches multiple subsystems filedrop can significantly ease maintenance and debugging compared to having a long traditional ansible recipe.

Documentation for the action is available at https://lod.github.io/filedrop/filedrop_module.html

To make best use of filedrop lean into configuration.d directories with configuration fragment.  This is increasingly the recommended Linux practice and makes managing configuration significantly simpler.
