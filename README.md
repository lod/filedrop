# Ansible Collection - lod.filedrop

This collection contains a single action, filedrop, that transfers a structured tree of files to a remote host.

This action coordinates directory creation, file copying, templates, permissions management and fine grained handler notification all in one. It can be configured through in-tree directory management files or via the `path_re` task argument.

Documentation for the action is available at https://lod.github.io/filedrop/filedrop_module.html

This collection is not yet published on ansible galaxy.

Filedrop is a useful utility for most ansible usage but particularly shines in really complex situations.  In particular when a role touches multiple subsystems filedrop can significantly ease maintenance and debugging compared to having a long traditional ansible recipe.

To make best use of filedrop lean into configuration.d directories with configuration fragment.  This is increasingly the recommended Linux practice and makes managing configuration significantly simpler.
