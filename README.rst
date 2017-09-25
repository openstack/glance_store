========================
Team and repository tags
========================

.. image:: http://governance.openstack.org/badges/glance_store.svg
    :target: http://governance.openstack.org/reference/tags/index.html
    :alt: The following tags have been asserted for the Glance Store
          Library:
          "project:official",
          "stable:follows-policy",
          "vulnerability:managed",
          "team:diverse-affiliation".
          Follow the link for an explanation of these tags.
.. NOTE(rosmaita): the alt text above will have to be updated when
   additional tags are asserted for glance_store.  (The SVG in the
   governance repo is updated automatically.)

.. Change things from this point on

Glance Store Library
====================

Glance's stores library

This library has been extracted from the Glance source code for the
specific use of the Glance and Glare projects.

The API it exposes is not stable, has some shortcomings, and is not a
general purpose interface. We would eventually like to change this,
but for now using this library outside of Glance or Glare will not be
supported by the core team.

* License: Apache License, Version 2.0
* Documentation: http://docs.openstack.org/developer/glance_store
* Source: http://git.openstack.org/cgit/openstack/glance_store
* Bugs: http://bugs.launchpad.net/glance-store
