glance_store
============

The glance_store library supports the creation, deletion and gather of data
assets from/to a set of several, different, storage technologies

Contents
========

.. toctree::
   :maxdepth: 1

Release Notes
=============

0.4.0
-----
* Deprecate the gridfs store
* Use oslo_config.cfg.ConfigOpts in glance_store
* _1426767: Make dependency on boto entirely conditional
* _1429785: Fix timeout during upload from slow resource
* _1418396: Throw NotFound exception when template is gone
* Correct such logic in store.get() when chunk_size param provided

.. _1426767: https://bugs.launchpad.net/glance-store/+bug/1426767
.. _1429785: https://bugs.launchpad.net/glance-store/+bug/1429785
.. _1418396: https://bugs.launchpad.net/glance-store/+bug/1418396

0.0.1a1
-------

* Initial release of glance_store_.

.. _glance_store: https://wiki.openstack.org/wiki/Glance/Store

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

