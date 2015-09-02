glance_store
============

The glance_store library supports the creation, deletion and gather of data
assets from/to a set of several, different, storage technologies.

Contents
========

.. toctree::
   :maxdepth: 1

Release Notes
=============

0.9.0
-----

* s3-proxy-support_: Proxy support to S3 Store
* rados-timeout_: Better handling of glance-api connections to rbd store

.. _s3-proxy-support: https://blueprints.launchpad.net/glance/+spec/http-proxy-support-for-s3
.. _rados-timeout: https://bugs.launchpad.net/glance-store/+bug/1469246


0.6.0
-----

* Dropped py26 support
* Disable propagating BadStoreConfiguration
* _1454695: Sync with global-requirements
* Handle optional dependency in vmware store

.. _1454695: https://bugs.launchpad.net/glance-store/+bug/1454695

0.5.0
-----

* _1449639: Fix failure when creating an image which already exists in the RBD store
* _1444663: Correctly instantiate Forbidden exception
* _1428257: Do not raise an exception when a duplicate path on filesystem store is used. Instead emmit a warning
* _1422699: Propagate BadStoreConfiguration to library user
* Initialize vmware session during store creation

.. _1449639: https://bugs.launchpad.net/glance-store/+bug/1449639
.. _1444663: https://bugs.launchpad.net/glance-store/+bug/1444663
.. _1428257: https://bugs.launchpad.net/glance-store/+bug/1428257
.. _1422699: https://bugs.launchpad.net/glance-store/+bug/1422699

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

0.3.0
-----
*  Deprecate VMware store single datastore options
*  VMware: Support Multiple Datastores. This adds a new config option
``vmware_datastores`` to configure multiple datastores.

0.2.0
------

* 1425617_: Support for deleting images stored as SLO in Swift
* Enable DRIVER_REUSABLE for vmware store

.. _1425617: https://bugs.launchpad.net/glance-store/+bug/1425617

0.1.12
------

* Show fully qualified store name in update_capabilities() logging
* Move to hacking 0.10
* Fix sorting query string keys for arbitrary url schemes
* Remove duplicate key
* Add coverage report to run_test.sh
* Use a named enum for capability values
* Convert httpretty tests to requests-mock

0.1.11
-------

* 1402354_: Check VMware session before uploading image
*  Add capabilities to storage driver
*  Replace snet config with endpoint config. Instead of constructing a URL with
a prefix from what is returned by auth, specify the URL via configuration.
* 1413852_: Remove retry on failed uploads to VMware datastore
* 1401778_: Validate metadata JSON file. Metadata JSON schema file should
be valid objects. This JSON object should contain keys 'id', 'mountpoint' and
value of both keys should be string. Example of valid metadata JSON::

    1. If there is only one mountpoint-
    {
      "id": "f0781415-cf81-47cd-8860-b83f9c2a415c",
      "mountpoint": "/var/lib/glance/images/"
    }

    2. If there are more than one mountpoints-
    [
      {
        "id": "f0781415-cf81-47cd-8860-b83f9c2a415c",
        "mountpoint": "/var/lib/glance/images1/"
      },
      {
        "id": "asd81415-cf81-47cd-8860-b83f9c2a415c",
        "mountpoint": "/var/lib/glance/images2/"
      }
    ]

* Add needed extra space to error message
* 1375857_: Define a new parameter to pass CA cert file. This change adds a new
parameter for the swift store driver that allows to speficy the name of the CA
cert file to use in the SSL connections for verifying certificates. This
parameter is passed to the swiftclient in the creation of the connection.
The parameter is called ``swift_store_cacert``.
* 1379798_: Raise appropriate exception if socket error occurs
* Swift Store to use Multiple Containers. Swift Store will now use multiple
containers in single-tenant mode in order to avoid swift rate limiting on a
single container.
* Remove deprecated options
* Correct GlanceStoreException to provide valid message - glance_store
* 1350010_: VMware store: Re-use api session token

.. _1402354: https://bugs.launchpad.net/glance-store/+bug/1402354
.. _1413852: https://bugs.launchpad.net/glance-store/+bug/1413852
.. _1401778: https://bugs.launchpad.net/glance-store/+bug/1401778
.. _1375857: https://bugs.launchpad.net/glance-store/+bug/1375857
.. _1379798: https://bugs.launchpad.net/glance-store/+bug/1379798
.. _1350010: https://bugs.launchpad.net/glance-store/+bug/1350010

0.0.1a1
-------

* Initial release of glance_store_.

.. _glance_store: https://wiki.openstack.org/wiki/Glance/Store

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

