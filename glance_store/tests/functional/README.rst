===============================
glance_store functional testing
===============================

Writing functional tests for glance_store
-----------------------------------------

The functional tests verify glance_store against a "live" backend.  The tests
are isolated so that a development environment doesn't have to all the backends
available, just the particular backend whose driver the developer is working
on.

To add tests for a driver:

1. Create a new module in ``glance_store/tests/functional`` with the driver
   name.

2. Create a submodule ``test_functional_{driver-name}`` containing a class
   that inherits from ``glance_store.tests.functional.BaseFunctionalTests``.
   The actual tests are in the ``BaseFunctionalTests`` class.  The test
   classes for each driver do any extra setup/teardown necessary for that
   particular driver.  (The idea is that all the backends should be able to
   pass the same tests.)

3. Add a testenv to ``tox.ini`` named ``functional-{driver-name}`` so
   that tox can run the tests for your driver.  (Use the other functional
   testenvs as examples.)

4. If your driver is well-supported by devstack, it shouldn't be too hard
   to set up a gate job for the functional tests in ``.zuul.yaml``.  (Use
   the other jobs defined in that file as examples.)


Configuration
-------------

The functional tests have been designed to work well with devstack so that
we can run them in the gate.  Thus the tests expect to find a yaml file
containing valid credentials just like the ``clouds.yaml`` file created by
devstack in the ``/etc/openstack`` directory.  The test code knows where
to find it, so if you're using devstack, you should be all set.

If you are not using devstack you should create a yaml file with the following
format::

 clouds:
   devstack-admin:
     auth:
       auth_url: https://172.16.132.143/identity
       password: example
       project_domain_id: default
       project_name: admin
       user_domain_id: default
       username: admin
     identity_api_version: '3'
     region_name: RegionOne
     volume_api_version: '3'

The clouds.yaml format allows for a set of credentials to be defined for each
named cloud.  By default, the tests will use the credentials for the cloud
named **devstack-admin** (that's the cloud shown in the example above).  You
can change which cloud is read from ``clouds.yaml`` by exporting the
environment variable ``OS_TEST_GLANCE_STORE_FUNC_TEST_CLOUD`` set to the name
of the cloud you want used.

Where to put clouds.yaml
------------------------

The tests will look for a file named ``clouds.yaml`` in the
following locations (in this order, first found wins):

* current directory
* ~/.config/openstack
* /etc/openstack

You may also set the environment variable ``OS_CLIENT_CONFIG_FILE``
to the absolute pathname of a file and that location will be
inserted at the front of the search list.
