# Copyright 2018 RedHat Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Tests the RBD backend store with multistore configuration"""

import io
from unittest import mock

from oslo_config import cfg
from oslo_utils import units

import glance_store as store
from glance_store._drivers import rbd as rbd_store
from glance_store import exceptions
from glance_store import location as g_location
from glance_store.tests import base
from glance_store.tests.unit import test_rbd_store_base as rbd_base
from glance_store.tests.unit import test_store_capabilities


class TestMultiStore(base.MultiStoreBaseTest,
                     rbd_base.TestRBDStoreBase,
                     test_store_capabilities.TestStoreCapabilitiesChecking):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        """Establish a clean test environment."""
        super(TestMultiStore, self).setUp()
        enabled_backends = {
            "ceph1": "rbd",
            "ceph2": "rbd"
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='ceph1', group='glance_store')

        # Ensure stores + locations cleared
        g_location.SCHEME_TO_CLS_BACKEND_MAP = {}

        with mock.patch.object(rbd_store.Store, '_set_url_prefix'):
            store.create_multi_stores(self.conf)

        self.addCleanup(setattr, g_location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.addCleanup(self.conf.reset)

        rbd_store.rados = rbd_base.MockRados
        rbd_store.rbd = rbd_base.MockRBD

        # Set class-level variables for multistore and backend
        self.multistore = True
        self.backend = 'ceph1'

        self.store = rbd_store.Store(self.conf, backend=self.backend)
        self.store.configure()
        self.store.chunk_size = 2
        self.called_commands_actual = []
        self.called_commands_expected = []
        self.store_specs = {'pool': 'fake_pool',
                            'image': 'fake_image',
                            'snapshot': 'fake_snapshot'}
        self.location = rbd_store.StoreLocation(self.store_specs,
                                                self.conf)
        # Provide enough data to get more than one chunk iteration.
        self.data_len = 3 * units.Ki
        self.data_iter = io.BytesIO(b'*' * self.data_len)

    def test_location_url_prefix_is_set(self):
        """Test that location URL prefix is set correctly."""
        expected_url_prefix = "rbd://"
        self.assertEqual(expected_url_prefix, self.store.url_prefix)

    def test_add(self):
        """Test that we can add an image via the RBD backend."""
        self._test_add()

    def test_add_to_different_backend(self):
        """Test that we can add an image via a different RBD backend."""
        self.backend = 'ceph2'
        self.store = rbd_store.Store(self.conf, backend=self.backend)
        self.store.configure()
        self._test_add()

    def test_add_image_exceeding_max_size_raises_exception(self):
        """Test that adding an image exceeding max size raises exception."""
        self._test_add_image_exceeding_max_size_raises_exception()

    def test_write_less_than_declared_raises_exception(self):
        """Test that writing less than declared raises exception."""
        self._test_write_less_than_declared_raises_exception()

    def test_thin_provisioning_is_disabled_by_default(self):
        """Test that thin provisioning is disabled by default."""
        self.assertEqual(self.store.thin_provisioning, False)

    def test_add_with_thick_provisioning(self):
        """Test adding image with thick provisioning."""
        self._test_add_with_thick_provisioning()

    def test_add_with_thin_provisioning(self):
        """Test adding image with thin provisioning."""
        self._test_add_with_thin_provisioning()

    def test_add_thick_provisioning_with_holes_in_file(self):
        """Test thick provisioning with holes in file."""
        self._test_add_with_thick_provisioning()

    def test_add_thin_provisioning_with_holes_in_file(self):
        """Test thin provisioning with holes in file."""
        self._test_add_with_thin_provisioning()

    def test_add_thick_provisioning_without_holes_in_file(self):
        """Test thick provisioning without holes in file."""
        self._test_add_thick_provisioning_without_holes()

    def test_add_thin_provisioning_without_holes_in_file(self):
        """Test thin provisioning without holes in file."""
        self._test_add_thin_provisioning_without_holes()

    def test_add_thick_provisioning_with_partial_holes_in_file(self):
        """Test thick provisioning with partial holes in file."""
        self._test_add_thick_provisioning_with_partial_holes()

    def test_add_thin_provisioning_with_partial_holes_in_file(self):
        """Test thin provisioning with partial holes in file."""
        self._test_add_thin_provisioning_with_partial_holes()

    def test_add_with_verifier(self):
        """Test that 'verifier.update' is called when verifier is provided."""
        self._test_add_with_verifier()

    def test_add_duplicate_image(self):
        """Test that adding a duplicate image raises exception."""
        self._test_add_duplicate_image()

    def test_add_w_image_size_zero(self):
        """Assert that correct size is returned even though 0 was provided."""
        self._test_add_w_image_size_zero()

    def test_add_w_image_size_zero_to_different_backend(self):
        """Assert that correct size is returned for different backend."""
        self.store = rbd_store.Store(self.conf, backend="ceph2")
        self.store.configure()
        self.called_commands_actual = []
        self.called_commands_expected = []
        self.store_specs = {'pool': 'fake_pool_1',
                            'image': 'fake_image_1',
                            'snapshot': 'fake_snapshot_1'}
        self.location = rbd_store.StoreLocation(self.store_specs,
                                                self.conf)
        # Provide enough data to get more than one chunk iteration.
        self.data_len = 3 * units.Ki
        self.data_iter = io.BytesIO(b'*' * self.data_len)
        self.store.chunk_size = units.Ki
        with mock.patch.object(rbd_store.rbd.Image, 'resize') as resize:
            with mock.patch.object(rbd_store.rbd.Image, 'write') as write:
                ret = self.store.add('fake_image_id', self.data_iter, 0)

                self.assertTrue(resize.called)
                self.assertTrue(write.called)
                self.assertEqual(ret[1], self.data_len)
                self.assertEqual("ceph2", ret[3]['store'])

    def test_add_w_rbd_image_exception(self):
        """Test adding image with RBD image exception."""
        self._test_add_w_rbd_image_exception()

    def test_add_w_rbd_no_space_exception(self):
        """Test adding image with RBD no space exception."""
        self._test_add_w_rbd_no_space_exception()

    def test_add_checksums(self):
        """Test that checksums are calculated correctly."""
        self._test_add_checksums()

    def test_add_w_image_size_zero_less_resizes(self):
        """Test that correct size is returned with fewer resizes."""
        self._test_add_w_image_size_zero_less_resizes()

    def test_resize_on_write_ceiling(self):
        """Test resize on write ceiling functionality."""
        self._test_resize_on_write_ceiling()

    def test_delete(self):
        """Test that we can delete an existing image in the RBD store."""
        self._test_delete()

    def test_delete_image(self):
        """Test deleting an image."""
        self._test_delete_image()

    def test_delete_non_existing(self):
        """Test that deleting a non-existing image raises exception."""
        self._test_delete_non_existing()

    def test_delete_image_with_snap(self):
        """Test deleting an image with snapshot."""
        self._test_delete_image_with_snap()

    def test_delete_image_with_unprotected_snap(self):
        """Test deleting an image with unprotected snapshot."""
        self._test_delete_image_with_unprotected_snap()

    def test_delete_image_with_snap_with_error(self):
        """Test deleting an image with snapshot that raises error."""
        self._test_delete_image_with_snap_with_error()

    def test_delete_image_with_snap_exc_image_busy(self):
        """Test deleting an image with snapshot that is busy."""
        self._test_delete_image_with_snap_exc_image_busy()

    def test_delete_image_snap_has_external_references(self):
        """Test deleting an image with snapshot that has references."""
        self._test_delete_image_snap_has_external_references()

    def test_delete_image_with_snap_exc_image_has_snap(self):
        """Test deleting an image with snapshot that has snapshots."""
        self._test_delete_image_with_snap_exc_image_has_snap()

    def test_get_partial_image(self):
        """Test that getting partial image raises exception."""
        self._test_get_partial_image()

    def test_rados_connect_error(self):
        """Test that rados connect error raises exception."""
        self._test_rados_connect_error()

    def test_create_image_conf_features(self):
        """Test creating image with configuration features."""
        self._test_create_image_conf_features()

    def test_create_image_in_native_thread(self):
        """Test creating image in native thread."""
        self._test_create_image_in_native_thread()

    def test_delete_image_in_native_thread(self):
        """Test deleting image in native thread."""
        self._test_delete_image_in_native_thread()

    def test_rbd_proxy(self):
        """Test RBD proxy functionality."""
        self._test_rbd_proxy()

    def test_get_non_existing_identifier(self):
        """Test trying to retrieve a store that doesn't exist raises error."""
        self.assertRaises(exceptions.UnknownScheme,
                          g_location.get_location_from_uri_and_backend,
                          "rbd://%s/%s" % (self.store_specs['pool'],
                                           self.store_specs['image']),
                          'ceph3', conf=self.conf)

    def tearDown(self):
        """Clean up after tests."""
        self.assertEqual(self.called_commands_expected,
                         self.called_commands_actual)
        super(TestMultiStore, self).tearDown()
