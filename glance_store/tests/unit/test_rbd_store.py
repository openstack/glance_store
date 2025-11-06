# Copyright 2013 OpenStack Foundation
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

"""Tests the RBD backend store"""

import io
from unittest import mock

from oslo_utils import units

from glance_store._drivers import rbd as rbd_store
from glance_store.tests import base
from glance_store.tests.unit import test_rbd_store_base as rbd_base
from glance_store.tests.unit import test_store_capabilities
from glance_store.tests import utils as test_utils


class TestReSize(base.StoreBaseTest,
                 test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        """Establish a clean test environment."""
        super(TestReSize, self).setUp()

        rbd_store.rados = rbd_base.MockRados
        rbd_store.rbd = rbd_base.MockRBD

        self.store = rbd_store.Store(self.conf)
        self.store.configure()
        self.store_specs = {'pool': 'fake_pool',
                            'image': 'fake_image',
                            'snapshot': 'fake_snapshot'}
        self.location = rbd_store.StoreLocation(self.store_specs,
                                                self.conf)
        self.hash_algo = 'sha256'

    def test_add_w_image_size_zero_less_resizes(self):
        """Assert that correct size is returned even though 0 was provided."""
        data_len = 57 * units.Mi
        data_iter = test_utils.FakeData(data_len)
        with mock.patch.object(rbd_store.rbd.Image, 'resize') as resize:
            with mock.patch.object(rbd_store.rbd.Image, 'write') as write:
                ret = self.store.add(
                    'fake_image_id', data_iter, 0, self.hash_algo)

                # We expect to trim at the end so +1
                expected = 1
                expected_calls = []
                data_len_temp = data_len
                resize_amount = self.store.WRITE_CHUNKSIZE
                while data_len_temp > 0:
                    resize_amount *= 2
                    expected_calls.append(resize_amount + (data_len -
                                                           data_len_temp))
                    data_len_temp -= resize_amount
                    expected += 1
                self.assertEqual(expected, resize.call_count)
                resize.assert_has_calls([mock.call(call) for call in
                                         expected_calls])
                expected = ([self.store.WRITE_CHUNKSIZE for i in range(int(
                            data_len / self.store.WRITE_CHUNKSIZE))] +
                            [(data_len % self.store.WRITE_CHUNKSIZE)])
                actual = ([len(args[0]) for args, kwargs in
                          write.call_args_list])
                self.assertEqual(expected, actual)
                self.assertEqual(data_len,
                                 resize.call_args_list[-1][0][0])
                self.assertEqual(data_len, ret[1])

    def test_resize_on_write_ceiling(self):
        """Test resize on write ceiling functionality."""
        image = mock.MagicMock()

        # Non-zero image size means no resize
        ret = self.store._resize_on_write(image, 32, 16, 16)
        self.assertEqual(0, ret)
        image.resize.assert_not_called()

        # Current size is smaller than we need
        self.store.size = 8
        ret = self.store._resize_on_write(image, 0, 16, 16)
        self.assertEqual(8 + self.store.WRITE_CHUNKSIZE * 2, ret)
        self.assertEqual(self.store.WRITE_CHUNKSIZE * 2,
                         self.store.resize_amount)
        image.resize.assert_called_once_with(ret)

        # More reads under the limit do not require a resize
        image.resize.reset_mock()
        self.store.size = ret
        ret = self.store._resize_on_write(image, 0, 64, 16)
        self.assertEqual(8 + self.store.WRITE_CHUNKSIZE * 2, ret)
        image.resize.assert_not_called()

        # Read past the limit triggers another resize
        ret = self.store._resize_on_write(image, 0, ret + 1, 16)
        self.assertEqual(8 + self.store.WRITE_CHUNKSIZE * 6, ret)
        image.resize.assert_called_once_with(ret)
        self.assertEqual(self.store.WRITE_CHUNKSIZE * 4,
                         self.store.resize_amount)

        # Check that we do not resize past the 8G ceiling.

        # Start with resize_amount at 2G, 1G read so far
        image.resize.reset_mock()
        self.store.resize_amount = 2 * units.Gi
        self.store.size = 1 * units.Gi

        # First resize happens and we get to 5G,
        # resize_amount goes to limit of 4G
        ret = self.store._resize_on_write(image, 0, 4097 * units.Mi, 16)
        self.assertEqual(4 * units.Gi, self.store.resize_amount)
        self.assertEqual((1 + 4) * units.Gi, ret)
        self.store.size = ret

        # Second resize happens and we stay at 13, no resize
        # resize amount stays at limit of 8G
        ret = self.store._resize_on_write(image, 0, 6144 * units.Mi, 16)
        self.assertEqual(8 * units.Gi, self.store.resize_amount)
        self.assertEqual((1 + 4 + 8) * units.Gi, ret)
        self.store.size = ret

        # Third resize happens and we get to 21,
        # resize amount stays at limit of 8G
        ret = self.store._resize_on_write(image, 0, 14336 * units.Mi, 16)
        self.assertEqual(8 * units.Gi, self.store.resize_amount)
        self.assertEqual((1 + 4 + 8 + 8) * units.Gi, ret)
        self.store.size = ret

        # Fourth resize happens and we get to 29,
        # resize amount stays at limit of 8G
        ret = self.store._resize_on_write(image, 0, 22528 * units.Mi, 16)
        self.assertEqual(8 * units.Gi, self.store.resize_amount)
        self.assertEqual((1 + 4 + 8 + 8 + 8) * units.Gi, ret)

        image.resize.assert_has_calls([
            mock.call(5 * units.Gi),
            mock.call(13 * units.Gi),
            mock.call(21 * units.Gi),
            mock.call(29 * units.Gi)])


class TestStore(base.StoreBaseTest,
                rbd_base.TestRBDStoreBase,
                test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        """Establish a clean test environment."""
        super(TestStore, self).setUp()

        rbd_store.rados = rbd_base.MockRados
        rbd_store.rbd = rbd_base.MockRBD

        # Set class-level variables for multistore and backend
        self.multistore = False
        self.backend = 'glance_store'

        self.store = rbd_store.Store(self.conf)
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
        self.hash_algo = 'sha256'

    def test_thin_provisioning_is_disabled_by_default(self):
        """Test that thin provisioning is disabled by default."""
        self.assertEqual(self.store.thin_provisioning, False)

    def test_add(self):
        """Test that we can add an image via the RBD backend."""
        self._test_add()

    def test_add_image_exceeding_max_size_raises_exception(self):
        """Test that adding an image exceeding max size raises exception."""
        self._test_add_image_exceeding_max_size_raises_exception()

    def test_write_less_than_declared_raises_exception(self):
        """Test that writing less than declared raises exception."""
        self._test_write_less_than_declared_raises_exception()

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

    def test_delete_image_with_snap_exc_image_has_snap_2(self):
        """Test deleting an image with snapshot that has snapshots (case 2)."""
        self._test_delete_image_with_snap_exc_image_has_snap_2()

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

    def tearDown(self):
        """Clean up after tests."""
        self.assertEqual(self.called_commands_expected,
                         self.called_commands_actual)
        super(TestStore, self).tearDown()
