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

import hashlib
import io
from unittest import mock

from oslo_utils.secretutils import md5
from oslo_utils import units

from glance_store._drivers import rbd as rbd_store
from glance_store import exceptions
from glance_store import location as g_location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities
from glance_store.tests import utils as test_utils


class TestException(Exception):
    pass


class MockRados(object):

    class Error(Exception):
        pass

    class ObjectNotFound(Exception):
        pass

    class ioctx(object):
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self, *args, **kwargs):
            return self

        def __exit__(self, *args, **kwargs):
            return False

        def close(self, *args, **kwargs):
            pass

    class Rados(object):

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self, *args, **kwargs):
            return self

        def __exit__(self, *args, **kwargs):
            return False

        def connect(self, *args, **kwargs):
            pass

        def open_ioctx(self, *args, **kwargs):
            return MockRados.ioctx()

        def shutdown(self, *args, **kwargs):
            pass

        def conf_get(self, *args, **kwargs):
            pass


class MockRBD(object):

    class ImageExists(Exception):
        pass

    class ImageHasSnapshots(Exception):
        pass

    class ImageBusy(Exception):
        pass

    class ImageNotFound(Exception):
        pass

    class InvalidArgument(Exception):
        pass

    class NoSpace(Exception):
        pass

    class Image(object):

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self, *args, **kwargs):
            return self

        def __exit__(self, *args, **kwargs):
            pass

        def create_snap(self, *args, **kwargs):
            pass

        def remove_snap(self, *args, **kwargs):
            pass

        def set_snap(self, *args, **kwargs):
            pass

        def list_children(self, *args, **kwargs):
            pass

        def protect_snap(self, *args, **kwargs):
            pass

        def unprotect_snap(self, *args, **kwargs):
            pass

        def read(self, *args, **kwargs):
            raise NotImplementedError()

        def write(self, *args, **kwargs):
            raise NotImplementedError()

        def resize(self, *args, **kwargs):
            pass

        def discard(self, offset, length):
            raise NotImplementedError()

        def close(self):
            pass

        def list_snaps(self):
            raise NotImplementedError()

        def parent_info(self):
            raise NotImplementedError()

        def size(self):
            raise NotImplementedError()

    class RBD(object):

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self, *args, **kwargs):
            return self

        def __exit__(self, *args, **kwargs):
            return False

        def create(self, *args, **kwargs):
            pass

        def remove(self, *args, **kwargs):
            pass

        def list(self, *args, **kwargs):
            raise NotImplementedError()

        def clone(self, *args, **kwargs):
            raise NotImplementedError()

        def trash_move(self, *args, **kwargs):
            pass

    RBD_FEATURE_LAYERING = 1


class TestReSize(base.StoreBaseTest,
                 test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        """Establish a clean test environment."""
        super(TestReSize, self).setUp()

        rbd_store.rados = MockRados
        rbd_store.rbd = MockRBD

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
        image = mock.MagicMock()

        # image, size, written, chunk

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
                test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        """Establish a clean test environment."""
        super(TestStore, self).setUp()

        rbd_store.rados = MockRados
        rbd_store.rbd = MockRBD

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
        self.assertEqual(self.store.thin_provisioning, False)

    def test_add_w_image_size_zero(self):
        """Assert that correct size is returned even though 0 was provided."""
        self.store.chunk_size = units.Ki
        with mock.patch.object(rbd_store.rbd.Image, 'resize') as resize:
            with mock.patch.object(rbd_store.rbd.Image, 'write') as write:
                ret = self.store.add(
                    'fake_image_id', self.data_iter, 0, self.hash_algo)

                self.assertTrue(resize.called)
                self.assertTrue(write.called)
                self.assertEqual(ret[1], self.data_len)

    @mock.patch.object(MockRBD.Image, '__enter__')
    @mock.patch.object(rbd_store.Store, '_create_image')
    @mock.patch.object(rbd_store.Store, '_delete_image')
    def test_add_w_rbd_image_exception(self, delete, create, enter):
        def _fake_create_image(*args, **kwargs):
            self.called_commands_actual.append('create')
            return self.location

        def _fake_delete_image(target_pool, image_name, snapshot_name=None):
            self.assertEqual(self.location.pool, target_pool)
            self.assertEqual(self.location.image, image_name)
            self.assertEqual(self.location.snapshot, snapshot_name)
            self.called_commands_actual.append('delete')

        def _fake_enter(*args, **kwargs):
            raise exceptions.NotFound(image="fake_image_id")
        create.side_effect = _fake_create_image
        delete.side_effect = _fake_delete_image
        enter.side_effect = _fake_enter

        self.assertRaises(exceptions.NotFound,
                          self.store.add,
                          'fake_image_id', self.data_iter, self.data_len,
                          self.hash_algo)

        self.called_commands_expected = ['create', 'delete']

    @mock.patch.object(MockRBD.Image, 'resize')
    @mock.patch.object(rbd_store.Store, '_create_image')
    @mock.patch.object(rbd_store.Store, '_delete_image')
    def test_add_w_rbd_no_space_exception(self, delete, create, resize):
        def _fake_create_image(*args, **kwargs):
            self.called_commands_actual.append('create')
            return self.location

        def _fake_delete_image(target_pool, image_name, snapshot_name=None):
            self.assertEqual(self.location.pool, target_pool)
            self.assertEqual(self.location.image, image_name)
            self.assertEqual(self.location.snapshot, snapshot_name)
            self.called_commands_actual.append('delete')

        def _fake_resize(*args, **kwargs):
            raise MockRBD.NoSpace()
        create.side_effect = _fake_create_image
        delete.side_effect = _fake_delete_image
        resize.side_effect = _fake_resize

        self.assertRaises(exceptions.StorageFull,
                          self.store.add,
                          'fake_image_id', self.data_iter, 0,
                          self.hash_algo)

        self.called_commands_expected = ['create', 'delete']

    def test_add_duplicate_image(self):

        def _fake_create_image(*args, **kwargs):
            self.called_commands_actual.append('create')
            raise MockRBD.ImageExists()

        with mock.patch.object(self.store, '_create_image') as create_image:
            create_image.side_effect = _fake_create_image

            self.assertRaises(exceptions.Duplicate,
                              self.store.add,
                              'fake_image_id', self.data_iter, self.data_len,
                              self.hash_algo)
            self.called_commands_expected = ['create']

    def test_add_with_verifier(self):
        """Assert 'verifier.update' is called when verifier is provided."""
        self.store.chunk_size = units.Ki
        verifier = mock.MagicMock(name='mock_verifier')
        image_id = 'fake_image_id'
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        image_file = io.BytesIO(file_contents)

        with mock.patch.object(rbd_store.rbd.Image, 'write'):
            self.store.add(image_id, image_file, file_size, self.hash_algo,
                           verifier=verifier)

        verifier.update.assert_called_with(file_contents)

    def test_add_checksums(self):
        self.store.chunk_size = units.Ki
        image_id = 'fake_image_id'
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        image_file = io.BytesIO(file_contents)
        expected_checksum = md5(file_contents,
                                usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(file_contents).hexdigest()

        with mock.patch.object(rbd_store.rbd.Image, 'write'):
            loc, size, checksum, multihash, _ = self.store.add(
                image_id, image_file, file_size, self.hash_algo)

        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

    def test_add_thick_provisioning_with_holes_in_file(self):
        """
        Tests that a file which contains null bytes chunks is fully
        written to rbd backend in a thick provisioning configuration.
        """
        chunk_size = units.Mi
        content = b"*" * chunk_size + b"\x00" * chunk_size + b"*" * chunk_size
        self._do_test_thin_provisioning(content, 3 * chunk_size, 3, False)

    def test_add_thin_provisioning_with_holes_in_file(self):
        """
        Tests that a file which contains null bytes chunks is sparsified
        in rbd backend with a thin provisioning configuration.
        """
        chunk_size = units.Mi
        content = b"*" * chunk_size + b"\x00" * chunk_size + b"*" * chunk_size
        self._do_test_thin_provisioning(content, 3 * chunk_size, 2, True)

    def test_add_thick_provisioning_without_holes_in_file(self):
        """
        Tests that a file which not contain null bytes chunks is fully
        written to rbd backend in a thick provisioning configuration.
        """
        chunk_size = units.Mi
        content = b"*" * 3 * chunk_size
        self._do_test_thin_provisioning(content, 3 * chunk_size, 3, False)

    def test_add_thin_provisioning_without_holes_in_file(self):
        """
        Tests that a file which not contain null bytes chunks is fully
        written to rbd backend in a thin provisioning configuration.
        """
        chunk_size = units.Mi
        content = b"*" * 3 * chunk_size
        self._do_test_thin_provisioning(content, 3 * chunk_size, 3, True)

    def test_add_thick_provisioning_with_partial_holes_in_file(self):
        """
        Tests that a file which contains null bytes not aligned with
        chunk size is fully written with a thick provisioning configuration.
        """
        chunk_size = units.Mi
        my_chunk = int(chunk_size * 1.5)
        content = b"*" * my_chunk + b"\x00" * my_chunk + b"*" * my_chunk
        self._do_test_thin_provisioning(content, 3 * my_chunk, 5, False)

    def test_add_thin_provisioning_with_partial_holes_in_file(self):
        """
        Tests that a file which contains null bytes not aligned with
        chunk size is sparsified with a thin provisioning configuration.
        """
        chunk_size = units.Mi
        my_chunk = int(chunk_size * 1.5)
        content = b"*" * my_chunk + b"\x00" * my_chunk + b"*" * my_chunk
        self._do_test_thin_provisioning(content, 3 * my_chunk, 4, True)

    def _do_test_thin_provisioning(self, content, size, write, thin):
        self.config(rbd_store_chunk_size=1,
                    rbd_thin_provisioning=thin)
        self.store.configure()

        image_id = 'fake_image_id'
        image_file = io.BytesIO(content)
        expected_checksum = md5(content,
                                usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(content).hexdigest()

        with mock.patch.object(rbd_store.rbd.Image, 'write') as mock_write:
            loc, size, checksum, multihash, _ = self.store.add(
                image_id, image_file, size, self.hash_algo)
            self.assertEqual(mock_write.call_count, write)

        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

    def test_delete(self):
        def _fake_remove(*args, **kwargs):
            self.called_commands_actual.append('remove')

        with mock.patch.object(MockRBD.RBD, 'remove') as remove_image:
            remove_image.side_effect = _fake_remove

            self.store.delete(g_location.Location('test_rbd_store',
                                                  rbd_store.StoreLocation,
                                                  self.conf,
                                                  uri=self.location.get_uri()))
            self.called_commands_expected = ['remove']

    def test_delete_image(self):
        def _fake_remove(*args, **kwargs):
            self.called_commands_actual.append('remove')

        with mock.patch.object(MockRBD.RBD, 'remove') as remove_image:
            remove_image.side_effect = _fake_remove

            self.store._delete_image('fake_pool', self.location.image)
            self.called_commands_expected = ['remove']

    def test_delete_image_exc_image_not_found(self):
        def _fake_remove(*args, **kwargs):
            self.called_commands_actual.append('remove')
            raise MockRBD.ImageNotFound()

        with mock.patch.object(MockRBD.RBD, 'remove') as remove:
            remove.side_effect = _fake_remove
            self.assertRaises(exceptions.NotFound, self.store._delete_image,
                              'fake_pool', self.location.image)

            self.called_commands_expected = ['remove']

    @mock.patch.object(MockRBD.RBD, 'remove')
    @mock.patch.object(MockRBD.Image, 'remove_snap')
    @mock.patch.object(MockRBD.Image, 'unprotect_snap')
    def test_delete_image_w_snap(self, unprotect, remove_snap, remove):
        def _fake_unprotect_snap(*args, **kwargs):
            self.called_commands_actual.append('unprotect_snap')

        def _fake_remove_snap(*args, **kwargs):
            self.called_commands_actual.append('remove_snap')

        def _fake_remove(*args, **kwargs):
            self.called_commands_actual.append('remove')

        remove.side_effect = _fake_remove
        unprotect.side_effect = _fake_unprotect_snap
        remove_snap.side_effect = _fake_remove_snap
        self.store._delete_image('fake_pool', self.location.image,
                                 snapshot_name='snap')

        self.called_commands_expected = ['unprotect_snap', 'remove_snap',
                                         'remove']

    @mock.patch.object(MockRBD.RBD, 'remove')
    @mock.patch.object(MockRBD.Image, 'remove_snap')
    @mock.patch.object(MockRBD.Image, 'unprotect_snap')
    def test_delete_image_w_unprotected_snap(self, unprotect, remove_snap,
                                             remove):
        def _fake_unprotect_snap(*args, **kwargs):
            self.called_commands_actual.append('unprotect_snap')
            raise MockRBD.InvalidArgument()

        def _fake_remove_snap(*args, **kwargs):
            self.called_commands_actual.append('remove_snap')

        def _fake_remove(*args, **kwargs):
            self.called_commands_actual.append('remove')

        remove.side_effect = _fake_remove
        unprotect.side_effect = _fake_unprotect_snap
        remove_snap.side_effect = _fake_remove_snap
        self.store._delete_image('fake_pool', self.location.image,
                                 snapshot_name='snap')

        self.called_commands_expected = ['unprotect_snap', 'remove_snap',
                                         'remove']

    @mock.patch.object(MockRBD.RBD, 'remove')
    @mock.patch.object(MockRBD.Image, 'remove_snap')
    @mock.patch.object(MockRBD.Image, 'unprotect_snap')
    def test_delete_image_w_snap_with_error(self, unprotect, remove_snap,
                                            remove):
        def _fake_unprotect_snap(*args, **kwargs):
            self.called_commands_actual.append('unprotect_snap')
            raise TestException()

        def _fake_remove_snap(*args, **kwargs):
            self.called_commands_actual.append('remove_snap')

        def _fake_remove(*args, **kwargs):
            self.called_commands_actual.append('remove')

        remove.side_effect = _fake_remove
        unprotect.side_effect = _fake_unprotect_snap
        remove_snap.side_effect = _fake_remove_snap
        self.assertRaises(TestException, self.store._delete_image,
                          'fake_pool', self.location.image,
                          snapshot_name='snap')

        self.called_commands_expected = ['unprotect_snap']

    def test_delete_image_w_snap_exc_image_busy(self):
        def _fake_unprotect_snap(*args, **kwargs):
            self.called_commands_actual.append('unprotect_snap')
            raise MockRBD.ImageBusy()

        with mock.patch.object(MockRBD.Image, 'unprotect_snap') as mocked:
            mocked.side_effect = _fake_unprotect_snap

            self.assertRaises(exceptions.InUseByStore,
                              self.store._delete_image,
                              'fake_pool', self.location.image,
                              snapshot_name='snap')

            self.called_commands_expected = ['unprotect_snap']

    def test_delete_image_snap_has_external_references(self):
        with mock.patch.object(MockRBD.Image, 'list_children') as mocked:
            mocked.return_value = True

            self.store._delete_image('fake_pool',
                                     self.location.image,
                                     snapshot_name='snap')

    def test_delete_image_w_snap_exc_image_has_snap(self):
        def _fake_remove(*args, **kwargs):
            self.called_commands_actual.append('remove')
            raise MockRBD.ImageHasSnapshots()

        mock.patch.object(MockRBD.RBD, 'trash_move').start()

        with mock.patch.object(MockRBD.RBD, 'remove') as remove:
            remove.side_effect = _fake_remove
            self.store._delete_image('fake_pool',
                                     self.location.image)

            self.called_commands_expected = ['remove']

        MockRBD.RBD.trash_move.assert_called_once_with(mock.ANY, 'fake_image')

    def test_delete_image_w_snap_exc_image_has_snap_2(self):
        def _fake_remove(*args, **kwargs):
            self.called_commands_actual.append('remove')
            raise MockRBD.ImageHasSnapshots()

        mock.patch.object(MockRBD.RBD, 'trash_move',
                          side_effect=MockRBD.ImageBusy).start()

        with mock.patch.object(MockRBD.RBD, 'remove') as remove:
            remove.side_effect = _fake_remove
            self.assertRaises(exceptions.InUseByStore,
                              self.store._delete_image,
                              'fake_pool',
                              self.location.image)

            self.called_commands_expected = ['remove']

        MockRBD.RBD.trash_move.assert_called_once_with(mock.ANY, 'fake_image')

    def test_get_partial_image(self):
        loc = g_location.Location('test_rbd_store', rbd_store.StoreLocation,
                                  self.conf, store_specs=self.store_specs)
        self.assertRaises(exceptions.StoreRandomGetNotSupported,
                          self.store.get, loc, chunk_size=1)

    @mock.patch.object(MockRados.Rados, 'connect', side_effect=MockRados.Error)
    def test_rados_connect_error(self, _):
        rbd_store.rados.Error = MockRados.Error
        rbd_store.rados.ObjectNotFound = MockRados.ObjectNotFound

        def test():
            with self.store.get_connection('conffile', 'rados_id'):
                pass
        self.assertRaises(exceptions.BackendException, test)

    def test_create_image_conf_features(self):
        # Tests that we use non-0 features from ceph.conf and cast to int.
        fsid = 'fake'
        features = '3'
        conf_get_mock = mock.Mock(return_value=features)
        conn = mock.Mock(conf_get=conf_get_mock)
        ioctxt = mock.sentinel.ioctxt
        name = '1'
        size = 1024
        order = 3
        with mock.patch.object(rbd_store.rbd.RBD, 'create') as create_mock:
            location = self.store._create_image(
                fsid, conn, ioctxt, name, size, order)
            self.assertEqual(fsid, location.specs['fsid'])
            self.assertEqual(rbd_store.DEFAULT_POOL, location.specs['pool'])
            self.assertEqual(name, location.specs['image'])
            self.assertEqual(rbd_store.DEFAULT_SNAPNAME,
                             location.specs['snapshot'])

        create_mock.assert_called_once_with(ioctxt, name, size, order,
                                            old_format=False, features=3)

    def tearDown(self):
        self.assertEqual(self.called_commands_expected,
                         self.called_commands_actual)
        super(TestStore, self).tearDown()

    @mock.patch('oslo_utils.eventletutils.is_monkey_patched')
    def test_create_image_in_native_thread(self, mock_patched):
        mock_patched.return_value = True
        # Tests that we use non-0 features from ceph.conf and cast to int.
        fsid = 'fake'
        features = '3'
        conf_get_mock = mock.Mock(return_value=features)
        conn = mock.Mock(conf_get=conf_get_mock)
        ioctxt = mock.sentinel.ioctxt
        name = '1'
        size = 1024
        order = 3
        fake_proxy = mock.MagicMock()
        fake_rbd = mock.MagicMock()

        with mock.patch.object(rbd_store.tpool, 'Proxy') as tpool_mock, \
                mock.patch.object(rbd_store.rbd, 'RBD') as rbd_mock:
            tpool_mock.return_value = fake_proxy
            rbd_mock.return_value = fake_rbd
            location = self.store._create_image(
                fsid, conn, ioctxt, name, size, order)
            self.assertEqual(fsid, location.specs['fsid'])
            self.assertEqual(rbd_store.DEFAULT_POOL, location.specs['pool'])
            self.assertEqual(name, location.specs['image'])
            self.assertEqual(rbd_store.DEFAULT_SNAPNAME,
                             location.specs['snapshot'])

        tpool_mock.assert_called_once_with(fake_rbd)
        fake_proxy.create.assert_called_once_with(ioctxt, name, size, order,
                                                  old_format=False, features=3)

    @mock.patch('oslo_utils.eventletutils.is_monkey_patched')
    def test_delete_image_in_native_thread(self, mock_patched):
        mock_patched.return_value = True
        fake_proxy = mock.MagicMock()
        fake_rbd = mock.MagicMock()
        fake_ioctx = mock.MagicMock()

        with mock.patch.object(rbd_store.tpool, 'Proxy') as tpool_mock, \
                mock.patch.object(rbd_store.rbd, 'RBD') as rbd_mock, \
                mock.patch.object(self.store, 'get_connection') as mock_conn:

            mock_get_conn = mock_conn.return_value.__enter__.return_value
            mock_ioctx = mock_get_conn.open_ioctx.return_value.__enter__
            mock_ioctx.return_value = fake_ioctx
            tpool_mock.return_value = fake_proxy
            rbd_mock.return_value = fake_rbd

            self.store._delete_image('fake_pool', self.location.image)

            tpool_mock.assert_called_once_with(fake_rbd)
            fake_proxy.remove.assert_called_once_with(fake_ioctx,
                                                      self.location.image)

    @mock.patch.object(rbd_store, 'rbd')
    @mock.patch.object(rbd_store, 'tpool')
    @mock.patch('oslo_utils.eventletutils.is_monkey_patched')
    def test_rbd_proxy(self, mock_patched, mock_tpool, mock_rbd):
        mock_patched.return_value = False
        self.assertEqual(mock_rbd.RBD(), self.store.RBDProxy())

        mock_patched.return_value = True
        self.assertEqual(mock_tpool.Proxy.return_value, self.store.RBDProxy())
