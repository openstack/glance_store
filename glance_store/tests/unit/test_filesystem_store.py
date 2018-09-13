# Copyright 2011 OpenStack Foundation
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

"""Tests the filesystem backend store"""

import errno
import hashlib
import json
import mock
import os
import stat
import uuid

import fixtures
from oslo_utils import units
import six
from six.moves import builtins
# NOTE(jokke): simplified transition to py3, behaves like py2 xrange
from six.moves import range

from glance_store._drivers import filesystem
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities


class TestStore(base.StoreBaseTest,
                test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        """Establish a clean test environment."""
        super(TestStore, self).setUp()
        self.store = filesystem.Store(self.conf)
        self.config(filesystem_store_datadir=self.test_dir,
                    filesystem_store_chunk_size=10,
                    stores=['glance.store.filesystem.Store'],
                    group="glance_store")
        self.store.configure()
        self.register_store_schemes(self.store, 'file')
        self.hash_algo = 'sha256'

    def _create_metadata_json_file(self, metadata):
        expected_image_id = str(uuid.uuid4())
        jsonfilename = os.path.join(self.test_dir,
                                    "storage_metadata.%s" % expected_image_id)

        self.config(filesystem_store_metadata_file=jsonfilename,
                    group="glance_store")
        with open(jsonfilename, 'w') as fptr:
            json.dump(metadata, fptr)

    def _store_image(self, in_metadata):
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 10
        expected_file_contents = b"*" * expected_file_size
        image_file = six.BytesIO(expected_file_contents)
        self.store.FILESYSTEM_STORE_METADATA = in_metadata
        return self.store.add(expected_image_id, image_file,
                              expected_file_size, self.hash_algo)

    def test_get(self):
        """Test a "normal" retrieval of an image in chunks."""
        # First add an image...
        image_id = str(uuid.uuid4())
        file_contents = b"chunk00000remainder"
        image_file = six.BytesIO(file_contents)

        loc, size, checksum, multihash, _ = self.store.add(
            image_id, image_file, len(file_contents), self.hash_algo)

        # Now read it back...
        uri = "file:///%s/%s" % (self.test_dir, image_id)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        (image_file, image_size) = self.store.get(loc)

        expected_data = b"chunk00000remainder"
        expected_num_chunks = 2
        data = b""
        num_chunks = 0

        for chunk in image_file:
            num_chunks += 1
            data += chunk
        self.assertEqual(expected_data, data)
        self.assertEqual(expected_num_chunks, num_chunks)

    def test_get_random_access(self):
        """Test a "normal" retrieval of an image in chunks."""
        # First add an image...
        image_id = str(uuid.uuid4())
        file_contents = b"chunk00000remainder"
        image_file = six.BytesIO(file_contents)

        loc, size, checksum, multihash, _ = self.store.add(
            image_id, image_file, len(file_contents), self.hash_algo)

        # Now read it back...
        uri = "file:///%s/%s" % (self.test_dir, image_id)
        loc = location.get_location_from_uri(uri, conf=self.conf)

        data = b""
        for offset in range(len(file_contents)):
            (image_file, image_size) = self.store.get(loc,
                                                      offset=offset,
                                                      chunk_size=1)
            for chunk in image_file:
                data += chunk

        self.assertEqual(file_contents, data)

        data = b""
        chunk_size = 5
        (image_file, image_size) = self.store.get(loc,
                                                  offset=chunk_size,
                                                  chunk_size=chunk_size)
        for chunk in image_file:
            data += chunk

        self.assertEqual(b'00000', data)
        self.assertEqual(chunk_size, image_size)

    def test_get_non_existing(self):
        """
        Test that trying to retrieve a file that doesn't exist
        raises an error
        """
        loc = location.get_location_from_uri(
            "file:///%s/non-existing" % self.test_dir, conf=self.conf)
        self.assertRaises(exceptions.NotFound,
                          self.store.get,
                          loc)

    def test_add(self):
        """Test that we can add an image via the filesystem backend."""
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()
        expected_location = "file://%s/%s" % (self.test_dir,
                                              expected_image_id)
        image_file = six.BytesIO(expected_file_contents)

        loc, size, checksum, multihash, _ = self.store.add(
            expected_image_id, image_file, expected_file_size, self.hash_algo)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

        uri = "file:///%s/%s" % (self.test_dir, expected_image_id)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        (new_image_file, new_image_size) = self.store.get(loc)
        new_image_contents = b""
        new_image_file_size = 0

        for chunk in new_image_file:
            new_image_file_size += len(chunk)
            new_image_contents += chunk

        self.assertEqual(expected_file_contents, new_image_contents)
        self.assertEqual(expected_file_size, new_image_file_size)

    def test_add_with_verifier(self):
        """Test that 'verifier.update' is called when verifier is provided."""
        verifier = mock.MagicMock(name='mock_verifier')
        self.config(filesystem_store_chunk_size=units.Ki,
                    group='glance_store')
        self.store.configure()

        image_id = str(uuid.uuid4())
        file_size = units.Ki  # 1K
        file_contents = b"*" * file_size
        image_file = six.BytesIO(file_contents)

        self.store.add(image_id, image_file, file_size, self.hash_algo,
                       verifier=verifier)

        verifier.update.assert_called_with(file_contents)

    def test_add_check_metadata_with_invalid_mountpoint_location(self):
        in_metadata = [{'id': 'abcdefg',
                       'mountpoint': '/xyz/images'}]
        location, size, checksum, multihash, metadata = self._store_image(
            in_metadata)
        self.assertEqual({}, metadata)

    def test_add_check_metadata_list_with_invalid_mountpoint_locations(self):
        in_metadata = [{'id': 'abcdefg', 'mountpoint': '/xyz/images'},
                       {'id': 'xyz1234', 'mountpoint': '/pqr/images'}]
        location, size, checksum, multihash, metadata = self._store_image(
            in_metadata)
        self.assertEqual({}, metadata)

    def test_add_check_metadata_list_with_valid_mountpoint_locations(self):
        in_metadata = [{'id': 'abcdefg', 'mountpoint': '/tmp'},
                       {'id': 'xyz1234', 'mountpoint': '/xyz'}]
        location, size, checksum, multihash, metadata = self._store_image(
            in_metadata)
        self.assertEqual(in_metadata[0], metadata)

    def test_add_check_metadata_bad_nosuch_file(self):
        expected_image_id = str(uuid.uuid4())
        jsonfilename = os.path.join(self.test_dir,
                                    "storage_metadata.%s" % expected_image_id)

        self.config(filesystem_store_metadata_file=jsonfilename,
                    group="glance_store")
        expected_file_size = 10
        expected_file_contents = b"*" * expected_file_size
        image_file = six.BytesIO(expected_file_contents)

        location, size, checksum, multihash, metadata = self.store.add(
            expected_image_id, image_file, expected_file_size, self.hash_algo)

        self.assertEqual(metadata, {})

    def test_add_already_existing(self):
        """
        Tests that adding an image with an existing identifier
        raises an appropriate exception
        """
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        image_file = six.BytesIO(file_contents)

        location, size, checksum, multihash, _ = self.store.add(
            image_id, image_file, file_size, self.hash_algo)
        image_file = six.BytesIO(b"nevergonnamakeit")
        self.assertRaises(exceptions.Duplicate,
                          self.store.add,
                          image_id, image_file, 0, self.hash_algo)

    def _do_test_add_write_failure(self, errno, exception):
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        path = os.path.join(self.test_dir, image_id)
        image_file = six.BytesIO(file_contents)

        with mock.patch.object(builtins, 'open') as popen:
            e = IOError()
            e.errno = errno
            popen.side_effect = e

            self.assertRaises(exception,
                              self.store.add,
                              image_id, image_file, 0, self.hash_algo)
            self.assertFalse(os.path.exists(path))

    def test_add_storage_full(self):
        """
        Tests that adding an image without enough space on disk
        raises an appropriate exception
        """
        self._do_test_add_write_failure(errno.ENOSPC, exceptions.StorageFull)

    def test_add_file_too_big(self):
        """
        Tests that adding an excessively large image file
        raises an appropriate exception
        """
        self._do_test_add_write_failure(errno.EFBIG, exceptions.StorageFull)

    def test_add_storage_write_denied(self):
        """
        Tests that adding an image with insufficient filestore permissions
        raises an appropriate exception
        """
        self._do_test_add_write_failure(errno.EACCES,
                                        exceptions.StorageWriteDenied)

    def test_add_other_failure(self):
        """
        Tests that a non-space-related IOError does not raise a
        StorageFull exceptions.
        """
        self._do_test_add_write_failure(errno.ENOTDIR, IOError)

    def test_add_cleanup_on_read_failure(self):
        """
        Tests the partial image file is cleaned up after a read
        failure.
        """
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        path = os.path.join(self.test_dir, image_id)
        image_file = six.BytesIO(file_contents)

        def fake_Error(size):
            raise AttributeError()

        with mock.patch.object(image_file, 'read') as mock_read:
            mock_read.side_effect = fake_Error

            self.assertRaises(AttributeError,
                              self.store.add,
                              image_id, image_file, 0, self.hash_algo)
            self.assertFalse(os.path.exists(path))

    def test_delete(self):
        """
        Test we can delete an existing image in the filesystem store
        """
        # First add an image
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        image_file = six.BytesIO(file_contents)

        loc, size, checksum, multihash, _ = self.store.add(
            image_id, image_file, file_size, self.hash_algo)

        # Now check that we can delete it
        uri = "file:///%s/%s" % (self.test_dir, image_id)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.store.delete(loc)

        self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def test_delete_non_existing(self):
        """
        Test that trying to delete a file that doesn't exist
        raises an error
        """
        loc = location.get_location_from_uri(
            "file:///tmp/glance-tests/non-existing", conf=self.conf)
        self.assertRaises(exceptions.NotFound,
                          self.store.delete,
                          loc)

    def test_delete_forbidden(self):
        """
        Tests that trying to delete a file without permissions
        raises the correct error
        """
        # First add an image
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        image_file = six.BytesIO(file_contents)

        loc, size, checksum, multihash, _ = self.store.add(
            image_id, image_file, file_size, self.hash_algo)

        uri = "file:///%s/%s" % (self.test_dir, image_id)
        loc = location.get_location_from_uri(uri, conf=self.conf)

        # Mock unlink to raise an OSError for lack of permissions
        # and make sure we can't delete the image
        with mock.patch.object(os, 'unlink') as unlink:
            e = OSError()
            e.errno = errno
            unlink.side_effect = e

            self.assertRaises(exceptions.Forbidden,
                              self.store.delete,
                              loc)

            # Make sure the image didn't get deleted
            self.store.get(loc)

    def test_configure_add_with_multi_datadirs(self):
        """
        Tests multiple filesystem specified by filesystem_store_datadirs
        are parsed correctly.
        """
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group='glance_store')
        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200"],
                               group='glance_store')
        self.store.configure_add()

        expected_priority_map = {100: [store_map[0]], 200: [store_map[1]]}
        expected_priority_list = [200, 100]
        self.assertEqual(expected_priority_map, self.store.priority_data_map)
        self.assertEqual(expected_priority_list, self.store.priority_list)

    def test_configure_add_with_metadata_file_success(self):
        metadata = {'id': 'asdf1234',
                    'mountpoint': '/tmp'}
        self._create_metadata_json_file(metadata)
        self.store.configure_add()
        self.assertEqual([metadata], self.store.FILESYSTEM_STORE_METADATA)

    def test_configure_add_check_metadata_list_of_dicts_success(self):
        metadata = [{'id': 'abcdefg', 'mountpoint': '/xyz/images'},
                    {'id': 'xyz1234', 'mountpoint': '/tmp/'}]
        self._create_metadata_json_file(metadata)
        self.store.configure_add()
        self.assertEqual(metadata, self.store.FILESYSTEM_STORE_METADATA)

    def test_configure_add_check_metadata_success_list_val_for_some_key(self):
        metadata = {'akey': ['value1', 'value2'], 'id': 'asdf1234',
                    'mountpoint': '/tmp'}
        self._create_metadata_json_file(metadata)
        self.store.configure_add()
        self.assertEqual([metadata], self.store.FILESYSTEM_STORE_METADATA)

    def test_configure_add_check_metadata_bad_data(self):
        metadata = {'akey': 10, 'id': 'asdf1234',
                    'mountpoint': '/tmp'}  # only unicode is allowed
        self._create_metadata_json_file(metadata)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def test_configure_add_check_metadata_with_no_id_or_mountpoint(self):
        metadata = {'mountpoint': '/tmp'}
        self._create_metadata_json_file(metadata)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

        metadata = {'id': 'asdfg1234'}
        self._create_metadata_json_file(metadata)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def test_configure_add_check_metadata_id_or_mountpoint_is_not_string(self):
        metadata = {'id': 10, 'mountpoint': '/tmp'}
        self._create_metadata_json_file(metadata)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

        metadata = {'id': 'asdf1234', 'mountpoint': 12345}
        self._create_metadata_json_file(metadata)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def test_configure_add_check_metadata_list_with_no_id_or_mountpoint(self):
        metadata = [{'id': 'abcdefg', 'mountpoint': '/xyz/images'},
                    {'mountpoint': '/pqr/images'}]
        self._create_metadata_json_file(metadata)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

        metadata = [{'id': 'abcdefg'},
                    {'id': 'xyz1234', 'mountpoint': '/pqr/images'}]
        self._create_metadata_json_file(metadata)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def test_add_check_metadata_list_id_or_mountpoint_is_not_string(self):
        metadata = [{'id': 'abcdefg', 'mountpoint': '/xyz/images'},
                    {'id': 1234, 'mountpoint': '/pqr/images'}]
        self._create_metadata_json_file(metadata)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

        metadata = [{'id': 'abcdefg', 'mountpoint': 1234},
                    {'id': 'xyz1234', 'mountpoint': '/pqr/images'}]
        self._create_metadata_json_file(metadata)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def test_configure_add_same_dir_multiple_times(self):
        """
        Tests BadStoreConfiguration exception is raised if same directory
        is specified multiple times in filesystem_store_datadirs.
        """
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.clear_override('filesystem_store_datadir',
                                 group='glance_store')
        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200",
                                store_map[0] + ":300"],
                               group='glance_store')
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def test_configure_add_same_dir_multiple_times_same_priority(self):
        """
        Tests BadStoreConfiguration exception is raised if same directory
        is specified multiple times in filesystem_store_datadirs.
        """
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group='glance_store')
        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200",
                                store_map[0] + ":100"],
                               group='glance_store')
        try:
            self.store.configure()
        except exceptions.BadStoreConfiguration:
            self.fail("configure() raised BadStoreConfiguration unexpectedly!")

        # Test that we can add an image via the filesystem backend
        filesystem.ChunkedFile.CHUNKSIZE = 1024
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()
        expected_location = "file://%s/%s" % (store_map[1],
                                              expected_image_id)
        image_file = six.BytesIO(expected_file_contents)

        loc, size, checksum, multihash, _ = self.store.add(
            expected_image_id, image_file, expected_file_size, self.hash_algo)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

        loc = location.get_location_from_uri(expected_location,
                                             conf=self.conf)
        (new_image_file, new_image_size) = self.store.get(loc)
        new_image_contents = b""
        new_image_file_size = 0

        for chunk in new_image_file:
            new_image_file_size += len(chunk)
            new_image_contents += chunk

        self.assertEqual(expected_file_contents, new_image_contents)
        self.assertEqual(expected_file_size, new_image_file_size)

    def test_add_with_multiple_dirs(self):
        """Test adding multiple filesystem directories."""
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group='glance_store')

        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200"],
                               group='glance_store')

        self.store.configure()

        # Test that we can add an image via the filesystem backend
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()
        expected_location = "file://%s/%s" % (store_map[1],
                                              expected_image_id)
        image_file = six.BytesIO(expected_file_contents)

        loc, size, checksum, multihash, _ = self.store.add(
            expected_image_id, image_file, expected_file_size, self.hash_algo)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

        loc = location.get_location_from_uri(expected_location,
                                             conf=self.conf)
        (new_image_file, new_image_size) = self.store.get(loc)
        new_image_contents = b""
        new_image_file_size = 0

        for chunk in new_image_file:
            new_image_file_size += len(chunk)
            new_image_contents += chunk

        self.assertEqual(expected_file_contents, new_image_contents)
        self.assertEqual(expected_file_size, new_image_file_size)

    def test_add_with_multiple_dirs_storage_full(self):
        """
        Test StorageFull exception is raised if no filesystem directory
        is found that can store an image.
        """
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group='glance_store')
        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200"],
                               group='glance_store')

        self.store.configure_add()

        def fake_get_capacity_info(mount_point):
            return 0

        with mock.patch.object(self.store, '_get_capacity_info') as capacity:
            capacity.return_value = 0

            filesystem.ChunkedFile.CHUNKSIZE = units.Ki
            expected_image_id = str(uuid.uuid4())
            expected_file_size = 5 * units.Ki  # 5K
            expected_file_contents = b"*" * expected_file_size
            image_file = six.BytesIO(expected_file_contents)

            self.assertRaises(exceptions.StorageFull,
                              self.store.add,
                              expected_image_id,
                              image_file,
                              expected_file_size,
                              self.hash_algo)

    def test_configure_add_with_file_perm(self):
        """
        Tests filesystem specified by filesystem_store_file_perm
        are parsed correctly.
        """
        store = self.useFixture(fixtures.TempDir()).path
        self.conf.set_override('filesystem_store_datadir', store,
                               group='glance_store')
        self.conf.set_override('filesystem_store_file_perm', 700,  # -rwx------
                               group='glance_store')
        self.store.configure_add()
        self.assertEqual(self.store.datadir, store)

    def test_configure_add_with_unaccessible_file_perm(self):
        """
        Tests BadStoreConfiguration exception is raised if an invalid
        file permission specified in filesystem_store_file_perm.
        """
        store = self.useFixture(fixtures.TempDir()).path
        self.conf.set_override('filesystem_store_datadir', store,
                               group='glance_store')
        self.conf.set_override('filesystem_store_file_perm', 7,  # -------rwx
                               group='glance_store')
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def test_add_with_file_perm_for_group_other_users_access(self):
        """
        Test that we can add an image via the filesystem backend with a
        required image file permission.
        """
        store = self.useFixture(fixtures.TempDir()).path
        self.conf.set_override('filesystem_store_datadir', store,
                               group='glance_store')
        self.conf.set_override('filesystem_store_file_perm', 744,  # -rwxr--r--
                               group='glance_store')

        # -rwx------
        os.chmod(store, 0o700)
        self.assertEqual(0o700, stat.S_IMODE(os.stat(store)[stat.ST_MODE]))

        self.store.configure_add()

        filesystem.Store.WRITE_CHUNKSIZE = units.Ki
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()
        expected_location = "file://%s/%s" % (store,
                                              expected_image_id)
        image_file = six.BytesIO(expected_file_contents)

        location, size, checksum, multihash, _ = self.store.add(
            expected_image_id, image_file, expected_file_size, self.hash_algo)

        self.assertEqual(expected_location, location)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

        # -rwx--x--x for store directory
        self.assertEqual(0o711, stat.S_IMODE(os.stat(store)[stat.ST_MODE]))
        # -rwxr--r-- for image file
        mode = os.stat(expected_location[len('file:/'):])[stat.ST_MODE]
        perm = int(str(self.conf.glance_store.filesystem_store_file_perm), 8)
        self.assertEqual(perm, stat.S_IMODE(mode))

    def test_add_with_file_perm_for_owner_users_access(self):
        """
        Test that we can add an image via the filesystem backend with a
        required image file permission.
        """
        store = self.useFixture(fixtures.TempDir()).path
        self.conf.set_override('filesystem_store_datadir', store,
                               group='glance_store')
        self.conf.set_override('filesystem_store_file_perm', 600,  # -rw-------
                               group='glance_store')

        # -rwx------
        os.chmod(store, 0o700)
        self.assertEqual(0o700, stat.S_IMODE(os.stat(store)[stat.ST_MODE]))

        self.store.configure_add()

        filesystem.Store.WRITE_CHUNKSIZE = units.Ki
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()
        expected_location = "file://%s/%s" % (store,
                                              expected_image_id)
        image_file = six.BytesIO(expected_file_contents)

        location, size, checksum, multihash, _ = self.store.add(
            expected_image_id, image_file, expected_file_size, self.hash_algo)

        self.assertEqual(expected_location, location)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

        # -rwx------ for store directory
        self.assertEqual(0o700, stat.S_IMODE(os.stat(store)[stat.ST_MODE]))
        # -rw------- for image file
        mode = os.stat(expected_location[len('file:/'):])[stat.ST_MODE]
        perm = int(str(self.conf.glance_store.filesystem_store_file_perm), 8)
        self.assertEqual(perm, stat.S_IMODE(mode))

    def test_configure_add_chunk_size(self):
        # This definitely won't be the default
        chunk_size = units.Gi
        self.config(filesystem_store_chunk_size=chunk_size,
                    group="glance_store")
        self.store.configure_add()

        self.assertEqual(chunk_size, self.store.chunk_size)
        self.assertEqual(chunk_size, self.store.READ_CHUNKSIZE)
        self.assertEqual(chunk_size, self.store.WRITE_CHUNKSIZE)
