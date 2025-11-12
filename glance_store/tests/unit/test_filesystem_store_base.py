# Copyright 2025 RedHat Inc.
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
import builtins
import errno
import hashlib
import io
import os
import stat
from unittest import mock
import uuid

import fixtures
from oslo_utils import units

from glance_store._drivers import filesystem
from glance_store import exceptions
from glance_store import location


class TestFilerStoreBase(object):

    def _test_get(self):
        image_id = str(uuid.uuid4())
        file_contents = b"chunk00000remainder"
        image_file = io.BytesIO(file_contents)

        if self.multistore:
            loc, size, checksum, metadata = self.store.add(
                image_id, image_file, len(file_contents))
            self.assertEqual(self.backend, metadata['store'])
        else:
            loc, size, checksum, multihash, _ = self.store.add(
                image_id, image_file, len(file_contents), self.hash_algo)

        # Now read it back...
        uri = "file:///%s/%s" % (self.test_dir, image_id)
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(uri, self.backend,
                                                             conf=self.conf)
        else:
            loc = location.get_location_from_uri(uri, conf=self.conf)

        (image_file, image_size) = self.store.get(loc)

        data_chunks = list(image_file)
        data = b"".join(data_chunks)

        self.assertEqual(file_contents, data)
        self.assertEqual(2, len(data_chunks))

    def _test_get_random_access(self):
        image_id = str(uuid.uuid4())
        file_contents = b"chunk00000remainder"
        image_file = io.BytesIO(file_contents)

        if self.multistore:
            loc, size, checksum, metadata = self.store.add(
                image_id, image_file, len(file_contents))
            self.assertEqual(self.backend, metadata['store'])
        else:
            loc, size, checksum, multihash, _ = self.store.add(
                image_id, image_file, len(file_contents), self.hash_algo)

        # Now read it back...
        uri = "file:///%s/%s" % (self.test_dir, image_id)
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(uri, self.backend,
                                                             conf=self.conf)
        else:
            loc = location.get_location_from_uri(uri, conf=self.conf)

        # Test reading one byte at a time from every offset
        data = bytearray()
        for offset in range(len(file_contents)):
            image_file, image_size = self.store.get(
                loc, offset=offset, chunk_size=1)
            for chunk in image_file:
                data.extend(chunk)
        self.assertEqual(file_contents, bytes(data))

        # Test reading a chunk from a specific offset
        chunk_size = 5
        image_file, image_size = self.store.get(
            loc, offset=chunk_size, chunk_size=chunk_size)
        chunk_data = b"".join(chunk for chunk in image_file)
        self.assertEqual(b'00000', chunk_data)
        self.assertEqual(chunk_size, image_size)

    def _test_get_non_existing(self):
        image_id = str(uuid.uuid4())
        uri = "file:///%s/%s" % (self.test_dir, image_id)
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(uri, self.backend,
                                                             conf=self.conf)
        else:
            loc = location.get_location_from_uri(uri, conf=self.conf)

        self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def _test_add(self):
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents,
                                        usedforsecurity=False).hexdigest()
        expected_location = "file://%s/%s" % (self.test_dir,
                                              expected_image_id)
        image_file = io.BytesIO(expected_file_contents)

        if self.multistore:
            loc, size, checksum, metadata = self.store.add(
                expected_image_id, image_file, expected_file_size)
            self.assertEqual(self.backend, metadata['store'])
        else:
            loc, size, checksum, multihash, _ = self.store.add(
                expected_image_id, image_file, expected_file_size,
                self.hash_algo)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)

        # Check the location
        uri = "file:///%s/%s" % (self.test_dir, expected_image_id)
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(uri, self.backend,
                                                             conf=self.conf)
        else:
            loc = location.get_location_from_uri(uri, conf=self.conf)

        (new_image_file, new_image_size) = self.store.get(loc)
        new_image_contents = b""
        new_image_file_size = 0

        for chunk in new_image_file:
            new_image_file_size += len(chunk)
            new_image_contents += chunk

        self.assertEqual(expected_file_contents, new_image_contents)
        self.assertEqual(expected_file_size, new_image_file_size)

    def _test_add_image_exceeding_max_size_raises_exception(self):
        expected_image_id = str(uuid.uuid4())
        path = os.path.join(self.test_dir, expected_image_id)
        # expected total size
        expected_file_size = 1020
        # simulate input with extra data
        image_file = io.BytesIO(b'a' * (expected_file_size + 100))

        # Call method and assert exception
        if self.multistore:
            self.assertRaisesRegex(
                exceptions.Invalid, "Size exceeds: expected",
                self.store.add, expected_image_id, image_file,
                expected_file_size)
        else:
            self.assertRaisesRegex(
                exceptions.Invalid, "Size exceeds: expected",
                self.store.add, expected_image_id, image_file,
                expected_file_size, self.hash_algo)

        # Verify partial data is deleted from backend
        self.assertFalse(os.path.exists(path))

        # Verify that the stream's position reflects the number of bytes read,
        # which should be exactly at expected_file_size plus the last buffer
        # size read.
        expected_read = expected_file_size + self.store.WRITE_CHUNKSIZE
        self.assertEqual(expected_read, image_file.tell(),
                         "The stream was not read only up to the expected "
                         "size.")

    def _test_write_less_than_declared_raises_exception(self):
        # Setup
        expected_image_id = str(uuid.uuid4())
        path = os.path.join(self.test_dir, expected_image_id)
        # expected total size
        actual_data_size = 800
        # declared size larger than actual data
        declared_size = 1000
        image_file = io.BytesIO(b'b' * actual_data_size)

        # Call method and assert exception
        if self.multistore:
            self.assertRaisesRegex(
                exceptions.Invalid, "Size mismatch: expected",
                self.store.add, expected_image_id, image_file,
                declared_size)
        else:
            self.assertRaisesRegex(
                exceptions.Invalid, "Size mismatch: expected",
                self.store.add, expected_image_id, image_file,
                declared_size, self.hash_algo)

        # Verify partial data is deleted from backend
        self.assertFalse(os.path.exists(path))
        # The input buffer should be fully read
        self.assertEqual(actual_data_size, image_file.tell(),
                         "Input stream was not fully read as expected")

    def _do_test_add(self, enable_thin_provisoning):
        """Test that we can add an image via the filesystem backend."""
        self.config(filesystem_store_chunk_size=units.Ki,
                    filesystem_thin_provisioning=enable_thin_provisoning,
                    group=self.backend)
        self.store.configure()

        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()
        expected_location = "file://%s/%s" % (self.test_dir,
                                              expected_image_id)
        image_file = io.BytesIO(expected_file_contents)

        if self.multistore:
            loc, size, checksum, metadata = self.store.add(
                expected_image_id, image_file, expected_file_size)
            self.assertEqual({'store': self.backend}, metadata)
        else:
            loc, size, checksum, multihash, _ = self.store.add(
                expected_image_id, image_file, expected_file_size,
                self.hash_algo)
            self.assertEqual(expected_multihash, multihash)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)

        uri = "file:///%s/%s" % (self.test_dir, expected_image_id)
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(uri, self.backend,
                                                             conf=self.conf)
        else:
            loc = location.get_location_from_uri(uri, conf=self.conf)

        (new_image_file, new_image_size) = self.store.get(loc)
        new_image_contents = b""
        new_image_file_size = 0

        for chunk in new_image_file:
            new_image_file_size += len(chunk)
            new_image_contents += chunk

        self.assertEqual(expected_file_contents, new_image_contents)
        self.assertEqual(expected_file_size, new_image_file_size)

    def _do_test_thin_provisioning(self, content, size, truncate, write, thin):
        self.config(filesystem_store_chunk_size=units.Ki,
                    filesystem_thin_provisioning=thin,
                    group=self.backend)
        self.store.configure()

        image_file = io.BytesIO(content)
        image_id = str(uuid.uuid4())
        with mock.patch.object(builtins, 'open') as popen:
            if self.multistore:
                self.store.add(image_id, image_file, size)
            else:
                self.store.add(image_id, image_file, size, self.hash_algo)

            write_count = popen.return_value.__enter__().write.call_count
            truncate_count = popen.return_value.__enter__().truncate.call_count
            self.assertEqual(write_count, write)
            self.assertEqual(truncate_count, truncate)

    def _test_add_with_verifier(self):
        """Test that 'verifier.update' is called when verifier is provided."""
        verifier = mock.MagicMock(name='mock_verifier')
        self.config(filesystem_store_chunk_size=units.Ki,
                    group=self.backend)
        self.store.configure()

        image_id = str(uuid.uuid4())
        file_size = units.Ki  # 1K
        file_contents = b"*" * file_size
        image_file = io.BytesIO(file_contents)

        if self.multistore:
            location, size, checksum, metadata = self.store.add(
                image_id, image_file, file_size, verifier=verifier)
        else:
            self.store.add(image_id, image_file, file_size, self.hash_algo,
                           verifier=verifier)

        verifier.update.assert_called_with(file_contents)

    def _test_add_check_metadata_with_invalid_mountpoint_location(self):
        in_metadata = [{'id': 'abcdefg',
                        'mountpoint': '/xyz/images'}]
        if self.multistore:
            location, size, checksum, metadata = self._store_image(in_metadata)
            self.assertEqual({'store': 'file1'}, metadata)
        else:
            location, size, checksum, multihash, metadata = self._store_image(
                in_metadata)
            self.assertEqual({}, metadata)

    def _test_add_check_metadata_list_with_invalid_mountpoint_locations(self):
        in_metadata = [{'id': 'abcdefg', 'mountpoint': '/xyz/images'},
                       {'id': 'xyz1234', 'mountpoint': '/pqr/images'}]
        if self.multistore:
            location, size, checksum, metadata = self._store_image(in_metadata)
            self.assertEqual({'store': 'file1'}, metadata)
        else:
            location, size, checksum, multihash, metadata = self._store_image(
                in_metadata)
            self.assertEqual({}, metadata)

    def _test_add_check_metadata_list_with_valid_mountpoint_locations(self):
        in_metadata = [{'id': 'abcdefg', 'mountpoint': '/tmp'},
                       {'id': 'xyz1234', 'mountpoint': '/xyz'}]
        if self.multistore:
            location, size, checksum, metadata = self._store_image(in_metadata)
            self.assertEqual("file1", metadata["store"])
        else:
            location, size, checksum, multihash, metadata = self._store_image(
                in_metadata)

        self.assertEqual(in_metadata[0], metadata)

    def _test_add_check_metadata_bad_nosuch_file(self):
        expected_image_id = str(uuid.uuid4())
        jsonfilename = os.path.join(self.test_dir,
                                    "storage_metadata.%s" % expected_image_id)

        self.config(filesystem_store_metadata_file=jsonfilename,
                    group=self.backend)
        expected_file_size = 10
        expected_file_contents = b"*" * expected_file_size
        image_file = io.BytesIO(expected_file_contents)

        if self.multistore:
            location, size, checksum, metadata = self.store.add(
                expected_image_id, image_file, expected_file_size)
            self.assertEqual({'store': self.backend}, metadata)
        else:
            location, size, checksum, multihash, metadata = self.store.add(
                expected_image_id, image_file, expected_file_size,
                self.hash_algo)
            self.assertEqual({}, metadata)

    def _test_add_already_existing(self):
        """
        Tests that adding an image with an existing identifier
        raises an appropriate exception
        """
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        image_file = io.BytesIO(file_contents)
        dup_image_file = io.BytesIO(b"nevergonnamakeit")
        if self.multistore:
            location, size, checksum, metadata = self.store.add(
                image_id, image_file, file_size)
            self.assertEqual("file1", metadata["store"])
            self.assertRaises(exceptions.Duplicate,
                              self.store.add,
                              image_id, dup_image_file, 0)
        else:
            location, size, checksum, multihash, metadata = self.store.add(
                image_id, image_file, file_size, self.hash_algo)
            self.assertEqual({}, metadata)
            self.assertRaises(exceptions.Duplicate,
                              self.store.add,
                              image_id, dup_image_file, 0, self.hash_algo)

    def _do_test_add_write_failure(self, errno, exception):
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        path = os.path.join(self.test_dir, image_id)
        image_file = io.BytesIO(file_contents)

        with mock.patch.object(builtins, 'open') as popen:
            e = IOError()
            e.errno = errno
            popen.side_effect = e

            if self.multistore:
                self.assertRaises(exception,
                                  self.store.add,
                                  image_id, image_file, 0)
            else:
                self.assertRaises(exception,
                                  self.store.add,
                                  image_id, image_file, 0, self.hash_algo)
            self.assertFalse(os.path.exists(path))

    def _test_add_cleanup_on_read_failure(self):
        """Tests partial image is cleaned up after a read failure."""
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        path = os.path.join(self.test_dir, image_id)
        image_file = io.BytesIO(file_contents)

        def fake_Error(size):
            raise AttributeError()

        with mock.patch.object(image_file, 'read') as mock_read:
            mock_read.side_effect = fake_Error

            if self.multistore:
                self.assertRaises(AttributeError,
                                  self.store.add,
                                  image_id, image_file, 0)
            else:
                self.assertRaises(AttributeError,
                                  self.store.add,
                                  image_id, image_file, 0, self.hash_algo)
            self.assertFalse(os.path.exists(path))

    def _test_delete(self):
        """
        Test we can delete an existing image in the filesystem store
        """
        # First add an image
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        image_file = io.BytesIO(file_contents)

        if self.multistore:
            loc, size, checksum, metadata = self.store.add(
                image_id, image_file, file_size)
            self.assertEqual('file1', metadata['store'])
        else:
            loc, size, checksum, multihash, _ = self.store.add(
                image_id, image_file, file_size, self.hash_algo)

        # Now check that we can delete it
        uri = "file:///%s/%s" % (self.test_dir, image_id)
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(uri, 'file1',
                                                             conf=self.conf)
        else:
            loc = location.get_location_from_uri(uri, conf=self.conf)

        self.store.delete(loc)
        self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def _test_delete_non_existing(self):
        """
        Test that trying to delete a file that doesn't exist
        raises an error
        """
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                "file:///tmp/glance-tests/non-existing", 'file1',
                conf=self.conf)
        else:
            loc = location.get_location_from_uri(
                "file:///tmp/glance-tests/non-existing", conf=self.conf)

        self.assertRaises(exceptions.NotFound,
                          self.store.delete,
                          loc)

    def _test_delete_forbidden(self):
        """
        Tests that trying to delete a file without permissions
        raises the correct error
        """
        # First add an image
        image_id = str(uuid.uuid4())
        file_size = 5 * units.Ki  # 5K
        file_contents = b"*" * file_size
        image_file = io.BytesIO(file_contents)

        if self.multistore:
            loc, size, checksum, metadata = self.store.add(
                image_id, image_file, file_size)
        else:
            loc, size, checksum, multihash, _ = self.store.add(
                image_id, image_file, file_size, self.hash_algo)

        uri = "file:///%s/%s" % (self.test_dir, image_id)
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(uri, 'file1',
                                                             conf=self.conf)
        else:
            loc = location.get_location_from_uri(uri, conf=self.conf)

        # Mock unlink to raise an OSError for lack of permissions
        # and make sure we can't delete the image
        with mock.patch.object(os, 'unlink') as unlink:
            e = OSError()
            e.errno = errno.EACCES
            unlink.side_effect = e

            self.assertRaises(exceptions.Forbidden,
                              self.store.delete,
                              loc)

            # Make sure the image didn't get deleted
            self.store.get(loc)

    def _test_configure_add_with_multi_datadirs(self):
        """Test multiple filesystems are parsed correctly."""
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group=self.backend)
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group='backend_defaults')
        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200"],
                               group=self.backend)
        self.store.configure_add()

        expected_priority_map = {100: [store_map[0]], 200: [store_map[1]]}
        expected_priority_list = [200, 100]
        self.assertEqual(expected_priority_map, self.store.priority_data_map)
        self.assertEqual(expected_priority_list, self.store.priority_list)

    def _test_configure_add_with_metadata_file_success(self):
        metadata = {'id': 'asdf1234',
                    'mountpoint': '/tmp'}
        self._create_metadata_json_file(metadata, group=self.backend)
        self.store.configure_add()
        self.assertEqual([metadata], self.store.FILESYSTEM_STORE_METADATA)

    def _test_configure_add_check_metadata_list_of_dicts_success(self):
        metadata = [{'id': 'abcdefg', 'mountpoint': '/xyz/images'},
                    {'id': 'xyz1234', 'mountpoint': '/tmp/'}]
        self._create_metadata_json_file(metadata, group=self.backend)
        self.store.configure_add()
        self.assertEqual(metadata, self.store.FILESYSTEM_STORE_METADATA)

    def _test_configure_add_check_metadata_success_list_val_for_some_key(self):
        metadata = {'akey': ['value1', 'value2'], 'id': 'asdf1234',
                    'mountpoint': '/tmp'}
        self._create_metadata_json_file(metadata, group=self.backend)
        self.store.configure_add()
        self.assertEqual([metadata], self.store.FILESYSTEM_STORE_METADATA)

    def _test_configure_add_check_metadata_bad_data(self):
        metadata = {'akey': 10, 'id': 'asdf1234',
                    'mountpoint': '/tmp'}  # only unicode is allowed
        self._create_metadata_json_file(metadata, group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def _test_configure_add_check_metadata_with_no_id_or_mountpoint(self):
        metadata = {'mountpoint': '/tmp'}
        self._create_metadata_json_file(metadata, group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

        metadata = {'id': 'asdfg1234'}
        self._create_metadata_json_file(metadata, group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def _test_cfg_add_check_metadata_id_or_mountpoint_is_not_string(self):
        metadata = {'id': 10, 'mountpoint': '/tmp'}
        self._create_metadata_json_file(metadata, group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

        metadata = {'id': 'asdf1234', 'mountpoint': 12345}
        self._create_metadata_json_file(metadata, group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def _test_cfg_add_check_metadata_list_with_no_id_or_mountpoint(self):
        metadata = [{'id': 'abcdefg', 'mountpoint': '/xyz/images'},
                    {'mountpoint': '/pqr/images'}]
        self._create_metadata_json_file(metadata, group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

        metadata = [{'id': 'abcdefg'},
                    {'id': 'xyz1234', 'mountpoint': '/pqr/images'}]
        self._create_metadata_json_file(metadata, group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def _test_add_check_metadata_list_id_or_mountpoint_is_not_string(self):
        metadata = [{'id': 'abcdefg', 'mountpoint': '/xyz/images'},
                    {'id': 1234, 'mountpoint': '/pqr/images'}]
        self._create_metadata_json_file(metadata, group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

        metadata = [{'id': 'abcdefg', 'mountpoint': 1234},
                    {'id': 'xyz1234', 'mountpoint': '/pqr/images'}]
        self._create_metadata_json_file(metadata, group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def _test_configure_add_same_dir_multiple_times(self):
        """Tests handling of same dir in config multiple times.

        Tests BadStoreConfiguration exception is raised if same directory
        is specified multiple times in filesystem_store_datadirs with different
        priorities.
        """
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.clear_override('filesystem_store_datadir',
                                 group=self.backend)
        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200",
                                store_map[0] + ":300"],
                               group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def _test_configure_add_same_dir_multiple_times_same_priority(self):
        """Tests handling of same dir in config multiple times.

        Tests BadStoreConfiguration exception is raised if same directory
        is specified multiple times in filesystem_store_datadirs with the same
        priority.
        """
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group=self.backend)
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group='backend_defaults')
        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200",
                                store_map[0] + ":100"],
                               group=self.backend)
        try:
            self.store.configure()
        except exceptions.BadStoreConfiguration:
            self.fail("configure() raised BadStoreConfiguration unexpectedly!")

        # Test that we can add an image via the filesystem backend
        filesystem.ChunkedFile.CHUNKSIZE = 1024
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents,
                                        usedforsecurity=False).hexdigest()
        expected_location = "file://%s/%s" % (store_map[1],
                                              expected_image_id)
        image_file = io.BytesIO(expected_file_contents)

        if self.multistore:
            loc, size, checksum, metadata = self.store.add(expected_image_id,
                                                           image_file,
                                                           expected_file_size)
            self.assertEqual("file1", metadata["store"])
        else:
            loc, size, checksum, multihash, _ = self.store.add(
                expected_image_id, image_file, expected_file_size,
                self.hash_algo)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)

        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                expected_location, "file1", conf=self.conf)
        else:
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

    def _test_add_with_multiple_dirs(self):
        """Test adding multiple filesystem directories."""
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group=self.backend)
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group='backend_defaults')

        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200"],
                               group=self.backend)

        self.store.configure()

        # Test that we can add an image via the filesystem backend
        filesystem.ChunkedFile.CHUNKSIZE = units.Ki
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()
        expected_location = "file://%s/%s" % (store_map[1],
                                              expected_image_id)
        image_file = io.BytesIO(expected_file_contents)

        if self.multistore:
            loc, size, checksum, metadata = self.store.add(
                expected_image_id, image_file, expected_file_size)
            self.assertEqual("file1", metadata["store"])
        else:
            loc, size, checksum, multihash, _ = self.store.add(
                expected_image_id, image_file, expected_file_size,
                self.hash_algo)
            self.assertEqual(expected_multihash, multihash)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)

        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                expected_location, self.backend, conf=self.conf)
        else:
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

    def _test_add_with_multiple_dirs_storage_full(self):
        """Tests adding dirs with storage full.

        Test StorageFull exception is raised if no filesystem directory
        is found that can store an image.
        """
        store_map = [self.useFixture(fixtures.TempDir()).path,
                     self.useFixture(fixtures.TempDir()).path]
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group=self.backend)
        self.conf.set_override('filesystem_store_datadir',
                               override=None,
                               group='backend_defaults')
        self.conf.set_override('filesystem_store_datadirs',
                               [store_map[0] + ":100",
                                store_map[1] + ":200"],
                               group=self.backend)

        self.store.configure_add()

        def fake_get_capacity_info(mount_point):
            return 0

        with mock.patch.object(self.store, '_get_capacity_info') as capacity:
            capacity.return_value = 0

            filesystem.ChunkedFile.CHUNKSIZE = units.Ki
            expected_image_id = str(uuid.uuid4())
            expected_file_size = 5 * units.Ki  # 5K
            expected_file_contents = b"*" * expected_file_size
            image_file = io.BytesIO(expected_file_contents)

            if self.multistore:
                self.assertRaises(exceptions.StorageFull, self.store.add,
                                  expected_image_id, image_file,
                                  expected_file_size)
            else:
                self.assertRaises(exceptions.StorageFull, self.store.add,
                                  expected_image_id, image_file,
                                  expected_file_size, self.hash_algo)

    def _test_configure_add_with_file_perm(self):
        """Tests adding with permissions.

        Tests filesystem specified by filesystem_store_file_perm
        are parsed correctly.
        """
        store = self.useFixture(fixtures.TempDir()).path
        self.conf.set_override('filesystem_store_datadir', store,
                               group=self.backend)
        self.conf.set_override('filesystem_store_file_perm', 700,  # -rwx------
                               group=self.backend)
        self.store.configure_add()
        self.assertEqual(self.store.datadir, store)

    def _test_configure_add_with_inaccessible_file_perm(self):
        """Tests adding with inaccessible file permissions.

        Tests BadStoreConfiguration exception is raised if an invalid
        file permission specified in filesystem_store_file_perm.
        """
        store = self.useFixture(fixtures.TempDir()).path
        self.conf.set_override('filesystem_store_datadir', store,
                               group=self.backend)
        self.conf.set_override('filesystem_store_file_perm', 7,  # -------rwx
                               group=self.backend)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure_add)

    def _test_add_with_file_perm_for_group_other_users_access(self):
        """Tests adding image with file permissions.

        Test that we can add an image via the filesystem backend with a
        required image file permission.
        """
        store = self.useFixture(fixtures.TempDir()).path
        self.conf.set_override('filesystem_store_datadir', store,
                               group=self.backend)
        self.conf.set_override('filesystem_store_file_perm', 744,  # -rwxr--r--
                               group=self.backend)

        # -rwx------
        os.chmod(store, 0o700)
        self.assertEqual(0o700, stat.S_IMODE(os.stat(store)[stat.ST_MODE]))

        self.store.configure_add()

        filesystem.Store.WRITE_CHUNKSIZE = units.Ki
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents,
                                        usedforsecurity=False).hexdigest()
        expected_location = "file://%s/%s" % (store,
                                              expected_image_id)
        image_file = io.BytesIO(expected_file_contents)

        if self.multistore:
            location, size, checksum, metadata = self.store.add(
                expected_image_id, image_file, expected_file_size)
            self.assertEqual("file1", metadata["store"])
        else:
            location, size, checksum, multihash, metadata = self.store.add(
                expected_image_id, image_file, expected_file_size,
                self.hash_algo)

        self.assertEqual(expected_location, location)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)

        # -rwx--x--x for store directory
        self.assertEqual(0o711, stat.S_IMODE(os.stat(store)[stat.ST_MODE]))
        # -rwxr--r-- for image file
        mode = os.stat(expected_location[len('file:/'):])[stat.ST_MODE]
        perm = int(str(getattr(self.conf,
                               self.backend).filesystem_store_file_perm), 8)
        self.assertEqual(perm, stat.S_IMODE(mode))

    def _test_add_with_file_perm_for_owner_users_access(self):
        """Tests adding image with file permissions.

        Test that we can add an image via the filesystem backend with a
        required image file permission.
        """
        store = self.useFixture(fixtures.TempDir()).path
        self.conf.set_override('filesystem_store_datadir', store,
                               group=self.backend)
        self.conf.set_override('filesystem_store_file_perm', 600,  # -rw-------
                               group=self.backend)

        # -rwx------
        os.chmod(store, 0o700)
        self.assertEqual(0o700, stat.S_IMODE(os.stat(store)[stat.ST_MODE]))

        self.store.configure_add()

        filesystem.Store.WRITE_CHUNKSIZE = units.Ki
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 5 * units.Ki  # 5K
        expected_file_contents = b"*" * expected_file_size
        expected_checksum = hashlib.md5(expected_file_contents,
                                        usedforsecurity=False).hexdigest()
        expected_location = "file://%s/%s" % (store,
                                              expected_image_id)
        image_file = io.BytesIO(expected_file_contents)

        if self.multistore:
            location, size, checksum, metadata = self.store.add(
                expected_image_id, image_file, expected_file_size)
            self.assertEqual("file1", metadata["store"])
        else:
            location, size, checksum, multihash, metadata = self.store.add(
                expected_image_id, image_file, expected_file_size,
                self.hash_algo)

        self.assertEqual(expected_location, location)
        self.assertEqual(expected_file_size, size)
        self.assertEqual(expected_checksum, checksum)

        # -rwx------ for store directory
        self.assertEqual(0o700, stat.S_IMODE(os.stat(store)[stat.ST_MODE]))
        # -rw------- for image file
        mode = os.stat(expected_location[len('file:/'):])[stat.ST_MODE]
        perm = int(str(getattr(self.conf,
                               self.backend).filesystem_store_file_perm), 8)
        self.assertEqual(perm, stat.S_IMODE(mode))

    def _test_configure_add_chunk_size(self):
        # This definitely won't be the default
        chunk_size = units.Gi
        self.config(filesystem_store_chunk_size=chunk_size,
                    group=self.backend)
        self.store.configure_add()

        self.assertEqual(chunk_size, self.store.chunk_size)
        self.assertEqual(chunk_size, self.store.READ_CHUNKSIZE)
        self.assertEqual(chunk_size, self.store.WRITE_CHUNKSIZE)
