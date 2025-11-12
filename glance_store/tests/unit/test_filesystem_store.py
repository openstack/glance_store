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
import io
import json
import os
import uuid

from oslo_utils import units

from glance_store._drivers import filesystem
from glance_store import exceptions
from glance_store.tests import base
from glance_store.tests.unit import test_filesystem_store_base as file_base
from glance_store.tests.unit import test_store_capabilities


class TestStore(base.StoreBaseTest,
                file_base.TestFilerStoreBase,
                test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        super(TestStore, self).setUp()
        # Set default values for multistore and backend
        self.multistore = False
        self.backend = 'glance_store'

        self.store = filesystem.Store(self.conf)
        self.config(filesystem_store_datadir=self.test_dir,
                    filesystem_store_chunk_size=10,
                    stores=['glance.store.filesystem.Store'],
                    group="glance_store")
        self.store.configure()
        self.register_store_schemes(self.store, 'file')
        self.hash_algo = 'sha256'

    def _create_metadata_json_file(self, metadata, group=None):
        expected_image_id = str(uuid.uuid4())
        jsonfilename = os.path.join(self.test_dir,
                                    "storage_metadata.%s" % expected_image_id)
        self.config(filesystem_store_metadata_file=jsonfilename,
                    group=group)
        with open(jsonfilename, 'w') as fptr:
            json.dump(metadata, fptr)

    def _store_image(self, in_metadata):
        expected_image_id = str(uuid.uuid4())
        expected_file_size = 10
        expected_file_contents = b"*" * expected_file_size
        image_file = io.BytesIO(expected_file_contents)
        self.store.FILESYSTEM_STORE_METADATA = in_metadata
        return self.store.add(expected_image_id, image_file,
                              expected_file_size, self.hash_algo)

    def test_get(self):
        self._test_get()

    def test_get_random_access(self):
        self._test_get_random_access()

    def test_get_non_existing(self):
        """
        Test that trying to retrieve a file that doesn't exist
        raises an error
        """
        self._test_get_non_existing()

    def test_add(self):
        self._test_add()

    def test_add_image_exceeding_max_size_raises_exception(self):
        self._test_add_image_exceeding_max_size_raises_exception()

    def test_write_less_than_declared_raises_exception(self):
        self._test_write_less_than_declared_raises_exception()

    def test_thin_provisioning_is_disabled_by_default(self):
        self.assertEqual(self.store.thin_provisioning, False)

    def test_add_with_thick_provisioning(self):
        self._do_test_add(enable_thin_provisoning=False)

    def test_add_with_thin_provisioning(self):
        self._do_test_add(enable_thin_provisoning=True)

    def test_add_thick_provisioning_with_holes_in_file(self):
        """
        Tests that a file which contains null bytes chunks is fully
        written with a thick provisioning configuration.
        """
        chunk_size = units.Ki  # 1K
        content = b"*" * chunk_size + b"\x00" * chunk_size + b"*" * chunk_size
        self._do_test_thin_provisioning(content, 3 * chunk_size, 0, 3, False)

    def test_add_thin_provisioning_with_holes_in_file(self):
        """
        Tests that a file which contains null bytes chunks is sparsified
        with a thin provisioning configuration.
        """
        chunk_size = units.Ki  # 1K
        content = b"*" * chunk_size + b"\x00" * chunk_size + b"*" * chunk_size
        self._do_test_thin_provisioning(content, 3 * chunk_size, 1, 2, True)

    def test_add_thick_provisioning_without_holes_in_file(self):
        """
        Tests that a file which not contain null bytes chunks is fully
        written with a thick provisioning configuration.
        """
        chunk_size = units.Ki  # 1K
        content = b"*" * 3 * chunk_size
        self._do_test_thin_provisioning(content, 3 * chunk_size, 0, 3, False)

    def test_add_thin_provisioning_without_holes_in_file(self):
        """
        Tests that a file which not contain null bytes chunks is fully
        written with a thin provisioning configuration.
        """
        chunk_size = units.Ki  # 1K
        content = b"*" * 3 * chunk_size
        self._do_test_thin_provisioning(content, 3 * chunk_size, 0, 3, True)

    def test_add_thick_provisioning_with_partial_holes_in_file(self):
        """
        Tests that a file which contains null bytes not aligned with
        chunk size is fully written with a thick provisioning configuration.
        """
        chunk_size = units.Ki  # 1K
        my_chunk = int(chunk_size * 1.5)
        content = b"*" * my_chunk + b"\x00" * my_chunk + b"*" * my_chunk
        self._do_test_thin_provisioning(content, 3 * my_chunk, 0, 5, False)

    def test_add_thin_provisioning_with_partial_holes_in_file(self):
        """
        Tests that a file which contains null bytes not aligned with
        chunk size is sparsified with a thin provisioning configuration.
        """
        chunk_size = units.Ki  # 1K
        my_chunk = int(chunk_size * 1.5)
        content = b"*" * my_chunk + b"\x00" * my_chunk + b"*" * my_chunk
        self._do_test_thin_provisioning(content, 3 * my_chunk, 1, 4, True)

    def test_add_with_verifier(self):
        self._test_add_with_verifier()

    def test_add_check_metadata_with_invalid_mountpoint_location(self):
        self._test_add_check_metadata_with_invalid_mountpoint_location()

    def test_add_check_metadata_list_with_invalid_mountpoint_locations(self):
        self._test_add_check_metadata_list_with_invalid_mountpoint_locations()

    def test_add_check_metadata_list_with_valid_mountpoint_locations(self):
        self._test_add_check_metadata_list_with_valid_mountpoint_locations()

    def test_add_check_metadata_bad_nosuch_file(self):
        self._test_add_check_metadata_bad_nosuch_file()

    def test_add_already_existing(self):
        self._test_add_already_existing()

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
        self._test_add_cleanup_on_read_failure()

    def test_delete(self):
        self._test_delete()

    def test_delete_non_existing(self):
        self._test_delete_non_existing()

    def test_delete_forbidden(self):
        self._test_delete_forbidden()

    def test_configure_add_with_multi_datadirs(self):
        self._test_configure_add_with_multi_datadirs()

    def test_configure_add_with_metadata_file_success(self):
        self._test_configure_add_with_metadata_file_success()

    def test_configure_add_check_metadata_list_of_dicts_success(self):
        self._test_configure_add_check_metadata_list_of_dicts_success()

    def test_configure_add_check_metadata_success_list_val_for_some_key(self):
        self._test_configure_add_check_metadata_success_list_val_for_some_key()

    def test_configure_add_check_metadata_bad_data(self):
        self._test_configure_add_check_metadata_bad_data()

    def test_configure_add_check_metadata_with_no_id_or_mountpoint(self):
        self._test_configure_add_check_metadata_with_no_id_or_mountpoint()

    def test_configure_add_check_metadata_id_or_mountpoint_is_not_string(self):
        self._test_cfg_add_check_metadata_id_or_mountpoint_is_not_string()

    def test_configure_add_check_metadata_list_with_no_id_or_mountpoint(self):
        self._test_cfg_add_check_metadata_list_with_no_id_or_mountpoint()

    def test_add_check_metadata_list_id_or_mountpoint_is_not_string(self):
        self._test_add_check_metadata_list_id_or_mountpoint_is_not_string()

    def test_configure_add_same_dir_multiple_times(self):
        self._test_configure_add_same_dir_multiple_times()

    def test_configure_add_same_dir_multiple_times_same_priority(self):
        self._test_configure_add_same_dir_multiple_times_same_priority()

    def test_add_with_multiple_dirs(self):
        self._test_add_with_multiple_dirs()

    def test_add_with_multiple_dirs_storage_full(self):
        self._test_add_with_multiple_dirs_storage_full()

    def test_configure_add_with_file_perm(self):
        self._test_configure_add_with_file_perm()

    def test_configure_add_with_inaccessible_file_perm(self):
        self._test_configure_add_with_inaccessible_file_perm()

    def test_add_with_file_perm_for_group_other_users_access(self):
        self._test_add_with_file_perm_for_group_other_users_access()

    def test_add_with_file_perm_for_owner_users_access(self):
        self._test_add_with_file_perm_for_owner_users_access()

    def test_configure_add_chunk_size(self):
        self._test_configure_add_chunk_size()
