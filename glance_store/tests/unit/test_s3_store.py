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

"""Tests the S3 backend store"""

from glance_store._drivers import s3
from glance_store.tests import base
from glance_store.tests.unit import test_s3_store_base
from glance_store.tests.unit import test_store_capabilities

S3_CONF = {
    's3_store_access_key': 'user',
    's3_store_secret_key': 'key',
    's3_store_region_name': '',
    's3_store_host': 'localhost',
    's3_store_bucket': 'glance',
    's3_store_large_object_size': 9,  # over 9MB is large
    's3_store_large_object_chunk_size': 6,  # part size is 6MB
}


class TestStore(base.StoreBaseTest,
                test_s3_store_base.TestS3StoreBase,
                test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        """Establish a clean test environment."""
        super(TestStore, self).setUp()
        # Set default values for multistore and backend
        self.multistore = False
        self.backend = 'glance_store'

        self.store = s3.Store(self.conf)
        self.config(**S3_CONF)
        self.store.configure()
        self.register_store_schemes(self.store, 's3')

        self.hash_algo = 'sha256'

    def test_get_invalid_bucket_name(self):
        self._test_get_invalid_bucket_name()

    def test_client_custom_region_name(self):
        self._test_client_custom_region_name()

    def test_client_custom_ca_cert_bundle(self):
        self._test_client_custom_ca_cert_bundle()

    def test_get(self):
        self._test_get()

    def test_partial_get(self):
        self._test_partial_get()

    def test_get_non_existing(self):
        self._test_get_non_existing()

    def test_add_singlepart(self):
        self._test_add_singlepart()

    def test_add_singlepart_size_exceeding_max_size(self):
        self._test_add_singlepart_size_exceeding_max_size()

    def test_add_singlepart_write_less_than_declared(self):
        self._test_add_singlepart_write_less_than_declared()

    def test_add_singlepart_bigger_than_write_chunk(self):
        self._test_add_singlepart_bigger_than_write_chunk()

    def test_add_with_verifier(self):
        self._test_add_with_verifier()

    def test_add_multipart(self):
        self._test_add_multipart()

    def test_add_multipart_size_exceeding_max_size(self):
        self._test_add_multipart_size_exceeding_max_size()

    def test_add_multipart_write_less_than_declared(self):
        self._test_add_multipart_write_less_than_declared()

    def test_add_already_existing(self):
        self._test_add_already_existing()

    def test_no_access_key(self):
        self._test_no_access_key()

    def test_no_secret_key(self):
        self._test_no_secret_key()

    def test_no_host(self):
        self._test_no_host()

    def test_no_bucket(self):
        self._test_no_bucket()

    def test_delete_non_existing(self):
        self._test_delete_non_existing()

    def test_get_s3_good_location(self):
        self._test_get_s3_good_location()

    def test_get_my_object_storage_location(self):
        self._test_get_my_object_storage_location()
