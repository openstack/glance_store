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

"""Tests the Multiple S3 backend store"""

import hashlib
import io
from unittest import mock
import uuid

import boto3
import botocore
from botocore import stub
from oslo_config import cfg

import glance_store as store
from glance_store._drivers import s3
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_s3_store_base
from glance_store.tests.unit import test_store_capabilities

S3_CONF = {
    's3_store_access_key': 'user',
    's3_store_secret_key': 'key',
    's3_store_host': 'https://s3-region1.com',
    's3_store_bucket': 'glance',
    's3_store_large_object_size': 9,  # over 9MB is large
    's3_store_large_object_chunk_size': 6,  # part size is 6MB
}


class TestMultiS3Store(base.MultiStoreBaseTest,
                       test_s3_store_base.TestS3StoreBase,
                       test_store_capabilities.TestStoreCapabilitiesChecking):
    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        """Establish a clean test environment."""
        super(TestMultiS3Store, self).setUp()
        enabled_backends = {
            "s3_region1": "s3",
            "s3_region2": "s3"
        }
        self.hash_algo = 'sha256'
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='s3_region1', group='glance_store')

        # set s3 related config options
        self.config(group='s3_region1',
                    s3_store_access_key='user',
                    s3_store_secret_key='key',
                    s3_store_host='https://s3-region1.com',
                    s3_store_region_name='custom_region_name',
                    s3_store_cacert='path/to/cert/bundle.pem',
                    s3_store_bucket='glance',
                    s3_store_large_object_size=S3_CONF[
                        's3_store_large_object_size'
                    ],
                    s3_store_large_object_chunk_size=6)

        self.config(group='s3_region2',
                    s3_store_access_key='user',
                    s3_store_secret_key='key',
                    s3_store_host='http://s3-region2.com',
                    s3_store_bucket='glance',
                    s3_store_large_object_size=S3_CONF[
                        's3_store_large_object_size'
                    ],
                    s3_store_large_object_chunk_size=6)
        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}
        store.create_multi_stores(self.conf)

        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.addCleanup(self.conf.reset)

        self.store = s3.Store(self.conf, backend="s3_region1")
        self.store.configure()
        self.register_store_backend_schemes(self.store, 's3', 's3_region1')

        # Set default multistore and backend parameters
        self.multistore = True
        self.backend = 's3_region1'

    def test_location_url_prefix_is_set(self):
        expected_url_prefix = "s3+https://user:key@s3-region1.com/glance"
        self.assertEqual(expected_url_prefix, self.store.url_prefix)

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
        """Test that we can add an image via the s3 backend."""
        self._test_add_singlepart()

    def test_add_singlepart_size_exceeding_max_size(self):
        self._test_add_singlepart_size_exceeding_max_size()

    def test_add_singlepart_write_less_than_declared(self):
        self._test_add_singlepart_write_less_than_declared()

    def test_add_singlepart_bigger_than_write_chunk(self):
        self._test_add_singlepart_bigger_than_write_chunk()

    def test_add_different_backend(self):
        self._test_add_different_backend()

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

    def test_delete_non_existing(self):
        self._test_delete_non_existing()

    def test_no_access_key(self):
        self._test_no_access_key()

    def test_no_secret_key(self):
        self._test_no_secret_key()

    def test_no_host(self):
        self._test_no_host()

    def test_no_bucket(self):
        self._test_no_bucket()

    def test_get_s3_good_location(self):
        self._test_get_s3_good_location()

    def test_add_multipart_zero_byte_image(self):
        """Bug #2124829: add a zero-byte image using multipart upload."""
        expected_image_id = str(uuid.uuid4())
        expected_s3_size = 0
        expected_s3_contents = b""
        expected_checksum = hashlib.md5(expected_s3_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_s3_contents).hexdigest()
        backend_conf = getattr(self.conf, self.backend)

        expected_location = test_s3_store_base.format_s3_location(
            backend_conf.s3_store_access_key,
            backend_conf.s3_store_secret_key,
            backend_conf.s3_store_host,
            backend_conf.s3_store_bucket,
            expected_image_id)
        image_s3 = io.BytesIO(expected_s3_contents)

        self.config(group=self.backend, s3_store_large_object_size=0)
        self.store.configure()
        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket
                                 })
            stubber.add_client_error(
                method='head_object', service_error_code='404',
                service_message='',
                expected_params={
                    'Bucket': backend_conf.s3_store_bucket,
                    'Key': expected_image_id})
            stubber.add_response(method='create_multipart_upload',
                                 service_response={
                                     "Bucket": backend_conf.s3_store_bucket,
                                     "Key": expected_image_id,
                                     "UploadId": 'UploadId'
                                 },
                                 expected_params={
                                     "Bucket": backend_conf.s3_store_bucket,
                                     "Key": expected_image_id,
                                 })

            stubber.add_response(method='abort_multipart_upload',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket,
                                     'Key': expected_image_id,
                                     'UploadId': 'UploadId'
                                 })
            stubber.add_response(method='put_object',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket,
                                     'Key': expected_image_id,
                                     'Body': b''
                                 })

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client

                loc, size, checksum, multihash, metadata = \
                    self.store.add(expected_image_id, image_s3,
                                   expected_s3_size,
                                   self.hash_algo)

                stubber.assert_no_pending_responses()
                self.assertEqual(self.backend, metadata["store"])
                self.assertEqual(expected_location, loc)
                self.assertEqual(expected_s3_size, size)
                self.assertEqual(expected_checksum, checksum)
                self.assertEqual(expected_multihash, multihash)

    def test_get_my_object_storage_location(self):
        self._test_get_my_object_storage_location()
