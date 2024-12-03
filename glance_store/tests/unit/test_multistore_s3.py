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
from botocore import exceptions as boto_exceptions
from botocore import stub
from oslo_config import cfg
from oslo_utils import units

import glance_store as store
from glance_store._drivers import s3
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities


FAKE_UUID = str(uuid.uuid4())

FIVE_KB = 5 * units.Ki
S3_CONF = {
    's3_store_access_key': 'user',
    's3_store_secret_key': 'key',
    's3_store_host': 'https://s3-region1.com',
    's3_store_bucket': 'glance',
    's3_store_large_object_size': 9,        # over 9MB is large
    's3_store_large_object_chunk_size': 6,  # part size is 6MB
}


def format_s3_location(user, key, authurl, bucket, obj):
    """Helper method that returns a S3 store URI given the component pieces."""
    scheme = 's3'
    if authurl.startswith('https://'):
        scheme = 's3+https'
        authurl = authurl[8:]
    elif authurl.startswith('http://'):
        authurl = authurl[7:]
    authurl = authurl.strip('/')
    return "%s://%s:%s@%s/%s/%s" % (scheme, user, key, authurl,
                                    bucket, obj)


class TestMultiS3Store(base.MultiStoreBaseTest,
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

    def test_location_url_prefix_is_set(self):
        expected_url_prefix = "s3+https://user:key@s3-region1.com/glance"
        self.assertEqual(expected_url_prefix, self.store.url_prefix)

    def test_get_invalid_bucket_name(self):
        self.config(s3_store_bucket_url_format='virtual', group='s3_region1')

        invalid_buckets = ['not.dns.compliant', 'aa', 'bucket-']
        for bucket in invalid_buckets:
            loc = location.get_location_from_uri_and_backend(
                "s3+https://user:key@auth_address/%s/key" % bucket,
                's3_region1', conf=self.conf)
            self.assertRaises(boto_exceptions.InvalidDNSNameError,
                              self.store.get, loc)

    @mock.patch('glance_store.location.Location')
    @mock.patch.object(boto3.session.Session, "client")
    def test_client_custom_region_name(self, mock_client, mock_loc):
        """Test a custom s3_store_region_name in config"""
        mock_loc.accesskey = 'abcd'
        mock_loc.secretkey = 'efgh'
        mock_loc.bucket = 'bucket1'
        self.store._create_s3_client(mock_loc)
        mock_client.assert_called_with(
            config=mock.ANY,
            endpoint_url='https://s3-region1.com',
            region_name='custom_region_name',
            service_name='s3',
            use_ssl=False,
            verify='path/to/cert/bundle.pem',
        )

    @mock.patch('glance_store.location.Location')
    @mock.patch.object(boto3.session.Session, "client")
    def test_client_custom_ca_cert_bundle(self, mock_client, mock_loc):
        """Test a custom s3_store_cacert in config"""
        mock_loc.accesskey = 'abcd'
        mock_loc.secretkey = 'efgh'
        mock_loc.bucket = 'bucket1'
        self.store._create_s3_client(mock_loc)
        mock_client.assert_called_with(
            config=mock.ANY,
            endpoint_url='https://s3-region1.com',
            region_name='custom_region_name',
            service_name='s3',
            use_ssl=False,
            verify='path/to/cert/bundle.pem',
        )

    @mock.patch.object(boto3.session.Session, "client")
    def test_get(self, mock_client):
        """Test a "normal" retrieval of an image in chunks."""
        bucket, key = 'glance', FAKE_UUID
        fixture_object = {
            'Body': io.BytesIO(b"*" * FIVE_KB),
            'ContentLength': FIVE_KB
        }
        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_object',
                                 service_response={},
                                 expected_params={
                                     'Bucket': bucket,
                                     'Key': key
                                 })
            stubber.add_response(method='get_object',
                                 service_response=fixture_object,
                                 expected_params={
                                     'Bucket': bucket,
                                     'Key': key
                                 })
            mock_client.return_value = fake_s3_client

            loc = location.get_location_from_uri_and_backend(
                "s3+https://user:key@auth_address/%s/%s" % (bucket, key),
                's3_region1', conf=self.conf)
            (image_s3, image_size) = self.store.get(loc)

            self.assertEqual(FIVE_KB, image_size)

            expected_data = b"*" * FIVE_KB
            data = b""

            for chunk in image_s3:
                data += chunk
            self.assertEqual(expected_data, data)

    def test_partial_get(self):
        loc = location.get_location_from_uri_and_backend(
            "s3+https://user:key@auth_address/glance/%s" % FAKE_UUID,
            's3_region1', conf=self.conf)
        self.assertRaises(exceptions.StoreRandomGetNotSupported,
                          self.store.get, loc, chunk_size=1)

    @mock.patch.object(boto3.session.Session, "client")
    def test_get_non_existing(self, mock_client):
        """Test that trying to retrieve a s3 that doesn't exist raises an
        error
        """
        bucket, key = 'glance', 'no_exist'
        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_client_error(method='head_object',
                                     service_error_code='404',
                                     service_message='''
                                     The specified key does not exist.
                                     ''',
                                     expected_params={
                                         'Bucket': bucket,
                                         'Key': key
                                     })
            mock_client.return_value = fake_s3_client

            uri = "s3+https://user:key@auth_address/%s/%s" % (bucket, key)
            loc = location.get_location_from_uri_and_backend(uri,
                                                             's3_region1',
                                                             conf=self.conf)
            self.assertRaises(exceptions.NotFound, self.store.get, loc)

    @mock.patch.object(boto3.session.Session, "client")
    def test_add_singlepart(self, mock_client):
        """Test that we can add an image via the s3 backend."""
        expected_image_id = str(uuid.uuid4())
        # 5KiB is smaller than WRITE_CHUNKSIZE
        expected_s3_size = FIVE_KB
        expected_s3_contents = b"*" * expected_s3_size
        expected_checksum = hashlib.md5(expected_s3_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_s3_contents).hexdigest()
        expected_location = format_s3_location(
            S3_CONF['s3_store_access_key'],
            S3_CONF['s3_store_secret_key'],
            S3_CONF['s3_store_host'],
            S3_CONF['s3_store_bucket'],
            expected_image_id)
        image_s3 = io.BytesIO(expected_s3_contents)

        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': S3_CONF['s3_store_bucket']
                                 })
            stubber.add_client_error(method='head_object',
                                     service_error_code='404',
                                     service_message='',
                                     expected_params={
                                         'Bucket': S3_CONF['s3_store_bucket'],
                                         'Key': expected_image_id
                                     })
            stubber.add_response(method='put_object',
                                 service_response={},
                                 expected_params={
                                     'Bucket': S3_CONF['s3_store_bucket'],
                                     'Key': expected_image_id,
                                     'Body': botocore.stub.ANY
                                 })

            mock_client.return_value = fake_s3_client
            loc, size, checksum, multihash, metadata = \
                self.store.add(expected_image_id, image_s3, expected_s3_size,
                               self.hash_algo)
            self.assertEqual("s3_region1", metadata["store"])

            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_s3_size, size)
            self.assertEqual(expected_checksum, checksum)
            self.assertEqual(expected_multihash, multihash)

    @mock.patch.object(boto3.session.Session, "client")
    def test_add_singlepart_bigger_than_write_chunk(self, mock_client):
        """Test that we can add an image via the s3 backend."""
        expected_image_id = str(uuid.uuid4())
        # 8 MiB is bigger than WRITE_CHUNKSIZE(=5MiB),
        # but smaller than s3_store_large_object_size
        expected_s3_size = 8 * units.Mi
        expected_s3_contents = b"*" * expected_s3_size
        expected_checksum = hashlib.md5(expected_s3_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_s3_contents).hexdigest()
        expected_location = format_s3_location(
            S3_CONF['s3_store_access_key'],
            S3_CONF['s3_store_secret_key'],
            S3_CONF['s3_store_host'],
            S3_CONF['s3_store_bucket'],
            expected_image_id)
        image_s3 = io.BytesIO(expected_s3_contents)

        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': S3_CONF['s3_store_bucket']
                                 })
            stubber.add_client_error(method='head_object',
                                     service_error_code='404',
                                     service_message='',
                                     expected_params={
                                         'Bucket': S3_CONF['s3_store_bucket'],
                                         'Key': expected_image_id
                                     })
            stubber.add_response(method='put_object',
                                 service_response={},
                                 expected_params={
                                     'Bucket': S3_CONF['s3_store_bucket'],
                                     'Key': expected_image_id,
                                     'Body': botocore.stub.ANY
                                 })

            mock_client.return_value = fake_s3_client
            loc, size, checksum, multihash, metadata = \
                self.store.add(expected_image_id, image_s3, expected_s3_size,
                               self.hash_algo)
            self.assertEqual("s3_region1", metadata["store"])

            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_s3_size, size)
            self.assertEqual(expected_checksum, checksum)
            self.assertEqual(expected_multihash, multihash)

    @mock.patch.object(boto3.session.Session, "client")
    def test_add_different_backend(self, mock_client):
        self.store = s3.Store(self.conf, backend="s3_region2")
        self.store.configure()
        self.register_store_backend_schemes(self.store, 's3', 's3_region2')

        expected_image_id = str(uuid.uuid4())
        expected_s3_size = FIVE_KB
        expected_s3_contents = b"*" * expected_s3_size
        expected_checksum = hashlib.md5(expected_s3_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_s3_contents).hexdigest()
        expected_location = format_s3_location(
            S3_CONF['s3_store_access_key'],
            S3_CONF['s3_store_secret_key'],
            'http://s3-region2.com',
            S3_CONF['s3_store_bucket'],
            expected_image_id)
        image_s3 = io.BytesIO(expected_s3_contents)

        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': S3_CONF['s3_store_bucket']
                                 })
            stubber.add_client_error(method='head_object',
                                     service_error_code='404',
                                     service_message='',
                                     expected_params={
                                         'Bucket': S3_CONF['s3_store_bucket'],
                                         'Key': expected_image_id
                                     })
            stubber.add_response(method='put_object',
                                 service_response={},
                                 expected_params={
                                     'Bucket': S3_CONF['s3_store_bucket'],
                                     'Key': expected_image_id,
                                     'Body': botocore.stub.ANY
                                 })

            mock_client.return_value = fake_s3_client
            loc, size, checksum, multihash, metadata = \
                self.store.add(expected_image_id, image_s3, expected_s3_size,
                               self.hash_algo)
            self.assertEqual("s3_region2", metadata["store"])

            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_s3_size, size)
            self.assertEqual(expected_checksum, checksum)
            self.assertEqual(expected_multihash, multihash)

    @mock.patch.object(boto3.session.Session, "client")
    def test_add_with_verifier(self, mock_client):
        """Assert 'verifier.update' is called when verifier is provided"""
        expected_image_id = str(uuid.uuid4())
        expected_s3_size = FIVE_KB
        expected_s3_contents = b"*" * expected_s3_size
        image_s3 = io.BytesIO(expected_s3_contents)

        fake_s3_client = botocore.session.get_session().create_client('s3')
        verifier = mock.MagicMock(name='mock_verifier')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket', service_response={})
            stubber.add_client_error(method='head_object',
                                     service_error_code='404',
                                     service_message='')
            stubber.add_response(method='put_object', service_response={})

            mock_client.return_value = fake_s3_client
            self.store.add(expected_image_id, image_s3, expected_s3_size,
                           self.hash_algo, verifier=verifier)
        verifier.update.assert_called_with(expected_s3_contents)

    @mock.patch.object(boto3.session.Session, "client")
    def test_add_multipart(self, mock_client):
        """Test that we can add an image via the s3 backend."""
        expected_image_id = str(uuid.uuid4())
        expected_s3_size = 16 * units.Mi
        expected_s3_contents = b"*" * expected_s3_size
        expected_checksum = hashlib.md5(expected_s3_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_s3_contents).hexdigest()
        expected_location = format_s3_location(
            S3_CONF['s3_store_access_key'],
            S3_CONF['s3_store_secret_key'],
            S3_CONF['s3_store_host'],
            S3_CONF['s3_store_bucket'],
            expected_image_id)
        image_s3 = io.BytesIO(expected_s3_contents)

        fake_s3_client = botocore.session.get_session().create_client('s3')

        num_parts = 3  # image size = 16MB and chunk size is 6MB
        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': S3_CONF['s3_store_bucket']
                                 })
            stubber.add_client_error(method='head_object',
                                     service_error_code='404',
                                     service_message='',
                                     expected_params={
                                         'Bucket': S3_CONF['s3_store_bucket'],
                                         'Key': expected_image_id
                                     })
            stubber.add_response(method='create_multipart_upload',
                                 service_response={
                                     "Bucket": S3_CONF['s3_store_bucket'],
                                     "Key": expected_image_id,
                                     "UploadId": 'UploadId'
                                 },
                                 expected_params={
                                     "Bucket": S3_CONF['s3_store_bucket'],
                                     "Key": expected_image_id,
                                 })
            parts = []
            remaining_image_size = expected_s3_size
            chunk_size = S3_CONF['s3_store_large_object_chunk_size'] * units.Mi
            for i in range(num_parts):
                part_number = i + 1
                stubber.add_response(method='upload_part',
                                     service_response={
                                         'ETag': 'ETag'
                                     },
                                     expected_params={
                                         "Bucket": S3_CONF['s3_store_bucket'],
                                         "Key": expected_image_id,
                                         "Body": botocore.stub.ANY,
                                         'ContentLength': chunk_size,
                                         "PartNumber": part_number,
                                         "UploadId": 'UploadId'
                                     })
                parts.append({'ETag': 'ETag', 'PartNumber': part_number})

                remaining_image_size -= chunk_size
                if remaining_image_size < chunk_size:
                    chunk_size = remaining_image_size

            stubber.add_response(method='complete_multipart_upload',
                                 service_response={
                                     "Bucket": S3_CONF['s3_store_bucket'],
                                     "Key": expected_image_id,
                                     'ETag': 'ETag'
                                 },
                                 expected_params={
                                     "Bucket": S3_CONF['s3_store_bucket'],
                                     "Key": expected_image_id,
                                     "MultipartUpload": {
                                         "Parts": parts
                                     },
                                     "UploadId": 'UploadId'
                                 })

            mock_client.return_value = fake_s3_client
            loc, size, checksum, multihash, metadata = \
                self.store.add(expected_image_id, image_s3, expected_s3_size,
                               self.hash_algo)
            self.assertEqual("s3_region1", metadata["store"])

            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_s3_size, size)
            self.assertEqual(expected_checksum, checksum)
            self.assertEqual(expected_multihash, multihash)

    @mock.patch.object(boto3.session.Session, "client")
    def test_add_already_existing(self, mock_client):
        """Tests that adding an image with an existing identifier raises an
        appropriate exception
        """
        image_s3 = io.BytesIO(b"never_gonna_make_it")

        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket', service_response={})
            stubber.add_response(method='head_object', service_response={})
            mock_client.return_value = fake_s3_client
            self.assertRaises(exceptions.Duplicate, self.store.add,
                              FAKE_UUID, image_s3, 0, self.hash_algo)

    @mock.patch.object(boto3.session.Session, "client")
    def test_delete_non_existing(self, mock_client):
        """Test that trying to delete a s3 that doesn't exist raises an error
        """
        bucket, key = 'glance', 'no_exist'
        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_client_error(method='head_object',
                                     service_error_code='404',
                                     service_message='''
                                     The specified key does not exist.
                                     ''',
                                     expected_params={
                                         'Bucket': bucket,
                                         'Key': key
                                     })
            fake_s3_client.head_bucket = mock.MagicMock()
            mock_client.return_value = fake_s3_client

            uri = "s3+https://user:key@auth_address/%s/%s" % (bucket, key)
            loc = location.get_location_from_uri_and_backend(uri,
                                                             's3_region1',
                                                             conf=self.conf)
            self.assertRaises(exceptions.NotFound, self.store.delete, loc)
