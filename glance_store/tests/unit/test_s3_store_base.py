# Copyright 2025 OpenStack Foundation
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
import uuid

import boto3
import botocore
from botocore import exceptions as boto_exceptions
from botocore import stub
from oslo_utils import units

from glance_store._drivers import s3
from glance_store import capabilities
from glance_store import exceptions
from glance_store import location

# Constants
FAKE_UUID = str(uuid.uuid4())
FIVE_KB = 5 * units.Ki
S3_CONF = {
    's3_store_access_key': 'user',
    's3_store_secret_key': 'key',
    's3_store_region_name': '',
    's3_store_host': 'localhost',
    's3_store_bucket': 'glance',
    's3_store_large_object_size': 9,  # over 9MB is large
    's3_store_large_object_chunk_size': 6,  # part size is 6MB
}


def format_s3_location(user, key, authurl, bucket, obj):
    """Helper method that returns a S3 store URI given the component pieces."""
    scheme = 's3'
    if authurl.startswith('https://'):
        scheme = 's3+https'
        authurl = authurl[len('https://'):]
    elif authurl.startswith('http://'):
        authurl = authurl[len('http://'):]
    authurl = authurl.strip('/')
    return "%s://%s:%s@%s/%s/%s" % (scheme, user, key, authurl, bucket, obj)


class TestS3StoreBase(object):

    def _test_get(self):
        """Test a "normal" retrieval of an image in chunks."""
        bucket, key = 'glance', str(uuid.uuid4())
        fixture_object = {
            'Body': io.BytesIO(b"*" * 5 * units.Ki),
            'ContentLength': 5 * units.Ki
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

            with mock.patch.object(boto3.session.Session,
                                   "client") as mock_client:
                mock_client.return_value = fake_s3_client

                if self.multistore:
                    loc = location.get_location_from_uri_and_backend(
                        "s3://user:key@auth_address/%s/%s" % (bucket, key),
                        self.backend, conf=self.conf)
                else:
                    loc = location.get_location_from_uri(
                        "s3://user:key@auth_address/%s/%s" % (bucket, key),
                        conf=self.conf)
                (image_s3, image_size) = self.store.get(loc)

                self.assertEqual(5 * units.Ki, image_size)

                expected_data = b"*" * 5 * units.Ki
                data = b""

                for chunk in image_s3:
                    data += chunk
                self.assertEqual(expected_data, data)

    def _test_get_non_existing(self):
        """Test trying to retrieve a s3 that doesn't exist raises an error."""
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

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client

                uri = "s3://user:key@auth_address/%s/%s" % (bucket, key)
                if self.multistore:
                    loc = location.get_location_from_uri_and_backend(
                        uri, self.backend, conf=self.conf)
                else:
                    loc = location.get_location_from_uri(uri, conf=self.conf)
                self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def _test_add_singlepart(self):
        """Test that we can add an image via the s3 backend."""
        expected_image_id = str(uuid.uuid4())
        # 5KiB is smaller than WRITE_CHUNKSIZE
        expected_s3_size = 5 * units.Ki
        expected_s3_contents = b"*" * expected_s3_size
        expected_checksum = hashlib.md5(expected_s3_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_s3_contents).hexdigest()
        backend_conf = getattr(self.conf, self.backend)

        expected_location = format_s3_location(
            backend_conf.s3_store_access_key,
            backend_conf.s3_store_secret_key,
            backend_conf.s3_store_host,
            backend_conf.s3_store_bucket,
            expected_image_id)
        image_s3 = io.BytesIO(expected_s3_contents)

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
            stubber.add_response(method='put_object',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket,
                                     'Key': expected_image_id,
                                     'Body': botocore.stub.ANY
                                 })

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client

                if self.multistore:
                    loc, size, checksum, multihash, metadata = \
                        self.store.add(expected_image_id, image_s3,
                                       expected_s3_size, self.hash_algo)
                    self.assertEqual(self.backend, metadata["store"])
                else:
                    loc, size, checksum, multihash, _ = \
                        self.store.add(expected_image_id, image_s3,
                                       expected_s3_size, self.hash_algo)

                self.assertEqual(expected_location, loc)
                self.assertEqual(expected_s3_size, size)
                self.assertEqual(expected_checksum, checksum)
                self.assertEqual(expected_multihash, multihash)

    def _test_add_singlepart_size_exceeding_max_size(self):
        """Test size validation during add for singlepart upload."""
        self.store.WRITE_CHUNKSIZE = 1024
        expected_image_id = str(uuid.uuid4())
        # Provide a smaller expected size than actual data to trigger
        # size mismatch
        expected_s3_size = 5 * units.Ki
        # 5KB more than expected
        actual_s3_contents = b"*" * (expected_s3_size * 2)
        image_s3 = io.BytesIO(actual_s3_contents)
        backend_conf = getattr(self.conf, self.backend)

        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket
                                 })
            stubber.add_client_error(
                method='head_object', service_error_code='404',
                service_message='', expected_params={
                    'Bucket': backend_conf.s3_store_bucket,
                    'Key': expected_image_id})
            stubber.add_response(method='put_object',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket,
                                     'Key': expected_image_id,
                                     'Body': botocore.stub.ANY
                                 })

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client

                # Expect an exception due to size mismatch
                self.assertRaisesRegex(exceptions.Invalid,
                                       'Size exceeds: expected',
                                       self.store.add,
                                       expected_image_id, image_s3,
                                       expected_s3_size, self.hash_algo)

                # Verify that the stream's position reflects the number of
                # bytes read, which should be exactly at expected_file_size
                # plus the last buffer size read.
                actual_read_size = image_s3.tell()
                expected_read = expected_s3_size + self.store.WRITE_CHUNKSIZE
                self.assertEqual(actual_read_size, expected_read,
                                 "The stream was not read only up to the"
                                 " expected size.")

    def _test_add_singlepart_write_less_than_declared(self):
        """Test size validation during add for singlepart upload."""
        expected_image_id = str(uuid.uuid4())
        # Provide a smaller expected size than actual data to trigger
        # size mismatch
        expected_s3_size = 5 * units.Ki
        # 100 bytes smaller than expected
        actual_s3_contents = b"*" * (5 * units.Ki - 100)
        image_s3 = io.BytesIO(actual_s3_contents)
        backend_conf = getattr(self.conf, self.backend)

        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket
                                 })
            stubber.add_client_error(
                method='head_object', service_error_code='404',
                service_message='', expected_params={
                    'Bucket': backend_conf.s3_store_bucket,
                    'Key': expected_image_id})
            stubber.add_response(method='put_object',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket,
                                     'Key': expected_image_id,
                                     'Body': botocore.stub.ANY
                                 })

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client

                # Expect an exception due to size mismatch
                self.assertRaisesRegex(exceptions.Invalid,
                                       'Size mismatch: expected',
                                       self.store.add,
                                       expected_image_id, image_s3,
                                       expected_s3_size, self.hash_algo)
                # The input buffer should be fully read
                # depending on implementation
                total_input_size = len(actual_s3_contents)
                self.assertEqual(image_s3.tell(), total_input_size)

    def _test_add_singlepart_bigger_than_write_chunk(self):
        """Test that we can add a large image via the s3 backend."""
        expected_image_id = str(uuid.uuid4())
        # 8 MiB is bigger than WRITE_CHUNKSIZE(=5MiB),
        # but smaller than s3_store_large_object_size
        expected_s3_size = 8 * units.Mi
        expected_s3_contents = b"*" * expected_s3_size
        expected_checksum = hashlib.md5(expected_s3_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_s3_contents).hexdigest()
        backend_conf = getattr(self.conf, self.backend)

        expected_location = format_s3_location(
            backend_conf.s3_store_access_key,
            backend_conf.s3_store_secret_key,
            backend_conf.s3_store_host,
            backend_conf.s3_store_bucket,
            expected_image_id)
        image_s3 = io.BytesIO(expected_s3_contents)

        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket
                                 })
            stubber.add_client_error(
                method='head_object', service_error_code='404',
                service_message='', expected_params={
                    'Bucket': backend_conf.s3_store_bucket,
                    'Key': expected_image_id})
            stubber.add_response(method='put_object',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket,
                                     'Key': expected_image_id,
                                     'Body': botocore.stub.ANY
                                 })

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client

                if self.multistore:
                    loc, size, checksum, multihash, metadata = \
                        self.store.add(
                            expected_image_id, image_s3, expected_s3_size,
                            self.hash_algo)
                    self.assertEqual(self.backend, metadata["store"])
                else:
                    loc, size, checksum, multihash, _ = \
                        self.store.add(expected_image_id, image_s3,
                                       expected_s3_size, self.hash_algo)

                self.assertEqual(expected_location, loc)
                self.assertEqual(expected_s3_size, size)
                self.assertEqual(expected_checksum, checksum)
                self.assertEqual(expected_multihash, multihash)

    def _test_add_with_verifier(self):
        """Assert 'verifier.update' is called when verifier is provided."""
        expected_image_id = str(uuid.uuid4())
        expected_s3_size = 5 * units.Ki
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

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client
                self.store.add(expected_image_id, image_s3,
                               expected_s3_size, self.hash_algo,
                               verifier=verifier)
        verifier.update.assert_called_with(expected_s3_contents)

    def _test_add_multipart(self):
        """Test that we can add an image via the s3 backend."""
        expected_image_id = str(uuid.uuid4())
        expected_s3_size = 16 * units.Mi
        expected_s3_contents = b"*" * expected_s3_size
        expected_checksum = hashlib.md5(expected_s3_contents,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_s3_contents).hexdigest()
        backend_conf = getattr(self.conf, self.backend)

        expected_location = format_s3_location(
            backend_conf.s3_store_access_key,
            backend_conf.s3_store_secret_key,
            backend_conf.s3_store_host,
            backend_conf.s3_store_bucket,
            expected_image_id)
        image_s3 = io.BytesIO(expected_s3_contents)

        fake_s3_client = botocore.session.get_session().create_client('s3')

        num_parts = 3  # image size is 16MB and chunk size is 6MB
        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': backend_conf.s3_store_bucket
                                 })
            stubber.add_client_error(
                method='head_object', service_error_code='404',
                service_message='', expected_params={
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
            parts = []
            remaining_image_size = expected_s3_size
            large_chunk_size = backend_conf.s3_store_large_object_chunk_size
            chunk_size = large_chunk_size * units.Mi
            for i in range(num_parts):
                part_number = i + 1
                stubber.add_response(
                    method='upload_part',
                    service_response={'ETag': 'ETag'},
                    expected_params={
                        "Bucket": backend_conf.s3_store_bucket,
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
                                     "Bucket": backend_conf.s3_store_bucket,
                                     "Key": expected_image_id,
                                     'ETag': 'ETag'
                                 },
                                 expected_params={
                                     "Bucket": backend_conf.s3_store_bucket,
                                     "Key": expected_image_id,
                                     "MultipartUpload": {
                                         "Parts": parts
                                     },
                                     "UploadId": 'UploadId'
                                 })

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client

                if self.multistore:
                    loc, size, checksum, multihash, metadata = \
                        self.store.add(expected_image_id, image_s3,
                                       expected_s3_size,
                                       self.hash_algo)
                    self.assertEqual(self.backend, metadata["store"])
                else:
                    loc, size, checksum, multihash, _ = \
                        self.store.add(expected_image_id, image_s3,
                                       expected_s3_size,
                                       self.hash_algo)

                self.assertEqual(expected_location, loc)
                self.assertEqual(expected_s3_size, size)
                self.assertEqual(expected_checksum, checksum)
                self.assertEqual(expected_multihash, multihash)

    def _test_add_multipart_size_exceeding_max_size(self):
        """Test size validation during multipart upload."""
        expected_image_id = str(uuid.uuid4())
        expected_s3_size = 15 * units.Mi
        self.store.WRITE_CHUNKSIZE = 5 * units.Mi
        # Actual data is larger than expected to trigger size validation
        # failure, 5MB larger
        total_size = expected_s3_size + self.store.WRITE_CHUNKSIZE
        expected_s3_contents = b"*" * total_size
        image_s3 = io.BytesIO(expected_s3_contents)
        conf = getattr(self.conf, self.backend)

        fake_s3_client = botocore.session.get_session().create_client('s3')
        # Patch abort_multipart_upload on the client to a Mock
        fake_s3_client.abort_multipart_upload = mock.Mock()
        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': conf.s3_store_bucket
                                 })
            stubber.add_client_error(method='head_object',
                                     service_error_code='404',
                                     service_message='',
                                     expected_params={
                                         'Bucket': conf.s3_store_bucket,
                                         'Key': expected_image_id
                                     })
            stubber.add_response(method='create_multipart_upload',
                                 service_response={
                                     "Bucket": conf.s3_store_bucket,
                                     "Key": expected_image_id,
                                     "UploadId": 'UploadId'
                                 },
                                 expected_params={
                                     "Bucket": conf.s3_store_bucket,
                                     "Key": expected_image_id,
                                 })
            stubber.add_response(method='abort_multipart_upload',
                                 service_response={},
                                 expected_params={
                                     'Bucket': conf.s3_store_bucket,
                                     'Key': expected_image_id,
                                     'UploadId': 'UploadId'
                                 })

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client
                # Expect an exception due to size mismatch
                self.assertRaisesRegex(
                    exceptions.Invalid, "Size exceeds: expected",
                    self.store.add, expected_image_id, image_s3,
                    expected_s3_size, self.hash_algo)

                # Verify that the stream's position reflects the number of
                # bytes read, which should be exactly at expected_file_size
                # plus the last buffer size read.
                actual_read_size = image_s3.tell()
                self.assertEqual(actual_read_size, total_size,
                                 "The stream was not read only up to the "
                                 "expected size.")

                # Assert that abort_multipart_upload was called
                fake_s3_client.abort_multipart_upload.assert_called_once_with(
                    Bucket=conf.s3_store_bucket,
                    Key=expected_image_id,
                    UploadId='UploadId'
                )

    def _test_add_multipart_write_less_than_declared(self):
        """Test size validation during multipart upload."""
        expected_image_id = str(uuid.uuid4())
        expected_s3_size = 16 * units.Mi
        # Actual data is less than expected to trigger size validation
        # failure, 1MB less
        expected_s3_contents = b"*" * (expected_s3_size - 1 * units.Mi)
        image_s3 = io.BytesIO(expected_s3_contents)
        conf = getattr(self.conf, self.backend)

        fake_s3_client = botocore.session.get_session().create_client('s3')
        # Patch abort_multipart_upload on the client to a Mock
        fake_s3_client.abort_multipart_upload = mock.Mock()
        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket',
                                 service_response={},
                                 expected_params={
                                     'Bucket': conf.s3_store_bucket
                                 })
            stubber.add_client_error(method='head_object',
                                     service_error_code='404',
                                     service_message='',
                                     expected_params={
                                         'Bucket': conf.s3_store_bucket,
                                         'Key': expected_image_id
                                     })
            stubber.add_response(method='create_multipart_upload',
                                 service_response={
                                     "Bucket": conf.s3_store_bucket,
                                     "Key": expected_image_id,
                                     "UploadId": 'UploadId'
                                 },
                                 expected_params={
                                     "Bucket": conf.s3_store_bucket,
                                     "Key": expected_image_id,
                                 })
            stubber.add_response(method='abort_multipart_upload',
                                 service_response={},
                                 expected_params={
                                     'Bucket': conf.s3_store_bucket,
                                     'Key': expected_image_id,
                                     'UploadId': 'UploadId'
                                 })

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client
                # Expect an exception due to size mismatch
                self.assertRaisesRegex(exceptions.Invalid,
                                       'Size mismatch: expected',
                                       self.store.add,
                                       expected_image_id, image_s3,
                                       expected_s3_size, self.hash_algo)

                # The input buffer should be fully read depending on
                # implementation
                total_input_size = len(expected_s3_contents)
                self.assertEqual(image_s3.tell(), total_input_size)

                # Assert that abort_multipart_upload was called
                fake_s3_client.abort_multipart_upload.assert_called_once_with(
                    Bucket=conf.s3_store_bucket,
                    Key=expected_image_id,
                    UploadId='UploadId'
                )

    def _test_add_already_existing(self):
        """Tests that adding an image with an existing identifier
        raises an appropriate exception
        """
        image_s3 = io.BytesIO(b"never_gonna_make_it")
        fake_s3_client = botocore.session.get_session().create_client('s3')

        with stub.Stubber(fake_s3_client) as stubber:
            stubber.add_response(method='head_bucket', service_response={})
            stubber.add_response(method='head_object', service_response={})

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client
                self.assertRaises(exceptions.Duplicate, self.store.add,
                                  str(uuid.uuid4()), image_s3, 0,
                                  self.hash_algo)

    def _test_delete_non_existing(self):
        """Test trying to delete a s3 that doesn't exist raises an error."""
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

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client

                uri = "s3://user:key@auth_address/%s/%s" % (bucket, key)
                if self.multistore:
                    loc = location.get_location_from_uri_and_backend(
                        uri, self.backend, conf=self.conf)
                else:
                    loc = location.get_location_from_uri(uri, conf=self.conf)
                self.assertRaises(exceptions.NotFound, self.store.delete, loc)

    def _do_test_get_s3_location(self, host, loc):
        """Helper method to test S3 location derivation"""
        self.assertEqual(s3.get_s3_location(host), loc)
        self.assertEqual(s3.get_s3_location(host + '/'), loc)
        self.assertEqual(s3.get_s3_location(host + ':80'), loc)
        self.assertEqual(s3.get_s3_location(host + ':80/'), loc)
        self.assertEqual(s3.get_s3_location('http://' + host), loc)
        self.assertEqual(s3.get_s3_location('http://' + host + '/'), loc)
        self.assertEqual(s3.get_s3_location('http://' + host + ':80'), loc)
        self.assertEqual(s3.get_s3_location('http://' + host + ':80/'), loc)
        self.assertEqual(s3.get_s3_location('https://' + host), loc)
        self.assertEqual(s3.get_s3_location('https://' + host + '/'), loc)
        self.assertEqual(s3.get_s3_location('https://' + host + ':80'), loc)
        self.assertEqual(s3.get_s3_location('https://' + host + ':80/'), loc)

    def _test_get_invalid_bucket_name(self):
        """Test that invalid bucket names raise appropriate exceptions"""
        if self.multistore:
            self.config(s3_store_bucket_url_format='virtual',
                        group=self.backend)
            invalid_buckets = ['not.dns.compliant', 'aa', 'bucket-']
            for bucket in invalid_buckets:
                loc = location.get_location_from_uri_and_backend(
                    "s3+https://user:key@auth_address/%s/key" % bucket,
                    self.backend, conf=self.conf)
                self.assertRaises(boto_exceptions.InvalidDNSNameError,
                                  self.store.get, loc)
        else:
            self.config(s3_store_bucket_url_format='virtual')
            invalid_buckets = ['not.dns.compliant', 'aa', 'bucket-']
            for bucket in invalid_buckets:
                loc = location.get_location_from_uri(
                    "s3://user:key@auth_address/%s/key" % bucket,
                    conf=self.conf)
                self.assertRaises(boto_exceptions.InvalidDNSNameError,
                                  self.store.get, loc)

    def _test_client_custom_region_name(self):
        """Test a custom s3_store_region_name in config"""
        if self.multistore:
            mock_loc = mock.MagicMock()
            mock_loc.accesskey = 'abcd'
            mock_loc.secretkey = 'efgh'
            mock_loc.bucket = 'bucket1'

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                self.store._create_s3_client(mock_loc)
                mock_client.assert_called_with(
                    config=mock.ANY,
                    endpoint_url='https://s3-region1.com',
                    region_name='custom_region_name',
                    service_name='s3',
                    use_ssl=False,
                    verify='path/to/cert/bundle.pem',
                )
        else:
            self.config(s3_store_host='http://example.com')
            self.config(s3_store_region_name='regionOne')
            self.config(s3_store_bucket_url_format='path')
            self.store.configure()

            mock_loc = mock.MagicMock()
            mock_loc.accesskey = 'abcd'
            mock_loc.secretkey = 'efgh'
            mock_loc.bucket = 'bucket1'

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                self.store._create_s3_client(mock_loc)
                mock_client.assert_called_with(
                    config=mock.ANY,
                    endpoint_url='http://example.com',
                    region_name='regionOne',
                    service_name='s3',
                    use_ssl=False,
                    verify=None,
                )

    def _test_client_custom_ca_cert_bundle(self):
        """Test a custom s3_store_cacert in config"""
        if self.multistore:
            mock_loc = mock.MagicMock()
            mock_loc.accesskey = 'abcd'
            mock_loc.secretkey = 'efgh'
            mock_loc.bucket = 'bucket1'

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                self.store._create_s3_client(mock_loc)
                mock_client.assert_called_with(
                    config=mock.ANY,
                    endpoint_url='https://s3-region1.com',
                    region_name='custom_region_name',
                    service_name='s3',
                    use_ssl=False,
                    verify='path/to/cert/bundle.pem',
                )
        else:
            self.config(s3_store_host='http://example.com')
            self.config(s3_store_cacert='path/to/cert/bundle.pem')
            self.config(s3_store_bucket_url_format='path')
            self.store.configure()

            mock_loc = mock.MagicMock()
            mock_loc.accesskey = 'abcd'
            mock_loc.secretkey = 'efgh'
            mock_loc.bucket = 'bucket1'

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                self.store._create_s3_client(mock_loc)
                mock_client.assert_called_with(
                    config=mock.ANY,
                    endpoint_url='http://example.com',
                    region_name=None,
                    service_name='s3',
                    use_ssl=False,
                    verify='path/to/cert/bundle.pem',
                )

    def _test_partial_get(self):
        """Test that partial get operations raise appropriate exceptions"""
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                "s3+https://user:key@auth_address/glance/%s" % FAKE_UUID,
                self.backend, conf=self.conf)
        else:
            loc = location.get_location_from_uri(
                "s3://user:key@auth_address/glance/%s" % FAKE_UUID,
                conf=self.conf)
        self.assertRaises(exceptions.StoreRandomGetNotSupported,
                          self.store.get, loc, chunk_size=1)

    def _test_get_s3_good_location(self):
        """Test that the s3 location can be derived from the host"""
        good_locations = [
            ('s3.amazonaws.com', ''),
            ('s3-us-east-1.amazonaws.com', 'us-east-1'),
            ('s3-us-east-2.amazonaws.com', 'us-east-2'),
            ('s3-us-west-1.amazonaws.com', 'us-west-1'),
            ('s3-us-west-2.amazonaws.com', 'us-west-2'),
            ('s3-ap-east-1.amazonaws.com', 'ap-east-1'),
            ('s3-ap-south-1.amazonaws.com', 'ap-south-1'),
            ('s3-ap-northeast-1.amazonaws.com', 'ap-northeast-1'),
            ('s3-ap-northeast-2.amazonaws.com', 'ap-northeast-2'),
            ('s3-ap-northeast-3.amazonaws.com', 'ap-northeast-3'),
            ('s3-ap-southeast-1.amazonaws.com', 'ap-southeast-1'),
            ('s3-ap-southeast-2.amazonaws.com', 'ap-southeast-2'),
            ('s3-ca-central-1.amazonaws.com', 'ca-central-1'),
            ('s3-cn-north-1.amazonaws.com.cn', 'cn-north-1'),
            ('s3-cn-northwest-1.amazonaws.com.cn', 'cn-northwest-1'),
            ('s3-eu-central-1.amazonaws.com', 'eu-central-1'),
            ('s3-eu-west-1.amazonaws.com', 'eu-west-1'),
            ('s3-eu-west-2.amazonaws.com', 'eu-west-2'),
            ('s3-eu-west-3.amazonaws.com', 'eu-west-3'),
            ('s3-eu-north-1.amazonaws.com', 'eu-north-1'),
            ('s3-sa-east-1.amazonaws.com', 'sa-east-1'),
        ]
        for (url, expected) in good_locations:
            self._do_test_get_s3_location(url, expected)

    def _test_get_my_object_storage_location(self):
        """Test that the my object storage location convert to ''"""
        my_object_storage_locations = [
            ('my-object-storage.com', ''),
            ('s3-my-object.jp', ''),
            ('192.168.100.12', ''),
        ]
        for (url, expected) in my_object_storage_locations:
            self._do_test_get_s3_location(url, expected)

    def _test_no_access_key(self):
        """Tests that options without access key disables the add method"""
        self.assertTrue(self._option_required(
            's3_store_access_key'))

    def _test_no_secret_key(self):
        """Tests that options without secret key disables the add method"""
        self.assertTrue(self._option_required(
            's3_store_secret_key'))

    def _test_no_host(self):
        """Tests that options without host disables the add method"""
        self.assertTrue(self._option_required(
            's3_store_host'))

    def _test_no_bucket(self):
        """Tests that options without bucket name disables the add method"""
        self.assertTrue(self._option_required(
            's3_store_bucket'))

    def _option_required(self, key):
        """Helper method to test if a configuration option is required"""
        conf = S3_CONF.copy()
        conf[key] = None

        try:
            self.config(**conf, group=self.backend)
            self.store = s3.Store(self.conf)
            self.store.configure()
            return not self.store.is_capable(
                capabilities.BitMasks.WRITE_ACCESS)
        except Exception:
            return False

    def _test_add_different_backend(self):
        """Test adding to a different backend in multistore mode"""
        if not self.multistore:
            self.skipTest("This test is only for multistore mode")

        # Switch to different backend
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

            with mock.patch.object(
                    boto3.session.Session, "client") as mock_client:
                mock_client.return_value = fake_s3_client
                loc, size, checksum, multihash, metadata = \
                    self.store.add(expected_image_id, image_s3,
                                   expected_s3_size,
                                   self.hash_algo)
                self.assertEqual("s3_region2", metadata["store"])

                self.assertEqual(expected_location, loc)
                self.assertEqual(expected_s3_size, size)
                self.assertEqual(expected_checksum, checksum)
                self.assertEqual(expected_multihash, multihash)
