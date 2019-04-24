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

"""Tests the Swift backend store"""

import copy
import fixtures
import hashlib
import mock
import tempfile
import uuid

from oslo_config import cfg
from oslo_utils import encodeutils
from oslo_utils import units
import requests_mock
import six
from six import moves
from six.moves import http_client
# NOTE(jokke): simplified transition to py3, behaves like py2 xrange
from six.moves import range
import swiftclient

from glance_store._drivers.swift import connection_manager as manager
from glance_store._drivers.swift import store as swift
from glance_store._drivers.swift import utils as sutils
from glance_store import capabilities
from glance_store import exceptions
from glance_store import location
import glance_store.multi_backend as store
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities


CONF = cfg.CONF

FAKE_UUID = lambda: str(uuid.uuid4())
FAKE_UUID2 = lambda: str(uuid.uuid4())

Store = swift.Store
FIVE_KB = 5 * units.Ki
FIVE_GB = 5 * units.Gi
MAX_SWIFT_OBJECT_SIZE = FIVE_GB
SWIFT_PUT_OBJECT_CALLS = 0
SWIFT_CONF = {'swift_store_auth_address': 'localhost:8080',
              'swift_store_container': 'glance',
              'swift_store_user': 'user',
              'swift_store_key': 'key',
              'swift_store_retry_get_count': 1,
              'default_swift_reference': 'ref1'
              }


class SwiftTests(object):

    def mock_keystone_client(self):
        # mock keystone client functions to avoid dependency errors
        swift.ks_v3 = mock.MagicMock()
        swift.ks_session = mock.MagicMock()
        swift.ks_client = mock.MagicMock()

    def stub_out_swiftclient(self, swift_store_auth_version):
        fixture_containers = ['glance']
        fixture_container_headers = {}
        fixture_headers = {
            'glance/%s' % FAKE_UUID: {
                'content-length': FIVE_KB,
                'etag': 'c2e5db72bd7fd153f53ede5da5a06de3'
            },
            'glance/%s' % FAKE_UUID2: {'x-static-large-object': 'true', },
        }
        fixture_objects = {
            'glance/%s' % FAKE_UUID: six.BytesIO(b"*" * FIVE_KB),
            'glance/%s' % FAKE_UUID2: six.BytesIO(b"*" * FIVE_KB),
        }

        def fake_head_container(url, token, container, **kwargs):
            if container not in fixture_containers:
                msg = "No container %s found" % container
                status = http_client.NOT_FOUND
                raise swiftclient.ClientException(msg, http_status=status)
            return fixture_container_headers

        def fake_put_container(url, token, container, **kwargs):
            fixture_containers.append(container)

        def fake_post_container(url, token, container, headers, **kwargs):
            for key, value in headers.items():
                fixture_container_headers[key] = value

        def fake_put_object(url, token, container, name, contents, **kwargs):
            # PUT returns the ETag header for the newly-added object
            # Large object manifest...
            global SWIFT_PUT_OBJECT_CALLS
            SWIFT_PUT_OBJECT_CALLS += 1
            CHUNKSIZE = 64 * units.Ki
            fixture_key = "%s/%s" % (container, name)
            if fixture_key not in fixture_headers:
                if kwargs.get('headers'):
                    manifest = kwargs.get('headers').get('X-Object-Manifest')
                    etag = kwargs.get('headers') \
                                 .get('ETag', hashlib.md5(b'').hexdigest())
                    fixture_headers[fixture_key] = {
                        'manifest': True,
                        'etag': etag,
                        'x-object-manifest': manifest
                    }
                    fixture_objects[fixture_key] = None
                    return etag
                if hasattr(contents, 'read'):
                    fixture_object = six.BytesIO()
                    read_len = 0
                    chunk = contents.read(CHUNKSIZE)
                    checksum = hashlib.md5()
                    while chunk:
                        fixture_object.write(chunk)
                        read_len += len(chunk)
                        checksum.update(chunk)
                        chunk = contents.read(CHUNKSIZE)
                    etag = checksum.hexdigest()
                else:
                    fixture_object = six.BytesIO(contents)
                    read_len = len(contents)
                    etag = hashlib.md5(fixture_object.getvalue()).hexdigest()
                if read_len > MAX_SWIFT_OBJECT_SIZE:
                    msg = ('Image size:%d exceeds Swift max:%d' %
                           (read_len, MAX_SWIFT_OBJECT_SIZE))
                    raise swiftclient.ClientException(
                        msg, http_status=http_client.REQUEST_ENTITY_TOO_LARGE)
                fixture_objects[fixture_key] = fixture_object
                fixture_headers[fixture_key] = {
                    'content-length': read_len,
                    'etag': etag}
                return etag
            else:
                msg = ("Object PUT failed - Object with key %s already exists"
                       % fixture_key)
                raise swiftclient.ClientException(
                    msg, http_status=http_client.CONFLICT)

        def fake_get_object(conn, container, name, **kwargs):
            # GET returns the tuple (list of headers, file object)
            fixture_key = "%s/%s" % (container, name)
            if fixture_key not in fixture_headers:
                msg = "Object GET failed"
                status = http_client.NOT_FOUND
                raise swiftclient.ClientException(msg, http_status=status)

            byte_range = None
            headers = kwargs.get('headers', dict())
            if headers is not None:
                headers = dict((k.lower(), v) for k, v in headers.items())
                if 'range' in headers:
                    byte_range = headers.get('range')

            fixture = fixture_headers[fixture_key]
            if 'manifest' in fixture:
                # Large object manifest... we return a file containing
                # all objects with prefix of this fixture key
                chunk_keys = sorted([k for k in fixture_headers.keys()
                                     if k.startswith(fixture_key) and
                                     k != fixture_key])
                result = six.BytesIO()
                for key in chunk_keys:
                    result.write(fixture_objects[key].getvalue())
            else:
                result = fixture_objects[fixture_key]

            if byte_range is not None:
                start = int(byte_range.split('=')[1].strip('-'))
                result = six.BytesIO(result.getvalue()[start:])
                fixture_headers[fixture_key]['content-length'] = len(
                    result.getvalue())

            return fixture_headers[fixture_key], result

        def fake_head_object(url, token, container, name, **kwargs):
            # HEAD returns the list of headers for an object
            try:
                fixture_key = "%s/%s" % (container, name)
                return fixture_headers[fixture_key]
            except KeyError:
                msg = "Object HEAD failed - Object does not exist"
                status = http_client.NOT_FOUND
                raise swiftclient.ClientException(msg, http_status=status)

        def fake_delete_object(url, token, container, name, **kwargs):
            # DELETE returns nothing
            fixture_key = "%s/%s" % (container, name)
            if fixture_key not in fixture_headers:
                msg = "Object DELETE failed - Object does not exist"
                status = http_client.NOT_FOUND
                raise swiftclient.ClientException(msg, http_status=status)
            else:
                del fixture_headers[fixture_key]
                del fixture_objects[fixture_key]

        def fake_http_connection(*args, **kwargs):
            return None

        def fake_get_auth(url, user, key, auth_version, **kwargs):
            if url is None:
                return None, None
            if 'http' in url and '://' not in url:
                raise ValueError('Invalid url %s' % url)
            # Check the auth version against the configured value
            if swift_store_auth_version != auth_version:
                msg = 'AUTHENTICATION failed (version mismatch)'
                raise swiftclient.ClientException(msg)
            return None, None

        self.useFixture(fixtures.MockPatch(
            'swiftclient.client.head_container', fake_head_container))
        self.useFixture(fixtures.MockPatch(
            'swiftclient.client.put_container', fake_put_container))
        self.useFixture(fixtures.MockPatch(
            'swiftclient.client.post_container', fake_post_container))
        self.useFixture(fixtures.MockPatch(
            'swiftclient.client.put_object', fake_put_object))
        self.useFixture(fixtures.MockPatch(
            'swiftclient.client.delete_object', fake_delete_object))
        self.useFixture(fixtures.MockPatch(
            'swiftclient.client.head_object', fake_head_object))
        self.useFixture(fixtures.MockPatch(
            'swiftclient.client.Connection.get_object', fake_get_object))
        self.useFixture(fixtures.MockPatch(
            'swiftclient.client.get_auth', fake_get_auth))
        self.useFixture(fixtures.MockPatch(
            'swiftclient.client.http_connection', fake_http_connection))

    @property
    def swift_store_user(self):
        return 'tenant:user1'

    def test_get_size(self):
        """
        Test that we can get the size of an object in the swift store
        """
        uri = "swift://%s:key@auth_address/glance/%s" % (
            self.swift_store_user, FAKE_UUID)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        image_size = self.store.get_size(loc)
        self.assertEqual(5120, image_size)

    @mock.patch.object(store,
                       'get_store_from_store_identifier')
    def test_get_size_with_multi_tenant_on(self, mock_get):
        """Test that single tenant uris work with multi tenant on."""
        mock_get.return_value = self.store
        uri = ("swift://%s:key@auth_address/glance/%s" %
               (self.swift_store_user, FAKE_UUID))
        self.config(group="swift1", swift_store_config_file=None)
        self.config(group="swift1", swift_store_multi_tenant=True)
        # NOTE(markwash): ensure the image is found
        ctxt = mock.MagicMock()
        size = store.get_size_from_uri_and_backend(
            uri, "swift1", context=ctxt)
        self.assertEqual(5120, size)

    def test_multi_tenant_with_swift_config(self):
        """
        Test that Glance does not start when a config file is set on
        multi-tenant mode
        """
        schemes = ['swift', 'swift+config']
        for s in schemes:
            self.config(group='glance_store', default_backend="swift1")
            self.config(group="swift1",
                        swift_store_config_file='not/none',
                        swift_store_multi_tenant=True)
            self.assertRaises(exceptions.BadStoreConfiguration,
                              Store, self.conf, backend="swift1")

    def test_get(self):
        """Test a "normal" retrieval of an image in chunks."""
        uri = "swift://%s:key@auth_address/glance/%s" % (
            self.swift_store_user, FAKE_UUID)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        (image_swift, image_size) = self.store.get(loc)
        self.assertEqual(5120, image_size)

        expected_data = b"*" * FIVE_KB
        data = b""

        for chunk in image_swift:
            data += chunk
        self.assertEqual(expected_data, data)

    def test_get_with_retry(self):
        """
        Test a retrieval where Swift does not get the full image in a single
        request.
        """
        uri = "swift://%s:key@auth_address/glance/%s" % (
            self.swift_store_user, FAKE_UUID)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        ctxt = mock.MagicMock()
        (image_swift, image_size) = self.store.get(loc, context=ctxt)
        resp_full = b''.join([chunk for chunk in image_swift.wrapped])
        resp_half = resp_full[:len(resp_full) // 2]
        resp_half = six.BytesIO(resp_half)
        manager = self.store.get_manager(loc.store_location, ctxt)

        image_swift.wrapped = swift.swift_retry_iter(resp_half, image_size,
                                                     self.store,
                                                     loc.store_location,
                                                     manager)
        self.assertEqual(5120, image_size)

        expected_data = b"*" * FIVE_KB
        data = b""

        for chunk in image_swift:
            data += chunk
        self.assertEqual(expected_data, data)

    def test_get_with_http_auth(self):
        """
        Test a retrieval from Swift with an HTTP authurl. This is
        specified either via a Location header with swift+http:// or using
        http:// in the swift_store_auth_address config value
        """
        loc = location.get_location_from_uri_and_backend(
            "swift+http://%s:key@auth_address/glance/%s" %
            (self.swift_store_user, FAKE_UUID), "swift1", conf=self.conf)

        ctxt = mock.MagicMock()
        (image_swift, image_size) = self.store.get(loc, context=ctxt)
        self.assertEqual(5120, image_size)

        expected_data = b"*" * FIVE_KB
        data = b""

        for chunk in image_swift:
            data += chunk
        self.assertEqual(expected_data, data)

    def test_get_non_existing(self):
        """
        Test that trying to retrieve a swift that doesn't exist
        raises an error
        """
        loc = location.get_location_from_uri_and_backend(
            "swift://%s:key@authurl/glance/noexist" % (self.swift_store_user),
            "swift1", conf=self.conf)
        self.assertRaises(exceptions.NotFound,
                          self.store.get,
                          loc)

    def test_buffered_reader_opts(self):
        self.config(group="swift1", swift_buffer_on_upload=True)
        self.config(group="swift1", swift_upload_buffer_dir=self.test_dir)
        try:
            self.store = Store(self.conf, backend="swift1")
        except exceptions.BadStoreConfiguration:
            self.fail("Buffered Reader exception raised when it "
                      "should not have been")

    def test_buffered_reader_with_invalid_path(self):
        self.config(group="swift1", swift_buffer_on_upload=True)
        self.config(group="swift1", swift_upload_buffer_dir="/some/path")
        self.store = Store(self.conf, backend="swift1")
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure)

    def test_buffered_reader_with_no_path_given(self):
        self.config(group="swift1", swift_buffer_on_upload=True)
        self.store = Store(self.conf, backend="swift1")
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.configure)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=False))
    def test_add(self):
        """Test that we can add an image via the swift backend."""
        moves.reload_module(swift)
        self.mock_keystone_client()
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()
        expected_swift_size = FIVE_KB
        expected_swift_contents = b"*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        loc = "swift+https://tenant%%3Auser1:key@localhost:8080/glance/%s"
        expected_location = loc % (expected_image_id)
        image_swift = six.BytesIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        loc, size, checksum, metadata = self.store.add(
            expected_image_id, image_swift, expected_swift_size)

        self.assertEqual("swift1", metadata["backend"])
        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        # Expecting a single object to be created on Swift i.e. no chunking.
        self.assertEqual(1, SWIFT_PUT_OBJECT_CALLS)

        loc = location.get_location_from_uri_and_backend(
            expected_location, "swift1", conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = b''.join([chunk for chunk in new_image_swift])
        new_image_swift_size = len(new_image_swift)

        self.assertEqual(expected_swift_contents, new_image_contents)
        self.assertEqual(expected_swift_size, new_image_swift_size)

    def test_add_multi_store(self):

        conf = copy.deepcopy(SWIFT_CONF)
        conf['default_swift_reference'] = 'store_2'
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.mock_keystone_client()
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()

        expected_swift_size = FIVE_KB
        expected_swift_contents = b"*" * expected_swift_size
        expected_image_id = str(uuid.uuid4())
        image_swift = six.BytesIO(expected_swift_contents)
        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0
        loc = 'swift+config://store_2/glance/%s'

        expected_location = loc % (expected_image_id)

        location, size, checksum, arg = self.store.add(expected_image_id,
                                                       image_swift,
                                                       expected_swift_size)
        self.assertEqual("swift1", arg['backend'])
        self.assertEqual(expected_location, location)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=False))
    def test_multi_tenant_image_add_uses_users_context(self):
        expected_swift_size = FIVE_KB
        expected_swift_contents = b"*" * expected_swift_size
        expected_image_id = str(uuid.uuid4())
        expected_container = 'container_' + expected_image_id
        loc = 'swift+https://some_endpoint/%s/%s'
        expected_location = loc % (expected_container, expected_image_id)
        image_swift = six.BytesIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        self.config(group='swift1', swift_store_container='container')
        self.config(group='swift1', swift_store_create_container_on_put=True)
        self.config(group='swift1', swift_store_multi_tenant=True)
        service_catalog = [
            {
                'endpoint_links': [],
                'endpoints': [
                    {
                        'adminURL': 'https://some_admin_endpoint',
                        'region': 'RegionOne',
                        'internalURL': 'https://some_internal_endpoint',
                        'publicURL': 'https://some_endpoint',
                    },
                ],
                'type': 'object-store',
                'name': 'Object Storage Service',
            }
        ]
        ctxt = mock.MagicMock(
            user='user', tenant='tenant', auth_token='123',
            service_catalog=service_catalog)
        store = swift.MultiTenantStore(self.conf, backend='swift1')
        store.configure()
        loc, size, checksum, metadata = store.add(expected_image_id,
                                                  image_swift,
                                                  expected_swift_size,
                                                  context=ctxt)

        self.assertEqual("swift1", metadata['backend'])
        # ensure that image add uses user's context
        self.assertEqual(expected_location, loc)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=True))
    def test_add_auth_url_variations(self):
        """
        Test that we can add an image via the swift backend with
        a variety of different auth_address values
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(group="swift1", **conf)

        variations = {
            'store_4': 'swift+config://store_4/glance/%s',
            'store_5': 'swift+config://store_5/glance/%s',
            'store_6': 'swift+config://store_6/glance/%s'
        }

        for variation, expected_location in variations.items():
            image_id = str(uuid.uuid4())
            expected_location = expected_location % image_id
            expected_swift_size = FIVE_KB
            expected_swift_contents = b"*" * expected_swift_size
            expected_checksum = \
                hashlib.md5(expected_swift_contents).hexdigest()

            image_swift = six.BytesIO(expected_swift_contents)

            global SWIFT_PUT_OBJECT_CALLS
            SWIFT_PUT_OBJECT_CALLS = 0
            conf['default_swift_reference'] = variation
            self.config(group="swift1", **conf)
            moves.reload_module(swift)
            self.mock_keystone_client()
            self.store = Store(self.conf, backend="swift1")
            self.store.configure()
            loc, size, checksum, metadata = self.store.add(image_id,
                                                           image_swift,
                                                           expected_swift_size)

            self.assertEqual("swift1", metadata['backend'])
            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_swift_size, size)
            self.assertEqual(expected_checksum, checksum)
            self.assertEqual(1, SWIFT_PUT_OBJECT_CALLS)

            loc = location.get_location_from_uri_and_backend(
                expected_location, "swift1", conf=self.conf)
            (new_image_swift, new_image_size) = self.store.get(loc)
            new_image_contents = b''.join([chunk for chunk in new_image_swift])
            new_image_swift_size = len(new_image_swift)

            self.assertEqual(expected_swift_contents, new_image_contents)
            self.assertEqual(expected_swift_size, new_image_swift_size)

    def test_add_no_container_no_create(self):
        """
        Tests that adding an image with a non-existing container
        raises an appropriate exception
        """
        conf = copy.deepcopy(SWIFT_CONF)
        conf['swift_store_user'] = 'tenant:user'
        conf['swift_store_create_container_on_put'] = False
        conf['swift_store_container'] = 'noexist'
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.mock_keystone_client()

        self.store = Store(self.conf, backend='swift1')
        self.store.configure()

        image_swift = six.BytesIO(b"nevergonnamakeit")

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        # We check the exception text to ensure the container
        # missing text is found in it, otherwise, we would have
        # simply used self.assertRaises here
        exception_caught = False
        try:
            self.store.add(str(uuid.uuid4()), image_swift, 0)
        except exceptions.BackendException as e:
            exception_caught = True
            self.assertIn("container noexist does not exist in Swift",
                          encodeutils.exception_to_unicode(e))
        self.assertTrue(exception_caught)
        self.assertEqual(0, SWIFT_PUT_OBJECT_CALLS)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=True))
    def test_add_no_container_and_create(self):
        """
        Tests that adding an image with a non-existing container
        creates the container automatically if flag is set
        """
        expected_swift_size = FIVE_KB
        expected_swift_contents = b"*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        loc = 'swift+config://ref1/noexist/%s'
        expected_location = loc % (expected_image_id)
        image_swift = six.BytesIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0
        conf = copy.deepcopy(SWIFT_CONF)
        conf['swift_store_user'] = 'tenant:user'
        conf['swift_store_create_container_on_put'] = True
        conf['swift_store_container'] = 'noexist'
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.mock_keystone_client()
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()
        loc, size, checksum, metadata = self.store.add(expected_image_id,
                                                       image_swift,
                                                       expected_swift_size)

        self.assertEqual("swift1", metadata['backend'])
        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(1, SWIFT_PUT_OBJECT_CALLS)

        loc = location.get_location_from_uri_and_backend(
            expected_location, "swift1", conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = b''.join([chunk for chunk in new_image_swift])
        new_image_swift_size = len(new_image_swift)

        self.assertEqual(expected_swift_contents, new_image_contents)
        self.assertEqual(expected_swift_size, new_image_swift_size)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=True))
    def test_add_no_container_and_multiple_containers_create(self):
        """
        Tests that adding an image with a non-existing container while using
        multi containers will create the container automatically if flag is set
        """
        expected_swift_size = FIVE_KB
        expected_swift_contents = b"*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        container = 'randomname_' + expected_image_id[:2]
        loc = 'swift+config://ref1/%s/%s'
        expected_location = loc % (container, expected_image_id)
        image_swift = six.BytesIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0
        conf = copy.deepcopy(SWIFT_CONF)
        conf['swift_store_user'] = 'tenant:user'
        conf['swift_store_create_container_on_put'] = True
        conf['swift_store_container'] = 'randomname'
        conf['swift_store_multiple_containers_seed'] = 2
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.mock_keystone_client()

        self.store = Store(self.conf, backend="swift1")
        self.store.configure()
        loc, size, checksum, metadata = self.store.add(expected_image_id,
                                                       image_swift,
                                                       expected_swift_size)

        self.assertEqual("swift1", metadata['backend'])
        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(1, SWIFT_PUT_OBJECT_CALLS)

        loc = location.get_location_from_uri_and_backend(
            expected_location, "swift1", conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = b''.join([chunk for chunk in new_image_swift])
        new_image_swift_size = len(new_image_swift)

        self.assertEqual(expected_swift_contents, new_image_contents)
        self.assertEqual(expected_swift_size, new_image_swift_size)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=True))
    def test_add_no_container_and_multiple_containers_no_create(self):
        """
        Tests that adding an image with a non-existing container while using
        multiple containers raises an appropriate exception
        """
        conf = copy.deepcopy(SWIFT_CONF)
        conf['swift_store_user'] = 'tenant:user'
        conf['swift_store_create_container_on_put'] = False
        conf['swift_store_container'] = 'randomname'
        conf['swift_store_multiple_containers_seed'] = 2
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.mock_keystone_client()

        expected_image_id = str(uuid.uuid4())
        expected_container = 'randomname_' + expected_image_id[:2]

        self.store = Store(self.conf, backend="swift1")
        self.store.configure()

        image_swift = six.BytesIO(b"nevergonnamakeit")

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        # We check the exception text to ensure the container
        # missing text is found in it, otherwise, we would have
        # simply used self.assertRaises here
        exception_caught = False
        try:
            self.store.add(expected_image_id, image_swift, 0)
        except exceptions.BackendException as e:
            exception_caught = True
            expected_msg = "container %s does not exist in Swift"
            expected_msg = expected_msg % expected_container
            self.assertIn(expected_msg, encodeutils.exception_to_unicode(e))
        self.assertTrue(exception_caught)
        self.assertEqual(0, SWIFT_PUT_OBJECT_CALLS)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=True))
    def test_add_with_verifier(self):
        """Test that the verifier is updated when verifier is provided."""
        swift_size = FIVE_KB
        base_byte = b"12345678"
        swift_contents = base_byte * (swift_size // 8)
        image_id = str(uuid.uuid4())
        image_swift = six.BytesIO(swift_contents)

        self.store = Store(self.conf, backend="swift1")
        self.store.configure()
        orig_max_size = self.store.large_object_size
        orig_temp_size = self.store.large_object_chunk_size
        custom_size = units.Ki
        verifier = mock.MagicMock(name='mock_verifier')

        try:
            self.store.large_object_size = custom_size
            self.store.large_object_chunk_size = custom_size
            self.store.add(image_id, image_swift, swift_size,
                           verifier=verifier)
        finally:
            self.store.large_object_chunk_size = orig_temp_size
            self.store.large_object_size = orig_max_size

        # Confirm verifier update called expected number of times
        self.assertEqual(2 * swift_size / custom_size,
                         verifier.update.call_count)

        # define one chunk of the contents
        swift_contents_piece = base_byte * (custom_size // 8)

        # confirm all expected calls to update have occurred
        calls = [mock.call(swift_contents_piece),
                 mock.call(b''),
                 mock.call(swift_contents_piece),
                 mock.call(b''),
                 mock.call(swift_contents_piece),
                 mock.call(b''),
                 mock.call(swift_contents_piece),
                 mock.call(b''),
                 mock.call(swift_contents_piece),
                 mock.call(b'')]
        verifier.update.assert_has_calls(calls)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=True))
    def test_add_with_verifier_small(self):
        """Test that the verifier is updated for smaller images."""
        swift_size = FIVE_KB
        base_byte = b"12345678"
        swift_contents = base_byte * (swift_size // 8)
        image_id = str(uuid.uuid4())
        image_swift = six.BytesIO(swift_contents)

        self.store = Store(self.conf, backend="swift1")
        self.store.configure()
        orig_max_size = self.store.large_object_size
        orig_temp_size = self.store.large_object_chunk_size
        custom_size = 6 * units.Ki
        verifier = mock.MagicMock(name='mock_verifier')

        try:
            self.store.large_object_size = custom_size
            self.store.large_object_chunk_size = custom_size
            self.store.add(image_id, image_swift, swift_size,
                           verifier=verifier)
        finally:
            self.store.large_object_chunk_size = orig_temp_size
            self.store.large_object_size = orig_max_size

        # Confirm verifier update called expected number of times
        self.assertEqual(2, verifier.update.call_count)

        # define one chunk of the contents
        swift_contents_piece = base_byte * (swift_size // 8)

        # confirm all expected calls to update have occurred
        calls = [mock.call(swift_contents_piece),
                 mock.call(b'')]
        verifier.update.assert_has_calls(calls)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=False))
    def test_multi_container_doesnt_impact_multi_tenant_add(self):
        expected_swift_size = FIVE_KB
        expected_swift_contents = b"*" * expected_swift_size
        expected_image_id = str(uuid.uuid4())
        expected_container = 'container_' + expected_image_id
        loc = 'swift+https://some_endpoint/%s/%s'
        expected_location = loc % (expected_container, expected_image_id)
        image_swift = six.BytesIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        self.config(group="swift1", swift_store_container='container')
        self.config(group="swift1", swift_store_create_container_on_put=True)
        self.config(group="swift1", swift_store_multiple_containers_seed=2)
        service_catalog = [
            {
                'endpoint_links': [],
                'endpoints': [
                    {
                        'adminURL': 'https://some_admin_endpoint',
                        'region': 'RegionOne',
                        'internalURL': 'https://some_internal_endpoint',
                        'publicURL': 'https://some_endpoint',
                    },
                ],
                'type': 'object-store',
                'name': 'Object Storage Service',
            }
        ]
        ctxt = mock.MagicMock(
            user='user', tenant='tenant', auth_token='123',
            service_catalog=service_catalog)
        store = swift.MultiTenantStore(self.conf, backend="swift1")
        store.configure()
        location, size, checksum, metadata = store.add(expected_image_id,
                                                       image_swift,
                                                       expected_swift_size,
                                                       context=ctxt)

        self.assertEqual("swift1", metadata['backend'])
        self.assertEqual(expected_location, location)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=True))
    def test_add_large_object(self):
        """
        Tests that adding a very large image. We simulate the large
        object by setting store.large_object_size to a small number
        and then verify that there have been a number of calls to
        put_object()...
        """
        expected_swift_size = FIVE_KB
        expected_swift_contents = b"*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        loc = 'swift+config://ref1/glance/%s'
        expected_location = loc % (expected_image_id)
        image_swift = six.BytesIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        self.store = Store(self.conf, backend="swift1")
        self.store.configure()
        orig_max_size = self.store.large_object_size
        orig_temp_size = self.store.large_object_chunk_size
        try:
            self.store.large_object_size = units.Ki
            self.store.large_object_chunk_size = units.Ki
            loc, size, checksum, metadata = self.store.add(expected_image_id,
                                                           image_swift,
                                                           expected_swift_size)
        finally:
            self.store.large_object_chunk_size = orig_temp_size
            self.store.large_object_size = orig_max_size

        self.assertEqual("swift1", metadata['backend'])
        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        # Expecting 6 objects to be created on Swift -- 5 chunks and 1
        # manifest.
        self.assertEqual(6, SWIFT_PUT_OBJECT_CALLS)

        loc = location.get_location_from_uri_and_backend(
            expected_location, "swift1", conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = b''.join([chunk for chunk in new_image_swift])
        new_image_swift_size = len(new_image_contents)

        self.assertEqual(expected_swift_contents, new_image_contents)
        self.assertEqual(expected_swift_size, new_image_swift_size)

    def test_add_large_object_zero_size(self):
        """
        Tests that adding an image to Swift which has both an unknown size and
        exceeds Swift's maximum limit of 5GB is correctly uploaded.

        We avoid the overhead of creating a 5GB object for this test by
        temporarily setting MAX_SWIFT_OBJECT_SIZE to 1KB, and then adding
        an object of 5KB.

        Bug lp:891738
        """
        # Set up a 'large' image of 5KB
        expected_swift_size = FIVE_KB
        expected_swift_contents = b"*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        loc = 'swift+config://ref1/glance/%s'
        expected_location = loc % (expected_image_id)
        image_swift = six.BytesIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        # Temporarily set Swift MAX_SWIFT_OBJECT_SIZE to 1KB and add our image,
        # explicitly setting the image_length to 0

        self.store = Store(self.conf, backend="swift1")
        self.store.configure()
        orig_max_size = self.store.large_object_size
        orig_temp_size = self.store.large_object_chunk_size
        global MAX_SWIFT_OBJECT_SIZE
        orig_max_swift_object_size = MAX_SWIFT_OBJECT_SIZE
        try:
            MAX_SWIFT_OBJECT_SIZE = units.Ki
            self.store.large_object_size = units.Ki
            self.store.large_object_chunk_size = units.Ki
            loc, size, checksum, metadata = self.store.add(expected_image_id,
                                                           image_swift,
                                                           0)
        finally:
            self.store.large_object_chunk_size = orig_temp_size
            self.store.large_object_size = orig_max_size
            MAX_SWIFT_OBJECT_SIZE = orig_max_swift_object_size

        self.assertEqual("swift1", metadata['backend'])
        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        # Expecting 6 calls to put_object -- 5 chunks, and the manifest.
        self.assertEqual(6, SWIFT_PUT_OBJECT_CALLS)

        loc = location.get_location_from_uri_and_backend(
            expected_location, "swift1", conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = b''.join([chunk for chunk in new_image_swift])
        new_image_swift_size = len(new_image_contents)

        self.assertEqual(expected_swift_contents, new_image_contents)
        self.assertEqual(expected_swift_size, new_image_swift_size)

    def test_add_already_existing(self):
        """
        Tests that adding an image with an existing identifier
        raises an appropriate exception
        """
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()
        image_swift = six.BytesIO(b"nevergonnamakeit")
        self.assertRaises(exceptions.Duplicate,
                          self.store.add,
                          FAKE_UUID, image_swift, 0)

    def _option_required(self, key):
        conf = self.getConfig()
        conf[key] = None

        try:
            self.config(group="swift1", **conf)
            self.store = Store(self.conf, backend="swift1")
            return not self.store.is_capable(
                capabilities.BitMasks.WRITE_ACCESS)
        except Exception:
            return False

    def test_no_store_credentials(self):
        """
        Tests that options without a valid credentials disables the add method
        """
        self.store = Store(self.conf, backend="swift1")
        self.store.ref_params = {'ref1': {'auth_address':
                                          'authurl.com', 'user': '',
                                          'key': ''}}
        self.store.configure()
        self.assertFalse(self.store.is_capable(
            capabilities.BitMasks.WRITE_ACCESS))

    def test_no_auth_address(self):
        """
        Tests that options without auth address disables the add method
        """
        self.store = Store(self.conf, backend="swift1")
        self.store.ref_params = {'ref1': {'auth_address':
                                          '', 'user': 'user1',
                                          'key': 'key1'}}
        self.store.configure()
        self.assertFalse(self.store.is_capable(
            capabilities.BitMasks.WRITE_ACCESS))

    def test_delete(self):
        """
        Test we can delete an existing image in the swift store
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.mock_keystone_client()
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()

        uri = "swift://%s:key@authurl/glance/%s" % (
            self.swift_store_user, FAKE_UUID)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        self.store.delete(loc)

        self.assertRaises(exceptions.NotFound, self.store.get, loc)

    @mock.patch.object(swiftclient.client, 'delete_object')
    def test_delete_slo(self, mock_del_obj):
        """
        Test we can delete an existing image stored as SLO, static large object
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()

        uri = "swift://%s:key@authurl/glance/%s" % (self.swift_store_user,
                                                    FAKE_UUID2)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        self.store.delete(loc)

        self.assertEqual(1, mock_del_obj.call_count)
        _, kwargs = mock_del_obj.call_args
        self.assertEqual('multipart-manifest=delete',
                         kwargs.get('query_string'))

    @mock.patch.object(swiftclient.client, 'delete_object')
    def test_delete_nonslo_not_deleted_as_slo(self, mock_del_obj):
        """
        Test that non-SLOs are not being deleted the SLO way
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.mock_keystone_client()
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()

        uri = "swift://%s:key@authurl/glance/%s" % (self.swift_store_user,
                                                    FAKE_UUID)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        self.store.delete(loc)

        self.assertEqual(1, mock_del_obj.call_count)
        _, kwargs = mock_del_obj.call_args
        self.assertIsNone(kwargs.get('query_string'))

    def test_delete_with_reference_params(self):
        """
        Test we can delete an existing image in the swift store
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        # mock client because v3 uses it to receive auth_info
        self.mock_keystone_client()
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()

        uri = "swift+config://ref1/glance/%s" % (FAKE_UUID)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        self.store.delete(loc)

        self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def test_delete_non_existing(self):
        """
        Test that trying to delete a swift that doesn't exist
        raises an error
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()

        loc = location.get_location_from_uri_and_backend(
            "swift://%s:key@authurl/glance/noexist" % (self.swift_store_user),
            "swift1", conf=self.conf)
        self.assertRaises(exceptions.NotFound, self.store.delete, loc)

    def test_delete_with_some_segments_failing(self):
        """
        Tests that delete of a segmented object recovers from error(s) while
        deleting one or more segments.
        To test this we add a segmented object first and then delete it, while
        simulating errors on one or more segments.
        """

        test_image_id = str(uuid.uuid4())

        def fake_head_object(container, object_name):
            object_manifest = '/'.join([container, object_name]) + '-'
            return {'x-object-manifest': object_manifest}

        def fake_get_container(container, **kwargs):
            # Returning 5 fake segments
            return None, [{'name': '%s-%03d' % (test_image_id, x)}
                          for x in range(1, 6)]

        def fake_delete_object(container, object_name):
            # Simulate error on 1st and 3rd segments
            global SWIFT_DELETE_OBJECT_CALLS
            SWIFT_DELETE_OBJECT_CALLS += 1
            if object_name.endswith('-001') or object_name.endswith('-003'):
                raise swiftclient.ClientException('Object DELETE failed')
            else:
                pass

        conf = copy.deepcopy(SWIFT_CONF)
        self.config(group="swift1", **conf)
        moves.reload_module(swift)
        self.store = Store(self.conf, backend="swift1")
        self.store.configure()

        loc_uri = "swift+https://%s:key@localhost:8080/glance/%s"
        loc_uri = loc_uri % (self.swift_store_user, test_image_id)
        loc = location.get_location_from_uri_and_backend(
            loc_uri, "swift1", conf=self.conf)

        conn = self.store.get_connection(loc.store_location)
        conn.delete_object = fake_delete_object
        conn.head_object = fake_head_object
        conn.get_container = fake_get_container

        global SWIFT_DELETE_OBJECT_CALLS
        SWIFT_DELETE_OBJECT_CALLS = 0

        self.store.delete(loc, connection=conn)
        # Expecting 6 delete calls, 5 for the segments and 1 for the manifest
        self.assertEqual(6, SWIFT_DELETE_OBJECT_CALLS)

    def test_read_acl_public(self):
        """
        Test that we can set a public read acl.
        """
        self.config(group="swift1", swift_store_config_file=None)
        self.config(group="swift1", swift_store_multi_tenant=True)
        store = Store(self.conf, backend="swift1")
        store.configure()
        uri = "swift+http://storeurl/glance/%s" % FAKE_UUID
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        ctxt = mock.MagicMock()
        store.set_acls(loc, public=True, context=ctxt)
        container_headers = swiftclient.client.head_container('x', 'y',
                                                              'glance')
        self.assertEqual("*:*", container_headers['X-Container-Read'])

    def test_read_acl_tenants(self):
        """
        Test that we can set read acl for tenants.
        """
        self.config(group="swift1", swift_store_config_file=None)
        self.config(group="swift1", swift_store_multi_tenant=True)
        store = Store(self.conf, backend="swift1")
        store.configure()
        uri = "swift+http://storeurl/glance/%s" % FAKE_UUID
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        read_tenants = ['matt', 'mark']
        ctxt = mock.MagicMock()
        store.set_acls(loc, read_tenants=read_tenants, context=ctxt)
        container_headers = swiftclient.client.head_container('x', 'y',
                                                              'glance')
        self.assertEqual('matt:*,mark:*', container_headers[
            'X-Container-Read'])

    def test_write_acls(self):
        """
        Test that we can set write acl for tenants.
        """
        self.config(group="swift1", swift_store_config_file=None)
        self.config(group="swift1", swift_store_multi_tenant=True)
        store = Store(self.conf, backend="swift1")
        store.configure()
        uri = "swift+http://storeurl/glance/%s" % FAKE_UUID
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        read_tenants = ['frank', 'jim']
        ctxt = mock.MagicMock()
        store.set_acls(loc, write_tenants=read_tenants, context=ctxt)
        container_headers = swiftclient.client.head_container('x', 'y',
                                                              'glance')
        self.assertEqual('frank:*,jim:*', container_headers[
            'X-Container-Write'])

    @mock.patch("glance_store._drivers.swift."
                "connection_manager.MultiTenantConnectionManager")
    def test_get_connection_manager_multi_tenant(self, manager_class):
        manager = mock.MagicMock()
        manager_class.return_value = manager
        self.config(group="swift1", swift_store_config_file=None)
        self.config(group="swift1", swift_store_multi_tenant=True)
        store = Store(self.conf, backend="swift1")
        store.configure()
        loc = mock.MagicMock()
        self.assertEqual(store.get_manager(loc), manager)

    @mock.patch("glance_store._drivers.swift."
                "connection_manager.SingleTenantConnectionManager")
    def test_get_connection_manager_single_tenant(self, manager_class):
        manager = mock.MagicMock()
        manager_class.return_value = manager
        store = Store(self.conf, backend="swift1")
        store.configure()
        loc = mock.MagicMock()
        self.assertEqual(store.get_manager(loc), manager)

    def test_get_connection_manager_failed(self):
        store = swift.BaseStore(mock.MagicMock())
        loc = mock.MagicMock()
        self.assertRaises(NotImplementedError, store.get_manager, loc)

    def test_init_client_multi_tenant(self):
        """Test that keystone client was initialized correctly"""
        self._init_client(verify=True, swift_store_multi_tenant=True,
                          swift_store_config_file=None)

    def test_init_client_multi_tenant_insecure(self):
        """
        Test that keystone client was initialized correctly with no
        certificate verification.
        """
        self._init_client(verify=False, swift_store_multi_tenant=True,
                          swift_store_auth_insecure=True,
                          swift_store_config_file=None)

    @mock.patch("glance_store._drivers.swift.store.ks_identity")
    @mock.patch("glance_store._drivers.swift.store.ks_session")
    @mock.patch("glance_store._drivers.swift.store.ks_client")
    def _init_client(self, mock_client, mock_session, mock_identity, verify,
                     **kwargs):
        # initialize store and connection parameters
        self.config(group="swift1", **kwargs)
        store = Store(self.conf, backend="swift1")
        store.configure()
        ref_params = sutils.SwiftParams(self.conf, backend="swift1").params
        default_ref = getattr(self.conf, "swift1").default_swift_reference
        default_swift_reference = ref_params.get(default_ref)
        # prepare client and session
        trustee_session = mock.MagicMock()
        trustor_session = mock.MagicMock()
        main_session = mock.MagicMock()
        trustee_client = mock.MagicMock()
        trustee_client.session.get_user_id.return_value = 'fake_user'
        trustor_client = mock.MagicMock()
        trustor_client.session.auth.get_auth_ref.return_value = {
            'roles': [{'name': 'fake_role'}]
        }
        trustor_client.trusts.create.return_value = mock.MagicMock(
            id='fake_trust')
        main_client = mock.MagicMock()
        mock_session.Session.side_effect = [trustor_session, trustee_session,
                                            main_session]
        mock_client.Client.side_effect = [trustor_client, trustee_client,
                                          main_client]
        # initialize client
        ctxt = mock.MagicMock()
        client = store.init_client(location=mock.MagicMock(), context=ctxt)
        # test trustor usage
        mock_identity.V3Token.assert_called_once_with(
            auth_url=default_swift_reference.get('auth_address'),
            token=ctxt.auth_token,
            project_id=ctxt.tenant
        )
        mock_session.Session.assert_any_call(auth=mock_identity.V3Token(),
                                             verify=verify)
        mock_client.Client.assert_any_call(session=trustor_session)
        # test trustee usage and trust creation
        tenant_name, user = default_swift_reference.get('user').split(':')
        mock_identity.V3Password.assert_any_call(
            auth_url=default_swift_reference.get('auth_address'),
            username=user,
            password=default_swift_reference.get('key'),
            project_name=tenant_name,
            user_domain_id=default_swift_reference.get('user_domain_id'),
            user_domain_name=default_swift_reference.get('user_domain_name'),
            project_domain_id=default_swift_reference.get('project_domain_id'),
            project_domain_name=default_swift_reference.get(
                'project_domain_name')
        )
        mock_session.Session.assert_any_call(auth=mock_identity.V3Password(),
                                             verify=verify)
        mock_client.Client.assert_any_call(session=trustee_session)
        trustor_client.trusts.create.assert_called_once_with(
            trustee_user='fake_user', trustor_user=ctxt.user,
            project=ctxt.tenant, impersonation=True,
            role_names=['fake_role']
        )
        mock_identity.V3Password.assert_any_call(
            auth_url=default_swift_reference.get('auth_address'),
            username=user,
            password=default_swift_reference.get('key'),
            trust_id='fake_trust',
            user_domain_id=default_swift_reference.get('user_domain_id'),
            user_domain_name=default_swift_reference.get('user_domain_name'),
            project_domain_id=default_swift_reference.get('project_domain_id'),
            project_domain_name=default_swift_reference.get(
                'project_domain_name')
        )
        mock_client.Client.assert_any_call(session=main_session)
        self.assertEqual(main_client, client)


class TestStoreAuthV1(base.MultiStoreBaseTest, SwiftTests,
                      test_store_capabilities.TestStoreCapabilitiesChecking):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def getConfig(self):
        conf = SWIFT_CONF.copy()
        conf['swift_store_auth_version'] = '1'
        conf['swift_store_user'] = 'tenant:user1'
        return conf

    def setUp(self):
        """Establish a clean test environment."""
        super(TestStoreAuthV1, self).setUp()
        enabled_backends = {
            "swift1": "swift",
            "swift2": "swift",
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='swift1', group='glance_store')

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}

        store.create_multi_stores(self.conf)
        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.test_dir = self.useFixture(fixtures.TempDir()).path

        config = self.getConfig()

        conf_file = 'glance-swift.conf'
        self.swift_config_file = self.copy_data_file(conf_file, self.test_dir)
        config.update({'swift_store_config_file': self.swift_config_file})

        self.stub_out_swiftclient(config['swift_store_auth_version'])
        self.mock_keystone_client()
        self.store = Store(self.conf, backend="swift1")
        self.config(group="swift1", **config)
        self.store.configure()

        self.register_store_backend_schemes(self.store, 'swift', 'swift1')
        self.addCleanup(self.conf.reset)


class TestStoreAuthV2(TestStoreAuthV1):

    def getConfig(self):
        config = super(TestStoreAuthV2, self).getConfig()
        config['swift_store_auth_version'] = '2'
        config['swift_store_user'] = 'tenant:user1'
        return config

    def test_v2_with_no_tenant(self):
        uri = "swift://failme:key@auth_address/glance/%s" % (FAKE_UUID)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        self.assertRaises(exceptions.BadStoreUri,
                          self.store.get,
                          loc)

    def test_v2_multi_tenant_location(self):
        config = self.getConfig()
        config['swift_store_multi_tenant'] = True
        self.config(group="swift1", **config)
        uri = "swift://auth_address/glance/%s" % (FAKE_UUID)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        self.assertEqual('swift', loc.store_name)


class TestStoreAuthV3(TestStoreAuthV1):

    def getConfig(self):
        config = super(TestStoreAuthV3, self).getConfig()
        config['swift_store_auth_version'] = '3'
        config['swift_store_user'] = 'tenant:user1'
        return config

    @mock.patch("glance_store._drivers.swift.store.ks_identity")
    @mock.patch("glance_store._drivers.swift.store.ks_session")
    @mock.patch("glance_store._drivers.swift.store.ks_client")
    def test_init_client_single_tenant(self,
                                       mock_client,
                                       mock_session,
                                       mock_identity):
        """Test that keystone client was initialized correctly"""
        # initialize client
        store = Store(self.conf, backend="swift1")
        store.configure()
        uri = "swift://%s:key@auth_address/glance/%s" % (
            self.swift_store_user, FAKE_UUID)
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        ctxt = mock.MagicMock()
        store.init_client(location=loc.store_location, context=ctxt)
        # check that keystone was initialized correctly
        tenant = None if store.auth_version == '1' else "tenant"
        username = "tenant:user1" if store.auth_version == '1' else "user1"
        mock_identity.V3Password.assert_called_once_with(
            auth_url=loc.store_location.swift_url + '/',
            username=username, password="key",
            project_name=tenant,
            project_domain_id='default', project_domain_name='default',
            user_domain_id='default', user_domain_name='default',)
        mock_session.Session.assert_called_once_with(
            auth=mock_identity.V3Password(), verify=True)
        mock_client.Client.assert_called_once_with(
            session=mock_session.Session())


class FakeConnection(object):
    def __init__(self, authurl=None, user=None, key=None, retries=5,
                 preauthurl=None, preauthtoken=None, starting_backoff=1,
                 tenant_name=None, os_options=None, auth_version="1",
                 insecure=False, ssl_compression=True, cacert=None):
        if os_options is None:
            os_options = {}

        self.authurl = authurl
        self.user = user
        self.key = key
        self.preauthurl = preauthurl
        self.preauthtoken = preauthtoken
        self.tenant_name = tenant_name
        self.os_options = os_options
        self.auth_version = auth_version
        self.insecure = insecure
        self.cacert = cacert


class TestSingleTenantStoreConnections(base.MultiStoreBaseTest):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        super(TestSingleTenantStoreConnections, self).setUp()
        enabled_backends = {
            "swift1": "swift",
            "swift2": "swift",
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='swift1', group='glance_store')

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}

        store.create_multi_stores(self.conf)
        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.test_dir = self.useFixture(fixtures.TempDir()).path

        self.useFixture(fixtures.MockPatch(
            'swiftclient.Connection', FakeConnection))
        self.store = swift.SingleTenantStore(self.conf, backend="swift1")
        self.store.configure()
        specs = {'scheme': 'swift',
                 'auth_or_store_url': 'example.com/v2/',
                 'user': 'tenant:user1',
                 'key': 'key1',
                 'container': 'cont',
                 'obj': 'object'}
        self.location = swift.StoreLocation(specs, self.conf,
                                            backend_group="swift1")

        self.register_store_backend_schemes(self.store, 'swift', 'swift1')
        self.addCleanup(self.conf.reset)

    def test_basic_connection(self):
        connection = self.store.get_connection(self.location)
        self.assertEqual('https://example.com/v2/', connection.authurl)
        self.assertEqual('2', connection.auth_version)
        self.assertEqual('user1', connection.user)
        self.assertEqual('tenant', connection.tenant_name)
        self.assertEqual('key1', connection.key)
        self.assertIsNone(connection.preauthurl)
        self.assertFalse(connection.insecure)
        self.assertEqual({'service_type': 'object-store',
                          'endpoint_type': 'publicURL'},
                         connection.os_options)

    def test_connection_with_conf_endpoint(self):
        ctx = mock.MagicMock(user='tenant:user1', tenant='tenant')
        self.config(group="swift1",
                    swift_store_endpoint='https://internal.com')
        self.store.configure()
        connection = self.store.get_connection(self.location, context=ctx)
        self.assertEqual('https://example.com/v2/', connection.authurl)
        self.assertEqual('2', connection.auth_version)
        self.assertEqual('user1', connection.user)
        self.assertEqual('tenant', connection.tenant_name)
        self.assertEqual('key1', connection.key)
        self.assertEqual('https://internal.com', connection.preauthurl)
        self.assertFalse(connection.insecure)
        self.assertEqual({'service_type': 'object-store',
                          'endpoint_type': 'publicURL'},
                         connection.os_options)

    def test_connection_with_conf_endpoint_no_context(self):
        self.config(group="swift1",
                    swift_store_endpoint='https://internal.com')
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertEqual('https://example.com/v2/', connection.authurl)
        self.assertEqual('2', connection.auth_version)
        self.assertEqual('user1', connection.user)
        self.assertEqual('tenant', connection.tenant_name)
        self.assertEqual('key1', connection.key)
        self.assertEqual('https://internal.com', connection.preauthurl)
        self.assertFalse(connection.insecure)
        self.assertEqual({'service_type': 'object-store',
                          'endpoint_type': 'publicURL'},
                         connection.os_options)

    def test_connection_with_no_trailing_slash(self):
        self.location.auth_or_store_url = 'example.com/v2'
        connection = self.store.get_connection(self.location)
        self.assertEqual('https://example.com/v2/', connection.authurl)

    def test_connection_insecure(self):
        self.config(group="swift1", swift_store_auth_insecure=True)
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertTrue(connection.insecure)

    def test_connection_with_auth_v1(self):
        self.config(group="swift1", swift_store_auth_version='1')
        self.store.configure()
        self.location.user = 'auth_v1_user'
        connection = self.store.get_connection(self.location)
        self.assertEqual('1', connection.auth_version)
        self.assertEqual('auth_v1_user', connection.user)
        self.assertIsNone(connection.tenant_name)

    def test_connection_invalid_user(self):
        self.store.configure()
        self.location.user = 'invalid:format:user'
        self.assertRaises(exceptions.BadStoreUri,
                          self.store.get_connection, self.location)

    def test_connection_missing_user(self):
        self.store.configure()
        self.location.user = None
        self.assertRaises(exceptions.BadStoreUri,
                          self.store.get_connection, self.location)

    def test_connection_with_region(self):
        self.config(group="swift1", swift_store_region='Sahara')
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertEqual({'region_name': 'Sahara',
                          'service_type': 'object-store',
                          'endpoint_type': 'publicURL'},
                         connection.os_options)

    def test_connection_with_service_type(self):
        self.config(group="swift1", swift_store_service_type='shoe-store')
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertEqual({'service_type': 'shoe-store',
                          'endpoint_type': 'publicURL'},
                         connection.os_options)

    def test_connection_with_endpoint_type(self):
        self.config(group="swift1", swift_store_endpoint_type='internalURL')
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertEqual({'service_type': 'object-store',
                          'endpoint_type': 'internalURL'},
                         connection.os_options)

    def test_bad_location_uri(self):
        self.store.configure()
        self.location.uri = 'http://bad_uri://'
        self.assertRaises(exceptions.BadStoreUri,
                          self.location.parse_uri,
                          self.location.uri)

    def test_bad_location_uri_invalid_credentials(self):
        self.store.configure()
        self.location.uri = 'swift://bad_creds@uri/cont/obj'
        self.assertRaises(exceptions.BadStoreUri,
                          self.location.parse_uri,
                          self.location.uri)

    def test_bad_location_uri_invalid_object_path(self):
        self.store.configure()
        self.location.uri = 'swift://user:key@uri/cont'
        self.assertRaises(exceptions.BadStoreUri,
                          self.location.parse_uri,
                          self.location.uri)

    def test_ref_overrides_defaults(self):
        self.config(group="swift1", swift_store_auth_version='2',
                    swift_store_user='testuser',
                    swift_store_key='testpass',
                    swift_store_auth_address='testaddress',
                    swift_store_endpoint_type='internalURL',
                    swift_store_config_file='somefile')

        self.store.ref_params = {'ref1': {'auth_address': 'authurl.com',
                                          'auth_version': '3',
                                          'user': 'user:pass',
                                          'user_domain_id': 'default',
                                          'user_domain_name': 'ignored',
                                          'project_domain_id': 'default',
                                          'project_domain_name': 'ignored'}}

        self.store.configure()

        self.assertEqual('user:pass', self.store.user)
        self.assertEqual('3', self.store.auth_version)
        self.assertEqual('authurl.com', self.store.auth_address)
        self.assertEqual('default', self.store.user_domain_id)
        self.assertEqual('ignored', self.store.user_domain_name)
        self.assertEqual('default', self.store.project_domain_id)
        self.assertEqual('ignored', self.store.project_domain_name)

    def test_with_v3_auth(self):
        self.store.ref_params = {'ref1': {'auth_address': 'authurl.com',
                                          'auth_version': '3',
                                          'user': 'user:pass',
                                          'key': 'password',
                                          'user_domain_id': 'default',
                                          'user_domain_name': 'ignored',
                                          'project_domain_id': 'default',
                                          'project_domain_name': 'ignored'}}
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertEqual('3', connection.auth_version)
        self.assertEqual({'service_type': 'object-store',
                          'endpoint_type': 'publicURL',
                          'user_domain_id': 'default',
                          'user_domain_name': 'ignored',
                          'project_domain_id': 'default',
                          'project_domain_name': 'ignored'},
                         connection.os_options)


class TestMultiTenantStoreConnections(base.MultiStoreBaseTest):
    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        super(TestMultiTenantStoreConnections, self).setUp()
        enabled_backends = {
            "swift1": "swift",
            "swift2": "swift",
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='swift1', group='glance_store')

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}

        store.create_multi_stores(self.conf)
        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.test_dir = self.useFixture(fixtures.TempDir()).path

        self.useFixture(fixtures.MockPatch(
            'swiftclient.Connection', FakeConnection))
        self.context = mock.MagicMock(
            user='tenant:user1', tenant='tenant', auth_token='0123')
        self.store = swift.MultiTenantStore(self.conf, backend="swift1")
        specs = {'scheme': 'swift',
                 'auth_or_store_url': 'example.com',
                 'container': 'cont',
                 'obj': 'object'}
        self.location = swift.StoreLocation(specs, self.conf,
                                            backend_group="swift1")
        self.addCleanup(self.conf.reset)

    def test_basic_connection(self):
        self.store.configure()
        connection = self.store.get_connection(self.location,
                                               context=self.context)
        self.assertIsNone(connection.authurl)
        self.assertEqual('1', connection.auth_version)
        self.assertIsNone(connection.user)
        self.assertIsNone(connection.tenant_name)
        self.assertIsNone(connection.key)
        self.assertEqual('https://example.com', connection.preauthurl)
        self.assertEqual('0123', connection.preauthtoken)
        self.assertEqual({}, connection.os_options)

    def test_connection_does_not_use_endpoint_from_catalog(self):
        self.store.configure()
        self.context.service_catalog = [
            {
                'endpoint_links': [],
                'endpoints': [
                    {
                        'region': 'RegionOne',
                        'publicURL': 'https://scexample.com',
                    },
                ],
                'type': 'object-store',
                'name': 'Object Storage Service',
            }
        ]
        connection = self.store.get_connection(self.location,
                                               context=self.context)
        self.assertIsNone(connection.authurl)
        self.assertEqual('1', connection.auth_version)
        self.assertIsNone(connection.user)
        self.assertIsNone(connection.tenant_name)
        self.assertIsNone(connection.key)
        self.assertNotEqual('https://scexample.com', connection.preauthurl)
        self.assertEqual('https://example.com', connection.preauthurl)
        self.assertEqual('0123', connection.preauthtoken)
        self.assertEqual({}, connection.os_options)

    def test_connection_manager_does_not_use_endpoint_from_catalog(self):
        self.store.configure()
        self.context.service_catalog = [
            {
                'endpoint_links': [],
                'endpoints': [
                    {
                        'region': 'RegionOne',
                        'publicURL': 'https://scexample.com',
                    },
                ],
                'type': 'object-store',
                'name': 'Object Storage Service',
            }
        ]
        connection_manager = manager.MultiTenantConnectionManager(
            store=self.store,
            store_location=self.location,
            context=self.context
        )
        conn = connection_manager._init_connection()
        self.assertNotEqual('https://scexample.com', conn.preauthurl)
        self.assertEqual('https://example.com', conn.preauthurl)


class TestMultiTenantStoreContext(base.MultiStoreBaseTest):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        """Establish a clean test environment."""
        super(TestMultiTenantStoreContext, self).setUp()
        config = SWIFT_CONF.copy()

        enabled_backends = {
            "swift1": "swift",
            "swift2": "swift",
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='swift1', group='glance_store')

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}

        store.create_multi_stores(self.conf)
        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.test_dir = self.useFixture(fixtures.TempDir()).path

        self.store = Store(self.conf, backend="swift1")
        self.config(group="swift1", **config)
        self.store.configure()
        self.register_store_backend_schemes(self.store, 'swift', 'swift1')

        service_catalog = [
            {
                'endpoint_links': [],
                'endpoints': [
                    {
                        'region': 'RegionOne',
                        'publicURL': 'http://127.0.0.1:0',
                    },
                ],
                'type': 'object-store',
                'name': 'Object Storage Service',
            }
        ]
        self.ctx = mock.MagicMock(
            service_catalog=service_catalog, user='tenant:user1',
            tenant='tenant', auth_token='0123')
        self.addCleanup(self.conf.reset)

    @requests_mock.mock()
    def test_download_context(self, m):
        """Verify context (ie token) is passed to swift on download."""
        self.config(group="swift1", swift_store_multi_tenant=True)
        store = Store(self.conf, backend="swift1")
        store.configure()
        uri = "swift+http://127.0.0.1/glance_123/123"
        loc = location.get_location_from_uri_and_backend(
            uri, "swift1", conf=self.conf)
        m.get("http://127.0.0.1/glance_123/123",
              headers={'Content-Length': '0'})
        store.get(loc, context=self.ctx)
        self.assertEqual(b'0123', m.last_request.headers['X-Auth-Token'])

    @requests_mock.mock()
    def test_upload_context(self, m):
        """Verify context (ie token) is passed to swift on upload."""
        head_req = m.head("http://127.0.0.1/glance_123",
                          text='Some data',
                          status_code=201)
        put_req = m.put("http://127.0.0.1/glance_123/123")

        self.config(group="swift1", swift_store_multi_tenant=True)
        store = Store(self.conf, backend="swift1")
        store.configure()
        content = b'Some data'
        pseudo_file = six.BytesIO(content)
        store.add('123', pseudo_file, len(content),
                  context=self.ctx)
        self.assertEqual(b'0123',
                         head_req.last_request.headers['X-Auth-Token'])
        self.assertEqual(b'0123',
                         put_req.last_request.headers['X-Auth-Token'])


class TestCreatingLocations(base.MultiStoreBaseTest):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        super(TestCreatingLocations, self).setUp()
        enabled_backends = {
            "swift1": "swift",
            "swift2": "swift",
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='swift1', group='glance_store')

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}

        store.create_multi_stores(self.conf)
        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.test_dir = self.useFixture(fixtures.TempDir()).path

        config = copy.deepcopy(SWIFT_CONF)
        self.store = Store(self.conf, backend="swift1")
        self.config(group="swift1", **config)
        self.store.configure()
        self.register_store_backend_schemes(self.store, 'swift', 'swift1')

        moves.reload_module(swift)
        self.addCleanup(self.conf.reset)

        service_catalog = [
            {
                'endpoint_links': [],
                'endpoints': [
                    {
                        'adminURL': 'https://some_admin_endpoint',
                        'region': 'RegionOne',
                        'internalURL': 'https://some_internal_endpoint',
                        'publicURL': 'https://some_endpoint',
                    },
                ],
                'type': 'object-store',
                'name': 'Object Storage Service',
            }
        ]
        self.ctxt = mock.MagicMock(user='user', tenant='tenant',
                                   auth_token='123',
                                   service_catalog=service_catalog)

    def test_single_tenant_location(self):
        conf = copy.deepcopy(SWIFT_CONF)
        conf['swift_store_container'] = 'container'
        conf_file = "glance-swift.conf"
        self.swift_config_file = self.copy_data_file(conf_file, self.test_dir)
        conf.update({'swift_store_config_file': self.swift_config_file})
        conf['default_swift_reference'] = 'ref1'
        self.config(group="swift1", **conf)
        moves.reload_module(swift)

        store = swift.SingleTenantStore(self.conf, backend="swift1")
        store.configure()
        location = store.create_location('image-id')
        self.assertEqual('swift+https', location.scheme)
        self.assertEqual('https://example.com', location.swift_url)
        self.assertEqual('container', location.container)
        self.assertEqual('image-id', location.obj)
        self.assertEqual('tenant:user1', location.user)
        self.assertEqual('key1', location.key)

    def test_single_tenant_location_http(self):
        conf_file = "glance-swift.conf"
        test_dir = self.useFixture(fixtures.TempDir()).path
        self.swift_config_file = self.copy_data_file(conf_file, test_dir)
        self.config(group="swift1", swift_store_container='container',
                    default_swift_reference='ref2',
                    swift_store_config_file=self.swift_config_file)

        store = swift.SingleTenantStore(self.conf, backend="swift1")
        store.configure()
        location = store.create_location('image-id')
        self.assertEqual('swift+http', location.scheme)
        self.assertEqual('http://example.com', location.swift_url)

    def test_multi_tenant_location(self):
        self.config(group="swift1", swift_store_container='container')
        store = swift.MultiTenantStore(self.conf, backend="swift1")
        store.configure()
        location = store.create_location('image-id', context=self.ctxt)
        self.assertEqual('swift+https', location.scheme)
        self.assertEqual('https://some_endpoint', location.swift_url)
        self.assertEqual('container_image-id', location.container)
        self.assertEqual('image-id', location.obj)
        self.assertIsNone(location.user)
        self.assertIsNone(location.key)

    def test_multi_tenant_location_http(self):
        store = swift.MultiTenantStore(self.conf, backend="swift1")
        store.configure()
        self.ctxt.service_catalog[0]['endpoints'][0]['publicURL'] = \
            'http://some_endpoint'
        location = store.create_location('image-id', context=self.ctxt)
        self.assertEqual('swift+http', location.scheme)
        self.assertEqual('http://some_endpoint', location.swift_url)

    def test_multi_tenant_location_with_region(self):
        self.config(group="swift1", swift_store_region='WestCarolina')
        store = swift.MultiTenantStore(self.conf, backend="swift1")
        store.configure()
        self.ctxt.service_catalog[0]['endpoints'][0]['region'] = 'WestCarolina'
        self.assertEqual('https://some_endpoint',
                         store._get_endpoint(self.ctxt))

    def test_multi_tenant_location_custom_service_type(self):
        self.config(group="swift1", swift_store_service_type='toy-store')
        self.ctxt.service_catalog[0]['type'] = 'toy-store'
        store = swift.MultiTenantStore(self.conf, backend="swift1")
        store.configure()
        store._get_endpoint(self.ctxt)
        self.assertEqual('https://some_endpoint',
                         store._get_endpoint(self.ctxt))

    def test_multi_tenant_location_custom_endpoint_type(self):
        self.config(group="swift1", swift_store_endpoint_type='internalURL')
        store = swift.MultiTenantStore(self.conf, backend="swift1")
        store.configure()
        self.assertEqual('https://some_internal_endpoint',
                         store._get_endpoint(self.ctxt))


class TestChunkReader(base.MultiStoreBaseTest):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        super(TestChunkReader, self).setUp()
        enabled_backends = {
            "swift1": "swift",
            "swift2": "swift",
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='swift1', group='glance_store')

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}

        store.create_multi_stores(self.conf)
        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.test_dir = self.useFixture(fixtures.TempDir()).path

        config = copy.deepcopy(SWIFT_CONF)
        self.store = Store(self.conf, backend="swift1")
        self.config(group="swift1", **config)
        self.store.configure()
        self.register_store_backend_schemes(self.store, 'swift', 'swift1')

        self.addCleanup(self.conf.reset)

    def test_read_all_data(self):
        """
        Replicate what goes on in the Swift driver with the
        repeated creation of the ChunkReader object
        """
        CHUNKSIZE = 100
        data = b'*' * units.Ki
        expected_checksum = hashlib.md5(data).hexdigest()
        expected_multihash = hashlib.sha256(data).hexdigest()
        data_file = tempfile.NamedTemporaryFile()
        data_file.write(data)
        data_file.flush()
        infile = open(data_file.name, 'rb')
        bytes_read = 0
        checksum = hashlib.md5()
        os_hash_value = hashlib.sha256()
        while True:
            cr = swift.ChunkReader(infile, checksum, os_hash_value, CHUNKSIZE)
            chunk = cr.read(CHUNKSIZE)
            if len(chunk) == 0:
                self.assertEqual(True, cr.is_zero_size)
                break
            bytes_read += len(chunk)
        self.assertEqual(units.Ki, bytes_read)
        self.assertEqual(expected_checksum,
                         cr.checksum.hexdigest())
        self.assertEqual(expected_multihash,
                         cr.os_hash_value.hexdigest())
        data_file.close()
        infile.close()

    def test_read_zero_size_data(self):
        """
        Replicate what goes on in the Swift driver with the
        repeated creation of the ChunkReader object
        """
        expected_checksum = hashlib.md5(b'').hexdigest()
        expected_multihash = hashlib.sha256(b'').hexdigest()
        CHUNKSIZE = 100
        checksum = hashlib.md5()
        os_hash_value = hashlib.sha256()
        data_file = tempfile.NamedTemporaryFile()
        infile = open(data_file.name, 'rb')
        bytes_read = 0
        while True:
            cr = swift.ChunkReader(infile, checksum, os_hash_value, CHUNKSIZE)
            chunk = cr.read(CHUNKSIZE)
            if len(chunk) == 0:
                break
            bytes_read += len(chunk)
        self.assertEqual(True, cr.is_zero_size)
        self.assertEqual(0, bytes_read)
        self.assertEqual(expected_checksum, cr.checksum.hexdigest())
        self.assertEqual(expected_multihash, cr.os_hash_value.hexdigest())
        data_file.close()
        infile.close()


class TestMultipleContainers(base.MultiStoreBaseTest):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        super(TestMultipleContainers, self).setUp()

        enabled_backends = {
            "swift1": "swift",
            "swift2": "swift",
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='swift1', group='glance_store')

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}

        store.create_multi_stores(self.conf)
        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.test_dir = self.useFixture(fixtures.TempDir()).path

        self.config(group="swift1", swift_store_multiple_containers_seed=3)
        self.store = swift.SingleTenantStore(self.conf, backend="swift1")
        self.store.configure()
        self.register_store_backend_schemes(self.store, 'swift', 'swift1')

        self.addCleanup(self.conf.reset)

    def test_get_container_name_happy_path_with_seed_three(self):

        test_image_id = 'fdae39a1-bac5-4238-aba4-69bcc726e848'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container_fda'
        self.assertEqual(expected, actual)

    def test_get_container_name_with_negative_seed(self):
        self.assertRaises(ValueError, self.config,
                          group="swift1",
                          swift_store_multiple_containers_seed=-1)

    def test_get_container_name_with_seed_beyond_max(self):
        self.assertRaises(ValueError, self.config,
                          group="swift1",
                          swift_store_multiple_containers_seed=33)

    def test_get_container_name_with_max_seed(self):
        self.config(group="swift1", swift_store_multiple_containers_seed=32)
        self.store = swift.SingleTenantStore(
            self.conf, backend="swift1")

        test_image_id = 'fdae39a1-bac5-4238-aba4-69bcc726e848'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container_' + test_image_id
        self.assertEqual(expected, actual)

    def test_get_container_name_with_dash(self):
        self.config(group="swift1", swift_store_multiple_containers_seed=10)
        self.store = swift.SingleTenantStore(
            self.conf, backend="swift1")

        test_image_id = 'fdae39a1-bac5-4238-aba4-69bcc726e848'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container_' + 'fdae39a1-ba'
        self.assertEqual(expected, actual)

    def test_get_container_name_with_min_seed(self):
        self.config(group="swift1", swift_store_multiple_containers_seed=1)
        self.store = swift.SingleTenantStore(
            self.conf, backend="swift1")

        test_image_id = 'fdae39a1-bac5-4238-aba4-69bcc726e848'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container_' + 'f'
        self.assertEqual(expected, actual)

    def test_get_container_name_with_multiple_containers_turned_off(self):
        self.config(group="swift1", swift_store_multiple_containers_seed=0)
        self.store.configure()

        test_image_id = 'random_id'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container'
        self.assertEqual(expected, actual)
