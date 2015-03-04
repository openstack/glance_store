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

"""Tests the Swift backend store"""

import copy
import fixtures
import hashlib
import httplib
import mock
import tempfile
import uuid

from oslo_config import cfg
from oslo_utils import units
from oslotest import moxstubout
import requests_mock
import six
# NOTE(jokke): simplified transition to py3, behaves like py2 xrange
from six.moves import range
import StringIO
import swiftclient

from glance_store._drivers.swift import store as swift
from glance_store import backend
from glance_store import BackendException
from glance_store import capabilities
from glance_store.common import auth
from glance_store.common import utils
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from tests.unit import test_store_capabilities


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
              'swift_store_auth_address': 'localhost:8080',
              'swift_store_container': 'glance',
              'swift_store_retry_get_count': 1,
              'default_swift_reference': 'ref1'
              }


# We stub out as little as possible to ensure that the code paths
# between swift and swiftclient are tested
# thoroughly
def stub_out_swiftclient(stubs, swift_store_auth_version):
    fixture_containers = ['glance']
    fixture_container_headers = {}
    fixture_headers = {
        'glance/%s' % FAKE_UUID: {
            'content-length': FIVE_KB,
            'etag': 'c2e5db72bd7fd153f53ede5da5a06de3'
        },
        'glance/%s' % FAKE_UUID2: {'x-static-large-object': 'true', },
    }
    fixture_objects = {'glance/%s' % FAKE_UUID: six.StringIO("*" * FIVE_KB),
                       'glance/%s' % FAKE_UUID2: six.StringIO("*" * FIVE_KB), }

    def fake_head_container(url, token, container, **kwargs):
        if container not in fixture_containers:
            msg = "No container %s found" % container
            raise swiftclient.ClientException(msg,
                                              http_status=httplib.NOT_FOUND)
        return fixture_container_headers

    def fake_put_container(url, token, container, **kwargs):
        fixture_containers.append(container)

    def fake_post_container(url, token, container, headers, http_conn=None):
        for key, value in six.iteritems(headers):
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
                etag = kwargs['headers']['ETag']
                manifest = kwargs.get('headers').get('X-Object-Manifest')
                fixture_headers[fixture_key] = {'manifest': True,
                                                'etag': etag,
                                                'x-object-manifest': manifest}
                fixture_objects[fixture_key] = None
                return etag
            if hasattr(contents, 'read'):
                fixture_object = six.StringIO()
                chunk = contents.read(CHUNKSIZE)
                checksum = hashlib.md5()
                while chunk:
                    fixture_object.write(chunk)
                    checksum.update(chunk)
                    chunk = contents.read(CHUNKSIZE)
                etag = checksum.hexdigest()
            else:
                fixture_object = six.StringIO(contents)
                etag = hashlib.md5(fixture_object.getvalue()).hexdigest()
            read_len = fixture_object.len
            if read_len > MAX_SWIFT_OBJECT_SIZE:
                msg = ('Image size:%d exceeds Swift max:%d' %
                       (read_len, MAX_SWIFT_OBJECT_SIZE))
                raise swiftclient.ClientException(
                    msg, http_status=httplib.REQUEST_ENTITY_TOO_LARGE)
            fixture_objects[fixture_key] = fixture_object
            fixture_headers[fixture_key] = {
                'content-length': read_len,
                'etag': etag}
            return etag
        else:
            msg = ("Object PUT failed - Object with key %s already exists"
                   % fixture_key)
            raise swiftclient.ClientException(msg,
                                              http_status=httplib.CONFLICT)

    def fake_get_object(url, token, container, name, **kwargs):
        # GET returns the tuple (list of headers, file object)
        fixture_key = "%s/%s" % (container, name)
        if fixture_key not in fixture_headers:
            msg = "Object GET failed"
            raise swiftclient.ClientException(msg,
                                              http_status=httplib.NOT_FOUND)

        byte_range = None
        headers = kwargs.get('headers', dict())
        if headers is not None:
            headers = dict((k.lower(), v) for k, v in six.iteritems(headers))
            if 'range' in headers:
                byte_range = headers.get('range')

        fixture = fixture_headers[fixture_key]
        if 'manifest' in fixture:
            # Large object manifest... we return a file containing
            # all objects with prefix of this fixture key
            chunk_keys = sorted([k for k in fixture_headers.keys()
                                 if k.startswith(fixture_key) and
                                 k != fixture_key])
            result = six.StringIO()
            for key in chunk_keys:
                result.write(fixture_objects[key].getvalue())
        else:
            result = fixture_objects[fixture_key]

        if byte_range is not None:
            start = int(byte_range.split('=')[1].strip('-'))
            result = six.StringIO(result.getvalue()[start:])
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
            raise swiftclient.ClientException(msg,
                                              http_status=httplib.NOT_FOUND)

    def fake_delete_object(url, token, container, name, **kwargs):
        # DELETE returns nothing
        fixture_key = "%s/%s" % (container, name)
        if fixture_key not in fixture_headers:
            msg = "Object DELETE failed - Object does not exist"
            raise swiftclient.ClientException(msg,
                                              http_status=httplib.NOT_FOUND)
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

    stubs.Set(swiftclient.client,
              'head_container', fake_head_container)
    stubs.Set(swiftclient.client,
              'put_container', fake_put_container)
    stubs.Set(swiftclient.client,
              'post_container', fake_post_container)
    stubs.Set(swiftclient.client,
              'put_object', fake_put_object)
    stubs.Set(swiftclient.client,
              'delete_object', fake_delete_object)
    stubs.Set(swiftclient.client,
              'head_object', fake_head_object)
    stubs.Set(swiftclient.client,
              'get_object', fake_get_object)
    stubs.Set(swiftclient.client,
              'get_auth', fake_get_auth)
    stubs.Set(swiftclient.client,
              'http_connection', fake_http_connection)


class SwiftTests(object):

    @property
    def swift_store_user(self):
        return 'tenant:user1'

    def test_get_size(self):
        """
        Test that we can get the size of an object in the swift store
        """
        uri = "swift://%s:key@auth_address/glance/%s" % (
            self.swift_store_user, FAKE_UUID)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        image_size = self.store.get_size(loc)
        self.assertEqual(image_size, 5120)

    def test_get_size_with_multi_tenant_on(self):
        """Test that single tenant uris work with multi tenant on."""
        uri = ("swift://%s:key@auth_address/glance/%s" %
               (self.swift_store_user, FAKE_UUID))
        self.config(swift_store_multi_tenant=True)
        # NOTE(markwash): ensure the image is found
        ctxt = mock.MagicMock()
        size = backend.get_size_from_backend(uri, context=ctxt)
        self.assertEqual(size, 5120)

    def test_get(self):
        """Test a "normal" retrieval of an image in chunks."""
        uri = "swift://%s:key@auth_address/glance/%s" % (
            self.swift_store_user, FAKE_UUID)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        (image_swift, image_size) = self.store.get(loc)
        self.assertEqual(image_size, 5120)

        expected_data = "*" * FIVE_KB
        data = ""

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
        loc = location.get_location_from_uri(uri, conf=self.conf)
        ctxt = mock.MagicMock()
        (image_swift, image_size) = self.store.get(loc, context=ctxt)
        resp_full = ''.join([chunk for chunk in image_swift.wrapped])
        resp_half = resp_full[:len(resp_full) / 2]
        image_swift.wrapped = swift.swift_retry_iter(resp_half, image_size,
                                                     self.store,
                                                     loc.store_location,
                                                     ctxt)
        self.assertEqual(image_size, 5120)

        expected_data = "*" * FIVE_KB
        data = ""

        for chunk in image_swift:
            data += chunk
        self.assertEqual(expected_data, data)

    def test_get_with_http_auth(self):
        """
        Test a retrieval from Swift with an HTTP authurl. This is
        specified either via a Location header with swift+http:// or using
        http:// in the swift_store_auth_address config value
        """
        loc = location.get_location_from_uri(
            "swift+http://%s:key@auth_address/glance/%s" %
            (self.swift_store_user, FAKE_UUID), conf=self.conf)

        ctxt = mock.MagicMock()
        (image_swift, image_size) = self.store.get(loc, context=ctxt)
        self.assertEqual(image_size, 5120)

        expected_data = "*" * FIVE_KB
        data = ""

        for chunk in image_swift:
            data += chunk
        self.assertEqual(expected_data, data)

    def test_get_non_existing(self):
        """
        Test that trying to retrieve a swift that doesn't exist
        raises an error
        """
        loc = location.get_location_from_uri(
            "swift://%s:key@authurl/glance/noexist" % (self.swift_store_user),
            conf=self.conf)
        self.assertRaises(exceptions.NotFound,
                          self.store.get,
                          loc)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=False))
    def test_add(self):
        """Test that we can add an image via the swift backend."""
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()
        expected_swift_size = FIVE_KB
        expected_swift_contents = "*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        loc = "swift+https://tenant%%3Auser1:key@localhost:8080/glance/%s"
        expected_location = loc % (expected_image_id)
        image_swift = six.StringIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        loc, size, checksum, _ = self.store.add(expected_image_id,
                                                image_swift,
                                                expected_swift_size)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        # Expecting a single object to be created on Swift i.e. no chunking.
        self.assertEqual(SWIFT_PUT_OBJECT_CALLS, 1)

        loc = location.get_location_from_uri(expected_location, conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = ''.join([chunk for chunk in new_image_swift])
        new_image_swift_size = len(new_image_swift)

        self.assertEqual(expected_swift_contents, new_image_contents)
        self.assertEqual(expected_swift_size, new_image_swift_size)

    def test_add_multi_store(self):

        conf = copy.deepcopy(SWIFT_CONF)
        conf['default_swift_reference'] = 'store_2'
        self.config(**conf)
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()

        expected_swift_size = FIVE_KB
        expected_swift_contents = "*" * expected_swift_size
        expected_image_id = str(uuid.uuid4())
        image_swift = six.StringIO(expected_swift_contents)
        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0
        loc = 'swift+config://store_2/glance/%s'

        expected_location = loc % (expected_image_id)

        location, size, checksum, arg = self.store.add(expected_image_id,
                                                       image_swift,
                                                       expected_swift_size)
        self.assertEqual(expected_location, location)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=True))
    def test_add_auth_url_variations(self):
        """
        Test that we can add an image via the swift backend with
        a variety of different auth_address values
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(**conf)

        variations = {
            'store_4': 'swift+config://store_4/glance/%s',
            'store_5': 'swift+config://store_5/glance/%s',
            'store_6': 'swift+config://store_6/glance/%s'
        }

        for variation, expected_location in variations.items():
            image_id = str(uuid.uuid4())
            expected_location = expected_location % image_id
            expected_swift_size = FIVE_KB
            expected_swift_contents = "*" * expected_swift_size
            expected_checksum = \
                hashlib.md5(expected_swift_contents).hexdigest()

            image_swift = six.StringIO(expected_swift_contents)

            global SWIFT_PUT_OBJECT_CALLS
            SWIFT_PUT_OBJECT_CALLS = 0
            conf['default_swift_reference'] = variation
            self.config(**conf)
            reload(swift)
            self.store = Store(self.conf)
            self.store.configure()
            loc, size, checksum, _ = self.store.add(image_id, image_swift,
                                                    expected_swift_size)

            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_swift_size, size)
            self.assertEqual(expected_checksum, checksum)
            self.assertEqual(SWIFT_PUT_OBJECT_CALLS, 1)

            loc = location.get_location_from_uri(expected_location,
                                                 conf=self.conf)
            (new_image_swift, new_image_size) = self.store.get(loc)
            new_image_contents = ''.join([chunk for chunk in new_image_swift])
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
        self.config(**conf)
        reload(swift)

        self.store = Store(self.conf)
        self.store.configure()

        image_swift = six.StringIO("nevergonnamakeit")

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        # We check the exception text to ensure the container
        # missing text is found in it, otherwise, we would have
        # simply used self.assertRaises here
        exception_caught = False
        try:
            self.store.add(str(uuid.uuid4()), image_swift, 0)
        except BackendException as e:
            exception_caught = True
            self.assertIn("container noexist does not exist "
                          "in Swift", utils.exception_to_str(e))
        self.assertTrue(exception_caught)
        self.assertEqual(SWIFT_PUT_OBJECT_CALLS, 0)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=True))
    def test_add_no_container_and_create(self):
        """
        Tests that adding an image with a non-existing container
        creates the container automatically if flag is set
        """
        expected_swift_size = FIVE_KB
        expected_swift_contents = "*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        loc = 'swift+config://ref1/noexist/%s'
        expected_location = loc % (expected_image_id)
        image_swift = six.StringIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0
        conf = copy.deepcopy(SWIFT_CONF)
        conf['swift_store_user'] = 'tenant:user'
        conf['swift_store_create_container_on_put'] = True
        conf['swift_store_container'] = 'noexist'
        self.config(**conf)
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()
        loc, size, checksum, _ = self.store.add(expected_image_id,
                                                image_swift,
                                                expected_swift_size)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(SWIFT_PUT_OBJECT_CALLS, 1)

        loc = location.get_location_from_uri(expected_location, conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = ''.join([chunk for chunk in new_image_swift])
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
        expected_swift_contents = "*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        container = 'randomname_' + expected_image_id[:2]
        loc = 'swift+config://ref1/%s/%s'
        expected_location = loc % (container, expected_image_id)
        image_swift = six.StringIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0
        conf = copy.deepcopy(SWIFT_CONF)
        conf['swift_store_user'] = 'tenant:user'
        conf['swift_store_create_container_on_put'] = True
        conf['swift_store_container'] = 'randomname'
        conf['swift_store_multiple_containers_seed'] = 2
        self.config(**conf)
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()
        loc, size, checksum, _ = self.store.add(expected_image_id,
                                                image_swift,
                                                expected_swift_size)

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(SWIFT_PUT_OBJECT_CALLS, 1)

        loc = location.get_location_from_uri(expected_location, conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = ''.join([chunk for chunk in new_image_swift])
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
        self.config(**conf)
        reload(swift)

        expected_image_id = str(uuid.uuid4())
        expected_container = 'randomname_' + expected_image_id[:2]

        self.store = Store(self.conf)
        self.store.configure()

        image_swift = six.StringIO("nevergonnamakeit")

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        # We check the exception text to ensure the container
        # missing text is found in it, otherwise, we would have
        # simply used self.assertRaises here
        exception_caught = False
        try:
            self.store.add(expected_image_id, image_swift, 0)
        except BackendException as e:
            exception_caught = True
            expected_msg = "container %s does not exist in Swift"
            expected_msg = expected_msg % expected_container
            self.assertIn(expected_msg, utils.exception_to_str(e))
        self.assertTrue(exception_caught)
        self.assertEqual(SWIFT_PUT_OBJECT_CALLS, 0)

    @mock.patch('glance_store._drivers.swift.utils'
                '.is_multiple_swift_store_accounts_enabled',
                mock.Mock(return_value=False))
    def test_multi_container_doesnt_impact_multi_tenant_add(self):
        expected_swift_size = FIVE_KB
        expected_swift_contents = "*" * expected_swift_size
        expected_image_id = str(uuid.uuid4())
        expected_container = 'container_' + expected_image_id
        loc = 'swift+https://some_endpoint/%s/%s'
        expected_location = loc % (expected_container, expected_image_id)
        image_swift = six.StringIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        self.config(swift_store_container='container')
        self.config(swift_store_create_container_on_put=True)
        self.config(swift_store_multiple_containers_seed=2)
        fake_get_endpoint = FakeGetEndpoint('https://some_endpoint')
        self.stubs.Set(auth, 'get_endpoint', fake_get_endpoint)
        ctxt = mock.MagicMock(
            user='user', tenant='tenant', auth_token='123',
            service_catalog={})
        store = swift.MultiTenantStore(self.conf)
        store.configure()
        location, size, checksum, _ = store.add(expected_image_id, image_swift,
                                                expected_swift_size,
                                                context=ctxt)
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
        expected_swift_contents = "*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        loc = 'swift+config://ref1/glance/%s'
        expected_location = loc % (expected_image_id)
        image_swift = six.StringIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        self.store = Store(self.conf)
        self.store.configure()
        orig_max_size = self.store.large_object_size
        orig_temp_size = self.store.large_object_chunk_size
        try:
            self.store.large_object_size = units.Ki
            self.store.large_object_chunk_size = units.Ki
            loc, size, checksum, _ = self.store.add(expected_image_id,
                                                    image_swift,
                                                    expected_swift_size)
        finally:
            self.store.large_object_chunk_size = orig_temp_size
            self.store.large_object_size = orig_max_size

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        # Expecting 6 objects to be created on Swift -- 5 chunks and 1
        # manifest.
        self.assertEqual(SWIFT_PUT_OBJECT_CALLS, 6)

        loc = location.get_location_from_uri(expected_location, conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = ''.join([chunk for chunk in new_image_swift])
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
        expected_swift_contents = "*" * expected_swift_size
        expected_checksum = hashlib.md5(expected_swift_contents).hexdigest()
        expected_image_id = str(uuid.uuid4())
        loc = 'swift+config://ref1/glance/%s'
        expected_location = loc % (expected_image_id)
        image_swift = six.StringIO(expected_swift_contents)

        global SWIFT_PUT_OBJECT_CALLS
        SWIFT_PUT_OBJECT_CALLS = 0

        # Temporarily set Swift MAX_SWIFT_OBJECT_SIZE to 1KB and add our image,
        # explicitly setting the image_length to 0

        self.store = Store(self.conf)
        self.store.configure()
        orig_max_size = self.store.large_object_size
        orig_temp_size = self.store.large_object_chunk_size
        global MAX_SWIFT_OBJECT_SIZE
        orig_max_swift_object_size = MAX_SWIFT_OBJECT_SIZE
        try:
            MAX_SWIFT_OBJECT_SIZE = units.Ki
            self.store.large_object_size = units.Ki
            self.store.large_object_chunk_size = units.Ki
            loc, size, checksum, _ = self.store.add(expected_image_id,
                                                    image_swift, 0)
        finally:
            self.store.large_object_chunk_size = orig_temp_size
            self.store.large_object_size = orig_max_size
            MAX_SWIFT_OBJECT_SIZE = orig_max_swift_object_size

        self.assertEqual(expected_location, loc)
        self.assertEqual(expected_swift_size, size)
        self.assertEqual(expected_checksum, checksum)
        # Expecting 7 calls to put_object -- 5 chunks, a zero chunk which is
        # then deleted, and the manifest.  Note the difference with above
        # where the image_size is specified in advance (there's no zero chunk
        # in that case).
        self.assertEqual(SWIFT_PUT_OBJECT_CALLS, 7)

        loc = location.get_location_from_uri(expected_location, conf=self.conf)
        (new_image_swift, new_image_size) = self.store.get(loc)
        new_image_contents = ''.join([chunk for chunk in new_image_swift])
        new_image_swift_size = len(new_image_contents)

        self.assertEqual(expected_swift_contents, new_image_contents)
        self.assertEqual(expected_swift_size, new_image_swift_size)

    def test_add_already_existing(self):
        """
        Tests that adding an image with an existing identifier
        raises an appropriate exception
        """
        self.store = Store(self.conf)
        self.store.configure()
        image_swift = six.StringIO("nevergonnamakeit")
        self.assertRaises(exceptions.Duplicate,
                          self.store.add,
                          FAKE_UUID, image_swift, 0)

    def _option_required(self, key):
        conf = self.getConfig()
        conf[key] = None

        try:
            self.config(**conf)
            self.store = Store(self.conf)
            return not self.store.is_capable(
                capabilities.BitMasks.WRITE_ACCESS)
        except Exception:
            return False
        return False

    def test_no_store_credentials(self):
        """
        Tests that options without a valid credentials disables the add method
        """
        self.store = Store(self.conf)
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
        self.store = Store(self.conf)
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
        self.config(**conf)
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()

        uri = "swift://%s:key@authurl/glance/%s" % (
            self.swift_store_user, FAKE_UUID)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.store.delete(loc)

        self.assertRaises(exceptions.NotFound, self.store.get, loc)

    @mock.patch.object(swiftclient.client, 'delete_object')
    def test_delete_slo(self, mock_del_obj):
        """
        Test we can delete an existing image stored as SLO, static large object
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(**conf)
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()

        uri = "swift://%s:key@authurl/glance/%s" % (self.swift_store_user,
                                                    FAKE_UUID2)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.store.delete(loc)

        mock_del_obj.assert_called_once()
        _, kwargs = mock_del_obj.call_args
        self.assertEqual('multipart-manifest=delete',
                         kwargs.get('query_string'))

    @mock.patch.object(swiftclient.client, 'delete_object')
    def test_delete_nonslo_not_deleted_as_slo(self, mock_del_obj):
        """
        Test that non-SLOs are not being deleted the SLO way
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(**conf)
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()

        uri = "swift://%s:key@authurl/glance/%s" % (self.swift_store_user,
                                                    FAKE_UUID)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.store.delete(loc)

        mock_del_obj.assert_called_once()
        _, kwargs = mock_del_obj.call_args
        self.assertEqual(None, kwargs.get('query_string'))

    def test_delete_with_reference_params(self):
        """
        Test we can delete an existing image in the swift store
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(**conf)
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()

        uri = "swift+config://ref1/glance/%s" % (FAKE_UUID)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.store.delete(loc)

        self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def test_delete_non_existing(self):
        """
        Test that trying to delete a swift that doesn't exist
        raises an error
        """
        conf = copy.deepcopy(SWIFT_CONF)
        self.config(**conf)
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()

        loc = location.get_location_from_uri(
            "swift://%s:key@authurl/glance/noexist" % (self.swift_store_user),
            conf=self.conf)
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
            return None, [{'name': '%s-%05d' % (test_image_id, x)}
                          for x in range(1, 6)]

        def fake_delete_object(container, object_name):
            # Simulate error on 1st and 3rd segments
            global SWIFT_DELETE_OBJECT_CALLS
            SWIFT_DELETE_OBJECT_CALLS += 1
            if object_name.endswith('001') or object_name.endswith('003'):
                raise swiftclient.ClientException('Object DELETE failed')
            else:
                pass

        conf = copy.deepcopy(SWIFT_CONF)
        self.config(**conf)
        reload(swift)
        self.store = Store(self.conf)
        self.store.configure()

        loc_uri = "swift+https://%s:key@localhost:8080/glance/%s"
        loc_uri = loc_uri % (self.swift_store_user, test_image_id)
        loc = location.get_location_from_uri(loc_uri)

        conn = self.store.get_connection(loc.store_location)
        conn.delete_object = fake_delete_object
        conn.head_object = fake_head_object
        conn.get_container = fake_get_container

        global SWIFT_DELETE_OBJECT_CALLS
        SWIFT_DELETE_OBJECT_CALLS = 0

        self.store.delete(loc, connection=conn)
        # Expecting 6 delete calls, 5 for the segments and 1 for the manifest
        self.assertEqual(SWIFT_DELETE_OBJECT_CALLS, 6)

    def test_read_acl_public(self):
        """
        Test that we can set a public read acl.
        """
        self.config(swift_store_multi_tenant=True)
        store = Store(self.conf)
        store.configure()
        uri = "swift+http://storeurl/glance/%s" % FAKE_UUID
        loc = location.get_location_from_uri(uri, conf=self.conf)
        ctxt = mock.MagicMock()
        store.set_acls(loc, public=True, context=ctxt)
        container_headers = swiftclient.client.head_container('x', 'y',
                                                              'glance')
        self.assertEqual(container_headers['X-Container-Read'],
                         "*:*")

    def test_read_acl_tenants(self):
        """
        Test that we can set read acl for tenants.
        """
        self.config(swift_store_multi_tenant=True)
        store = Store(self.conf)
        store.configure()
        uri = "swift+http://storeurl/glance/%s" % FAKE_UUID
        loc = location.get_location_from_uri(uri, conf=self.conf)
        read_tenants = ['matt', 'mark']
        ctxt = mock.MagicMock()
        store.set_acls(loc, read_tenants=read_tenants, context=ctxt)
        container_headers = swiftclient.client.head_container('x', 'y',
                                                              'glance')
        self.assertEqual(container_headers['X-Container-Read'],
                         'matt:*,mark:*')

    def test_write_acls(self):
        """
        Test that we can set write acl for tenants.
        """
        self.config(swift_store_multi_tenant=True)
        store = Store(self.conf)
        store.configure()
        uri = "swift+http://storeurl/glance/%s" % FAKE_UUID
        loc = location.get_location_from_uri(uri, conf=self.conf)
        read_tenants = ['frank', 'jim']
        ctxt = mock.MagicMock()
        store.set_acls(loc, write_tenants=read_tenants, context=ctxt)
        container_headers = swiftclient.client.head_container('x', 'y',
                                                              'glance')
        self.assertEqual(container_headers['X-Container-Write'],
                         'frank:*,jim:*')


class TestStoreAuthV1(base.StoreBaseTest, SwiftTests,
                      test_store_capabilities.TestStoreCapabilitiesChecking):

    _CONF = cfg.CONF

    def getConfig(self):
        conf = SWIFT_CONF.copy()
        conf['swift_store_auth_version'] = '1'
        conf['swift_store_user'] = 'tenant:user1'
        return conf

    def setUp(self):
        """Establish a clean test environment."""
        super(TestStoreAuthV1, self).setUp()
        conf = self.getConfig()

        conf_file = 'glance-swift.conf'
        self.swift_config_file = self.copy_data_file(conf_file, self.test_dir)
        conf.update({'swift_store_config_file': self.swift_config_file})

        moxfixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = moxfixture.stubs
        stub_out_swiftclient(self.stubs, conf['swift_store_auth_version'])
        self.store = Store(self.conf)
        self.config(**conf)
        self.store.configure()
        self.register_store_schemes(self.store, 'swift')
        self.addCleanup(self.conf.reset)


class TestStoreAuthV2(TestStoreAuthV1):

    def getConfig(self):
        conf = super(TestStoreAuthV2, self).getConfig()
        conf['swift_store_auth_version'] = '2'
        conf['swift_store_user'] = 'tenant:user1'
        return conf

    def test_v2_with_no_tenant(self):
        uri = "swift://failme:key@auth_address/glance/%s" % (FAKE_UUID)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.BadStoreUri,
                          self.store.get,
                          loc)

    def test_v2_multi_tenant_location(self):
        conf = self.getConfig()
        conf['swift_store_multi_tenant'] = True
        uri = "swift://auth_address/glance/%s" % (FAKE_UUID)
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertEqual('swift', loc.store_name)


class FakeConnection(object):
    def __init__(self, authurl, user, key, retries=5, preauthurl=None,
                 preauthtoken=None, starting_backoff=1, tenant_name=None,
                 os_options=None, auth_version="1", insecure=False,
                 ssl_compression=True, cacert=None):
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


class TestSingleTenantStoreConnections(base.StoreBaseTest):
    _CONF = cfg.CONF

    def setUp(self):
        super(TestSingleTenantStoreConnections, self).setUp()
        moxfixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = moxfixture.stubs
        self.stubs.Set(swiftclient, 'Connection', FakeConnection)
        self.store = swift.SingleTenantStore(self.conf)
        self.store.configure()
        specs = {'scheme': 'swift',
                 'auth_or_store_url': 'example.com/v2/',
                 'user': 'tenant:user1',
                 'key': 'key1',
                 'container': 'cont',
                 'obj': 'object'}
        self.location = swift.StoreLocation(specs, self.conf)
        self.addCleanup(self.conf.reset)

    def test_basic_connection(self):
        connection = self.store.get_connection(self.location)
        self.assertEqual(connection.authurl, 'https://example.com/v2/')
        self.assertEqual(connection.auth_version, '2')
        self.assertEqual(connection.user, 'user1')
        self.assertEqual(connection.tenant_name, 'tenant')
        self.assertEqual(connection.key, 'key1')
        self.assertIsNone(connection.preauthurl)
        self.assertFalse(connection.insecure)
        self.assertEqual(connection.os_options,
                         {'service_type': 'object-store',
                          'endpoint_type': 'publicURL'})

    def test_connection_with_conf_endpoint(self):
        ctx = mock.MagicMock(user='tenant:user1', tenant='tenant')
        self.config(swift_store_endpoint='https://internal.com')
        self.store.configure()
        connection = self.store.get_connection(self.location, context=ctx)
        self.assertEqual(connection.authurl, 'https://example.com/v2/')
        self.assertEqual(connection.auth_version, '2')
        self.assertEqual(connection.user, 'user1')
        self.assertEqual(connection.tenant_name, 'tenant')
        self.assertEqual(connection.key, 'key1')
        self.assertEqual(connection.preauthurl, 'https://internal.com')
        self.assertFalse(connection.insecure)
        self.assertEqual(connection.os_options,
                         {'service_type': 'object-store',
                          'endpoint_type': 'publicURL'})

    def test_connection_with_conf_endpoint_no_context(self):
        self.config(swift_store_endpoint='https://internal.com')
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertEqual(connection.authurl, 'https://example.com/v2/')
        self.assertEqual(connection.auth_version, '2')
        self.assertEqual(connection.user, 'user1')
        self.assertEqual(connection.tenant_name, 'tenant')
        self.assertEqual(connection.key, 'key1')
        self.assertEqual(connection.preauthurl, 'https://internal.com')
        self.assertFalse(connection.insecure)
        self.assertEqual(connection.os_options,
                         {'service_type': 'object-store',
                          'endpoint_type': 'publicURL'})

    def test_connection_with_no_trailing_slash(self):
        self.location.auth_or_store_url = 'example.com/v2'
        connection = self.store.get_connection(self.location)
        self.assertEqual(connection.authurl, 'https://example.com/v2/')

    def test_connection_insecure(self):
        self.config(swift_store_auth_insecure=True)
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertTrue(connection.insecure)

    def test_connection_with_auth_v1(self):
        self.config(swift_store_auth_version='1')
        self.store.configure()
        self.location.user = 'auth_v1_user'
        connection = self.store.get_connection(self.location)
        self.assertEqual(connection.auth_version, '1')
        self.assertEqual(connection.user, 'auth_v1_user')
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
        self.config(swift_store_region='Sahara')
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertEqual(connection.os_options,
                         {'region_name': 'Sahara',
                          'service_type': 'object-store',
                          'endpoint_type': 'publicURL'})

    def test_connection_with_service_type(self):
        self.config(swift_store_service_type='shoe-store')
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertEqual(connection.os_options,
                         {'service_type': 'shoe-store',
                          'endpoint_type': 'publicURL'})

    def test_connection_with_endpoint_type(self):
        self.config(swift_store_endpoint_type='internalURL')
        self.store.configure()
        connection = self.store.get_connection(self.location)
        self.assertEqual(connection.os_options,
                         {'service_type': 'object-store',
                          'endpoint_type': 'internalURL'})

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


class TestMultiTenantStoreConnections(base.StoreBaseTest):
    def setUp(self):
        super(TestMultiTenantStoreConnections, self).setUp()
        moxfixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = moxfixture.stubs
        self.stubs.Set(swiftclient, 'Connection', FakeConnection)
        self.context = mock.MagicMock(
            user='tenant:user1', tenant='tenant', auth_token='0123')
        self.store = swift.MultiTenantStore(self.conf)
        specs = {'scheme': 'swift',
                 'auth_or_store_url': 'example.com',
                 'container': 'cont',
                 'obj': 'object'}
        self.location = swift.StoreLocation(specs, self.conf)
        self.addCleanup(self.conf.reset)

    def test_basic_connection(self):
        self.store.configure()
        connection = self.store.get_connection(self.location,
                                               context=self.context)
        self.assertIsNone(connection.authurl)
        self.assertEqual(connection.auth_version, '2')
        self.assertEqual(connection.user, 'tenant:user1')
        self.assertEqual(connection.tenant_name, 'tenant')
        self.assertIsNone(connection.key)
        self.assertEqual(connection.preauthurl, 'https://example.com')
        self.assertEqual(connection.preauthtoken, '0123')
        self.assertEqual(connection.os_options, {})


class TestMultiTenantStoreContext(base.StoreBaseTest):

    _CONF = cfg.CONF

    def setUp(self):
        """Establish a clean test environment."""
        super(TestMultiTenantStoreContext, self).setUp()
        conf = SWIFT_CONF.copy()

        self.store = Store(self.conf)
        self.config(**conf)
        self.store.configure()
        self.register_store_schemes(self.store, 'swift')
        self.service_catalog = [{
            "name": "Object Storage",
            "type": "object-store",
            "endpoints": [{
                "publicURL": "http://127.0.0.1:0",
                "region": "region1",
                "versionId": "1.0",
            }]
        }]
        self.addCleanup(self.conf.reset)

    @requests_mock.mock()
    def test_download_context(self, m):
        """Verify context (ie token) is passed to swift on download."""
        self.config(swift_store_multi_tenant=True)
        store = Store(self.conf)
        store.configure()
        uri = "swift+http://127.0.0.1/glance_123/123"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        ctx = mock.MagicMock(
            service_catalog=self.service_catalog, user='tenant:user1',
            tenant='tenant', auth_token='0123')

        m.get("http://127.0.0.1/glance_123/123")
        store.get(loc, context=ctx)
        self.assertEqual('0123', m.last_request.headers['X-Auth-Token'])

    @requests_mock.mock()
    def test_upload_context(self, m):
        """Verify context (ie token) is passed to swift on upload."""
        head_req = m.head("http://127.0.0.1/glance_123",
                          text='Some data',
                          status_code=201)
        put_req = m.put("http://127.0.0.1/glance_123/123")

        self.config(swift_store_multi_tenant=True)
        store = Store(self.conf)
        store.configure()
        pseudo_file = StringIO.StringIO('Some data')
        ctx = mock.MagicMock(
            service_catalog=self.service_catalog, user='tenant:user1',
            tenant='tenant', auth_token='0123')
        store.add('123', pseudo_file, pseudo_file.len,
                  context=ctx)

        self.assertEqual('0123', head_req.last_request.headers['X-Auth-Token'])
        self.assertEqual('0123', put_req.last_request.headers['X-Auth-Token'])


class FakeGetEndpoint(object):
    def __init__(self, response):
        self.response = response

    def __call__(self, service_catalog, service_type=None,
                 endpoint_region=None, endpoint_type=None):
        self.service_type = service_type
        self.endpoint_region = endpoint_region
        self.endpoint_type = endpoint_type
        return self.response


class TestCreatingLocations(base.StoreBaseTest):
    _CONF = cfg.CONF

    def setUp(self):
        super(TestCreatingLocations, self).setUp()
        moxfixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = moxfixture.stubs
        conf = copy.deepcopy(SWIFT_CONF)
        self.store = Store(self.conf)
        self.config(**conf)
        reload(swift)
        self.addCleanup(self.conf.reset)

    def test_single_tenant_location(self):
        conf = copy.deepcopy(SWIFT_CONF)
        conf['swift_store_container'] = 'container'
        conf_file = "glance-swift.conf"
        self.swift_config_file = self.copy_data_file(conf_file, self.test_dir)
        conf.update({'swift_store_config_file': self.swift_config_file})
        conf['default_swift_reference'] = 'ref1'
        self.config(**conf)
        reload(swift)

        store = swift.SingleTenantStore(self.conf)
        store.configure()
        location = store.create_location('image-id')
        self.assertEqual(location.scheme, 'swift+https')
        self.assertEqual(location.swift_url, 'https://example.com')
        self.assertEqual(location.container, 'container')
        self.assertEqual(location.obj, 'image-id')
        self.assertEqual(location.user, 'tenant:user1')
        self.assertEqual(location.key, 'key1')

    def test_single_tenant_location_http(self):
        conf_file = "glance-swift.conf"
        test_dir = self.useFixture(fixtures.TempDir()).path
        self.swift_config_file = self.copy_data_file(conf_file, test_dir)
        self.config(swift_store_container='container',
                    default_swift_reference='ref2',
                    swift_store_config_file=self.swift_config_file)

        store = swift.SingleTenantStore(self.conf)
        store.configure()
        location = store.create_location('image-id')
        self.assertEqual(location.scheme, 'swift+http')
        self.assertEqual(location.swift_url, 'http://example.com')

    def test_multi_tenant_location(self):
        self.config(swift_store_container='container')
        fake_get_endpoint = FakeGetEndpoint('https://some_endpoint')
        self.stubs.Set(auth, 'get_endpoint', fake_get_endpoint)
        ctxt = mock.MagicMock(
            user='user', tenant='tenant', auth_token='123',
            service_catalog={})
        store = swift.MultiTenantStore(self.conf)
        store.configure()
        location = store.create_location('image-id', context=ctxt)
        self.assertEqual(location.scheme, 'swift+https')
        self.assertEqual(location.swift_url, 'https://some_endpoint')
        self.assertEqual(location.container, 'container_image-id')
        self.assertEqual(location.obj, 'image-id')
        self.assertIsNone(location.user)
        self.assertIsNone(location.key)
        self.assertEqual(fake_get_endpoint.service_type, 'object-store')

    def test_multi_tenant_location_http(self):
        fake_get_endpoint = FakeGetEndpoint('http://some_endpoint')
        self.stubs.Set(auth, 'get_endpoint', fake_get_endpoint)
        ctxt = mock.MagicMock(
            user='user', tenant='tenant', auth_token='123',
            service_catalog={})
        store = swift.MultiTenantStore(self.conf)
        store.configure()
        location = store.create_location('image-id', context=ctxt)
        self.assertEqual(location.scheme, 'swift+http')
        self.assertEqual(location.swift_url, 'http://some_endpoint')

    def test_multi_tenant_location_with_region(self):
        self.config(swift_store_region='WestCarolina')
        fake_get_endpoint = FakeGetEndpoint('https://some_endpoint')
        self.stubs.Set(auth, 'get_endpoint', fake_get_endpoint)
        ctxt = mock.MagicMock(
            user='user', tenant='tenant', auth_token='123',
            service_catalog={})
        store = swift.MultiTenantStore(self.conf)
        store.configure()
        store._get_endpoint(ctxt)
        self.assertEqual(fake_get_endpoint.endpoint_region, 'WestCarolina')

    def test_multi_tenant_location_custom_service_type(self):
        self.config(swift_store_service_type='toy-store')
        fake_get_endpoint = FakeGetEndpoint('https://some_endpoint')
        self.stubs.Set(auth, 'get_endpoint', fake_get_endpoint)
        ctxt = mock.MagicMock(
            user='user', tenant='tenant', auth_token='123',
            service_catalog={})
        store = swift.MultiTenantStore(self.conf)
        store.configure()
        store._get_endpoint(ctxt)
        self.assertEqual(fake_get_endpoint.service_type, 'toy-store')

    def test_multi_tenant_location_custom_endpoint_type(self):
        self.config(swift_store_endpoint_type='InternalURL')
        fake_get_endpoint = FakeGetEndpoint('https://some_endpoint')
        self.stubs.Set(auth, 'get_endpoint', fake_get_endpoint)
        ctxt = mock.MagicMock(
            user='user', tenant='tenant', auth_token='123',
            service_catalog={})
        store = swift.MultiTenantStore(self.conf)
        store.configure()
        store._get_endpoint(ctxt)
        self.assertEqual(fake_get_endpoint.endpoint_type, 'InternalURL')


class TestChunkReader(base.StoreBaseTest):
    _CONF = cfg.CONF

    def setUp(self):
        super(TestChunkReader, self).setUp()
        conf = copy.deepcopy(SWIFT_CONF)
        Store(self.conf)
        self.config(**conf)

    def test_read_all_data(self):
        """
        Replicate what goes on in the Swift driver with the
        repeated creation of the ChunkReader object
        """
        CHUNKSIZE = 100
        checksum = hashlib.md5()
        data_file = tempfile.NamedTemporaryFile()
        data_file.write('*' * units.Ki)
        data_file.flush()
        infile = open(data_file.name, 'rb')
        bytes_read = 0
        while True:
            cr = swift.ChunkReader(infile, checksum, CHUNKSIZE)
            chunk = cr.read(CHUNKSIZE)
            bytes_read += len(chunk)
            if not chunk:
                break
        self.assertEqual(units.Ki, bytes_read)
        data_file.close()


class TestMultipleContainers(base.StoreBaseTest):
    _CONF = cfg.CONF

    def setUp(self):
        super(TestMultipleContainers, self).setUp()
        self.config(swift_store_multiple_containers_seed=3)
        self.store = swift.SingleTenantStore(self.conf)
        self.store.configure()

    def test_get_container_name_happy_path_with_seed_three(self):

        test_image_id = 'fdae39a1-bac5-4238-aba4-69bcc726e848'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container_fda'
        self.assertEqual(expected, actual)

    def test_get_container_name_with_negative_seed(self):
        self.config(swift_store_multiple_containers_seed=-1)
        self.store = swift.SingleTenantStore(self.conf)

        test_image_id = 'random_id'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.get_container_name, test_image_id,
                          'default_container')

    def test_get_container_name_with_seed_beyond_max(self):
        self.config(swift_store_multiple_containers_seed=33)
        self.store = swift.SingleTenantStore(self.conf)

        test_image_id = 'random_id'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store.get_container_name, test_image_id,
                          'default_container')

    def test_get_container_name_with_max_seed(self):
        self.config(swift_store_multiple_containers_seed=32)
        self.store = swift.SingleTenantStore(self.conf)

        test_image_id = 'fdae39a1-bac5-4238-aba4-69bcc726e848'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container_' + test_image_id
        self.assertEqual(expected, actual)

    def test_get_container_name_with_dash(self):
        self.config(swift_store_multiple_containers_seed=10)
        self.store = swift.SingleTenantStore(self.conf)

        test_image_id = 'fdae39a1-bac5-4238-aba4-69bcc726e848'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container_' + 'fdae39a1-ba'
        self.assertEqual(expected, actual)

    def test_get_container_name_with_min_seed(self):
        self.config(swift_store_multiple_containers_seed=1)
        self.store = swift.SingleTenantStore(self.conf)

        test_image_id = 'fdae39a1-bac5-4238-aba4-69bcc726e848'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container_' + 'f'
        self.assertEqual(expected, actual)

    def test_get_container_name_with_multiple_containers_turned_off(self):
        self.config(swift_store_multiple_containers_seed=0)
        self.store.configure()

        test_image_id = 'random_id'
        actual = self.store.get_container_name(test_image_id,
                                               'default_container')
        expected = 'default_container'
        self.assertEqual(expected, actual)
