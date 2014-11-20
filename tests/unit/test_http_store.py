# Copyright 2010-2011 OpenStack Foundation
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

import mock

import glance_store
from glance_store._drivers import http
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests import utils
from tests.unit import test_store_capabilities


class TestHttpStore(base.StoreBaseTest,
                    test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        super(TestHttpStore, self).setUp()
        self.config(default_store='http', group='glance_store')
        http.Store.READ_CHUNKSIZE = 2
        self.store = http.Store(self.conf)

    def _mock_httplib(self):
        """Mock httplib connection object.

        Should be called when need to mock httplib response and request
        objects.
        """
        response = mock.patch('httplib.HTTPConnection.getresponse')
        self.response = response.start()
        self.response.return_value = utils.FakeHTTPResponse()
        self.addCleanup(response.stop)

        request = mock.patch('httplib.HTTPConnection.request')
        self.request = request.start()
        self.request.side_effect = lambda w, x, y, z: None
        self.addCleanup(request.stop)

    def test_http_get(self):
        self._mock_httplib()
        uri = "http://netloc/path/to/file.tar.gz"
        expected_returns = ['I ', 'am', ' a', ' t', 'ea', 'po', 't,', ' s',
                            'ho', 'rt', ' a', 'nd', ' s', 'to', 'ut', '\n']
        loc = location.get_location_from_uri(uri, conf=self.conf)
        (image_file, image_size) = self.store.get(loc)
        self.assertEqual(image_size, 31)
        chunks = [c for c in image_file]
        self.assertEqual(expected_returns, chunks)

    def test_http_partial_get(self):
        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.StoreRandomGetNotSupported,
                          self.store.get, loc, chunk_size=1)

    def test_http_get_redirect(self):
        # Add two layers of redirects to the response stack, which will
        # return the default 200 OK with the expected data after resolving
        # both redirects.
        self._mock_httplib()
        redirect1 = {"location": "http://example.com/teapot.img"}
        redirect2 = {"location": "http://example.com/teapot_real.img"}
        responses = [utils.FakeHTTPResponse(status=302, headers=redirect1),
                     utils.FakeHTTPResponse(status=301, headers=redirect2),
                     utils.FakeHTTPResponse()]

        def getresponse():
            return responses.pop()
        self.response.side_effect = getresponse

        uri = "http://netloc/path/to/file.tar.gz"
        expected_returns = ['I ', 'am', ' a', ' t', 'ea', 'po', 't,', ' s',
                            'ho', 'rt', ' a', 'nd', ' s', 'to', 'ut', '\n']

        loc = location.get_location_from_uri(uri, conf=self.conf)
        (image_file, image_size) = self.store.get(loc)
        self.assertEqual(image_size, 31)

        chunks = [c for c in image_file]
        self.assertEqual(chunks, expected_returns)

    def test_http_get_max_redirects(self):
        self._mock_httplib()
        redirect = {"location": "http://example.com/teapot.img"}
        responses = ([utils.FakeHTTPResponse(status=302, headers=redirect)]
                     * (http.MAX_REDIRECTS + 2))

        def getresponse():
            return responses.pop()
        self.response.side_effect = getresponse

        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.MaxRedirectsExceeded, self.store.get, loc)

    def test_http_get_redirect_invalid(self):
        self._mock_httplib()
        redirect = {"location": "http://example.com/teapot.img"}
        redirect_resp = utils.FakeHTTPResponse(status=307, headers=redirect)
        self.response.return_value = redirect_resp

        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.BadStoreUri, self.store.get, loc)

    def test_http_get_not_found(self):
        self._mock_httplib()
        fake = utils.FakeHTTPResponse(status=404, data="404 Not Found")
        self.response.return_value = fake

        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def test_http_delete_raise_error(self):
        self._mock_httplib()
        uri = "https://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.StoreDeleteNotSupported,
                          self.store.delete, loc)
        self.assertRaises(exceptions.StoreDeleteNotSupported,
                          glance_store.delete_from_backend, uri, {})

    def test_http_add_raise_error(self):
        self.assertRaises(exceptions.StoreAddDisabled,
                          self.store.add, None, None, None, None)
        self.assertRaises(exceptions.StoreAddDisabled,
                          glance_store.add_to_backend, None, None,
                          None, None, 'file')

    def test_http_get_size_with_non_existent_image_raises_Not_Found(self):
        self._mock_httplib()
        fake = utils.FakeHTTPResponse(status=404, data="404 Not Found")
        self.response.return_value = fake

        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.NotFound, self.store.get_size, loc)

    def test_http_get_raises_remote_service_unavailable(self):
        """Test http store raises RemoteServiceUnavailable."""
        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.RemoteServiceUnavailable,
                          self.store.get, loc)
