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

import requests

import glance_store
from glance_store._drivers import http
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities
from glance_store.tests import utils


class TestHttpStore(base.StoreBaseTest,
                    test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        super(TestHttpStore, self).setUp()
        self.config(default_store='http', group='glance_store')
        http.Store.READ_CHUNKSIZE = 2
        self.store = http.Store(self.conf)
        self.register_store_schemes(self.store, 'http')

    def _mock_requests(self):
        """Mock requests session object.

        Should be called when we need to mock request/response objects.
        """
        request = mock.patch('requests.Session.request')
        self.request = request.start()
        self.addCleanup(request.stop)

    def test_http_get(self):
        self._mock_requests()
        self.request.return_value = utils.fake_response()

        uri = "http://netloc/path/to/file.tar.gz"
        expected_returns = ['I ', 'am', ' a', ' t', 'ea', 'po', 't,', ' s',
                            'ho', 'rt', ' a', 'nd', ' s', 'to', 'ut', '\n']
        loc = location.get_location_from_uri(uri, conf=self.conf)
        (image_file, image_size) = self.store.get(loc)
        self.assertEqual(31, image_size)
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
        self._mock_requests()
        redirect1 = {"location": "http://example.com/teapot.img"}
        redirect2 = {"location": "http://example.com/teapot_real.img"}
        responses = [utils.fake_response(),
                     utils.fake_response(status_code=301, headers=redirect2),
                     utils.fake_response(status_code=302, headers=redirect1)]

        def getresponse(*args, **kwargs):
            return responses.pop()
        self.request.side_effect = getresponse

        uri = "http://netloc/path/to/file.tar.gz"
        expected_returns = ['I ', 'am', ' a', ' t', 'ea', 'po', 't,', ' s',
                            'ho', 'rt', ' a', 'nd', ' s', 'to', 'ut', '\n']

        loc = location.get_location_from_uri(uri, conf=self.conf)
        (image_file, image_size) = self.store.get(loc)
        self.assertEqual(0, len(responses))
        self.assertEqual(31, image_size)

        chunks = [c for c in image_file]
        self.assertEqual(expected_returns, chunks)

    def test_http_get_max_redirects(self):
        self._mock_requests()
        redirect = {"location": "http://example.com/teapot.img"}
        responses = ([utils.fake_response(status_code=302, headers=redirect)]
                     * (http.MAX_REDIRECTS + 2))

        def getresponse(*args, **kwargs):
            return responses.pop()

        self.request.side_effect = getresponse
        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.MaxRedirectsExceeded, self.store.get, loc)

    def test_http_get_redirect_invalid(self):
        self._mock_requests()
        redirect = {"location": "http://example.com/teapot.img"}
        redirect_resp = utils.fake_response(status_code=307, headers=redirect)
        self.request.return_value = redirect_resp

        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.BadStoreUri, self.store.get, loc)

    def test_http_get_not_found(self):
        self._mock_requests()
        fake = utils.fake_response(status_code=404, content="404 Not Found")
        self.request.return_value = fake

        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def test_http_delete_raise_error(self):
        self._mock_requests()
        self.request.return_value = utils.fake_response()

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
                          None, None, 'http')

    def test_http_get_size_with_non_existent_image_raises_Not_Found(self):
        self._mock_requests()
        self.request.return_value = utils.fake_response(
            status_code=404, content='404 Not Found')

        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.NotFound, self.store.get_size, loc)
        self.request.assert_called_once_with('HEAD', uri, stream=True,
                                             allow_redirects=False)

    def test_http_get_size_bad_status_line(self):
        self._mock_requests()
        # Note(sabari): Low-level httplib.BadStatusLine will be raised as
        # ConnectionErorr after migrating to requests.
        self.request.side_effect = requests.exceptions.ConnectionError

        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.BadStoreUri, self.store.get_size, loc)

    def test_http_store_location_initialization(self):
        """Test store location initialization from valid uris"""
        uris = [
            "http://127.0.0.1:8000/ubuntu.iso",
            "http://openstack.com:80/ubuntu.iso",
            "http://[1080::8:800:200C:417A]:80/ubuntu.iso"
        ]
        for uri in uris:
            location.get_location_from_uri(uri)

    def test_http_store_location_initialization_with_invalid_url(self):
        """Test store location initialization from incorrect uris."""
        incorrect_uris = [
            "http://127.0.0.1:~/ubuntu.iso",
            "http://openstack.com:some_text/ubuntu.iso",
            "http://[1080::8:800:200C:417A]:some_text/ubuntu.iso"
        ]
        for uri in incorrect_uris:
            self.assertRaises(exceptions.BadStoreUri,
                              location.get_location_from_uri, uri)

    def test_http_get_raises_remote_service_unavailable(self):
        """Test http store raises RemoteServiceUnavailable."""
        uri = "http://netloc/path/to/file.tar.gz"
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.RemoteServiceUnavailable,
                          self.store.get, loc)
