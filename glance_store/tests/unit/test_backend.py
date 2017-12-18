# Copyright 2016 OpenStack, LLC
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

"""Tests the backend store API's"""

import mock

from glance_store import backend
from glance_store import exceptions
from glance_store.tests import base


class TestStoreAddToBackend(base.StoreBaseTest):

    def setUp(self):
        super(TestStoreAddToBackend, self).setUp()
        self.image_id = "animage"
        self.data = "dataandstuff"
        self.size = len(self.data)
        self.location = "file:///ab/cde/fgh"
        self.checksum = "md5"
        self.multihash = 'multihash'
        self.default_hash_algo = 'md5'
        self.hash_algo = 'sha256'

    def _bad_metadata(self, in_metadata):
        mstore = mock.Mock()
        mstore.add.return_value = (self.location, self.size, self.checksum,
                                   in_metadata)
        mstore.__str__ = lambda self: "hello"
        mstore.__unicode__ = lambda self: "hello"

        self.assertRaises(exceptions.BackendException,
                          backend.store_add_to_backend,
                          self.image_id,
                          self.data,
                          self.size,
                          mstore)

        mstore.add.assert_called_once_with(self.image_id, mock.ANY,
                                           self.size,
                                           context=None, verifier=None)

        newstore = mock.Mock()
        newstore.add.return_value = (self.location, self.size, self.checksum,
                                     self.multihash, in_metadata)
        newstore.__str__ = lambda self: "hello"
        newstore.__unicode__ = lambda self: "hello"

        self.assertRaises(exceptions.BackendException,
                          backend.store_add_to_backend_with_multihash,
                          self.image_id,
                          self.data,
                          self.size,
                          self.hash_algo,
                          newstore)

        newstore.add.assert_called_once_with(self.image_id, mock.ANY,
                                             self.size, self.hash_algo,
                                             context=None, verifier=None)

    def _good_metadata(self, in_metadata):
        mstore = mock.Mock()
        mstore.add.return_value = (self.location, self.size, self.checksum,
                                   in_metadata)

        (location,
         size,
         checksum,
         metadata) = backend.store_add_to_backend(self.image_id,
                                                  self.data,
                                                  self.size,
                                                  mstore)

        mstore.add.assert_called_once_with(self.image_id, mock.ANY,
                                           self.size, context=None,
                                           verifier=None)

        self.assertEqual(self.location, location)
        self.assertEqual(self.size, size)
        self.assertEqual(self.checksum, checksum)
        self.assertEqual(in_metadata, metadata)

        newstore = mock.Mock()
        newstore.add.return_value = (self.location, self.size, self.checksum,
                                     self.multihash, in_metadata)
        (location,
         size,
         checksum,
         multihash,
         metadata) = backend.store_add_to_backend_with_multihash(
             self.image_id,
             self.data,
             self.size,
             self.hash_algo,
             newstore)

        newstore.add.assert_called_once_with(self.image_id, mock.ANY,
                                             self.size, self.hash_algo,
                                             context=None, verifier=None)

        self.assertEqual(self.location, location)
        self.assertEqual(self.size, size)
        self.assertEqual(self.checksum, checksum)
        self.assertEqual(self.multihash, multihash)
        self.assertEqual(in_metadata, metadata)

    def test_empty(self):
        metadata = {}
        self._good_metadata(metadata)

    def test_string(self):
        metadata = {'key': u'somevalue'}
        self._good_metadata(metadata)

    def test_list(self):
        m = {'key': [u'somevalue', u'2']}
        self._good_metadata(m)

    def test_unicode_dict(self):
        inner = {'key1': u'somevalue', 'key2': u'somevalue'}
        m = {'topkey': inner}
        self._good_metadata(m)

    def test_unicode_dict_list(self):
        inner = {'key1': u'somevalue', 'key2': u'somevalue'}
        m = {'topkey': inner, 'list': [u'somevalue', u'2'], 'u': u'2'}
        self._good_metadata(m)

    def test_nested_dict(self):
        inner = {'key1': u'somevalue', 'key2': u'somevalue'}
        inner = {'newkey': inner}
        inner = {'anotherkey': inner}
        m = {'topkey': inner}
        self._good_metadata(m)

    def test_bad_top_level_nonunicode(self):
        metadata = {'key': b'a string'}
        self._bad_metadata(metadata)

    def test_bad_nonunicode_dict_list(self):
        inner = {'key1': u'somevalue', 'key2': u'somevalue',
                 'k3': [1, object()]}
        m = {'topkey': inner, 'list': [u'somevalue', u'2'], 'u': u'2'}
        self._bad_metadata(m)

    def test_bad_metadata_not_dict(self):
        self._bad_metadata([])
