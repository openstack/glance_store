# Copyright 2013 OpenStack Foundation
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

import StringIO

import mock

from glance_store._drivers import gridfs as gfs
from glance_store.tests import base
from tests.unit import test_store_capabilities

try:
    import gridfs
    import pymongo
except ImportError:
    pymongo = None


GRIDFS_CONF = {'mongodb_store_uri': 'mongodb://fake_store_uri',
               'mongodb_store_db': 'fake_store_db'}


class FakeMongoClient(object):
    def __init__(self, *args, **kwargs):
        pass

    def __getitem__(self, key):
        return None


class FakeGridFS(object):
    image_data = {}
    called_commands = []

    def __init__(self, *args, **kwargs):
        pass

    def exists(self, image_id):
        self.called_commands.append('exists')
        return False

    def put(self, image_file, _id):
        self.called_commands.append('put')
        data = None
        while True:
            data = image_file.read(64)
            if data:
                self.image_data[_id] = \
                    self.image_data.setdefault(_id, '') + data
            else:
                break

    def delete(self, _id):
        self.called_commands.append('delete')

    def get(self, location):
        self.called_commands.append('get')

        class Image(object):
            _id = "test"
            length = 6
            md5 = "yoyo"

        return Image


class TestStore(base.StoreBaseTest,
                test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        """Establish a clean test environment."""
        super(TestStore, self).setUp()

        if pymongo is not None:
            conn = mock.patch.object(pymongo, 'MongoClient').start()
            conn.side_effect = FakeMongoClient
            self.addCleanup(conn.stop)

            pgfs = mock.patch.object(gridfs, 'GridFS').start()
            pgfs.side_effect = FakeGridFS
            self.addCleanup(pgfs.stop)

        self.store = gfs.Store(self.conf)
        self.config(group='glance_store', **GRIDFS_CONF)
        self.store.configure()

    def test_cleanup_when_add_image_exception(self):
        if pymongo is None:
            msg = 'GridFS store can not add images, skip test.'
            self.skipTest(msg)

        self.store.add('fake_image_id', StringIO.StringIO('xx'), 2)
        self.assertEqual(self.store.fs.called_commands,
                         ['exists', 'put', 'get'])
