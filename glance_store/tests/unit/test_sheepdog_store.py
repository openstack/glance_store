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

import hashlib
import mock
from oslo_concurrency import processutils
from oslo_utils import units
import oslotest
import six

from glance_store._drivers import sheepdog
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities


class TestStoreLocation(oslotest.base.BaseTestCase):
    def test_process_spec(self):
        mock_conf = mock.Mock()
        fake_spec = {
            'image': '6bd59e6e-c410-11e5-ab67-0a73f1fda51b',
            'addr': '127.0.0.1',
            'port': 7000,
        }
        loc = sheepdog.StoreLocation(fake_spec, mock_conf)
        self.assertEqual(fake_spec['image'], loc.image)
        self.assertEqual(fake_spec['addr'], loc.addr)
        self.assertEqual(fake_spec['port'], loc.port)

    def test_parse_uri(self):
        mock_conf = mock.Mock()
        fake_uri = ('sheepdog://127.0.0.1:7000'
                    ':6bd59e6e-c410-11e5-ab67-0a73f1fda51b')
        loc = sheepdog.StoreLocation({}, mock_conf)
        loc.parse_uri(fake_uri)
        self.assertEqual('6bd59e6e-c410-11e5-ab67-0a73f1fda51b', loc.image)
        self.assertEqual('127.0.0.1', loc.addr)
        self.assertEqual(7000, loc.port)


class TestSheepdogImage(oslotest.base.BaseTestCase):
    @mock.patch.object(processutils, 'execute')
    def test_run_command(self, mock_execute):
        image = sheepdog.SheepdogImage(
            '127.0.0.1', 7000, '6bd59e6e-c410-11e5-ab67-0a73f1fda51b',
            sheepdog.DEFAULT_CHUNKSIZE,
        )
        image._run_command('create', None)
        expected_cmd = (
            'collie', 'vdi', 'create', '-a', '127.0.0.1', '-p', 7000,
            '6bd59e6e-c410-11e5-ab67-0a73f1fda51b',
        )
        actual_cmd = mock_execute.call_args[0]
        self.assertEqual(expected_cmd, actual_cmd)


class TestSheepdogStore(base.StoreBaseTest,
                        test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        """Establish a clean test environment."""
        super(TestSheepdogStore, self).setUp()

        def _fake_execute(*cmd, **kwargs):
            pass

        self.config(default_store='sheepdog',
                    group='glance_store')

        execute = mock.patch.object(processutils, 'execute').start()
        execute.side_effect = _fake_execute
        self.addCleanup(execute.stop)
        self.store = sheepdog.Store(self.conf)
        self.store.configure()
        self.store_specs = {'image': '6bd59e6e-c410-11e5-ab67-0a73f1fda51b',
                            'addr': '127.0.0.1',
                            'port': 7000}
        self.hash_algo = 'sha256'

    @mock.patch.object(sheepdog.SheepdogImage, 'write')
    @mock.patch.object(sheepdog.SheepdogImage, 'create')
    @mock.patch.object(sheepdog.SheepdogImage, 'exist')
    def test_add_image(self, mock_exist, mock_create, mock_write):
        content = b'xx'
        data = six.BytesIO(content)
        mock_exist.return_value = False
        expected_checksum = hashlib.md5(content).hexdigest()
        expected_multihash = hashlib.sha256(content).hexdigest()

        (uri, size, checksum, multihash, loc) = self.store.add(
            'fake_image_id', data, 2, self.hash_algo)

        mock_exist.assert_called_once_with()
        mock_create.assert_called_once_with(2)
        mock_write.assert_called_once_with(b'xx', 0, 2)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

    @mock.patch.object(sheepdog.SheepdogImage, 'write')
    @mock.patch.object(sheepdog.SheepdogImage, 'exist')
    def test_add_bad_size_with_image(self, mock_exist, mock_write):
        data = six.BytesIO(b'xx')
        mock_exist.return_value = False

        self.assertRaises(exceptions.Forbidden, self.store.add,
                          'fake_image_id', data, 'test', self.hash_algo)

        mock_exist.assert_called_once_with()
        self.assertEqual(mock_write.call_count, 0)

    @mock.patch.object(sheepdog.SheepdogImage, 'delete')
    @mock.patch.object(sheepdog.SheepdogImage, 'write')
    @mock.patch.object(sheepdog.SheepdogImage, 'create')
    @mock.patch.object(sheepdog.SheepdogImage, 'exist')
    def test_cleanup_when_add_image_exception(self, mock_exist, mock_create,
                                              mock_write, mock_delete):
        data = six.BytesIO(b'xx')
        mock_exist.return_value = False
        mock_write.side_effect = exceptions.BackendException

        self.assertRaises(exceptions.BackendException, self.store.add,
                          'fake_image_id', data, 2, self.hash_algo)

        mock_exist.assert_called_once_with()
        mock_create.assert_called_once_with(2)
        mock_write.assert_called_once_with(b'xx', 0, 2)
        mock_delete.assert_called_once_with()

    def test_add_duplicate_image(self):
        def _fake_run_command(command, data, *params):
            if command == "list -r":
                return "= fake_volume 0 1000"

        with mock.patch.object(sheepdog.SheepdogImage, '_run_command') as cmd:
            cmd.side_effect = _fake_run_command
            data = six.BytesIO(b'xx')
            self.assertRaises(exceptions.Duplicate, self.store.add,
                              'fake_image_id', data, 2, self.hash_algo)

    def test_get(self):
        def _fake_run_command(command, data, *params):
            if command == "list -r":
                return "= fake_volume 0 1000"

        with mock.patch.object(sheepdog.SheepdogImage, '_run_command') as cmd:
            cmd.side_effect = _fake_run_command
            loc = location.Location('test_sheepdog_store',
                                    sheepdog.StoreLocation,
                                    self.conf, store_specs=self.store_specs)
            ret = self.store.get(loc)
            self.assertEqual(1000, ret[1])

    def test_partial_get(self):
        loc = location.Location('test_sheepdog_store', sheepdog.StoreLocation,
                                self.conf, store_specs=self.store_specs)
        self.assertRaises(exceptions.StoreRandomGetNotSupported,
                          self.store.get, loc, chunk_size=1)

    def test_get_size(self):
        def _fake_run_command(command, data, *params):
            if command == "list -r":
                return "= fake_volume 0 1000"

        with mock.patch.object(sheepdog.SheepdogImage, '_run_command') as cmd:
            cmd.side_effect = _fake_run_command
            loc = location.Location('test_sheepdog_store',
                                    sheepdog.StoreLocation,
                                    self.conf, store_specs=self.store_specs)
            ret = self.store.get_size(loc)
            self.assertEqual(1000, ret)

    def test_delete(self):
        called_commands = []

        def _fake_run_command(command, data, *params):
            called_commands.append(command)
            if command == "list -r":
                return "= fake_volume 0 1000"

        with mock.patch.object(sheepdog.SheepdogImage, '_run_command') as cmd:
            cmd.side_effect = _fake_run_command
            loc = location.Location('test_sheepdog_store',
                                    sheepdog.StoreLocation,
                                    self.conf, store_specs=self.store_specs)
            self.store.delete(loc)
            self.assertEqual(['list -r', 'delete'], called_commands)

    def test_add_with_verifier(self):
        """Test that 'verifier.update' is called when verifier is provided."""
        verifier = mock.MagicMock(name='mock_verifier')
        self.store.chunk_size = units.Ki
        image_id = 'fake_image_id'
        file_size = units.Ki  # 1K
        file_contents = b"*" * file_size
        image_file = six.BytesIO(file_contents)

        def _fake_run_command(command, data, *params):
            pass

        with mock.patch.object(sheepdog.SheepdogImage, '_run_command') as cmd:
            cmd.side_effect = _fake_run_command
            self.store.add(image_id, image_file, file_size, self.hash_algo,
                           verifier=verifier)

        verifier.update.assert_called_with(file_contents)
