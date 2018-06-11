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

import mock
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_utils import units
import six

import glance_store as store
from glance_store._drivers import sheepdog
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities as test_cap


class TestSheepdogMultiStore(base.MultiStoreBaseTest,
                             test_cap.TestStoreCapabilitiesChecking):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        """Establish a clean test environment."""
        super(TestSheepdogMultiStore, self).setUp()
        enabled_backends = {
            "sheepdog1": "sheepdog",
            "sheepdog2": "sheepdog",
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='sheepdog1', group='glance_store')

        # mock sheepdog commands
        def _fake_execute(*cmd, **kwargs):
            pass

        execute = mock.patch.object(processutils, 'execute').start()
        execute.side_effect = _fake_execute
        self.addCleanup(execute.stop)

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}

        store.create_multi_stores(self.conf)
        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.addCleanup(self.conf.reset)

        self.store = sheepdog.Store(self.conf, backend='sheepdog1')
        self.store.configure()
        self.store_specs = {'image': '6bd59e6e-c410-11e5-ab67-0a73f1fda51b',
                            'addr': '127.0.0.1',
                            'port': 7000}

    @mock.patch.object(sheepdog.SheepdogImage, 'write')
    @mock.patch.object(sheepdog.SheepdogImage, 'create')
    @mock.patch.object(sheepdog.SheepdogImage, 'exist')
    def test_add_image(self, mock_exist, mock_create, mock_write):
        data = six.BytesIO(b'xx')
        mock_exist.return_value = False

        (uri, size, checksum, loc) = self.store.add('fake_image_id', data, 2)
        self.assertEqual("sheepdog1", loc["backend"])

        mock_exist.assert_called_once_with()
        mock_create.assert_called_once_with(2)
        mock_write.assert_called_once_with(b'xx', 0, 2)

    @mock.patch.object(sheepdog.SheepdogImage, 'write')
    @mock.patch.object(sheepdog.SheepdogImage, 'create')
    @mock.patch.object(sheepdog.SheepdogImage, 'exist')
    def test_add_image_to_different_backend(self, mock_exist,
                                            mock_create, mock_write):
        self.store = sheepdog.Store(self.conf, backend='sheepdog2')
        self.store.configure()

        data = six.BytesIO(b'xx')
        mock_exist.return_value = False

        (uri, size, checksum, loc) = self.store.add('fake_image_id', data, 2)
        self.assertEqual("sheepdog2", loc["backend"])

        mock_exist.assert_called_once_with()
        mock_create.assert_called_once_with(2)
        mock_write.assert_called_once_with(b'xx', 0, 2)

    @mock.patch.object(sheepdog.SheepdogImage, 'write')
    @mock.patch.object(sheepdog.SheepdogImage, 'exist')
    def test_add_bad_size_with_image(self, mock_exist, mock_write):
        data = six.BytesIO(b'xx')
        mock_exist.return_value = False

        self.assertRaises(exceptions.Forbidden, self.store.add,
                          'fake_image_id', data, 'test')

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
                          'fake_image_id', data, 2)

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
                              'fake_image_id', data, 2)

    def test_get(self):
        def _fake_run_command(command, data, *params):
            if command == "list -r":
                return "= fake_volume 0 1000"

        with mock.patch.object(sheepdog.SheepdogImage, '_run_command') as cmd:
            cmd.side_effect = _fake_run_command
            loc = location.Location('test_sheepdog_store',
                                    sheepdog.StoreLocation,
                                    self.conf, store_specs=self.store_specs,
                                    backend='sheepdog1')
            ret = self.store.get(loc)
            self.assertEqual(1000, ret[1])

    def test_partial_get(self):
        loc = location.Location('test_sheepdog_store', sheepdog.StoreLocation,
                                self.conf, store_specs=self.store_specs,
                                backend='sheepdog1')
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
                                    self.conf, store_specs=self.store_specs,
                                    backend='sheepdog1')
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
                                    self.conf, store_specs=self.store_specs,
                                    backend='sheepdog1')
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
            (uri, size, checksum, loc) = self.store.add(
                image_id, image_file, file_size, verifier=verifier)
            self.assertEqual("sheepdog1", loc["backend"])

        verifier.update.assert_called_with(file_contents)
