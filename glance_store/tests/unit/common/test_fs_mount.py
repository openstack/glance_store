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

import sys
from unittest import mock

import fixtures
from oslo_concurrency import processutils
from oslo_config import cfg
from oslotest import base

from glance_store import exceptions

CONF = cfg.CONF


class HostMountManagerTestCase(base.BaseTestCase):

    class FakeHostMountState:
        def __init__(self):
            self.mountpoints = {mock.sentinel.mountpoint}

    def setUp(self):
        super(HostMountManagerTestCase, self).setUp()
        CONF.register_opt(cfg.DictOpt('enabled_backends'))
        CONF.set_override('enabled_backends', 'fake:file')
        # Since this is mocked in other tests, we unmock it here
        if 'glance_store.common.fs_mount' in sys.modules:
            sys.modules.pop('glance_store.common.fs_mount')
        # Since the _HostMountStateManager class instantiates on its
        # import, this import is done here to register the enabled_backends
        # config option before it is used during initialization
        from glance_store.common import fs_mount as mount  # noqa
        self.__manager__ = mount.__manager__

    def get_state(self):
        with self.__manager__.get_state() as state:
            return state

    def test_get_state_host_not_initialized(self):
        self.__manager__.state = None
        self.assertRaises(exceptions.HostNotInitialized,
                          self.get_state)

    def test_get_state(self):
        self.__manager__.state = self.FakeHostMountState()
        state = self.get_state()
        self.assertEqual({mock.sentinel.mountpoint}, state.mountpoints)


class HostMountStateTestCase(base.BaseTestCase):

    def setUp(self):
        super(HostMountStateTestCase, self).setUp()
        CONF.register_opt(cfg.DictOpt('enabled_backends'))
        CONF.set_override('enabled_backends', 'fake:file')
        # Since this is mocked in other tests, we unmock it here
        if 'glance_store.common.fs_mount' in sys.modules:
            sys.modules.pop('glance_store.common.fs_mount')
        # Since the _HostMountStateManager class instantiates on its
        # import, this import is done here to register the enabled_backends
        # config option before it is used during initialization
        from glance_store.common import fs_mount as mount  # noqa
        self.mounted = set()
        self.m = mount._HostMountState()

        def fake_execute(cmd, *args, **kwargs):
            if cmd == 'mount':
                path = args[-1]
                if path in self.mounted:
                    raise processutils.ProcessExecutionError('Already mounted')
                self.mounted.add(path)
            elif cmd == 'umount':
                path = args[-1]
                if path not in self.mounted:
                    raise processutils.ProcessExecutionError('Not mounted')
                self.mounted.remove(path)

        def fake_ismount(path):
            return path in self.mounted

        mock_execute = mock.MagicMock(side_effect=fake_execute)

        self.useFixture(fixtures.MonkeyPatch(
            'oslo_concurrency.processutils.execute',
            mock_execute))
        self.useFixture(fixtures.MonkeyPatch('os.path.ismount', fake_ismount))

    @staticmethod
    def _expected_sentinel_mount_calls(mountpoint=mock.sentinel.mountpoint):
        return [mock.call('mount', '-t', mock.sentinel.fstype,
                          mock.sentinel.option1, mock.sentinel.option2,
                          mock.sentinel.export, mountpoint,
                          root_helper=mock.sentinel.rootwrap_helper,
                          run_as_root=True)]

    @staticmethod
    def _expected_sentinel_umount_calls(mountpoint=mock.sentinel.mountpoint):
        return [mock.call('umount', mountpoint, attempts=3,
                          delay_on_retry=True,
                          root_helper=mock.sentinel.rootwrap_helper,
                          run_as_root=True)]

    def _sentinel_mount(self):
        self.m.mount(mock.sentinel.fstype, mock.sentinel.export,
                     mock.sentinel.vol, mock.sentinel.mountpoint,
                     mock.sentinel.host, mock.sentinel.rootwrap_helper,
                     [mock.sentinel.option1, mock.sentinel.option2])

    def _sentinel_umount(self):
        self.m.umount(mock.sentinel.vol, mock.sentinel.mountpoint,
                      mock.sentinel.host, mock.sentinel.rootwrap_helper)

    @mock.patch('os.makedirs')
    def test_mount(self, mock_makedirs):
        self._sentinel_mount()
        mock_makedirs.assert_called_once()
        processutils.execute.assert_has_calls(
            self._expected_sentinel_mount_calls())

    def test_unmount_without_mount(self):
        self._sentinel_umount()
        processutils.execute.assert_not_called()

    @mock.patch('os.rmdir')
    @mock.patch('os.makedirs')
    def test_umount_with_mount(self, mock_makedirs, mock_rmdir):
        self._sentinel_mount()
        self._sentinel_umount()
        mock_makedirs.assert_called_once()
        mock_rmdir.assert_called_once()
        processutils.execute.assert_has_calls(
            self._expected_sentinel_mount_calls() +
            self._expected_sentinel_umount_calls())
