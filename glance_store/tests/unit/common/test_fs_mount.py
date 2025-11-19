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
import json
from oslo_concurrency import processutils
from oslo_config import cfg
from oslotest import base

CONF = cfg.CONF


class HostMountStateTestCase(base.BaseTestCase):

    def setUp(self):
        super(HostMountStateTestCase, self).setUp()

        CONF.register_opt(cfg.DictOpt('enabled_backends'))
        CONF.set_override('enabled_backends', 'fake:file')
        # Since this is mocked in other tests, we unmock it here
        if 'glance_store.common.fs_mount' in sys.modules:
            sys.modules.pop('glance_store.common.fs_mount')
        # Since the _HostMountState class instantiates on module import,
        # this import is done here to register the enabled_backends
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

        def fake_synchronized(*args, **kwargs):
            """Mock decorator that returns the original function unchanged"""
            def decorator(func):
                return func
            return decorator

        mock_execute = mock.MagicMock(side_effect=fake_execute)

        self.useFixture(fixtures.MonkeyPatch(
            'oslo_concurrency.processutils.execute',
            mock_execute))
        self.useFixture(fixtures.MonkeyPatch('os.path.ismount', fake_ismount))

        self.useFixture(fixtures.MonkeyPatch(
            'oslo_concurrency.lockutils.synchronized',
            fake_synchronized))

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

    def test_mount(self):
        with (mock.patch('os.path.exists', return_value=False),
              mock.patch('os.makedirs') as mock_makedirs,
              mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):

            # Mock the _HostMountState methods
            self.m._get_state = mock.Mock(return_value={"attachment_count": 0})
            self.m._save_state = mock.Mock()

            self._sentinel_mount()

            mock_makedirs.assert_called_once()
            self.m._get_state.assert_called_once()
            self.m._save_state.assert_called_once()
            processutils.execute.assert_has_calls(
                self._expected_sentinel_mount_calls())

    def test_unmount_without_mount(self):
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):
            # Mock the _HostMountState methods
            self.m._get_state = mock.Mock(return_value={"attachment_count": 0})

            self._sentinel_umount()

            self.m._get_state.assert_called_once()
            processutils.execute.assert_not_called()

    def test_umount_with_mount(self):
        with (mock.patch('os.remove') as mock_remove,
              mock.patch('os.rmdir') as mock_rmdir,
              mock.patch('os.makedirs'),
              mock.patch('os.path.exists', side_effect=[False, True]),
              mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):

            # Configure mock to return different values for mount and umount
            mock_get_state = mock.Mock(side_effect=[
                {"attachment_count": 0},  # First call during mount
                {"attachment_count": 1}   # Second call during umount
            ])
            self.m._get_state = mock_get_state
            self.m._save_state = mock.Mock()

            self._sentinel_mount()
            self._sentinel_umount()

            mock_rmdir.assert_called_once()
            mock_remove.assert_called_once()  # State file should be removed
            # Should be called twice: once for mount, once for umount
            self.assertEqual(mock_get_state.call_count, 2)
            # Should be called once for mount (umount removes the file)
            self.m._save_state.assert_called_once()
            processutils.execute.assert_has_calls(
                self._expected_sentinel_mount_calls() +
                self._expected_sentinel_umount_calls())

    def test_mount_when_already_mounted(self):
        """Test mounting when path is already mounted"""
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):

            self.mounted.add(mock.sentinel.mountpoint)

            self.m._get_state = mock.Mock(return_value={"attachment_count": 1})
            self.m._save_state = mock.Mock()

            # Clear any previous calls
            processutils.execute.reset_mock()

            self._sentinel_mount()

            processutils.execute.assert_not_called()
            # State should be incremented from 1 to 2
            self.m._save_state.assert_called_once_with(
                mock.sentinel.mountpoint,
                {"attachment_count": 2})

    def test_mount_command_fails_not_mounted(self):
        """Test mount command fails and mountpoint not mounted"""
        with (mock.patch('os.path.exists', return_value=False),
              mock.patch('os.makedirs'),
              mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):

            self.m._get_state = mock.Mock(return_value={"attachment_count": 0})
            self.m._save_state = mock.Mock()

            processutils.execute.side_effect = (
                processutils.ProcessExecutionError('Mount failed'))

            self.assertRaises(processutils.ProcessExecutionError,
                              self._sentinel_mount)

            self.m._save_state.assert_not_called()

    def test_mount_with_existing_attachments(self):
        """Test mounting when attachment_count=1, should increment to 2"""
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):

            self.mounted.add(mock.sentinel.mountpoint)
            self.m._get_state = mock.Mock(
                return_value={"attachment_count": 1})
            self.m._save_state = mock.Mock()

            processutils.execute.reset_mock()

            self._sentinel_mount()

            processutils.execute.assert_not_called()
            # State should be incremented to 2
            self.m._save_state.assert_called_once_with(
                mock.sentinel.mountpoint,
                {"attachment_count": 2})

    def test_mount_increments_count_from_zero(self):
        """Test mount increments attachment_count from 0 to 1 with metadata"""
        with (mock.patch('os.path.exists', return_value=False),
              mock.patch('os.makedirs'),
              mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):

            self.m._get_state = mock.Mock(return_value={"attachment_count": 0})
            self.m._save_state = mock.Mock()

            self._sentinel_mount()

            # Verify state saved with count=1
            self.m._save_state.assert_called_once_with(
                mock.sentinel.mountpoint,
                {"attachment_count": 1})

    def test_mount_creates_mountpoint_directory(self):
        """Test mount creates mountpoint directory when it doesn't exist"""
        with (mock.patch('os.path.exists', return_value=False),
              mock.patch('os.makedirs') as mock_makedirs,
              mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):

            self.m._get_state = mock.Mock(return_value={"attachment_count": 0})
            self.m._save_state = mock.Mock()

            self._sentinel_mount()

            mock_makedirs.assert_called_with(
                mock.sentinel.mountpoint, mode=0o755, exist_ok=True)

    def test_umount_count_zero_not_mounted(self):
        """Test unmount with count=0 and not mounted - should return early"""
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):

            self.m._get_state = mock.Mock(return_value={"attachment_count": 0})
            self.m._real_umount = mock.Mock()

            processutils.execute.reset_mock()

            self._sentinel_umount()

            # Should not attempt to unmount
            self.m._real_umount.assert_not_called()
            processutils.execute.assert_not_called()

    def test_umount_count_zero_still_mounted_recovery_success(self):
        """Test recovery when count=0 but still mounted - unmount succeeds"""
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path'),
              mock.patch('os.remove') as mock_remove):

            # Simulate inconsistent state: count=0 but still mounted
            self.mounted.add(mock.sentinel.mountpoint)
            self.m._get_state = mock.Mock(return_value={"attachment_count": 0})
            self.m._get_state_file_path = mock.Mock(
                return_value='/test/path/_state/mount_state_test.json')

            # Mock _real_umount to return False (successfully unmounted)
            self.m._real_umount = mock.Mock(return_value=False)

            self._sentinel_umount()

            # Should attempt recovery unmount
            self.m._real_umount.assert_called_once_with(
                mock.sentinel.mountpoint, mock.sentinel.rootwrap_helper)
            # Should remove state file after successful unmount
            mock_remove.assert_called_once_with(
                '/test/path/_state/mount_state_test.json')

    def test_umount_count_zero_still_mounted_recovery_fails(self):
        """Test recovery when count=0 but unmount fails - state file kept"""
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path'),
              mock.patch('os.remove') as mock_remove):

            # Simulate inconsistent state: count=0 but still mounted
            self.mounted.add(mock.sentinel.mountpoint)
            self.m._get_state = mock.Mock(return_value={"attachment_count": 0})

            # Mock _real_umount to return True (still mounted after attempt)
            self.m._real_umount = mock.Mock(return_value=True)

            self._sentinel_umount()

            # Should attempt recovery unmount
            self.m._real_umount.assert_called_once_with(
                mock.sentinel.mountpoint, mock.sentinel.rootwrap_helper)

            # Should NOT remove state file since unmount failed
            mock_remove.assert_not_called()

    def test_umount_decrement_from_multiple_attachments(self):
        """Test unmount decrements from 3 to 2, no actual unmount"""
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path')):

            self.mounted.add(mock.sentinel.mountpoint)
            self.m._get_state = mock.Mock(
                return_value={"attachment_count": 3})
            self.m._save_state = mock.Mock()
            self.m._real_umount = mock.Mock()

            processutils.execute.reset_mock()

            self._sentinel_umount()

            # Should decrement to 2 and save state
            self.m._save_state.assert_called_once_with(
                mock.sentinel.mountpoint,
                {"attachment_count": 2})

            # Should NOT attempt to unmount (count > 0)
            self.m._real_umount.assert_not_called()

    def test_umount_decrement_to_zero_unmount_succeeds(self):
        """Test unmount with count=1→0, unmount succeeds"""
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path'),
              mock.patch('os.remove') as mock_remove,
              mock.patch('os.rmdir') as mock_rmdir):

            self.mounted.add(mock.sentinel.mountpoint)
            self.m._get_state = mock.Mock(
                return_value={"attachment_count": 1})
            self.m._get_state_file_path = mock.Mock(
                return_value='/test/path/_state/mount_state_test.json')

            self._sentinel_umount()

            # Should actually unmount
            processutils.execute.assert_called_once_with(
                'umount', mock.sentinel.mountpoint, attempts=3,
                delay_on_retry=True,
                root_helper=mock.sentinel.rootwrap_helper,
                run_as_root=True)
            # Should remove state file
            mock_remove.assert_called_once_with(
                '/test/path/_state/mount_state_test.json')
            # Should remove mountpoint directory
            mock_rmdir.assert_called_once_with(mock.sentinel.mountpoint)

    def test_umount_decrement_to_zero_unmount_fails(self):
        """Test unmount with count=1→0 but _real_umount fails"""
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path'),
              mock.patch('os.remove') as mock_remove,
              mock.patch(
                'oslo_concurrency.processutils.execute') as mock_execute):

            self.mounted.add(mock.sentinel.mountpoint)
            self.m._get_state = mock.Mock(
                return_value={"attachment_count": 1})
            self.m._save_state = mock.Mock()
            mock_execute.side_effect = (
                processutils.ProcessExecutionError('Umount failed'))

            self._sentinel_umount()

            # Should decrement attachment_count to 0 and save state despite
            # umount failure.
            self.m._save_state.assert_called_once_with(
                mock.sentinel.mountpoint,
                {"attachment_count": 0})

            # Should NOT remove state file (umount failed)
            mock_remove.assert_not_called()

    def test_umount_state_file_removal_fails(self):
        """Test unmount succeeds but state file removal raises Exception"""
        with (mock.patch('os.path.basename', return_value='test_mountpoint'),
              mock.patch('os.path.dirname', return_value='/test/path'),
              mock.patch('os.remove', return_value=Exception()) as mock_remove,
              mock.patch('os.rmdir')):

            self.mounted.add(mock.sentinel.mountpoint)
            self.m._get_state = mock.Mock(
                return_value={"attachment_count": 1})
            self.m._get_state_file_path = mock.Mock(
                return_value=mock.sentinel.state_file_path)

            # Should not raise exception despite file removal failure
            self._sentinel_umount()

            processutils.execute.assert_called_once()
            mock_remove.assert_called_once()

    def test_get_state_file_path_format(self):
        """Test _get_state_file_path returns correct path structure"""
        result = self.m._get_state_file_path('/mnt/base/hash123')
        self.assertEqual(result, '/mnt/base/_state/mount_state_hash123.json')

    def test_get_state_file_path_uses_basename(self):
        """Test _get_state_file_path uses only basename in filename"""
        result = self.m._get_state_file_path('/a/b/c/mount456')
        self.assertEqual(result, '/a/b/c/_state/mount_state_mount456.json')

    def test_get_state_file_not_exists(self):
        """Test _get_state returns default when file doesn't exist"""
        with mock.patch('builtins.open', side_effect=FileNotFoundError):
            result = self.m._get_state('/test/mountpoint')
            self.assertEqual(result, {"attachment_count": 0})

    def test_get_state_file_read_ioerror(self):
        """Test _get_state returns default when IOError occurs"""
        with mock.patch('builtins.open', side_effect=IOError()):
            result = self.m._get_state('/test/mountpoint')
            self.assertEqual(result, {"attachment_count": 0})

    def test_get_state_file_json_decode_error(self):
        """Test _get_state returns default when JSON parsing fails"""
        mock_file = mock.MagicMock()

        with (mock.patch('builtins.open', return_value=mock_file),
              mock.patch('json.load',
                         side_effect=json.JSONDecodeError(
                             'Invalid JSON', '', 0))):
            result = self.m._get_state('/test/mountpoint')
            self.assertEqual(result, {"attachment_count": 0})

    def test_get_state_attachment_count_is_string(self):
        """Test _get_state attachment_count is converted if it is a string"""
        mock_file = mock.MagicMock()
        mock_file.__enter__.return_value = mock_file

        expected_state = {
            "attachment_count": "5",
            "mountpoint": "/mnt/test",
            "export": "nfs://server"
        }

        with (mock.patch('builtins.open', return_value=mock_file),
              mock.patch('json.load', return_value=expected_state)):
            result = self.m._get_state('/test/mountpoint')
            self.assertIsInstance(result["attachment_count"], int)
            self.assertEqual(result["attachment_count"], 5)

    def test_get_state_success(self):
        """Test _get_state successful read with full state"""
        mock_file = mock.MagicMock()
        mock_file.__enter__.return_value = mock_file

        expected_state = {
            "attachment_count": 3,
            "mountpoint": "/mnt/test",
            "export": "nfs://server"
        }

        with (mock.patch('builtins.open', return_value=mock_file),
              mock.patch('json.load', return_value=expected_state)):
            result = self.m._get_state('/test/mountpoint')
            self.assertDictEqual(result, expected_state)

    def test_save_state_atomic_write(self):
        """Test _save_state creates temp file and renames atomically"""
        mock_file = mock.MagicMock()
        mock_file.__enter__.return_value = mock_file

        with (mock.patch('os.makedirs') as mock_makedirs,
              mock.patch('builtins.open',
                         return_value=mock_file) as mock_open,
              mock.patch('os.rename') as mock_rename,
              mock.patch('json.dump') as mock_json_dump):

            state = {"attachment_count": 2}
            self.m._save_state('/test/mountpoint', state)

            # Verify temp file was opened for writing
            expected_temp_dir = '/test/_state'
            expected_temp = '/test/_state/mount_state_mountpoint.json.tmp'

            mock_makedirs.assert_called_with(expected_temp_dir,
                                             mode=0o755, exist_ok=True)
            mock_open.assert_called_once_with(expected_temp, 'w')

            # Verify JSON was written
            mock_json_dump.assert_called_once_with(state, mock_file)

            # Verify atomic rename
            expected_final = '/test/_state/mount_state_mountpoint.json'
            mock_rename.assert_called_once_with(expected_temp, expected_final)

    def test_save_state_exception(self):
        """Test _save_state re-raises generic exceptions"""
        with (mock.patch('builtins.open',
                         side_effect=PermissionError('Access denied')),
              mock.patch('json.dump')):

            state = {"attachment_count": 1}

            self.assertRaises(PermissionError,
                              self.m._save_state,
                              '/test/mountpoint',
                              state)
