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

import json
import logging
import os

from oslo_concurrency import lockutils
from oslo_concurrency import processutils
from oslo_config import cfg

from glance_store.i18n import _LE, _LW


LOG = logging.getLogger(__name__)

CONF = cfg.CONF


class _HostMountState(object):
    """Manages filesystem mount operations and tracks attachment counts for
    each mountpoint. _HostMountState ensures that the glance node only attempts
    to mount a single mountpoint once, regardless of how many attachments use
    it, and it is not unmounted until the attachment count reaches zero.

    This implementation uses file-based state management to coordinate between
    multiple worker processes. Each mountpoint's state is stored in
    a separate JSON file containing the attachment count.

    _HostMountState manages concurrency itself. Independent callers do not need
    to consider interactions between multiple _HostMountState calls when
    designing their own locking.
    """

    def _get_state_file_path(self, mountpoint):
        """Generate a state file path for the given mountpoint.

        Creates a state file in the _state subdirectory using the
        mountpoint basename as the filename.

        :param mountpoint: The mountpoint path
        :returns: Path to the state file
        :rtype: str
        """

        # return '_state' subdirectory within the mountpoint's base directory
        state_dir = os.path.join(os.path.dirname(mountpoint), '_state')
        # Extract the mountpoint name from the full path in SHA256 hash format
        mountpoint_name = os.path.basename(mountpoint)
        state_file = os.path.join(state_dir,
                                  'mount_state_%s.json' % mountpoint_name)
        return state_file

    def _get_state(self, mountpoint):
        """Get the current state for a mountpoint.

        :param mountpoint: The mountpoint path
        :returns: State dictionary, defaults to {"attachment_count": 0} if file
                  doesn't exist or fails to read.
        :rtype: dict
        """
        state_file = self._get_state_file_path(mountpoint)
        state = {"attachment_count": 0}
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
                # Ensure attachment_count is an integer
                if "attachment_count" in state:
                    state["attachment_count"] = int(state["attachment_count"])
        except FileNotFoundError:
            # File doesn't exist yet, use default state
            pass
        except (IOError, ValueError, json.JSONDecodeError) as e:
            LOG.warning("Failed to read state file %s: %s", state_file, e)
        return state

    def _save_state(self, mountpoint, state):
        """Save the state for a mountpoint.

        Writes state atomically using a temporary file and rename.
        Creates the state directory if it doesn't exist.

        :param mountpoint: The mountpoint path
        :param state: The state dictionary to save
        """
        state_file = self._get_state_file_path(mountpoint)
        state_dir = os.path.dirname(state_file)
        temp_file = state_file + '.tmp'
        try:
            os.makedirs(state_dir, mode=0o755, exist_ok=True)
            # Write state atomically using a temporary file
            with open(temp_file, 'w') as f:
                json.dump(state, f)
            os.rename(temp_file, state_file)
        except Exception as e:
            LOG.error("Failed to write state file %s: %s", state_file, e)
            raise

    def mount(self, fstype, export, vol_name, mountpoint, host,
              rootwrap_helper, options):
        """Ensure a mountpoint is available for an attachment, mounting it
        if necessary.

        If this is the first attachment on this mountpoint, we will mount it
        with:

          mount -t <fstype> <options> <export> <mountpoint>

        :param fstype: The filesystem type to be passed to mount command.
        :param export: The type-specific identifier of the filesystem to be
                       mounted. e.g. for nfs 'host.example.com:/mountpoint'.
        :param vol_name: The name of the volume on the remote filesystem.
        :param mountpoint: The directory where the filesystem will be
                           mounted on the local compute host. Must be unique
                           to prevent state file and lock collisions between
                           different mounts.
        :param host: The host the volume will be attached to.
        :param options: An arbitrary list of additional arguments to be
                        passed to the mount command immediate before export
                        and mountpoint.
        """

        LOG.debug('_HostMountState.mount(fstype=%(fstype)s, '
                  'export=%(export)s, vol_name=%(vol_name)s, %(mountpoint)s, '
                  'options=%(options)s, host=%(host)s)',
                  {'fstype': fstype, 'export': export, 'vol_name': vol_name,
                   'mountpoint': mountpoint, 'options': options, 'host': host})

        @lockutils.synchronized('fs_mount_%s' % os.path.basename(mountpoint),
                                external=True)
        def _mount_with_lock():
            if not os.path.ismount(mountpoint):
                LOG.debug('Mounting %(mountpoint)s',
                          {'mountpoint': mountpoint})

                # Create mountpoint directory if it doesn't exist
                if not os.path.exists(mountpoint):
                    os.makedirs(mountpoint, mode=0o755, exist_ok=True)

                mount_cmd = ['mount', '-t', fstype]
                if options is not None:
                    mount_cmd.extend(options)
                mount_cmd.extend([export, mountpoint])

                try:
                    processutils.execute(*mount_cmd, run_as_root=True,
                                         root_helper=rootwrap_helper)
                except Exception:
                    # Check to see if mountpoint is mounted despite the error
                    # eg it was already mounted
                    if os.path.ismount(mountpoint):
                        # We're not going to raise the exception because we're
                        # in the desired state anyway. However, this is still
                        # unusual so we'll log it.
                        LOG.exception(_LE('Error mounting %(fstype)s export '
                                          '%(export)s on %(mountpoint)s. '
                                          'Continuing because mountpoint is '
                                          'mounted despite this.'),
                                      {'fstype': fstype, 'export': export,
                                       'mountpoint': mountpoint})

                    else:
                        # If the mount failed, don't increment attachment count
                        raise

            state = self._get_state(mountpoint)
            # Increment attachment count and add metadata
            state["attachment_count"] = state.get("attachment_count", 0) + 1
            self._save_state(mountpoint, state)

        _mount_with_lock()

        LOG.debug('_HostMountState.mount() for %(mountpoint)s '
                  'completed successfully',
                  {'mountpoint': mountpoint})

    def umount(self, vol_name, mountpoint, host, rootwrap_helper):
        """Mark an attachment as no longer in use, and unmount its mountpoint
        if necessary.

        :param vol_name: The name of the volume on the remote filesystem.
        :param mountpoint: The directory where the filesystem is be
                           mounted on the local compute host.
        :param host: The host the volume was attached to.
        """
        LOG.debug('_HostMountState.umount(vol_name=%(vol_name)s, '
                  'mountpoint=%(mountpoint)s, host=%(host)s)',
                  {'vol_name': vol_name, 'mountpoint': mountpoint,
                   'host': host})

        @lockutils.synchronized('fs_mount_%s' % os.path.basename(mountpoint),
                                external=True)
        def _umount_with_lock():
            state = self._get_state(mountpoint)
            current_count = state.get("attachment_count", 0)
            if current_count == 0:
                LOG.warning(_LW("Request to remove attachment "
                                "(%(vol_name)s, %(host)s) from "
                                "%(mountpoint)s, but attachment count is "
                                "already %(count)d."),
                            {'vol_name': vol_name, 'host': host,
                             'mountpoint': mountpoint,
                             'count': current_count})

                # Check if mountpoint is still mounted despite count reached
                # zero. If so, attempt to unmount as recovery measure.
                mounted = os.path.ismount(mountpoint)
                if mounted:
                    LOG.warning(
                        _LW("Mountpoint %(mountpoint)s is still mounted "
                            "despite attachment count being 0. Attempting to "
                            "unmount as recovery measure."),
                        {'mountpoint': mountpoint})

                    mounted = self._real_umount(mountpoint, rootwrap_helper)

                    # Delete state file if successfully unmounted
                    if not mounted:
                        try:
                            state_file = self._get_state_file_path(mountpoint)
                            os.remove(state_file)
                        except OSError as e:
                            LOG.warning("Failed to remove state file %s: %s",
                                        state_file, e)

                return

            # Decrement attachment count
            new_count = current_count - 1
            state["attachment_count"] = new_count
            if new_count == 0:
                mounted = self._real_umount(mountpoint, rootwrap_helper)
                # Delete state file if successfully unmounted
                if not mounted:
                    try:
                        state_file = self._get_state_file_path(mountpoint)
                        os.remove(state_file)
                    except OSError as e:
                        LOG.warning("Failed to remove state file %s: %s",
                                    state_file, e)
                else:
                    # update state despite failed to unmount
                    self._save_state(mountpoint, state)
            else:
                # Still has attachments, update state
                self._save_state(mountpoint, state)

        _umount_with_lock()

        LOG.debug('_HostMountState.umount() for %(mountpoint)s '
                  'completed successfully',
                  {'mountpoint': mountpoint})

    def _real_umount(self, mountpoint, rootwrap_helper):
        # Unmount and delete a mountpoint.
        # Return mount state after umount (i.e. True means still mounted)
        LOG.debug('Unmounting %(mountpoint)s', {'mountpoint': mountpoint})

        try:
            processutils.execute('umount', mountpoint, run_as_root=True,
                                 attempts=3, delay_on_retry=True,
                                 root_helper=rootwrap_helper)
        except processutils.ProcessExecutionError as ex:
            LOG.error(_LE("Couldn't unmount %(mountpoint)s: %(reason)s"),
                      {'mountpoint': mountpoint, 'reason': ex})

        if not os.path.ismount(mountpoint):
            try:
                os.rmdir(mountpoint)
            except Exception as ex:
                LOG.error(_LE("Couldn't remove directory %(mountpoint)s: "
                              "%(reason)s"),
                          {'mountpoint': mountpoint,
                           'reason': ex})
            return False

        return True


__state__ = _HostMountState()


def mount(fstype, export, vol_name, mountpoint, host, rootwrap_helper,
          options=None):
    """A convenience wrapper around _HostMountState.mount()"""

    __state__.mount(fstype, export, vol_name, mountpoint, host,
                    rootwrap_helper, options)


def umount(vol_name, mountpoint, host, rootwrap_helper):
    """A convenience wrapper around _HostMountState.umount()"""

    __state__.umount(vol_name, mountpoint, host, rootwrap_helper)
