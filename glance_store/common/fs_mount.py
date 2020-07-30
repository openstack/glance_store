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

import collections
import contextlib
import logging
import os
import socket
import threading

from oslo_concurrency import processutils
from oslo_config import cfg

from glance_store import exceptions
from glance_store.i18n import _LE, _LW


LOG = logging.getLogger(__name__)

HOST = socket.gethostname()
CONF = cfg.CONF


class HostMountStateManagerMeta(type):
    _instance = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instance:
            cls._instance[cls] = super(
                HostMountStateManagerMeta, cls).__call__(*args, **kwargs)
        return cls._instance[cls]


class _HostMountStateManager(metaclass=HostMountStateManagerMeta):
    """A global manager of filesystem mounts.

    _HostMountStateManager manages a _HostMountState object for the current
    glance node. Primarily it creates one on object initialization and returns
    it via get_state().

    _HostMountStateManager manages concurrency itself. Independent callers do
    not need to consider interactions between multiple _HostMountStateManager
    calls when designing their own locking.

    """
    # Reset state of global _HostMountStateManager
    state = None
    use_count = 0

    # Guards both state and use_count
    cond = threading.Condition()

    def __init__(self, host):
        """Initialise a new _HostMountState

        We will block before creating a new state until all operations
        using a previous state have completed.

        :param host: host
        """
        # Wait until all operations using a previous state are
        # complete before initialising a new one. Note that self.state is
        # already None, set either by initialisation or by host_down. This
        # means the current state will not be returned to any new callers,
        # and use_count will eventually reach zero.
        # We do this to avoid a race between _HostMountState initialisation
        # and an on-going mount/unmount operation
        self.host = host
        while self.use_count != 0:
            self.cond.wait()

        # Another thread might have initialised state while we were
        # waiting
        if self.state is None:
            LOG.debug('Initialising _HostMountState')
            self.state = _HostMountState()
            backends = []
            enabled_backends = CONF.enabled_backends
            if enabled_backends:
                for backend in enabled_backends:
                    if enabled_backends[backend] == 'cinder':
                        backends.append(backend)
            else:
                backends.append('glance_store')

            for backend in backends:
                mountpoint = getattr(CONF, backend).cinder_mount_point_base
                # This is currently designed for cinder nfs backend only.
                # Later can be modified to work with other *fs backends.
                mountpoint = os.path.join(mountpoint, 'nfs')
                # There will probably be the same rootwrap file for all stores,
                # generalizing this will be done in a later refactoring
                rootwrap = getattr(CONF, backend).rootwrap_config
                rootwrap = ('sudo glance-rootwrap %s' % rootwrap)
                dirs = []
                # fetch the directories in the mountpoint path
                if os.path.isdir(mountpoint):
                    dirs = os.listdir(mountpoint)
                else:
                    continue
                if not dirs:
                    return
                for dir in dirs:
                    # for every directory in the mountpath, we
                    # unmount it (if mounted) and remove it
                    dir = os.path.join(mountpoint, dir)
                    with self.get_state() as mount_state:
                        if os.path.exists(dir) and not os.path.ismount(dir):
                            try:
                                os.rmdir(dir)
                            except Exception as ex:
                                LOG.debug(
                                    "Couldn't remove directory "
                                    "%(mountpoint)s: %(reason)s",
                                    {'mountpoint': mountpoint,
                                     'reason': ex})
                        else:
                            mount_state.umount(None, dir, HOST, rootwrap)

    @contextlib.contextmanager
    def get_state(self):
        """Return the current mount state.

        _HostMountStateManager will not permit a new state object to be
        created while any previous state object is still in use.

        :rtype: _HostMountState
        """

        # We hold the instance lock here so that if a _HostMountState is
        # currently initialising we'll wait for it to complete rather than
        # fail.
        with self.cond:
            state = self.state
            if state is None:
                LOG.error('Host not initialized')
                raise exceptions.HostNotInitialized(host=self.host)
            self.use_count += 1
        try:
            LOG.debug('Got _HostMountState')
            yield state
        finally:
            with self.cond:
                self.use_count -= 1
                self.cond.notify_all()


class _HostMountState(object):
    """A data structure recording all managed mountpoints and the
    attachments in use for each one. _HostMountState ensures that the glance
    node only attempts to mount a single mountpoint in use by multiple
    attachments once, and that it is not unmounted until it is no longer in use
    by any attachments.

    Callers should not create a _HostMountState directly, but should obtain
    it via:

      with mount.get_manager().get_state() as state:
        state.mount(...)

    _HostMountState manages concurrency itself. Independent callers do not need
    to consider interactions between multiple _HostMountState calls when
    designing their own locking.
    """

    class _MountPoint(object):
        """A single mountpoint, and the set of attachments in use on it."""
        def __init__(self):
            # A guard for operations on this mountpoint
            # N.B. Care is required using this lock, as it will be deleted
            # if the containing _MountPoint is deleted.
            self.lock = threading.Lock()

            # The set of attachments on this mountpoint.
            self.attachments = set()

        def add_attachment(self, vol_name, host):
            self.attachments.add((vol_name, host))

        def remove_attachment(self, vol_name, host):
            self.attachments.remove((vol_name, host))

        def in_use(self):
            return len(self.attachments) > 0

    def __init__(self):
        """Initialise _HostMountState"""

        self.mountpoints = collections.defaultdict(self._MountPoint)

    @contextlib.contextmanager
    def _get_locked(self, mountpoint):
        """Get a locked mountpoint object

        :param mountpoint: The path of the mountpoint whose object we should
                           return.
        :rtype: _HostMountState._MountPoint
        """
        while True:
            mount = self.mountpoints[mountpoint]
            with mount.lock:
                if self.mountpoints[mountpoint] is mount:
                    yield mount
                    break

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
                           mounted on the local compute host.
        :param host: The host the volume will be attached to.
        :param options: An arbitrary list of additional arguments to be
                        passed to the mount command immediate before export
                        and mountpoint.
        """

        LOG.debug('_HostMountState.mount(fstype=%(fstype)s, '
                  'export=%(export)s, vol_name=%(vol_name)s, %(mountpoint)s, '
                  'options=%(options)s)',
                  {'fstype': fstype, 'export': export, 'vol_name': vol_name,
                   'mountpoint': mountpoint, 'options': options})
        with self._get_locked(mountpoint) as mount:
            if not os.path.ismount(mountpoint):
                LOG.debug('Mounting %(mountpoint)s',
                          {'mountpoint': mountpoint})

                os.makedirs(mountpoint)

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
                                          'Continuing because mountpount is '
                                          'mounted despite this.'),
                                      {'fstype': fstype, 'export': export,
                                       'mountpoint': mountpoint})

                    else:
                        # If the mount failed there's no reason for us to keep
                        # a record of it. It will be created again if the
                        # caller retries.

                        # Delete while holding lock
                        del self.mountpoints[mountpoint]

                        raise

            mount.add_attachment(vol_name, host)

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
                  'mountpoint=%(mountpoint)s)',
                  {'vol_name': vol_name, 'mountpoint': mountpoint})
        with self._get_locked(mountpoint) as mount:
            try:
                mount.remove_attachment(vol_name, host)
            except KeyError:
                LOG.warning(_LW("Request to remove attachment "
                                "(%(vol_name)s, %(host)s) from "
                                "%(mountpoint)s, but we don't think it's in "
                                "use."),
                            {'vol_name': vol_name, 'host': host,
                             'mountpoint': mountpoint})

            if not mount.in_use():
                mounted = os.path.ismount(mountpoint)

                if mounted:
                    mounted = self._real_umount(mountpoint, rootwrap_helper)

                # Delete our record entirely if it's unmounted
                if not mounted:
                    del self.mountpoints[mountpoint]

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


__manager__ = _HostMountStateManager(HOST)


def mount(fstype, export, vol_name, mountpoint, host, rootwrap_helper,
          options=None):
    """A convenience wrapper around _HostMountState.mount()"""

    with __manager__.get_state() as mount_state:
        mount_state.mount(fstype, export, vol_name, mountpoint, host,
                          rootwrap_helper, options)


def umount(vol_name, mountpoint, host, rootwrap_helper):
    """A convenience wrapper around _HostMountState.umount()"""

    with __manager__.get_state() as mount_state:
        mount_state.umount(vol_name, mountpoint, host, rootwrap_helper)
