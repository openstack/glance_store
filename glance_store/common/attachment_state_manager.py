# Copyright 2021 RedHat Inc.
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

import collections
import contextlib
import logging
import socket
import threading

from oslo_config import cfg

from glance_store.common import cinder_utils
from glance_store import exceptions
from glance_store.i18n import _LE, _LW


LOG = logging.getLogger(__name__)

HOST = socket.gethostname()
CONF = cfg.CONF


class AttachmentStateManagerMeta(type):
    _instance = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instance:
            cls._instance[cls] = super(
                AttachmentStateManagerMeta, cls).__call__(*args, **kwargs)
        return cls._instance[cls]


class _AttachmentStateManager(metaclass=AttachmentStateManagerMeta):
    """A global manager of a volume's multiple attachments.

    _AttachmentStateManager manages a _AttachmentState object for the current
    glance node. Primarily it creates one on object initialization and returns
    it via get_state().

    _AttachmentStateManager manages concurrency itself. Independent callers do
    not need to consider interactions between multiple _AttachmentStateManager
    calls when designing their own locking.

    """
    # Reset state of global _AttachmentStateManager
    state = None
    use_count = 0

    # Guards both state and use_count
    cond = threading.Condition()

    def __init__(self, host):
        """Initialise a new _AttachmentState

        We will block before creating a new state until all operations
        using a previous state have completed.

        :param host: host
        """
        # Wait until all operations using a previous state are
        # complete before initialising a new one. Note that self.state is
        # already None, set either by initialisation or by host_down. This
        # means the current state will not be returned to any new callers,
        # and use_count will eventually reach zero.
        # We do this to avoid a race between _AttachmentState initialisation
        # and an on-going attach/detach operation
        self.host = host
        while self.use_count != 0:
            self.cond.wait()

        # Another thread might have initialised state while we were
        # waiting
        if self.state is None:
            LOG.debug('Initialising _AttachmentStateManager')
            self.state = _AttachmentState()

    @contextlib.contextmanager
    def get_state(self):
        """Return the current attachment state.

        _AttachmentStateManager will not permit a new state object to be
        created while any previous state object is still in use.

        :rtype: _AttachmentState
        """

        # We hold the instance lock here so that if a _AttachmentState is
        # currently initialising we'll wait for it to complete rather than
        # fail.
        with self.cond:
            state = self.state
            if state is None:
                LOG.error('Host not initialized')
                raise exceptions.HostNotInitialized(host=self.host)
            self.use_count += 1
        try:
            LOG.debug('Got _AttachmentState')
            yield state
        finally:
            with self.cond:
                self.use_count -= 1
                self.cond.notify_all()


class _AttachmentState(object):
    """A data structure recording all managed attachments. _AttachmentState
    ensures that the glance node only attempts to a single multiattach volume
    in use by multiple attachments once, and that it is not disconnected until
    it is no longer in use by any attachments.

    Callers should not create a _AttachmentState directly, but should obtain
    it via:

      with attachment.get_manager().get_state() as state:
        state.attach(...)

    _AttachmentState manages concurrency itself. Independent callers do not
    need to consider interactions between multiple _AttachmentState calls when
    designing their own locking.
    """

    class _Attachment(object):
        # A single multiattach volume, and the set of attachments in use
        # on it.
        def __init__(self):
            # A guard for operations on this volume
            self.lock = threading.Lock()

            # The set of attachments on this volume
            self.attachments = set()

        def add_attachment(self, attachment_id, host):
            self.attachments.add((attachment_id, host))

        def remove_attachment(self, attachment_id, host):
            self.attachments.remove((attachment_id, host))

        def in_use(self):
            return len(self.attachments) > 0

    def __init__(self):
        """Initialise _AttachmentState"""

        self.volumes = collections.defaultdict(self._Attachment)
        self.volume_api = cinder_utils.API()

    @contextlib.contextmanager
    def _get_locked(self, volume):
        """Get a locked attachment object

        :param mountpoint: The path of the volume whose attachment we should
                           return.
        :rtype: _AttachmentState._Attachment
        """
        while True:
            vol = self.volumes[volume]
            with vol.lock:
                if self.volumes[volume] is vol:
                    yield vol
                    break

    def attach(self, client, volume_id, host, mode=None):
        """Ensure a volume is available for an attachment and create an
        attachment

        :param client: Cinderclient object
        :param volume_id: ID of the volume to attach
        :param host: The host the volume will be attached to
        :param mode: The attachment mode
        """

        LOG.debug('_AttachmentState.attach(volume_id=%(volume_id)s, '
                  'host=%(host)s, mode=%(mode)s)',
                  {'volume_id': volume_id, 'host': host, 'mode': mode})
        with self._get_locked(volume_id) as vol_attachment:

            try:
                attachment = self.volume_api.attachment_create(
                    client, volume_id, mode=mode)
            except Exception:
                LOG.exception(_LE('Error attaching volume %(volume_id)s'),
                              {'volume_id': volume_id})
                del self.volumes[volume_id]
                raise

            vol_attachment.add_attachment(attachment['id'], host)

        LOG.debug('_AttachmentState.attach for volume_id=%(volume_id)s '
                  'and attachment_id=%(attachment_id)s completed successfully',
                  {'volume_id': volume_id, 'attachment_id': attachment['id']})
        return attachment

    def detach(self, client, attachment_id, volume_id, host, conn,
               connection_info, device):
        """Delete the attachment no longer in use, and disconnect volume
        if necessary.

        :param client: Cinderclient object
        :param attachment_id: ID of the attachment between volume and host
        :param volume_id: ID of the volume to attach
        :param host: The host the volume was attached to
        :param conn: connector object
        :param connection_info: connection information of the volume we are
                                detaching
        :device: device used to write image

        """
        LOG.debug('_AttachmentState.detach(vol_id=%(volume_id)s, '
                  'attachment_id=%(attachment_id)s)',
                  {'volume_id': volume_id, 'attachment_id': attachment_id})
        with self._get_locked(volume_id) as vol_attachment:
            try:
                vol_attachment.remove_attachment(attachment_id, host)
            except KeyError:
                LOG.warning(_LW("Request to remove attachment "
                                "(%(volume_id)s, %(host)s) but we "
                                "don't think it's in use."),
                            {'volume_id': volume_id, 'host': host})

            if not vol_attachment.in_use():
                conn.disconnect_volume(device)
                del self.volumes[volume_id]
            self.volume_api.attachment_delete(client, attachment_id)

            LOG.debug('_AttachmentState.detach for volume %(volume_id)s '
                      'and attachment_id=%(attachment_id)s completed '
                      'successfully',
                      {'volume_id': volume_id,
                       'attachment_id': attachment_id})


__manager__ = _AttachmentStateManager(HOST)


def attach(client, volume_id, host, mode=None):
    """A convenience wrapper around _AttachmentState.attach()"""

    with __manager__.get_state() as attach_state:
        attachment = attach_state.attach(client, volume_id, host, mode=mode)
    return attachment


def detach(client, attachment_id, volume_id, host, conn, connection_info,
           device):
    """A convenience wrapper around _AttachmentState.detach()"""

    with __manager__.get_state() as attach_state:
        attach_state.detach(client, attachment_id, volume_id, host, conn,
                            connection_info, device)
