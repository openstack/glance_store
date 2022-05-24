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

from unittest import mock

from oslo_config import cfg
from oslotest import base

from cinderclient import exceptions as cinder_exception
from glance_store.common import attachment_state_manager as attach_manager
from glance_store.common import cinder_utils
from glance_store import exceptions

CONF = cfg.CONF


class AttachmentStateManagerTestCase(base.BaseTestCase):

    class FakeAttachmentState:
        def __init__(self):
            self.attachments = {mock.sentinel.attachments}

    def setUp(self):
        super(AttachmentStateManagerTestCase, self).setUp()
        self.__manager__ = attach_manager.__manager__

    def get_state(self):
        with self.__manager__.get_state() as state:
            return state

    def test_get_state_host_not_initialized(self):
        self.__manager__.state = None
        self.assertRaises(exceptions.HostNotInitialized,
                          self.get_state)

    def test_get_state(self):
        self.__manager__.state = self.FakeAttachmentState()
        state = self.get_state()
        self.assertEqual({mock.sentinel.attachments}, state.attachments)


class AttachmentStateTestCase(base.BaseTestCase):

    def setUp(self):
        super(AttachmentStateTestCase, self).setUp()
        self.attachments = set()
        self.m = attach_manager._AttachmentState()
        self.attach_call_1 = [mock.sentinel.client, mock.sentinel.volume_id]
        self.attach_call_2 = {'mode': mock.sentinel.mode}
        self.disconnect_vol_call = [mock.sentinel.device]
        self.detach_call = [mock.sentinel.client, mock.sentinel.attachment_id]
        self.attachment_dict = {'id': mock.sentinel.attachment_id}

    def _sentinel_attach(self):
        attachment_id = self.m.attach(
            mock.sentinel.client, mock.sentinel.volume_id,
            mock.sentinel.host, mode=mock.sentinel.mode)
        return attachment_id

    def _sentinel_detach(self, conn):
        self.m.detach(mock.sentinel.client, mock.sentinel.attachment_id,
                      mock.sentinel.volume_id, mock.sentinel.host,
                      conn, mock.sentinel.connection_info,
                      mock.sentinel.device)

    @mock.patch.object(cinder_utils.API, 'attachment_create')
    def test_attach(self, mock_attach_create):
        mock_attach_create.return_value = self.attachment_dict
        attachment = self._sentinel_attach()
        mock_attach_create.assert_called_once_with(
            *self.attach_call_1, **self.attach_call_2)
        self.assertEqual(mock.sentinel.attachment_id, attachment['id'])

    @mock.patch.object(cinder_utils.API, 'attachment_delete')
    def test_detach_without_attach(self, mock_attach_delete):
        ex = exceptions.BackendException
        conn = mock.MagicMock()
        mock_attach_delete.side_effect = ex()
        self.assertRaises(ex, self._sentinel_detach, conn)
        conn.disconnect_volume.assert_called_once_with(
            *self.disconnect_vol_call)

    @mock.patch.object(cinder_utils.API, 'attachment_create')
    @mock.patch.object(cinder_utils.API, 'attachment_delete')
    def test_detach_with_attach(self, mock_attach_delete, mock_attach_create):
        conn = mock.MagicMock()
        mock_attach_create.return_value = self.attachment_dict
        attachment = self._sentinel_attach()
        self._sentinel_detach(conn)
        mock_attach_create.assert_called_once_with(
            *self.attach_call_1, **self.attach_call_2)
        self.assertEqual(mock.sentinel.attachment_id, attachment['id'])
        conn.disconnect_volume.assert_called_once_with(
            *self.disconnect_vol_call)
        mock_attach_delete.assert_called_once_with(
            *self.detach_call)

    @mock.patch.object(cinder_utils.API, 'attachment_create')
    def test_attach_fails(self, mock_attach_create):
        mock_attach_create.side_effect = cinder_exception.BadRequest(code=400)
        self.assertRaises(
            cinder_exception.BadRequest, self.m.attach,
            mock.sentinel.client, mock.sentinel.volume_id,
            mock.sentinel.host, mode=mock.sentinel.mode)
