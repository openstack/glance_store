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
import uuid

from cinderclient.apiclient import exceptions as apiclient_exception
from cinderclient import exceptions as cinder_exception
from oslo_config import cfg
from oslotest import base

from glance_store.common import cinder_utils

CONF = cfg.CONF


class FakeObject(object):
    def __init__(self, **kwargs):
        for name, value in kwargs.items():
            setattr(self, name, value)


class CinderUtilsTestCase(base.BaseTestCase):

    def setUp(self):
        super(CinderUtilsTestCase, self).setUp()
        CONF.register_opt(cfg.DictOpt('enabled_backends'))
        CONF.set_override('enabled_backends', 'fake:cinder')
        self.volume_api = cinder_utils.API()
        self.fake_client = FakeObject(attachments=FakeObject(
            create=mock.MagicMock(), delete=mock.MagicMock(),
            complete=mock.MagicMock(), update=mock.MagicMock(),
            show=mock.MagicMock()))
        self.fake_vol_id = uuid.uuid4()
        self.fake_attach_id = uuid.uuid4()
        self.fake_connector = {
            'platform': 'x86_64', 'os_type': 'linux', 'ip': 'fake_ip',
            'host': 'fake_host', 'multipath': False,
            'initiator': 'fake_initiator', 'do_local_attach': False,
            'uuid': '3e1a7217-104e-41c1-b177-a37c491129a0',
            'system uuid': '98755544-c749-40ed-b30a-a1cb27b2a46d',
            'nqn': 'fake_nqn'}

    def test_attachment_create(self):
        self.volume_api.attachment_create(self.fake_client, self.fake_vol_id)
        self.fake_client.attachments.create.assert_called_once_with(
            self.fake_vol_id, None, mode=None)

    def test_attachment_create_with_connector_and_mountpoint(self):
        self.volume_api.attachment_create(
            self.fake_client, self.fake_vol_id,
            connector=self.fake_connector, mountpoint='fake_mountpoint')
        self.fake_connector['mountpoint'] = 'fake_mountpoint'
        self.fake_client.attachments.create.assert_called_once_with(
            self.fake_vol_id, self.fake_connector, mode=None)

    def test_attachment_create_client_exception(self):
        self.fake_client.attachments.create.side_effect = (
            cinder_exception.ClientException(code=1))
        self.assertRaises(
            cinder_exception.ClientException,
            self.volume_api.attachment_create,
            self.fake_client, self.fake_vol_id)

    @mock.patch('time.sleep', new=mock.Mock())
    def test_attachment_create_retries(self):

        fake_attach_id = 'fake-attach-id'
        # Make create fail two times and succeed on the third attempt.
        self.fake_client.attachments.create.side_effect = [
            cinder_exception.BadRequest(400),
            cinder_exception.BadRequest(400),
            fake_attach_id]

        # Make sure we get a clean result.
        fake_attachment_id = self.volume_api.attachment_create(
            self.fake_client, self.fake_vol_id)

        self.assertEqual(fake_attach_id, fake_attachment_id)
        # Assert that we called attachment create three times due to the retry
        # decorator.
        self.fake_client.attachments.create.assert_has_calls([
            mock.call(self.fake_vol_id, None, mode=None),
            mock.call(self.fake_vol_id, None, mode=None),
            mock.call(self.fake_vol_id, None, mode=None)])

    def test_attachment_get(self):
        self.volume_api.attachment_get(self.fake_client, self.fake_attach_id)
        self.fake_client.attachments.show.assert_called_once_with(
            self.fake_attach_id)

    def test_attachment_get_client_exception(self):
        self.fake_client.attachments.show.side_effect = (
            cinder_exception.ClientException(code=1))
        self.assertRaises(
            cinder_exception.ClientException,
            self.volume_api.attachment_get,
            self.fake_client, self.fake_attach_id)

    def test_attachment_update(self):
        self.volume_api.attachment_update(self.fake_client,
                                          self.fake_attach_id,
                                          self.fake_connector)
        self.fake_client.attachments.update.assert_called_once_with(
            self.fake_attach_id, self.fake_connector)

    def test_attachment_update_with_connector_and_mountpoint(self):
        self.volume_api.attachment_update(
            self.fake_client, self.fake_attach_id, self.fake_connector,
            mountpoint='fake_mountpoint')
        self.fake_connector['mountpoint'] = 'fake_mountpoint'
        self.fake_client.attachments.update.assert_called_once_with(
            self.fake_attach_id, self.fake_connector)

    def test_attachment_update_client_exception(self):
        self.fake_client.attachments.update.side_effect = (
            cinder_exception.ClientException(code=1))
        self.assertRaises(
            cinder_exception.ClientException,
            self.volume_api.attachment_update,
            self.fake_client, self.fake_attach_id, self.fake_connector)

    def test_attachment_complete(self):
        self.volume_api.attachment_complete(self.fake_client,
                                            self.fake_attach_id)
        self.fake_client.attachments.complete.assert_called_once_with(
            self.fake_attach_id)

    def test_attachment_complete_client_exception(self):
        self.fake_client.attachments.complete.side_effect = (
            cinder_exception.ClientException(code=1))
        self.assertRaises(
            cinder_exception.ClientException,
            self.volume_api.attachment_complete,
            self.fake_client, self.fake_attach_id)

    def test_attachment_delete(self):
        self.volume_api.attachment_delete(self.fake_client,
                                          self.fake_attach_id)
        self.fake_client.attachments.delete.assert_called_once_with(
            self.fake_attach_id)

    def test_attachment_delete_client_exception(self):
        self.fake_client.attachments.delete.side_effect = (
            cinder_exception.ClientException(code=1))
        self.assertRaises(
            cinder_exception.ClientException,
            self.volume_api.attachment_delete,
            self.fake_client, self.fake_attach_id)

    def test_attachment_delete_retries(self):
        # Make delete fail two times and succeed on the third attempt.
        self.fake_client.attachments.delete.side_effect = [
            apiclient_exception.InternalServerError(),
            apiclient_exception.InternalServerError(),
            lambda aid: 'foo']

        # Make sure we get a clean result.
        self.assertIsNone(self.volume_api.attachment_delete(
            self.fake_client, self.fake_attach_id))

        # Assert that we called delete three times due to the retry
        # decorator.
        self.fake_client.attachments.delete.assert_has_calls([
            mock.call(self.fake_attach_id),
            mock.call(self.fake_attach_id),
            mock.call(self.fake_attach_id)])
