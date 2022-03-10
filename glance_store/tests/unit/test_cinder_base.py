# Copyright 2022 RedHat Inc.
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

import contextlib
import os
from unittest import mock

import six
import socket
import sys
import tempfile
import time
import uuid

from os_brick.initiator import connector
from oslo_concurrency import processutils
from oslo_utils import units

from glance_store.common import attachment_state_manager
from glance_store.common import cinder_utils
from glance_store import exceptions
from glance_store import location

sys.modules['glance_store.common.fs_mount'] = mock.Mock()
from glance_store._drivers import cinder # noqa


class TestCinderStoreBase(object):

    def test_get_cinderclient(self):
        cc = self.store.get_cinderclient(self.context)
        self.assertEqual('fake_token', cc.client.auth.token)
        self.assertEqual('http://foo/public_url', cc.client.auth.endpoint)

    def test_temporary_chown(self):
        fake_stat = mock.MagicMock(st_uid=1)

        with mock.patch.object(os, 'stat', return_value=fake_stat), \
                mock.patch.object(os, 'getuid', return_value=2), \
                mock.patch.object(processutils, 'execute') as mock_execute, \
                mock.patch.object(cinder.Store, 'get_root_helper',
                                  return_value='sudo'):
            with self.store.temporary_chown('test'):
                pass
            expected_calls = [mock.call('chown', 2, 'test', run_as_root=True,
                                        root_helper='sudo'),
                              mock.call('chown', 1, 'test', run_as_root=True,
                                        root_helper='sudo')]
            self.assertEqual(expected_calls, mock_execute.call_args_list)

    @mock.patch.object(time, 'sleep')
    def test_wait_volume_status(self, mock_sleep):
        fake_manager = mock.MagicMock(get=mock.Mock())
        volume_available = mock.MagicMock(manager=fake_manager,
                                          id='fake-id',
                                          status='available')
        volume_in_use = mock.MagicMock(manager=fake_manager,
                                       id='fake-id',
                                       status='in-use')
        fake_manager.get.side_effect = [volume_available, volume_in_use]
        self.assertEqual(volume_in_use,
                         self.store._wait_volume_status(
                             volume_available, 'available', 'in-use'))
        fake_manager.get.assert_called_with('fake-id')
        mock_sleep.assert_called_once_with(0.5)

    @mock.patch.object(time, 'sleep')
    def test_wait_volume_status_unexpected(self, mock_sleep):
        fake_manager = mock.MagicMock(get=mock.Mock())
        volume_available = mock.MagicMock(manager=fake_manager,
                                          id='fake-id',
                                          status='error')
        fake_manager.get.return_value = volume_available
        self.assertRaises(exceptions.BackendException,
                          self.store._wait_volume_status,
                          volume_available, 'available', 'in-use')
        fake_manager.get.assert_called_with('fake-id')

    @mock.patch.object(time, 'sleep')
    def test_wait_volume_status_timeout(self, mock_sleep):
        fake_manager = mock.MagicMock(get=mock.Mock())
        volume_available = mock.MagicMock(manager=fake_manager,
                                          id='fake-id',
                                          status='available')
        fake_manager.get.return_value = volume_available
        self.assertRaises(exceptions.BackendException,
                          self.store._wait_volume_status,
                          volume_available, 'available', 'in-use')
        fake_manager.get.assert_called_with('fake-id')

    def _test_open_cinder_volume(self, open_mode, attach_mode, error,
                                 multipath_supported=False,
                                 enforce_multipath=False,
                                 encrypted_nfs=False, qcow2_vol=False,
                                 multiattach=False):
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()), status='available',
                                     multiattach=multiattach)
        fake_volume.manager.get.return_value = fake_volume
        fake_attachment_id = str(uuid.uuid4())
        fake_attachment_create = {'id': fake_attachment_id}
        if encrypted_nfs or qcow2_vol:
            fake_attachment_update = mock.MagicMock(
                id=fake_attachment_id,
                connection_info={'driver_volume_type': 'nfs'})
        else:
            fake_attachment_update = mock.MagicMock(id=fake_attachment_id)
        fake_conn_info = mock.MagicMock(connector={})
        fake_volumes = mock.MagicMock(get=lambda id: fake_volume)
        fake_client = mock.MagicMock(volumes=fake_volumes)
        _, fake_dev_path = tempfile.mkstemp(dir=self.test_dir)
        fake_devinfo = {'path': fake_dev_path}
        fake_connector = mock.MagicMock(
            connect_volume=mock.Mock(return_value=fake_devinfo),
            disconnect_volume=mock.Mock())

        @contextlib.contextmanager
        def fake_chown(path):
            yield

        def do_open():
            if multiattach:
                with mock.patch.object(
                        attachment_state_manager._AttachmentStateManager,
                        'get_state') as mock_get_state:
                    mock_get_state.return_value.__enter__.return_value = (
                        attachment_state_manager._AttachmentState())
                    with self.store._open_cinder_volume(
                            fake_client, fake_volume, open_mode):
                        pass
            else:
                with self.store._open_cinder_volume(
                        fake_client, fake_volume, open_mode):
                    if error:
                        raise error

        def fake_factory(protocol, root_helper, **kwargs):
            return fake_connector

        root_helper = "sudo glance-rootwrap /etc/glance/rootwrap.conf"
        with mock.patch.object(cinder.Store,
                               '_wait_volume_status',
                               return_value=fake_volume), \
                mock.patch.object(cinder.Store, 'temporary_chown',
                                  side_effect=fake_chown), \
                mock.patch.object(cinder.Store, 'get_root_helper',
                                  return_value=root_helper), \
                mock.patch.object(connector.InitiatorConnector, 'factory',
                                  side_effect=fake_factory
                                  ) as fake_conn_obj, \
                mock.patch.object(cinder_utils.API,
                                  'attachment_create',
                                  return_value=fake_attachment_create
                                  ) as attach_create, \
                mock.patch.object(cinder_utils.API,
                                  'attachment_update',
                                  return_value=fake_attachment_update
                                  ) as attach_update, \
                mock.patch.object(cinder_utils.API,
                                  'attachment_delete') as attach_delete, \
                mock.patch.object(cinder_utils.API,
                                  'attachment_get') as attach_get, \
                mock.patch.object(cinder_utils.API,
                                  'attachment_complete') as attach_complete, \
                mock.patch.object(socket,
                                  'gethostname') as mock_get_host, \
                mock.patch.object(socket,
                                  'getaddrinfo') as mock_get_host_ip:

            fake_host = 'fake_host'
            fake_addr_info = [[0, 1, 2, 3, ['127.0.0.1']]]
            fake_ip = fake_addr_info[0][4][0]
            mock_get_host.return_value = fake_host
            mock_get_host_ip.return_value = fake_addr_info

            with mock.patch.object(connector,
                                   'get_connector_properties',
                                   return_value=fake_conn_info) as mock_conn:
                if error:
                    self.assertRaises(error, do_open)
                elif encrypted_nfs or qcow2_vol:
                    fake_volume.encrypted = False
                    if encrypted_nfs:
                        fake_volume.encrypted = True
                    elif qcow2_vol:
                        attach_get.return_value = mock.MagicMock(
                            connection_info={'format': 'qcow2'})
                    try:
                        with self.store._open_cinder_volume(
                                fake_client, fake_volume, open_mode):
                            pass
                    except exceptions.BackendException:
                        attach_delete.assert_called_once_with(
                            fake_client, fake_attachment_id)
                else:
                    do_open()
                if not (encrypted_nfs or qcow2_vol):
                    mock_conn.assert_called_once_with(
                        root_helper, fake_ip,
                        multipath_supported, enforce_multipath,
                        host=fake_host)
                    fake_connector.connect_volume.assert_called_once_with(
                        mock.ANY)
                    fake_connector.disconnect_volume.assert_called_once_with(
                        mock.ANY, fake_devinfo)
                    fake_conn_obj.assert_called_once_with(
                        mock.ANY, root_helper, conn=mock.ANY,
                        use_multipath=multipath_supported)
                    attach_create.assert_called_once_with(
                        fake_client, fake_volume.id, mode=attach_mode)
                    attach_update.assert_called_once_with(
                        fake_client, fake_attachment_id,
                        fake_conn_info, mountpoint='glance_store')
                    attach_complete.assert_called_once_with(
                        fake_client, fake_attachment_id)
                    attach_delete.assert_called_once_with(fake_client,
                                                          fake_attachment_id)
                else:
                    mock_conn.assert_called_once_with(
                        root_helper, fake_ip,
                        multipath_supported, enforce_multipath,
                        host=fake_host)
                    fake_connector.connect_volume.assert_not_called()
                    fake_connector.disconnect_volume.assert_not_called()
                    fake_conn_obj.assert_called_once_with(
                        mock.ANY, root_helper, conn=mock.ANY,
                        use_multipath=multipath_supported)
                    attach_create.assert_called_once_with(
                        fake_client, fake_volume.id, mode=attach_mode)
                    attach_update.assert_called_once_with(
                        fake_client, fake_attachment_id,
                        fake_conn_info, mountpoint='glance_store')
                    attach_delete.assert_called_once_with(
                        fake_client, fake_attachment_id)

    def test_open_cinder_volume_rw(self):
        self._test_open_cinder_volume('wb', 'rw', None)

    def test_open_cinder_volume_ro(self):
        self._test_open_cinder_volume('rb', 'ro', None)

    def test_open_cinder_volume_error(self):
        self._test_open_cinder_volume('wb', 'rw', IOError)

    def test_open_cinder_volume_nfs_encrypted(self):
        self._test_open_cinder_volume('rb', 'ro', None, encrypted_nfs=True)

    def test_open_cinder_volume_nfs_qcow2_volume(self):
        self._test_open_cinder_volume('rb', 'ro', None, qcow2_vol=True)

    def test_open_cinder_volume_multiattach_volume(self):
        self._test_open_cinder_volume('rb', 'ro', None, multiattach=True)

    def _fake_volume_type_check(self, name):
        if name != 'some_type':
            raise cinder.cinder_exception.NotFound(code=404)

    def _test_configure_add_valid_type(self):

        with mock.patch.object(self.store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(
                volume_types=mock.MagicMock(
                    find=self._fake_volume_type_check))
            # If volume type exists, no exception is raised
            self.store.configure_add()

    def _test_configure_add_invalid_type(self):

        with mock.patch.object(self.store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(
                volume_types=mock.MagicMock(
                    find=self._fake_volume_type_check))
            with mock.patch.object(cinder, 'LOG') as mock_log:
                self.store.configure_add()
                mock_log.warning.assert_called_with(
                    "Invalid `cinder_volume_type some_random_type`")

    def _get_uri_loc(self, fake_volume_uuid, is_multi_store=False):
        if is_multi_store:
            uri = "cinder://cinder1/%s" % fake_volume_uuid
            loc = location.get_location_from_uri_and_backend(
                uri, "cinder1", conf=self.conf)
        else:
            uri = "cinder://%s" % fake_volume_uuid
            loc = location.get_location_from_uri(uri, conf=self.conf)

        return loc

    def _test_cinder_get(self, is_multi_store=False):
        expected_size = 5 * units.Ki
        expected_file_contents = b"*" * expected_size
        volume_file = six.BytesIO(expected_file_contents)
        fake_client = mock.MagicMock(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        fake_volume = mock.MagicMock(id=fake_volume_uuid,
                                     metadata={'image_size': expected_size},
                                     status='available')
        fake_volume.manager.get.return_value = fake_volume
        fake_volumes = mock.MagicMock(get=lambda id: fake_volume)

        @contextlib.contextmanager
        def fake_open(client, volume, mode):
            self.assertEqual('rb', mode)
            yield volume_file

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume',
                                  side_effect=fake_open):
            mock_cc.return_value = mock.MagicMock(client=fake_client,
                                                  volumes=fake_volumes)

            loc = self._get_uri_loc(fake_volume_uuid,
                                    is_multi_store=is_multi_store)

            (image_file, image_size) = self.store.get(loc,
                                                      context=self.context)

            expected_num_chunks = 2
            data = b""
            num_chunks = 0

            for chunk in image_file:
                num_chunks += 1
                data += chunk
            self.assertEqual(expected_num_chunks, num_chunks)
            self.assertEqual(expected_file_contents, data)

    def _test_cinder_get_size(self, is_multi_store=False):
        fake_client = mock.MagicMock(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        fake_volume = mock.MagicMock(size=5, metadata={})
        fake_volumes = {fake_volume_uuid: fake_volume}

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(client=fake_client,
                                                    volumes=fake_volumes)

            loc = self._get_uri_loc(fake_volume_uuid,
                                    is_multi_store=is_multi_store)

            image_size = self.store.get_size(loc, context=self.context)
            self.assertEqual(fake_volume.size * units.Gi, image_size)

    def _test_cinder_get_size_with_metadata(self, is_multi_store=False):
        fake_client = mock.MagicMock(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        expected_image_size = 4500 * units.Mi
        fake_volume = mock.MagicMock(
            size=5, metadata={'image_size': expected_image_size})
        fake_volumes = {fake_volume_uuid: fake_volume}

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(client=fake_client,
                                                    volumes=fake_volumes)

            loc = self._get_uri_loc(fake_volume_uuid,
                                    is_multi_store=is_multi_store)

            image_size = self.store.get_size(loc, context=self.context)
            self.assertEqual(expected_image_size, image_size)
