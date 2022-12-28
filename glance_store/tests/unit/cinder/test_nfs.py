# Copyright 2023 RedHat Inc.
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

import os
import sys
from unittest import mock

import ddt

from glance_store import exceptions
from glance_store.tests.unit.cinder import test_base as test_base_connector

sys.modules['glance_store.common.fs_mount'] = mock.Mock()
from glance_store._drivers.cinder import store as cinder # noqa
from glance_store._drivers.cinder import nfs # noqa


@ddt.ddt
class TestNfsBrickConnector(
        test_base_connector.TestBaseBrickConnectorInterface):

    def setUp(self):
        self.connection_info = {
            'export': 'localhost:/srv/fake-nfs-path',
            'name': 'volume-1fa96ca8-9e07-4dad-a0ed-990c6e86b938',
            'options': None,
            'format': 'raw',
            'qos_specs': None,
            'access_mode': 'rw',
            'encrypted': False,
            'cacheable': False,
            'driver_volume_type': 'nfs',
            'mount_point_base': '/opt/stack/data/cinder/mnt',
            'attachment_id': '7eb574ce-f32d-4173-a68b-870ead29fd84'}
        fake_attachment = mock.MagicMock(id='fake_attachment_uuid')
        self.mountpath = 'fake_mount_path'
        super().setUp(connection_info=self.connection_info,
                      attachment_obj=fake_attachment,
                      mountpoint_base=self.mountpath)

    @ddt.data(
        (False, 'raw'),
        (False, 'qcow2'),
        (True, 'raw'),
        (True, 'qcow2'))
    @ddt.unpack
    def test_connect_volume(self, encrypted, file_format):
        fake_vol = mock.MagicMock(id='fake_vol_uuid', encrypted=encrypted)
        fake_attachment = mock.MagicMock(
            id='fake_attachment_uuid',
            connection_info={'format': file_format})
        self.mock_object(self.connector.volume_api, 'attachment_get',
                         return_value=fake_attachment)
        if encrypted or file_format == 'qcow2':
            self.assertRaises(exceptions.BackendException,
                              self.connector.connect_volume,
                              fake_vol)
        else:
            fake_hash = 'fake_hash'
            fake_path = {'path': os.path.join(
                self.mountpath, fake_hash, self.connection_info['name'])}
            self.mock_object(nfs.NfsBrickConnector, 'get_hash_str',
                             return_value=fake_hash)
            fake_dev_path = self.connector.connect_volume(fake_vol)
            nfs.mount.mount.assert_called_once_with(
                'nfs', self.connection_info['export'],
                self.connection_info['name'],
                os.path.join(self.mountpath, fake_hash),
                self.connector.host, self.connector.root_helper,
                self.connection_info['options'])
            self.assertEqual(fake_path['path'], fake_dev_path['path'])

    def test_disconnect_volume(self):
        fake_hash = 'fake_hash'
        fake_path = {'path': os.path.join(
            self.mountpath, fake_hash, self.connection_info['name'])}
        mount_path, vol_name = fake_path['path'].rsplit('/', 1)
        self.connector.disconnect_volume(fake_path)
        nfs.mount.umount.assert_called_once_with(
            vol_name, mount_path, self.connector.host,
            self.connector.root_helper)

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError, self.connector.extend_volume)
