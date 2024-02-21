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

import sys
from unittest import mock

import ddt

from glance_store._drivers.cinder import base
from glance_store._drivers.cinder import scaleio
from glance_store.tests import base as test_base

sys.modules['glance_store.common.fs_mount'] = mock.Mock()
from glance_store._drivers.cinder import store as cinder # noqa
from glance_store._drivers.cinder import nfs # noqa


@ddt.ddt
class TestConnectorBase(test_base.StoreBaseTest):
    @ddt.data(
        ('iscsi', base.BaseBrickConnectorInterface),
        ('nfs', nfs.NfsBrickConnector),
        ('scaleio', scaleio.ScaleIOBrickConnector),
    )
    @ddt.unpack
    def test_factory(self, protocol, expected_class):
        connector_class = base.factory(
            connection_info={'driver_volume_type': protocol})
        self.assertIsInstance(connector_class, expected_class)


class TestBaseBrickConnectorInterface(test_base.StoreBaseTest):

    def get_connection_info(self):
        """Return iSCSI connection information"""
        return {
            'target_discovered': False,
            'target_portal': '0.0.0.0:3260',
            'target_iqn': 'iqn.2010-10.org.openstack:volume-fake-vol',
            'target_lun': 0,
            'volume_id': '007dedb8-ddc0-445c-88f1-d07acbe4efcb',
            'auth_method': 'CHAP',
            'auth_username': '2ttANgVaDRqxtMNK3hUj',
            'auth_password': 'fake-password',
            'encrypted': False,
            'qos_specs': None,
            'access_mode': 'rw',
            'cacheable': False,
            'driver_volume_type': 'iscsi',
            'attachment_id': '7f45b2fe-111a-42df-be3e-f02b312ad8ea'}

    def setUp(self, connection_info={}, **kwargs):
        super().setUp()
        self.connection_info = connection_info or self.get_connection_info()
        self.root_helper = 'fake_rootwrap'
        self.use_multipath = False
        self.properties = {
            'connection_info': self.connection_info,
            'root_helper': self.root_helper,
            'use_multipath': self.use_multipath}
        self.properties.update(kwargs)
        self.mock_object(base.connector.InitiatorConnector, 'factory')
        self.connector = base.factory(**self.properties)

    def mock_object(self, obj, attr_name, *args, **kwargs):
        """Use python mock to mock an object attribute

        Mocks the specified objects attribute with the given value.
        Automatically performs 'addCleanup' for the mock.
        """
        patcher = mock.patch.object(obj, attr_name, *args, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def test_connect_volume(self):
        if self.connection_info['driver_volume_type'] == 'nfs':
            self.skip('NFS tests have custom implementation of this method.')
        fake_vol = mock.MagicMock()
        fake_path = {'path': 'fake_dev_path'}
        self.mock_object(self.connector.conn, 'connect_volume',
                         return_value=fake_path)
        fake_dev_path = self.connector.connect_volume(fake_vol)
        self.connector.conn.connect_volume.assert_called_once_with(
            self.connector.connection_info)
        self.assertEqual(fake_path['path'], fake_dev_path['path'])

    def test_disconnect_volume(self):
        fake_device = 'fake_dev_path'
        self.mock_object(self.connector.conn, 'disconnect_volume')
        self.connector.disconnect_volume(fake_device)
        self.connector.conn.disconnect_volume.assert_called_once_with(
            self.connection_info, fake_device, force=True)

    def test_extend_volume(self):
        self.mock_object(self.connector.conn, 'extend_volume')
        self.connector.extend_volume()
        self.connector.conn.extend_volume.assert_called_once_with(
            self.connection_info)

    def test_yield_path(self):
        fake_vol = mock.MagicMock()
        fake_device = 'fake_dev_path'
        fake_dev_path = self.connector.yield_path(fake_vol, fake_device)
        self.assertEqual(fake_device, fake_dev_path)
