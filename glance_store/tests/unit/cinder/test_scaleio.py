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

import io
import math
import time
from unittest import mock

from oslo_utils import units

from glance_store._drivers.cinder import scaleio
from glance_store import exceptions
from glance_store.tests.unit.cinder import test_base as test_base_connector


class TestScaleioBrickConnector(
        test_base_connector.TestBaseBrickConnectorInterface):

    def setUp(self):
        connection_info = {
            'scaleIO_volname': 'TZpPr43ISgmNSgpo0LP2uw==',
            'hostIP': None, 'serverIP': 'l4-pflex154gw',
            'serverPort': 443,
            'serverUsername': 'admin',
            'iopsLimit': None,
            'bandwidthLimit': None,
            'scaleIO_volume_id': '3b2f23b00000000d',
            'config_group': 'powerflex1',
            'failed_over': False,
            'discard': True,
            'qos_specs': None,
            'access_mode': 'rw',
            'encrypted': False,
            'cacheable': False,
            'driver_volume_type': 'scaleio',
            'attachment_id': '22914c3a-5818-4840-9188-2ac9833b9f7b'}
        self.scaleio_connector = scaleio.ScaleIOBrickConnector
        super().setUp(connection_info=connection_info)

    def test__get_device_size(self):
        fake_data = b"fake binary data"
        fake_len = int(math.ceil(float(len(fake_data)) / units.Gi))
        fake_file = io.BytesIO(fake_data)
        # Get current file pointer
        original_pos = fake_file.tell()
        dev_size = self.scaleio_connector._get_device_size(fake_file)
        self.assertEqual(fake_len, dev_size)
        # Verify that file pointer points to the original location
        self.assertEqual(original_pos, fake_file.tell())

    def test__get_device_size_exception(self):
        fake_data = b"fake binary data"
        fake_file = io.BytesIO(fake_data)
        # Get current file pointer
        original_pos = fake_file.tell()
        with mock.patch.object(
                math, 'ceil', side_effect=exceptions.BackendException):
            self.assertRaises(
                exceptions.BackendException,
                self.scaleio_connector._get_device_size, fake_file)
        # Verify that file pointer points to the original location
        self.assertEqual(original_pos, fake_file.tell())

    @mock.patch.object(time, 'sleep')
    def test__wait_resize_device_resized(self, mock_sleep):
        fake_vol = mock.MagicMock()
        fake_vol.size = 2
        fake_file = io.BytesIO(b"fake binary data")
        with mock.patch.object(
                self.scaleio_connector,
                '_get_device_size') as mock_get_dev_size:
            mock_get_dev_size.side_effect = [1, 2]
            self.scaleio_connector._wait_resize_device(
                fake_vol, fake_file)

    @mock.patch.object(time, 'sleep')
    def test__wait_resize_device_fails(self, mock_sleep):
        fake_vol = mock.MagicMock()
        fake_vol.size = 2
        fake_file = io.BytesIO(b"fake binary data")
        with mock.patch.object(
                self.scaleio_connector, '_get_device_size',
                return_value=1):
            self.assertRaises(
                exceptions.BackendException,
                self.scaleio_connector._wait_resize_device,
                fake_vol, fake_file)

    def test_yield_path(self):
        fake_vol = mock.MagicMock(size=1)
        fake_device = io.BytesIO(b"fake binary data")
        # Get current file pointer
        original_pos = fake_device.tell()
        fake_dev_path = self.connector.yield_path(fake_vol, fake_device)
        self.assertEqual(fake_device, fake_dev_path)
        # Verify that file pointer points to the original location
        self.assertEqual(original_pos, fake_device.tell())
