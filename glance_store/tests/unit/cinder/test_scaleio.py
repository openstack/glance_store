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
from unittest import mock

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
        super().setUp(connection_info=connection_info)

    def test_yield_path(self):
        fake_vol = mock.MagicMock(size=1)
        fake_device = io.BytesIO(b"fake binary data")
        fake_dev_path = self.connector.yield_path(fake_vol, fake_device)
        self.assertEqual(fake_device, fake_dev_path)
