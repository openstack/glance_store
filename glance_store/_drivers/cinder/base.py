# Copyright 2023 Red Hat, Inc.
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

from oslo_utils import importutils

from os_brick.initiator import connector

NFS = 'nfs'
SCALEIO = "scaleio"

BASE = 'glance_store._drivers.cinder.base.BaseBrickConnectorInterface'

_connector_mapping = {
    NFS: 'glance_store._drivers.cinder.nfs.NfsBrickConnector',
    SCALEIO: 'glance_store._drivers.cinder.scaleio.ScaleIOBrickConnector',
}


def factory(*args, **kwargs):
    connection_info = kwargs.get('connection_info')
    protocol = connection_info['driver_volume_type']
    connector = _connector_mapping.get(protocol, BASE)
    conn_cls = importutils.import_class(connector)
    return conn_cls(*args, **kwargs)


class BaseBrickConnectorInterface(object):
    def __init__(self, *args, **kwargs):
        self.connection_info = kwargs.get('connection_info')
        self.root_helper = kwargs.get('root_helper')
        self.use_multipath = kwargs.get('use_multipath')
        self.conn = connector.InitiatorConnector.factory(
            self.connection_info['driver_volume_type'], self.root_helper,
            conn=self.connection_info, use_multipath=self.use_multipath)

    def connect_volume(self, volume):
        device = self.conn.connect_volume(self.connection_info)
        return device

    def disconnect_volume(self, device):
        # Bug #2004555: use force so there aren't any leftovers
        self.conn.disconnect_volume(self.connection_info, device, force=True)

    def extend_volume(self):
        self.conn.extend_volume(self.connection_info)

    def yield_path(self, volume, volume_path):
        """
        This method returns the volume file path.

        The reason for it's implementation is to fix Bug#2000584. More
        information is added in the ScaleIO connector which makes actual
        use of it's implementation.
        """
        return volume_path
