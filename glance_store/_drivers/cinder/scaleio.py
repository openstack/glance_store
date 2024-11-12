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

import logging
import math
import os
import time

from oslo_config import cfg
from oslo_utils import units

from glance_store._drivers.cinder import base
from glance_store import exceptions
from glance_store.i18n import _

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class ScaleIOBrickConnector(base.BaseBrickConnectorInterface):

    @staticmethod
    def _get_device_size(device_file):
        # os.fstat doesn't work with the block devices exported by
        # the ScaleIO/PowerFlex protocol and returns 0 as st_size
        # so we use the seek/tell logic.
        # Get the current position
        current_pos = device_file.tell()
        try:
            # Seek to the end of the file
            device_file.seek(0, os.SEEK_END)
            # Get the size of file (in bytes)
            device_size = device_file.tell()
            # Convert the bytes size into GB
            device_size = int(math.ceil(float(device_size) / units.Gi))
        finally:
            # Restore the file pointer to original position
            device_file.seek(current_pos, os.SEEK_SET)
        return device_size

    @staticmethod
    def _wait_resize_device(volume, device_file):
        timeout = 20
        max_recheck_wait = 10
        tries = 0
        elapsed = 0
        while ScaleIOBrickConnector._get_device_size(
                device_file) < volume.size:
            wait = min(0.5 * 2 ** tries, max_recheck_wait)
            time.sleep(wait)
            tries += 1
            elapsed += wait
            if elapsed >= timeout:
                msg = (_('Timeout while waiting while volume %(volume_id)s '
                         'to resize the device in %(tries)s tries.')
                       % {'volume_id': volume.id, 'tries': tries})
                LOG.error(msg)
                raise exceptions.BackendException(msg)

    def yield_path(self, volume, volume_path):
        """
        This method waits for the LUN size to match the volume size.

        This method is created to fix Bug#2000584 where NFS sparse volumes
        timeout waiting for the file size to match the volume.size field.
        The reason is that the volume is sparse and only takes up space of
        data which is written to it (similar to thin provisioned volumes).
        """
        # Sometimes the extended LUN on storage side takes time
        # to reflect in the device so we wait until the device
        # size is equal to the extended volume size.
        ScaleIOBrickConnector._wait_resize_device(volume, volume_path)
        return volume_path
