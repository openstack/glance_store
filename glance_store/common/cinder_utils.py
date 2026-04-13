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

import logging

from cinderclient.apiclient import exceptions as apiclient_exception
from cinderclient import exceptions as cinder_exception
from keystoneauth1 import exceptions as keystone_exc
from oslo_utils import excutils
import retrying

from glance_store import exceptions
from glance_store.i18n import _LE

LOG = logging.getLogger(__name__)


def handle_exceptions(method):
    """Transforms the exception for the volume but keeps its traceback intact.
    """
    def wrapper(self, ctx, volume_id, *args, **kwargs):
        try:
            res = method(self, ctx, volume_id, *args, **kwargs)
        except (keystone_exc.NotFound,
                cinder_exception.NotFound,
                cinder_exception.OverLimit) as e:
            raise exceptions.BackendException(str(e))
        return res
    return wrapper


def _retry_on_internal_server_error(e):
    if isinstance(e, apiclient_exception.InternalServerError):
        return True
    return False


def _retry_on_bad_request(e):
    if isinstance(e, cinder_exception.BadRequest):
        # Only retry on specific volume status errors
        error_msg = str(e).lower()
        expected_messages = (
            'status must be available or downloading to reserve',
            'status must be available or in-use or downloading to reserve',
        )
        # Check for either of the two expected error patterns
        for message in expected_messages:
            if message in error_msg:
                return True
    return False


class API(object):
    """API for interacting with the cinder."""

    def __init__(self, config=None):
        """Initialize the API with optional configuration.

        :param config: Configuration object containing retry parameters
        """
        self.config = config
        # Set retry parameter with defaults
        if config:
            self.attachment_create_retry_attempts = getattr(
                config, 'cinder_attachment_retry_attempts', 5)
        else:
            # Default value when no config is provided (24 seconds)
            self.attachment_create_retry_attempts = 5

    @handle_exceptions
    def create(self, client, size, name,
               volume_type=None, metadata=None):

        kwargs = dict(volume_type=volume_type,
                      metadata=metadata,
                      name=name)

        volume = client.volumes.create(size, **kwargs)
        return volume

    @handle_exceptions
    def get(self, client, volume_id):
        """Get the details about a volume given it's ID.

        :param client: cinderclient object
        :param volume_id: UUID of the volume to get
        """
        return client.volumes.get(volume_id)

    def delete(self, client, volume_id):
        client.volumes.delete(volume_id)

    @handle_exceptions
    def attachment_create(self, client, volume_id, connector=None,
                          mountpoint=None, mode=None):
        """Create a volume attachment. This requires microversion >= 3.54.

        The attachment_create call was introduced in microversion 3.27. We
        need 3.54 as minimum here as we need attachment_complete to finish the
        attaching process and it which was introduced in version 3.44 and
        we also pass the attach mode which was introduced in version 3.54.

        :param client: cinderclient object
        :param volume_id: UUID of the volume on which to create the attachment.
        :param connector: host connector dict; if None, the attachment will
            be 'reserved' but not yet attached.
        :param mountpoint: Optional mount device name for the attachment,
            e.g. "/dev/vdb". This is only used if a connector is provided.
        :param mode: The mode in which the attachment is made i.e.
            read only(ro) or read/write(rw)
        :returns: a dict created from the
            cinderclient.v3.attachments.VolumeAttachment object with a backward
            compatible connection_info dict
        """
        # Create a retry decorator with configurable retry attempts
        retry_decorator = retrying.retry(
            stop_max_attempt_number=self.attachment_create_retry_attempts,
            retry_on_exception=_retry_on_bad_request,
            wait_exponential_multiplier=1000,
            wait_exponential_max=10000
        )

        # This count is only used for logging purpose
        retry_attempts = 0

        @retry_decorator
        def _do_attachment_create():
            nonlocal retry_attempts
            retry_attempts += 1
            if connector and mountpoint and 'mountpoint' not in connector:
                connector['mountpoint'] = mountpoint

            try:
                attachment_ref = client.attachments.create(
                    volume_id, connector, mode=mode)
                return attachment_ref
            except cinder_exception.ClientException as ex:
                with excutils.save_and_reraise_exception():
                    # NOTE(whoami-rajat): While handling simultaneous
                    # requests, the volume can be in different states and we
                    # retry on attachment_create until the volume reaches a
                    # valid state for attachment. Hence, it is better to not
                    # log 400 cases as no action from users is needed in this
                    # case.
                    if getattr(ex, 'code', None) != 400:
                        LOG.error(_LE('Create attachment failed for volume '
                                      '%(volume_id)s. Error: %(msg)s '
                                      'Code: %(code)s'),
                                  {'volume_id': volume_id,
                                   'msg': str(ex),
                                   'code': getattr(ex, 'code', None)})

                    # Log DEBUG message for every retry attempt
                    if (retry_attempts < self.attachment_create_retry_attempts
                            and _retry_on_bad_request(ex)):
                        volume_state = '<unknown>'
                        error_msg = str(ex)
                        # NOTE(whoami-rajat): Doing a GET API call to cinder
                        # for logging the volume status would add overhead
                        # for simultaneous requests. The status already exists
                        # in the error message, we just need to extract it.
                        if 'current status is' in error_msg:
                            try:
                                # Example log:
                                # "... but the current status is reserved."
                                status_part = error_msg.split(
                                    'current status is')[1]
                                volume_state = (status_part.split('.')[0]
                                                .strip())
                            except (IndexError, AttributeError):
                                pass

                        # compute the wait time based on the values we passed
                        # when defining the retry decorator above
                        wait_time_s = min((2 ** (retry_attempts)), 10)

                        LOG.debug(
                            'Attachment create failed for volume '
                            '%(volume_id)s. Volume state: %(state)s. '
                            'Retrying in %(wait_time)d seconds.',
                            {'volume_id': volume_id,
                             'state': volume_state,
                             'wait_time': wait_time_s})

        return _do_attachment_create()

    @handle_exceptions
    def attachment_get(self, client, attachment_id):
        """Gets a volume attachment.

        :param client: cinderclient object
        :param attachment_id: UUID of the volume attachment to get.
        :returns: a dict created from the
            cinderclient.v3.attachments.VolumeAttachment object with a backward
            compatible connection_info dict
        """
        try:
            attachment_ref = client.attachments.show(
                attachment_id)
            return attachment_ref
        except cinder_exception.ClientException as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Show attachment failed for attachment '
                              '%(id)s. Error: %(msg)s Code: %(code)s'),
                          {'id': attachment_id,
                           'msg': str(ex),
                           'code': getattr(ex, 'code', None)})

    @handle_exceptions
    def attachment_update(self, client, attachment_id, connector,
                          mountpoint=None):
        """Updates the connector on the volume attachment. An attachment
        without a connector is considered reserved but not fully attached.

        :param client: cinderclient object
        :param attachment_id: UUID of the volume attachment to update.
        :param connector: host connector dict. This is required when updating
            a volume attachment. To terminate a connection, the volume
            attachment for that connection must be deleted.
        :param mountpoint: Optional mount device name for the attachment,
            e.g. "/dev/vdb". Theoretically this is optional per volume backend,
            but in practice it's normally required so it's best to always
            provide a value.
        :returns: a dict created from the
            cinderclient.v3.attachments.VolumeAttachment object with a backward
            compatible connection_info dict
        """
        if mountpoint and 'mountpoint' not in connector:
            connector['mountpoint'] = mountpoint

        try:
            attachment_ref = client.attachments.update(
                attachment_id, connector)
            return attachment_ref
        except cinder_exception.ClientException as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Update attachment failed for attachment '
                              '%(id)s. Error: %(msg)s Code: %(code)s'),
                          {'id': attachment_id,
                           'msg': str(ex),
                           'code': getattr(ex, 'code', None)})

    @handle_exceptions
    def attachment_complete(self, client, attachment_id):
        """Marks a volume attachment complete.

        This call should be used to inform Cinder that a volume attachment is
        fully connected on the host so Cinder can apply the necessary state
        changes to the volume info in its database.

        :param client: cinderclient object
        :param attachment_id: UUID of the volume attachment to update.
        """
        try:
            client.attachments.complete(attachment_id)
        except cinder_exception.ClientException as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Complete attachment failed for attachment '
                              '%(id)s. Error: %(msg)s Code: %(code)s'),
                          {'id': attachment_id,
                           'msg': str(ex),
                           'code': getattr(ex, 'code', None)})

    @handle_exceptions
    @retrying.retry(stop_max_attempt_number=5,
                    retry_on_exception=_retry_on_internal_server_error)
    def attachment_delete(self, client, attachment_id):
        try:
            client.attachments.delete(attachment_id)
        except cinder_exception.ClientException as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Delete attachment failed for attachment '
                              '%(id)s. Error: %(msg)s Code: %(code)s'),
                          {'id': attachment_id,
                           'msg': str(ex),
                           'code': getattr(ex, 'code', None)})

    @handle_exceptions
    def extend_volume(self, client, volume, new_size):
        """Extend volume

        :param client: cinderclient object
        :param volume: UUID of the volume to extend
        :param new_size: new size of the volume after extend
        """
        try:
            client.volumes.extend(volume, new_size)
        except cinder_exception.ClientException as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Extend volume failed for volume '
                              '%(id)s. Error: %(msg)s Code: %(code)s'),
                          {'id': volume.id,
                           'msg': str(ex),
                           'code': getattr(ex, 'code', None)})
