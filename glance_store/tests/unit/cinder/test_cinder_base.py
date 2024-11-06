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
import hashlib
import io
import os
from unittest import mock

import socket
import sys
import tempfile
import time
import uuid

from keystoneauth1 import exceptions as keystone_exc
from os_brick.initiator import connector
from oslo_concurrency import processutils
from oslo_utils.secretutils import md5
from oslo_utils import units

from glance_store.common import attachment_state_manager
from glance_store.common import cinder_utils
from glance_store import exceptions
from glance_store import location

sys.modules['glance_store.common.fs_mount'] = mock.Mock()
from glance_store._drivers.cinder import store as cinder # noqa
from glance_store._drivers.cinder import nfs # noqa


class TestCinderStoreBase(object):

    def test_get_cinderclient(self):
        cc = self.store.get_cinderclient(self.context)
        self.assertEqual('fake_token', cc.client.auth.token)
        self.assertEqual('http://foo/public_url', cc.client.auth.endpoint)

    def _get_cinderclient_with_user_overriden(self, group='glance_store',
                                              **kwargs):

        cinderclient_opts = {
            'cinder_store_user_name': 'test_user',
            'cinder_store_password': 'test_password',
            'cinder_store_project_name': 'test_project',
            'cinder_store_auth_address': 'test_address'}

        cinderclient_opts.update(kwargs)
        self.config(**cinderclient_opts, group=group)
        cc = self.store.get_cinderclient(self.context)
        return cc

    def _test_get_cinderclient_with_user_overriden(
            self, group='glance_store'):
        cc = self._get_cinderclient_with_user_overriden(
            group=group)
        self.assertEqual('test_project',
                         cc.client.session.auth.project_name)
        self.assertEqual('Default',
                         cc.client.session.auth.project_domain_name)

    def _test_get_cinderclient_with_user_overriden_and_region(
            self, group='glance_store'):
        cc = self._get_cinderclient_with_user_overriden(
            group=group, **{'cinder_os_region_name': 'test_region'})
        self.assertEqual('test_region', cc.client.region_name)

    def _test_get_cinderclient_with_api_insecure(
            self, group='glance_store'):
        self.config()
        with mock.patch.object(
            cinder.ksa_session, 'Session') as fake_session, \
            mock.patch.object(
                cinder.ksa_identity, 'V3Password') as fake_auth_method:
            fake_auth = fake_auth_method()
            self._get_cinderclient_with_user_overriden(
                group=group, **{'cinder_api_insecure': True})
            fake_session.assert_called_once_with(auth=fake_auth, verify=False)

    def _test_get_cinderclient_with_ca_certificates(
            self, group='glance_store'):
        fake_cert_path = 'fake_cert_path'
        with mock.patch.object(
            cinder.ksa_session, 'Session') as fake_session, \
            mock.patch.object(
                cinder.ksa_identity, 'V3Password') as fake_auth_method:
            fake_auth = fake_auth_method()
            self._get_cinderclient_with_user_overriden(
                group=group, **{'cinder_ca_certificates_file': fake_cert_path})
            fake_session.assert_called_once_with(
                auth=fake_auth, verify=fake_cert_path)

    def _test_get_cinderclient_cinder_endpoint_template(self,
                                                        group='glance_store'):
        fake_endpoint = 'http://cinder.openstack.example.com/v2/fake_project'
        self.config(cinder_endpoint_template=fake_endpoint, group=group)
        with mock.patch.object(
                cinder.ksa_token_endpoint, 'Token') as fake_token:
            self.store.get_cinderclient(self.context)
            fake_token.assert_called_once_with(endpoint=fake_endpoint,
                                               token=self.context.auth_token)

    def test_get_cinderclient_endpoint_exception(self):
        with mock.patch.object(cinder.ksa_session, 'Session'), \
            mock.patch.object(cinder.ksa_identity, 'V3Password'), \
            mock.patch.object(
                cinder.Store, 'is_user_overriden', return_value=False), \
            mock.patch.object(
                cinder.keystone_sc, 'ServiceCatalogV2') as service_catalog:
            service_catalog.side_effect = keystone_exc.EndpointNotFound
            self.assertRaises(
                exceptions.BadStoreConfiguration, self.store.get_cinderclient,
                self.context)

    def test__check_context(self):
        with mock.patch.object(cinder.Store, 'is_user_overriden',
                               return_value=True) as fake_overriden:
            self.store._check_context(self.context)
            fake_overriden.assert_called_once()

    def test__check_context_no_context(self):
        with mock.patch.object(
                cinder.Store, 'is_user_overriden', return_value=False):
            self.assertRaises(
                exceptions.BadStoreConfiguration, self.store._check_context,
                None)

    def test__check_context_no_service_catalog(self):
        with mock.patch.object(
                cinder.Store, 'is_user_overriden', return_value=False):
            fake_context = mock.MagicMock(service_catalog=None)
            self.assertRaises(
                exceptions.BadStoreConfiguration, self.store._check_context,
                fake_context)

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
                                 multiattach=False,
                                 update_attachment_error=None):
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
            fake_attachment_update = mock.MagicMock(
                id=fake_attachment_id,
                connection_info={'driver_volume_type': 'fake'})
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
                                  'getaddrinfo') as mock_get_host_ip, \
                mock.patch.object(cinder.strutils, 'mask_dict_password'):

            if update_attachment_error:
                attach_update.side_effect = update_attachment_error

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
                elif update_attachment_error:
                    self.assertRaises(type(update_attachment_error), do_open)
                else:
                    do_open()
                if update_attachment_error:
                    attach_delete.assert_called_once_with(
                        fake_client, fake_attachment_id)
                elif not (encrypted_nfs or qcow2_vol):
                    mock_conn.assert_called_once_with(
                        root_helper, fake_ip,
                        multipath_supported, enforce_multipath,
                        host=fake_host)
                    fake_connector.connect_volume.assert_called_once_with(
                        mock.ANY)
                    fake_connector.disconnect_volume.assert_called_once_with(
                        mock.ANY, fake_devinfo, force=True)
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

    def test_open_cinder_volume_update_attachment_error(self):
        err = Exception("update attachment fake error")
        self._test_open_cinder_volume('rb', 'ro', None,
                                      update_attachment_error=err)

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
        volume_file = io.BytesIO(expected_file_contents)
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

    def _test_cinder_volume_not_found(self, method_call, mock_method):
        fake_volume_uuid = str(uuid.uuid4())
        loc = mock.MagicMock(volume_id=fake_volume_uuid)
        mock_not_found = {mock_method: mock.MagicMock(
            side_effect=cinder.cinder_exception.NotFound(code=404))}
        fake_volumes = mock.MagicMock(**mock_not_found)

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(volumes=fake_volumes)
            self.assertRaises(exceptions.NotFound, method_call, loc,
                              context=self.context)

    def test_cinder_get_volume_not_found(self):
        self._test_cinder_volume_not_found(self.store.get, 'get')

    def test_cinder_get_size_volume_not_found(self):
        self._test_cinder_volume_not_found(self.store.get_size, 'get')

    def test_cinder_delete_volume_not_found(self):
        self._test_cinder_volume_not_found(self.store.delete, 'delete')

    def test_cinder_get_client_exception(self):
        fake_volume_uuid = str(uuid.uuid4())
        loc = mock.MagicMock(volume_id=fake_volume_uuid)

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc:
            mock_cc.side_effect = (
                cinder.cinder_exception.ClientException(code=500))
            self.assertRaises(exceptions.BackendException, self.store.get, loc,
                              context=self.context)

    def _test_cinder_get_size(self, is_multi_store=False):
        fake_client = mock.MagicMock(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        fake_volume = mock.MagicMock(size=5, metadata={})
        fake_volumes = mock.MagicMock(get=lambda fake_volume_uuid: fake_volume)

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

    def test_cinder_get_size_generic_exception(self):
        fake_volume_uuid = str(uuid.uuid4())
        loc = mock.MagicMock(volume_id=fake_volume_uuid)
        fake_volumes = mock.MagicMock(
            get=mock.MagicMock(side_effect=Exception()))

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(volumes=fake_volumes)
            image_size = self.store.get_size(loc, context=self.context)
            self.assertEqual(0, image_size)

    def _test_cinder_add(self, fake_volume, volume_file, size_kb=5,
                         verifier=None, backend='glance_store',
                         is_multi_store=False):
        expected_image_id = str(uuid.uuid4())
        expected_size = size_kb * units.Ki
        expected_file_contents = b"*" * expected_size
        image_file = io.BytesIO(expected_file_contents)
        expected_checksum = md5(expected_file_contents,
                                usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()

        expected_location = 'cinder://%s' % fake_volume.id
        if is_multi_store:
            # Default backend is 'glance_store' for single store but in case
            # of multi store, if the backend option is not passed, we should
            # assign it to the default i.e. 'cinder1'
            if backend == 'glance_store':
                backend = 'cinder1'
            expected_location = 'cinder://%s/%s' % (backend, fake_volume.id)
        self.config(cinder_volume_type='some_type', group=backend)

        fake_client = mock.MagicMock(auth_token=None, management_url=None)
        fake_volume.manager.get.return_value = fake_volume
        fake_volumes = mock.MagicMock(create=mock.Mock(
            return_value=fake_volume))

        @contextlib.contextmanager
        def fake_open(client, volume, mode):
            self.assertEqual('wb', mode)
            yield volume_file

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume',
                                  side_effect=fake_open):
            mock_cc.return_value = mock.MagicMock(client=fake_client,
                                                  volumes=fake_volumes)
            loc, size, checksum, multihash, metadata = self.store.add(
                expected_image_id, image_file, expected_size, self.hash_algo,
                self.context, verifier)
            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_size, size)
            self.assertEqual(expected_checksum, checksum)
            self.assertEqual(expected_multihash, multihash)
            fake_volumes.create.assert_called_once_with(
                1,
                name='image-%s' % expected_image_id,
                metadata={'image_owner': self.context.project_id,
                          'glance_image_id': expected_image_id,
                          'image_size': str(expected_size)},
                volume_type='some_type')
            if is_multi_store:
                self.assertEqual(backend, metadata["store"])

    def test_cinder_add_volume_not_found(self):
        image_file = mock.MagicMock()
        fake_image_id = str(uuid.uuid4())
        expected_size = 0
        fake_volumes = mock.MagicMock(create=mock.MagicMock(
            side_effect=cinder.cinder_exception.NotFound(code=404)))

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc:
            mock_cc.return_value = mock.MagicMock(volumes=fake_volumes)
            self.assertRaises(
                exceptions.BackendException, self.store.add,
                fake_image_id, image_file, expected_size, self.hash_algo,
                self.context, None)

    def _test_cinder_add_extend(self, is_multi_store=False, online=False):

        expected_volume_size = 2 * units.Gi
        expected_multihash = 'fake_hash'

        fakebuffer = mock.MagicMock()

        # CPython implementation detail: __len__ cannot return > sys.maxsize,
        # which on a 32-bit system is 2*units.Gi - 1
        # https://docs.python.org/3/reference/datamodel.html#object.__len__
        fakebuffer.__len__.return_value = int(expected_volume_size / 2)

        def get_fake_hash(type, secure=False):
            if type == 'md5':
                return mock.MagicMock(hexdigest=lambda: expected_checksum)
            else:
                return mock.MagicMock(hexdigest=lambda: expected_multihash)

        expected_image_id = str(uuid.uuid4())
        expected_volume_id = str(uuid.uuid4())
        expected_size = 0
        image_file = mock.MagicMock(
            read=mock.MagicMock(side_effect=[fakebuffer, fakebuffer, None]))
        fake_volume = mock.MagicMock(id=expected_volume_id, status='available',
                                     size=1)
        expected_checksum = 'fake_checksum'
        verifier = None
        backend = 'glance_store'

        expected_location = 'cinder://%s' % fake_volume.id
        if is_multi_store:
            # Default backend is 'glance_store' for single store but in case
            # of multi store, if the backend option is not passed, we should
            # assign it to the default i.e. 'cinder1'
            backend = 'cinder1'
            expected_location = 'cinder://%s/%s' % (backend, fake_volume.id)
        self.config(cinder_volume_type='some_type', group=backend)
        if online:
            self.config(cinder_do_extend_attached=True, group=backend)
            fake_connector = mock.MagicMock()
            fake_vol_connector_map = {expected_volume_id: fake_connector}
            self.store.volume_connector_map = fake_vol_connector_map

        fake_client = mock.MagicMock(auth_token=None, management_url=None)
        fake_volume.manager.get.return_value = fake_volume
        fake_volumes = mock.MagicMock(create=mock.Mock(
            return_value=fake_volume))

        @contextlib.contextmanager
        def fake_open(client, volume, mode):
            self.assertEqual('wb', mode)
            yield mock.MagicMock()

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume',
                                  side_effect=fake_open), \
                mock.patch.object(cinder.utils, 'get_hasher') as fake_hasher, \
                mock.patch.object(cinder.Store, '_wait_volume_status',
                                  return_value=fake_volume) as mock_wait, \
                mock.patch.object(cinder_utils.API,
                                  'extend_volume') as extend_vol:
            mock_cc_return_val = mock.MagicMock(client=fake_client,
                                                volumes=fake_volumes)
            mock_cc.return_value = mock_cc_return_val

            fake_hasher.side_effect = get_fake_hash
            loc, size, checksum, multihash, metadata = self.store.add(
                expected_image_id, image_file, expected_size, self.hash_algo,
                self.context, verifier)
            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_volume_size, size)
            self.assertEqual(expected_checksum, checksum)
            self.assertEqual(expected_multihash, multihash)
            fake_volumes.create.assert_called_once_with(
                1,
                name='image-%s' % expected_image_id,
                metadata={'image_owner': self.context.project_id,
                          'glance_image_id': expected_image_id,
                          'image_size': str(expected_volume_size)},
                volume_type='some_type')
            if is_multi_store:
                self.assertEqual(backend, metadata["store"])
            if online:
                extend_vol.assert_called_once_with(
                    mock_cc_return_val, fake_volume,
                    expected_volume_size // units.Gi)
                mock_wait.assert_has_calls(
                    [mock.call(fake_volume, 'creating', 'available'),
                     mock.call(fake_volume, 'extending', 'in-use')])
            else:
                fake_volume.extend.assert_called_once_with(
                    fake_volume, expected_volume_size // units.Gi)
                mock_wait.assert_has_calls(
                    [mock.call(fake_volume, 'creating', 'available'),
                     mock.call(fake_volume, 'extending', 'available')])

    def test_cinder_add_extend_storage_full(self):

        expected_volume_size = 2 * units.Gi

        fakebuffer = mock.MagicMock()

        # CPython implementation detail: __len__ cannot return > sys.maxsize,
        # which on a 32-bit system is 2*units.Gi - 1
        # https://docs.python.org/3/reference/datamodel.html#object.__len__
        fakebuffer.__len__.return_value = int(expected_volume_size / 2)

        expected_image_id = str(uuid.uuid4())
        expected_volume_id = str(uuid.uuid4())
        expected_size = 0
        image_file = mock.MagicMock(
            read=mock.MagicMock(side_effect=[fakebuffer, fakebuffer, None]))
        fake_volume = mock.MagicMock(id=expected_volume_id, status='available',
                                     size=1)
        verifier = None

        fake_client = mock.MagicMock()
        fake_volume.manager.get.return_value = fake_volume
        fake_volumes = mock.MagicMock(create=mock.Mock(
            return_value=fake_volume))

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume'), \
                mock.patch.object(cinder.utils, 'get_hasher'), \
                mock.patch.object(
                    cinder.Store, '_wait_volume_status') as mock_wait:

            mock_cc.return_value = mock.MagicMock(client=fake_client,
                                                  volumes=fake_volumes)

            mock_wait.side_effect = [fake_volume, exceptions.BackendException]
            self.assertRaises(
                exceptions.StorageFull, self.store.add, expected_image_id,
                image_file, expected_size, self.hash_algo, self.context,
                verifier)

    def test_cinder_add_extend_volume_delete_exception(self):

        expected_volume_size = 2 * units.Gi

        fakebuffer = mock.MagicMock()

        # CPython implementation detail: __len__ cannot return > sys.maxsize,
        # which on a 32-bit system is 2*units.Gi - 1
        # https://docs.python.org/3/reference/datamodel.html#object.__len__
        fakebuffer.__len__.return_value = int(expected_volume_size / 2)

        expected_image_id = str(uuid.uuid4())
        expected_volume_id = str(uuid.uuid4())
        expected_size = 0
        image_file = mock.MagicMock(
            read=mock.MagicMock(side_effect=[fakebuffer, fakebuffer, None]))
        fake_volume = mock.MagicMock(
            id=expected_volume_id, status='available', size=1,
            delete=mock.MagicMock(side_effect=Exception()))

        fake_client = mock.MagicMock()
        fake_volume.manager.get.return_value = fake_volume
        fake_volumes = mock.MagicMock(create=mock.Mock(
            return_value=fake_volume))
        verifier = None

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume'), \
                mock.patch.object(cinder.utils, 'get_hasher'), \
                mock.patch.object(
                    cinder.Store, '_wait_volume_status') as mock_wait:

            mock_cc.return_value = mock.MagicMock(client=fake_client,
                                                  volumes=fake_volumes)

            mock_wait.side_effect = [fake_volume, exceptions.BackendException]
            self.assertRaises(
                exceptions.StorageFull, self.store.add, expected_image_id,
                image_file, expected_size, self.hash_algo, self.context,
                verifier)
            fake_volume.delete.assert_called_once()

    def _test_cinder_delete(self, is_multi_store=False):
        fake_client = mock.MagicMock(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        fake_volumes = mock.MagicMock(delete=mock.Mock())

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(client=fake_client,
                                                    volumes=fake_volumes)

            loc = self._get_uri_loc(fake_volume_uuid,
                                    is_multi_store=is_multi_store)

            self.store.delete(loc, context=self.context)
            fake_volumes.delete.assert_called_once_with(fake_volume_uuid)

    def test_cinder_delete_client_exception(self):
        fake_volume_uuid = str(uuid.uuid4())
        loc = mock.MagicMock(volume_id=fake_volume_uuid)
        fake_volumes = mock.MagicMock(delete=mock.MagicMock(
            side_effect=cinder.cinder_exception.ClientException(code=500)))

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(volumes=fake_volumes)
            self.assertRaises(exceptions.BackendException, self.store.delete,
                              loc, context=self.context)

    def test_process_specs(self):
        self.location.process_specs()
        self.assertEqual('cinder', self.location.scheme)
        self.assertEqual(self.volume_id, self.location.volume_id)

    def _test_get_uri(self, expected_uri):
        uri = self.location.get_uri()
        self.assertEqual(expected_uri, uri)

    def _test_parse_uri_invalid(self, uri):
        self.assertRaises(
            exceptions.BadStoreUri, self.location.parse_uri, uri)

    def _test_get_root_helper(self, group='glance_store'):
        fake_rootwrap = 'fake_rootwrap'
        expected = 'sudo glance-rootwrap %s' % fake_rootwrap
        self.config(rootwrap_config=fake_rootwrap, group=group)
        res = self.store.get_root_helper()
        self.assertEqual(expected, res)

    def test_get_hash_str(self):
        nfs_conn = nfs.NfsBrickConnector()
        test_str = 'test_str'
        with mock.patch.object(nfs.hashlib, 'sha256') as fake_hashlib:
            nfs_conn.get_hash_str(test_str)
            test_str = test_str.encode('utf-8')
            fake_hashlib.assert_called_once_with(test_str)

    def test__get_mount_path(self):
        nfs_conn = nfs.NfsBrickConnector(mountpoint_base='fake_mount_path')
        fake_hex = 'fake_hex_digest'
        fake_share = 'fake_share'
        fake_path = 'fake_mount_path'
        expected_path = os.path.join(fake_path, fake_hex)
        with mock.patch.object(
                nfs.NfsBrickConnector, 'get_hash_str') as fake_hash:
            fake_hash.return_value = fake_hex
            res = nfs_conn._get_mount_path(fake_share, fake_path)
            self.assertEqual(expected_path, res)

    def test__get_host_ip_v6(self):
        fake_ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370'
        fake_socket_return = [[0, 1, 2, 3, [fake_ipv6]]]
        with mock.patch.object(cinder.socket, 'getaddrinfo') as fake_socket:
            fake_socket.return_value = fake_socket_return
            res = self.store._get_host_ip('fake_host')
            self.assertEqual(fake_ipv6, res)

    def test__get_host_ip_v4(self):
        fake_ip = '127.0.0.1'
        fake_socket_return = [[0, 1, 2, 3, [fake_ip]]]
        with mock.patch.object(cinder.socket, 'getaddrinfo') as fake_socket:
            fake_socket.side_effect = [socket.gaierror, fake_socket_return]
            res = self.store._get_host_ip('fake_host')
            self.assertEqual(fake_ip, res)
