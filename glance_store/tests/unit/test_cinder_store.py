# Copyright 2013 OpenStack Foundation
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
import errno
import hashlib
import mock
import os
import six
import socket
import tempfile
import time
import uuid

from cinderclient.v2 import client as cinderclient
from os_brick.initiator import connector
from oslo_concurrency import processutils
from oslo_utils import units

from glance_store._drivers import cinder
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities


class FakeObject(object):
    def __init__(self, **kwargs):
        for name, value in kwargs.items():
            setattr(self, name, value)


class TestCinderStore(base.StoreBaseTest,
                      test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        super(TestCinderStore, self).setUp()
        self.store = cinder.Store(self.conf)
        self.store.configure()
        self.register_store_schemes(self.store, 'cinder')
        self.store.READ_CHUNKSIZE = 4096
        self.store.WRITE_CHUNKSIZE = 4096

        fake_sc = [{u'endpoints': [{u'publicURL': u'http://foo/public_url'}],
                    u'endpoints_links': [],
                    u'name': u'cinder',
                    u'type': u'volumev2'}]
        self.context = FakeObject(service_catalog=fake_sc,
                                  user='fake_user',
                                  auth_token='fake_token',
                                  tenant='fake_tenant')
        self.hash_algo = 'sha256'

    def test_get_cinderclient(self):
        cc = cinder.get_cinderclient(self.conf, self.context)
        self.assertEqual('fake_token', cc.client.auth_token)
        self.assertEqual('http://foo/public_url', cc.client.management_url)

    def test_get_cinderclient_with_user_overriden(self):
        self.config(cinder_store_user_name='test_user')
        self.config(cinder_store_password='test_password')
        self.config(cinder_store_project_name='test_project')
        self.config(cinder_store_auth_address='test_address')
        cc = cinder.get_cinderclient(self.conf, self.context)
        self.assertIsNone(cc.client.auth_token)
        self.assertEqual('test_address', cc.client.management_url)

    def test_get_cinderclient_with_user_overriden_and_region(self):
        self.config(cinder_os_region_name='test_region')
        fake_client = FakeObject(client=FakeObject(auth_token=None))
        with mock.patch.object(cinderclient, 'Client',
                               return_value=fake_client) as mock_client:
            self.test_get_cinderclient_with_user_overriden()
            mock_client.assert_called_once_with(
                'test_user', 'test_password', 'test_project',
                auth_url='test_address', cacert=None, insecure=False,
                region_name='test_region', retries=3)

    def test_temporary_chown(self):
        class fake_stat(object):
            st_uid = 1

        with mock.patch.object(os, 'stat', return_value=fake_stat()), \
                mock.patch.object(os, 'getuid', return_value=2), \
                mock.patch.object(processutils, 'execute') as mock_execute, \
                mock.patch.object(cinder, 'get_root_helper',
                                  return_value='sudo'):
            with cinder.temporary_chown('test'):
                pass
            expected_calls = [mock.call('chown', 2, 'test', run_as_root=True,
                                        root_helper='sudo'),
                              mock.call('chown', 1, 'test', run_as_root=True,
                                        root_helper='sudo')]
            self.assertEqual(expected_calls, mock_execute.call_args_list)

    @mock.patch.object(time, 'sleep')
    def test_wait_volume_status(self, mock_sleep):
        fake_manager = FakeObject(get=mock.Mock())
        volume_available = FakeObject(manager=fake_manager,
                                      id='fake-id',
                                      status='available')
        volume_in_use = FakeObject(manager=fake_manager,
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
        fake_manager = FakeObject(get=mock.Mock())
        volume_available = FakeObject(manager=fake_manager,
                                      id='fake-id',
                                      status='error')
        fake_manager.get.return_value = volume_available
        self.assertRaises(exceptions.BackendException,
                          self.store._wait_volume_status,
                          volume_available, 'available', 'in-use')
        fake_manager.get.assert_called_with('fake-id')

    @mock.patch.object(time, 'sleep')
    def test_wait_volume_status_timeout(self, mock_sleep):
        fake_manager = FakeObject(get=mock.Mock())
        volume_available = FakeObject(manager=fake_manager,
                                      id='fake-id',
                                      status='available')
        fake_manager.get.return_value = volume_available
        self.assertRaises(exceptions.BackendException,
                          self.store._wait_volume_status,
                          volume_available, 'available', 'in-use')
        fake_manager.get.assert_called_with('fake-id')

    def _test_open_cinder_volume(self, open_mode, attach_mode, error):
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()), status='available')
        fake_volumes = FakeObject(get=lambda id: fake_volume,
                                  detach=mock.Mock())
        fake_client = FakeObject(volumes=fake_volumes)
        _, fake_dev_path = tempfile.mkstemp(dir=self.test_dir)
        fake_devinfo = {'path': fake_dev_path}
        fake_connector = FakeObject(
            connect_volume=mock.Mock(return_value=fake_devinfo),
            disconnect_volume=mock.Mock())

        @contextlib.contextmanager
        def fake_chown(path, backend=None):
            yield

        def do_open():
            with self.store._open_cinder_volume(
                    fake_client, fake_volume, open_mode):
                if error:
                    raise error

        def fake_factory(protocol, root_helper, **kwargs):
            self.assertEqual(fake_volume.initialize_connection.return_value,
                             kwargs['conn'])
            return fake_connector

        root_helper = "sudo glance-rootwrap /etc/glance/rootwrap.conf"
        with mock.patch.object(cinder.Store,
                               '_wait_volume_status',
                               return_value=fake_volume), \
                mock.patch.object(cinder, 'temporary_chown',
                                  side_effect=fake_chown), \
                mock.patch.object(cinder, 'get_root_helper',
                                  return_value=root_helper), \
                mock.patch.object(connector, 'get_connector_properties'), \
                mock.patch.object(connector.InitiatorConnector, 'factory',
                                  side_effect=fake_factory):

            if error:
                self.assertRaises(error, do_open)
            else:
                do_open()

            fake_connector.connect_volume.assert_called_once_with(mock.ANY)
            fake_connector.disconnect_volume.assert_called_once_with(
                mock.ANY, fake_devinfo)
            fake_volume.attach.assert_called_once_with(
                None, 'glance_store', attach_mode,
                host_name=socket.gethostname())
            fake_volumes.detach.assert_called_once_with(fake_volume)

    def test_open_cinder_volume_rw(self):
        self._test_open_cinder_volume('wb', 'rw', None)

    def test_open_cinder_volume_ro(self):
        self._test_open_cinder_volume('rb', 'ro', None)

    def test_open_cinder_volume_error(self):
        self._test_open_cinder_volume('wb', 'rw', IOError)

    def test_cinder_configure_add(self):
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._check_context, None)

        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._check_context,
                          FakeObject(service_catalog=None))

        self.store._check_context(FakeObject(service_catalog='fake'))

    def test_cinder_get(self):
        expected_size = 5 * units.Ki
        expected_file_contents = b"*" * expected_size
        volume_file = six.BytesIO(expected_file_contents)
        fake_client = FakeObject(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        fake_volume = mock.MagicMock(id=fake_volume_uuid,
                                     metadata={'image_size': expected_size},
                                     status='available')
        fake_volume.manager.get.return_value = fake_volume
        fake_volumes = FakeObject(get=lambda id: fake_volume)

        @contextlib.contextmanager
        def fake_open(client, volume, mode):
            self.assertEqual('rb', mode)
            yield volume_file

        with mock.patch.object(cinder, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume',
                                  side_effect=fake_open):
            mock_cc.return_value = FakeObject(client=fake_client,
                                              volumes=fake_volumes)
            uri = "cinder://%s" % fake_volume_uuid
            loc = location.get_location_from_uri(uri, conf=self.conf)
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

    def test_cinder_get_size(self):
        fake_client = FakeObject(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        fake_volume = FakeObject(size=5, metadata={})
        fake_volumes = {fake_volume_uuid: fake_volume}

        with mock.patch.object(cinder, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = FakeObject(client=fake_client,
                                                volumes=fake_volumes)

            uri = 'cinder://%s' % fake_volume_uuid
            loc = location.get_location_from_uri(uri, conf=self.conf)
            image_size = self.store.get_size(loc, context=self.context)
            self.assertEqual(fake_volume.size * units.Gi, image_size)

    def test_cinder_get_size_with_metadata(self):
        fake_client = FakeObject(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        expected_image_size = 4500 * units.Mi
        fake_volume = FakeObject(size=5,
                                 metadata={'image_size': expected_image_size})
        fake_volumes = {fake_volume_uuid: fake_volume}

        with mock.patch.object(cinder, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = FakeObject(client=fake_client,
                                                volumes=fake_volumes)

            uri = 'cinder://%s' % fake_volume_uuid
            loc = location.get_location_from_uri(uri, conf=self.conf)
            image_size = self.store.get_size(loc, context=self.context)
            self.assertEqual(expected_image_size, image_size)

    def _test_cinder_add(self, fake_volume, volume_file, size_kb=5,
                         verifier=None):
        expected_image_id = str(uuid.uuid4())
        expected_size = size_kb * units.Ki
        expected_file_contents = b"*" * expected_size
        image_file = six.BytesIO(expected_file_contents)
        expected_checksum = hashlib.md5(expected_file_contents).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()
        expected_location = 'cinder://%s' % fake_volume.id
        fake_client = FakeObject(auth_token=None, management_url=None)
        fake_volume.manager.get.return_value = fake_volume
        fake_volumes = FakeObject(create=mock.Mock(return_value=fake_volume))
        self.config(cinder_volume_type='some_type')

        @contextlib.contextmanager
        def fake_open(client, volume, mode):
            self.assertEqual('wb', mode)
            yield volume_file

        with mock.patch.object(cinder, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume',
                                  side_effect=fake_open):
            mock_cc.return_value = FakeObject(client=fake_client,
                                              volumes=fake_volumes)
            loc, size, checksum, multihash, _ = self.store.add(
                expected_image_id, image_file, expected_size, self.hash_algo,
                self.context, verifier)
            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_size, size)
            self.assertEqual(expected_checksum, checksum)
            self.assertEqual(expected_multihash, multihash)
            fake_volumes.create.assert_called_once_with(
                1,
                name='image-%s' % expected_image_id,
                metadata={'image_owner': self.context.tenant,
                          'glance_image_id': expected_image_id,
                          'image_size': str(expected_size)},
                volume_type='some_type')

    def test_cinder_add(self):
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        volume_file = six.BytesIO()
        self._test_cinder_add(fake_volume, volume_file)

    def test_cinder_add_with_verifier(self):
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        volume_file = six.BytesIO()
        verifier = mock.MagicMock()
        self._test_cinder_add(fake_volume, volume_file, 1, verifier)
        verifier.update.assert_called_with(b"*" * units.Ki)

    def test_cinder_add_volume_full(self):
        e = IOError()
        volume_file = six.BytesIO()
        e.errno = errno.ENOSPC
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        with mock.patch.object(volume_file, 'write', side_effect=e):
            self.assertRaises(exceptions.StorageFull,
                              self._test_cinder_add, fake_volume, volume_file)
        fake_volume.delete.assert_called_once_with()

    def test_cinder_delete(self):
        fake_client = FakeObject(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        fake_volume = FakeObject(delete=mock.Mock())
        fake_volumes = {fake_volume_uuid: fake_volume}

        with mock.patch.object(cinder, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = FakeObject(client=fake_client,
                                                volumes=fake_volumes)

            uri = 'cinder://%s' % fake_volume_uuid
            loc = location.get_location_from_uri(uri, conf=self.conf)
            self.store.delete(loc, context=self.context)
            fake_volume.delete.assert_called_once_with()
