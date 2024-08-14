# Copyright 2018-2019 RedHat Inc.
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
import os
from unittest import mock

import six
import socket
import sys
import tempfile
import time
import uuid

import fixtures
from os_brick.initiator import connector
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_utils import units

import glance_store as store
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities as test_cap

sys.modules['glance_store.common.fs_mount'] = mock.Mock()
from glance_store._drivers import cinder # noqa


class FakeObject(object):
    def __init__(self, **kwargs):
        for name, value in kwargs.items():
            setattr(self, name, value)


class TestMultiCinderStore(base.MultiStoreBaseTest,
                           test_cap.TestStoreCapabilitiesChecking):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        super(TestMultiCinderStore, self).setUp()
        enabled_backends = {
            "cinder1": "cinder",
            "cinder2": "cinder"
        }
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='cinder1', group='glance_store')

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}
        store.create_multi_stores(self.conf)

        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.test_dir = self.useFixture(fixtures.TempDir()).path
        self.addCleanup(self.conf.reset)

        self.store = cinder.Store(self.conf, backend="cinder1")
        self.store.configure()
        self.register_store_backend_schemes(self.store, 'cinder', 'cinder1')
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
        self.fake_admin_context = mock.MagicMock()
        self.fake_admin_context.elevated.return_value = FakeObject(
            service_catalog=fake_sc,
            user='admin_user',
            auth_token='admin_token',
            tenant='admin_project')

    def test_location_url_prefix_is_set(self):
        self.assertEqual("cinder://cinder1", self.store.url_prefix)

    def test_get_cinderclient(self):
        cc = self.store.get_cinderclient(self.context)
        self.assertEqual('fake_token', cc.client.auth_token)
        self.assertEqual('http://foo/public_url', cc.client.management_url)

    def test_get_cinderclient_with_user_overriden(self):
        self.config(cinder_store_user_name='test_user', group="cinder1")
        self.config(cinder_store_password='test_password', group="cinder1")
        self.config(cinder_store_project_name='test_project', group="cinder1")
        self.config(cinder_store_auth_address='test_address', group="cinder1")
        cc = self.store.get_cinderclient(self.context)
        self.assertIsNone(cc.client.auth_token)
        self.assertEqual('test_address', cc.client.management_url)

    def test_get_cinderclient_legacy_update(self):
        cc = self.store.get_cinderclient(self.fake_admin_context,
                                         legacy_update=True)
        self.assertEqual('admin_token', cc.client.auth_token)
        self.assertEqual('admin_user', cc.client.user)
        self.assertEqual('admin_project', cc.client.projectid)
        self.assertEqual('http://foo/public_url', cc.client.management_url)

    def test_temporary_chown(self):
        class fake_stat(object):
            st_uid = 1

        with mock.patch.object(os, 'stat', return_value=fake_stat()), \
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

    def _test_open_cinder_volume(self, open_mode, attach_mode, error,
                                 multipath_supported=False,
                                 enforce_multipath=False):
        self.config(cinder_mount_point_base=None, group='cinder1')
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
                mock.patch.object(cinder.Store, 'temporary_chown',
                                  side_effect=fake_chown), \
                mock.patch.object(cinder.Store, 'get_root_helper',
                                  return_value=root_helper), \
                mock.patch.object(connector.InitiatorConnector, 'factory',
                                  side_effect=fake_factory) as fake_conn_obj:

            with mock.patch.object(connector,
                                   'get_connector_properties') as mock_conn:
                if error:
                    self.assertRaises(error, do_open)
                else:
                    do_open()

                mock_conn.assert_called_once_with(
                    root_helper, socket.gethostname(), multipath_supported,
                    enforce_multipath)
                fake_connector.connect_volume.assert_called_once_with(mock.ANY)
                fake_connector.disconnect_volume.assert_called_once_with(
                    mock.ANY, fake_devinfo, force=True)
                fake_volume.attach.assert_called_once_with(
                    None, 'glance_store', attach_mode,
                    host_name=socket.gethostname())
                fake_volumes.detach.assert_called_once_with(fake_volume)
                fake_conn_obj.assert_called_once_with(
                    mock.ANY, root_helper, conn=mock.ANY,
                    use_multipath=multipath_supported)

    def test_open_cinder_volume_rw(self):
        self._test_open_cinder_volume('wb', 'rw', None)

    def test_open_cinder_volume_ro(self):
        self._test_open_cinder_volume('rb', 'ro', None)

    def test_open_cinder_volume_error(self):
        self._test_open_cinder_volume('wb', 'rw', IOError)

    def test_open_cinder_volume_multipath_disabled(self):
        self.config(cinder_use_multipath=False, group='cinder1')
        self._test_open_cinder_volume('wb', 'rw', None,
                                      multipath_supported=False)

    def test_open_cinder_volume_enforce_multipath(self):

        self.config(cinder_use_multipath=True, group='cinder1')
        self.config(cinder_enforce_multipath=True, group='cinder1')
        self._test_open_cinder_volume('wb', 'rw', None,
                                      multipath_supported=True,
                                      enforce_multipath=True)

    def test_cinder_check_context(self):
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._check_context, None)

        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._check_context,
                          FakeObject(service_catalog=None))

        self.store._check_context(FakeObject(service_catalog='fake'))

    def test_cinder_configure_add(self):
        with mock.patch.object(self.store, 'get_cinderclient') as mocked_cc:
            def raise_(ex):
                raise ex
            mocked_cc.return_value = FakeObject(volume_types=FakeObject(
                find=lambda name: 'some_type' if name == 'some_type'
                else raise_(cinder.cinder_exception.NotFound(code=404))))
            self.config(cinder_volume_type='some_type',
                        group=self.store.backend_group)
            # If volume type exists, no exception is raised
            self.store.configure_add()
            # setting cinder_volume_type to non-existent value will raise
            # BadStoreConfiguration exception
            self.config(cinder_volume_type='some_random_type',
                        group=self.store.backend_group)

            self.assertRaises(exceptions.BadStoreConfiguration,
                              self.store.configure_add)
            # when only 1 store is configured, BackendException is raised
            self.config(enabled_backends={'cinder1': 'cinder'})
            self.assertRaises(exceptions.BackendException,
                              self.store.configure_add)

    def test_is_image_associated_with_store(self):
        with mock.patch.object(self.store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = FakeObject(volumes=FakeObject(
                get=lambda volume_id: FakeObject(volume_type='some_type')),
                volume_types=FakeObject(
                    default=lambda: FakeObject(name='some_type')))
            # When cinder_volume_type is set and is same as volume's type
            self.config(cinder_volume_type='some_type',
                        group=self.store.backend_group)
            fake_vol_id = str(uuid.uuid4())
            type_match = self.store.is_image_associated_with_store(
                self.context, fake_vol_id)
            self.assertTrue(type_match)
            # When cinder_volume_type is not set and volume's type is same as
            # set default volume type
            self.config(cinder_volume_type=None,
                        group=self.store.backend_group)
            type_match = self.store.is_image_associated_with_store(
                self.context, fake_vol_id)
            self.assertTrue(type_match)
            # When cinder_volume_type is not set and volume's type does not
            # match with default volume type
            mocked_cc.return_value.volume_types = FakeObject(
                default=lambda: {'name': 'random_type'})
            type_match = self.store.is_image_associated_with_store(
                self.context, fake_vol_id)
            self.assertFalse(type_match)

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

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume',
                                  side_effect=fake_open):
            mock_cc.return_value = FakeObject(client=fake_client,
                                              volumes=fake_volumes)
            uri = "cinder://cinder1/%s" % fake_volume_uuid
            loc = location.get_location_from_uri_and_backend(uri,
                                                             "cinder1",
                                                             conf=self.conf)
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

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = FakeObject(client=fake_client,
                                                volumes=fake_volumes)

            uri = 'cinder://cinder1/%s' % fake_volume_uuid
            loc = location.get_location_from_uri_and_backend(uri,
                                                             "cinder1",
                                                             conf=self.conf)
            image_size = self.store.get_size(loc, context=self.context)
            self.assertEqual(fake_volume.size * units.Gi, image_size)

    def test_cinder_get_size_with_metadata(self):
        fake_client = FakeObject(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        expected_image_size = 4500 * units.Mi
        fake_volume = FakeObject(size=5,
                                 metadata={'image_size': expected_image_size})
        fake_volumes = {fake_volume_uuid: fake_volume}

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = FakeObject(client=fake_client,
                                                volumes=fake_volumes)

            uri = 'cinder://cinder1/%s' % fake_volume_uuid
            loc = location.get_location_from_uri_and_backend(uri,
                                                             "cinder1",
                                                             conf=self.conf)
            image_size = self.store.get_size(loc, context=self.context)
            self.assertEqual(expected_image_size, image_size)

    def _test_cinder_add(self, fake_volume, volume_file, size_kb=5,
                         verifier=None, backend="cinder1"):
        expected_image_id = str(uuid.uuid4())
        expected_size = size_kb * units.Ki
        expected_file_contents = b"*" * expected_size
        image_file = six.BytesIO(expected_file_contents)
        expected_checksum = hashlib.md5(expected_file_contents).hexdigest()
        expected_location = 'cinder://%s/%s' % (backend, fake_volume.id)
        fake_client = FakeObject(auth_token=None, management_url=None)
        fake_volume.manager.get.return_value = fake_volume
        fake_volumes = FakeObject(create=mock.Mock(return_value=fake_volume))
        self.config(cinder_volume_type='some_type', group=backend)

        @contextlib.contextmanager
        def fake_open(client, volume, mode):
            self.assertEqual('wb', mode)
            yield volume_file

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume',
                                  side_effect=fake_open):
            mock_cc.return_value = FakeObject(client=fake_client,
                                              volumes=fake_volumes)
            loc, size, checksum, metadata = self.store.add(expected_image_id,
                                                           image_file,
                                                           expected_size,
                                                           self.context,
                                                           verifier)
            self.assertEqual(expected_location, loc)
            self.assertEqual(expected_size, size)
            self.assertEqual(expected_checksum, checksum)
            fake_volumes.create.assert_called_once_with(
                1,
                name='image-%s' % expected_image_id,
                metadata={'image_owner': self.context.tenant,
                          'glance_image_id': expected_image_id,
                          'image_size': str(expected_size)},
                volume_type='some_type')
            self.assertEqual(backend, metadata["store"])

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

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = FakeObject(client=fake_client,
                                                volumes=fake_volumes)

            uri = 'cinder://cinder1/%s' % fake_volume_uuid
            loc = location.get_location_from_uri_and_backend(uri,
                                                             "cinder1",
                                                             conf=self.conf)
            self.store.delete(loc, context=self.context)
            fake_volume.delete.assert_called_once_with()

    def test_cinder_add_different_backend(self):
        self.store = cinder.Store(self.conf, backend="cinder2")
        self.store.configure()
        self.register_store_backend_schemes(self.store, 'cinder', 'cinder2')

        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        volume_file = six.BytesIO()
        self._test_cinder_add(fake_volume, volume_file, backend="cinder2")
