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
import io
import math
from unittest import mock

import six
import sys
import time
import uuid

from oslo_utils.secretutils import md5
from oslo_utils import units

from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_cinder_base
from glance_store.tests.unit import test_store_capabilities

sys.modules['glance_store.common.fs_mount'] = mock.Mock()
from glance_store._drivers import cinder # noqa


class TestCinderStore(base.StoreBaseTest,
                      test_store_capabilities.TestStoreCapabilitiesChecking,
                      test_cinder_base.TestCinderStoreBase):

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
                    u'type': u'volumev3'}]
        self.context = mock.MagicMock(service_catalog=fake_sc,
                                      user_id='fake_user',
                                      auth_token='fake_token',
                                      project_id='fake_project')
        self.hash_algo = 'sha256'
        cinder._reset_cinder_session()
        self.config(cinder_mount_point_base=None)

    def _test_get_cinderclient_with_user_overriden(self):
        self.config(cinder_store_user_name='test_user')
        self.config(cinder_store_password='test_password')
        self.config(cinder_store_project_name='test_project')
        self.config(cinder_store_auth_address='test_address')
        cc = self.store.get_cinderclient(self.context)
        self.assertEqual('test_project', cc.client.session.auth.project_name)
        self.assertEqual('Default', cc.client.session.auth.project_domain_name)
        return cc

    def test_get_cinderclient_with_user_overriden(self):
        self._test_get_cinderclient_with_user_overriden()

    def test_get_cinderclient_with_user_overriden_and_region(self):
        self.config(cinder_os_region_name='test_region')
        cc = self._test_get_cinderclient_with_user_overriden()
        self.assertEqual('test_region', cc.client.region_name)

    def test_open_cinder_volume_multipath_enabled(self):
        self.config(cinder_use_multipath=True)
        self._test_open_cinder_volume('wb', 'rw', None,
                                      multipath_supported=True)

    def test_open_cinder_volume_multipath_disabled(self):
        self.config(cinder_use_multipath=False)
        self._test_open_cinder_volume('wb', 'rw', None,
                                      multipath_supported=False)

    def test_open_cinder_volume_enforce_multipath(self):
        self.config(cinder_use_multipath=True)
        self.config(cinder_enforce_multipath=True)
        self._test_open_cinder_volume('wb', 'rw', None,
                                      multipath_supported=True,
                                      enforce_multipath=True)

    def test_cinder_configure_add(self):
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._check_context, None)

        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._check_context,
                          mock.MagicMock(service_catalog=None))

        self.store._check_context(mock.MagicMock(service_catalog='fake'))

    def test_cinder_get(self):
        self._test_cinder_get()

    def test_cinder_get_size(self):
        self._test_cinder_get_size()

    def test_cinder_get_size_with_metadata(self):
        self._test_cinder_get_size_with_metadata()

    def _test_cinder_add(self, fake_volume, volume_file, size_kb=5,
                         verifier=None, fail_resize=False):
        expected_image_id = str(uuid.uuid4())
        expected_size = size_kb * units.Ki
        expected_file_contents = b"*" * expected_size
        image_file = six.BytesIO(expected_file_contents)
        expected_checksum = md5(expected_file_contents,
                                usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(expected_file_contents).hexdigest()
        expected_location = 'cinder://%s' % fake_volume.id
        fake_client = mock.MagicMock(auth_token=None, management_url=None)
        fake_volume.manager.get.return_value = fake_volume
        fake_volumes = mock.MagicMock(create=mock.Mock(
            return_value=fake_volume))
        self.config(cinder_volume_type='some_type')

        @contextlib.contextmanager
        def fake_open(client, volume, mode):
            self.assertEqual('wb', mode)
            yield volume_file

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mock_cc, \
                mock.patch.object(self.store, '_open_cinder_volume',
                                  side_effect=fake_open), \
                mock.patch.object(
                    cinder.Store, '_wait_resize_device') as mock_wait_resize:
            if fail_resize:
                mock_wait_resize.side_effect = exceptions.BackendException()
            mock_cc.return_value = mock.MagicMock(client=fake_client,
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
                metadata={'image_owner': self.context.project_id,
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
        fake_client = mock.MagicMock(auth_token=None, management_url=None)
        fake_volume_uuid = str(uuid.uuid4())
        fake_volumes = mock.MagicMock(delete=mock.Mock())

        with mock.patch.object(cinder.Store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(client=fake_client,
                                                    volumes=fake_volumes)

            uri = 'cinder://%s' % fake_volume_uuid
            loc = location.get_location_from_uri(uri, conf=self.conf)
            self.store.delete(loc, context=self.context)
            fake_volumes.delete.assert_called_once_with(fake_volume_uuid)

    def test_set_url_prefix(self):
        self.assertEqual('cinder://', self.store._url_prefix)

    def test_configure_add_valid_type(self):
        self.config(cinder_volume_type='some_type')
        self._test_configure_add_valid_type()

    def test_configure_add_invalid_type(self):
        # setting cinder_volume_type to non-existent value will log a
        # warning
        self.config(cinder_volume_type='some_random_type')
        self._test_configure_add_invalid_type()

    def test__get_device_size(self):
        fake_data = b"fake binary data"
        fake_len = int(math.ceil(float(len(fake_data)) / units.Gi))
        fake_file = io.BytesIO(fake_data)
        dev_size = cinder.Store._get_device_size(fake_file)
        self.assertEqual(fake_len, dev_size)

    @mock.patch.object(time, 'sleep')
    def test__wait_resize_device_resized(self, mock_sleep):
        fake_vol = mock.MagicMock()
        fake_vol.size = 2
        fake_file = io.BytesIO(b"fake binary data")
        with mock.patch.object(
                cinder.Store, '_get_device_size') as mock_get_dev_size:
            mock_get_dev_size.side_effect = [1, 2]
            cinder.Store._wait_resize_device(fake_vol, fake_file)

    @mock.patch.object(time, 'sleep')
    def test__wait_resize_device_fails(self, mock_sleep):
        fake_vol = mock.MagicMock()
        fake_vol.size = 2
        fake_file = io.BytesIO(b"fake binary data")
        with mock.patch.object(
                cinder.Store, '_get_device_size',
                return_value=1):
            self.assertRaises(
                exceptions.BackendException,
                cinder.Store._wait_resize_device,
                fake_vol, fake_file)

    def test_cinder_add_fail_resize(self):
        volume_file = io.BytesIO()
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        self.assertRaises(exceptions.BackendException,
                          self._test_cinder_add, fake_volume, volume_file,
                          fail_resize=True)
        fake_volume.delete.assert_called_once()
