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

import errno
import io
from unittest import mock

import sys
import uuid

from glance_store import exceptions
from glance_store.tests import base
from glance_store.tests.unit.cinder import test_cinder_base
from glance_store.tests.unit import test_store_capabilities

sys.modules['glance_store.common.fs_mount'] = mock.Mock()
from glance_store._drivers.cinder import store as cinder # noqa


class TestCinderStore(base.StoreBaseTest,
                      test_store_capabilities.TestStoreCapabilitiesChecking,
                      test_cinder_base.TestCinderStoreBase):

    def setUp(self):
        super(TestCinderStore, self).setUp()
        self.is_multistore = False
        self.store = cinder.Store(self.conf)
        self.store.configure()
        self.register_store_schemes(self.store, 'cinder')
        self.store.READ_CHUNKSIZE = 4096
        self.store.WRITE_CHUNKSIZE = 4096

        fake_sc = [{'endpoints': [{'publicURL': 'http://foo/public_url'}],
                    'endpoints_links': [],
                    'name': 'cinder',
                    'type': 'volumev3'}]
        self.context = mock.MagicMock(service_catalog=fake_sc,
                                      user_id='fake_user',
                                      auth_token='fake_token',
                                      project_id='fake_project')
        self.hash_algo = 'sha256'
        cinder._reset_cinder_session()
        self.config(cinder_mount_point_base=None)
        self.volume_id = str(uuid.uuid4())
        specs = {'scheme': 'cinder',
                 'volume_id': self.volume_id}
        self.location = cinder.StoreLocation(specs, self.conf)

    def test_get_cinderclient_with_user_overriden(self):
        self._test_get_cinderclient_with_user_overriden()

    def test_get_cinderclient_with_user_overriden_and_region(self):
        self._test_get_cinderclient_with_user_overriden_and_region()

    def test_get_cinderclient_with_api_insecure(self):
        self._test_get_cinderclient_with_api_insecure()

    def test_get_cinderclient_with_ca_certificates(self):
        self._test_get_cinderclient_with_ca_certificates()

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

    def test_cinder_add_volume_full(self):
        e = IOError()
        volume_file = io.BytesIO()
        e.errno = errno.ENOSPC
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        with mock.patch.object(volume_file, 'write', side_effect=e):
            self.assertRaises(exceptions.StorageFull,
                              self._test_cinder_add, fake_volume, volume_file)
        fake_volume.delete.assert_called_once_with()

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

    def test_get_uri(self):
        expected_uri = 'cinder://%s' % self.volume_id
        self._test_get_uri(expected_uri)

    def test_parse_uri_valid(self):
        expected_uri = 'cinder://%s' % self.volume_id
        self.location.parse_uri(expected_uri)

    def test_parse_uri_invalid(self):
        uri = 'cinder://%s' % 'fake_volume'
        self._test_parse_uri_invalid(uri)

    def test_get_root_helper(self):
        self._test_get_root_helper()

    def test_get_cinderclient_cinder_endpoint_template(self):
        self._test_get_cinderclient_cinder_endpoint_template()

    def test_get_cinderclient_with_application_credential(self):
        self._test_get_cinderclient_with_application_credential()

    def test_get_cinderclient_with_application_credential_fallback(self):
        self._test_get_cinderclient_with_application_credential_fallback()

    def test_is_user_overriden_with_application_credential(self):
        self.config(
            cinder_store_application_credential_id='test_ac_id')
        self.config(
            cinder_store_application_credential_secret='test_ac_secret')
        self.config(cinder_store_auth_address='test_address')
        self.assertTrue(self.store.is_user_overriden())

    def test_is_user_overriden_with_partial_application_credential(self):
        self.config(cinder_store_application_credential_id='test_ac_id')
        self.config(cinder_store_auth_address='test_address')
        self.assertFalse(self.store.is_user_overriden())

    def test_get_cinder_session_with_application_credential(self):
        cinder._reset_cinder_session()
        self.config(
            cinder_store_application_credential_id='test_ac_id')
        self.config(
            cinder_store_application_credential_secret='test_ac_secret')
        self.config(cinder_store_auth_address='test_address')
        with mock.patch.object(
            cinder.ksa_session, 'Session') as fake_session, \
            mock.patch.object(
                cinder.ksa_identity,
                'V3ApplicationCredential') as fake_ac_method:
            fake_auth = mock.MagicMock()
            fake_ac_method.return_value = fake_auth
            cinder.get_cinder_session(self.store.store_conf)
            fake_ac_method.assert_called_once_with(
                application_credential_id='test_ac_id',
                application_credential_secret='test_ac_secret',
                auth_url='test_address')
            fake_session.assert_called_once_with(auth=fake_auth, verify=True)

    def test_get_cinder_session_fallback_to_password(self):
        cinder._reset_cinder_session()
        self.config(cinder_store_user_name='test_user')
        self.config(cinder_store_password='test_password')
        self.config(cinder_store_project_name='test_project')
        self.config(cinder_store_auth_address='test_address')
        with mock.patch.object(
            cinder.ksa_session, 'Session') as fake_session, \
            mock.patch.object(
                cinder.ksa_identity, 'V3Password') as fake_password_method, \
            mock.patch.object(
                cinder.ksa_identity,
                'V3ApplicationCredential') as fake_ac_method:
            fake_auth = mock.MagicMock()
            fake_password_method.return_value = fake_auth
            cinder.get_cinder_session(self.store.store_conf)
            fake_ac_method.assert_not_called()
            fake_password_method.assert_called_once()
            fake_session.assert_called_once_with(auth=fake_auth, verify=True)
