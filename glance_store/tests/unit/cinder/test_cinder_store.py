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

from oslo_utils import units

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

    def test_cinder_get(self):
        self._test_cinder_get()

    def test_cinder_get_size(self):
        self._test_cinder_get_size()

    def test_cinder_get_size_with_metadata(self):
        self._test_cinder_get_size_with_metadata()

    def test_cinder_add(self):
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        volume_file = io.BytesIO()
        self._test_cinder_add(fake_volume, volume_file)

    def test_cinder_add_with_verifier(self):
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        volume_file = io.BytesIO()
        verifier = mock.MagicMock()
        self._test_cinder_add(fake_volume, volume_file, 1, verifier)
        verifier.update.assert_called_with(b"*" * units.Ki)

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

    def test_cinder_add_extend(self):
        self._test_cinder_add_extend()

    def test_cinder_add_extend_online(self):
        self._test_cinder_add_extend(online=True)

    def test_cinder_delete(self):
        self._test_cinder_delete()

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
