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

import errno
import io
from unittest import mock

import sys
import uuid

import fixtures
from oslo_config import cfg
from oslo_utils import units

import glance_store as store
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit.cinder import test_cinder_base
from glance_store.tests.unit import test_store_capabilities as test_cap

sys.modules['glance_store.common.fs_mount'] = mock.Mock()
from glance_store._drivers.cinder import store as cinder # noqa


class TestMultiCinderStore(base.MultiStoreBaseTest,
                           test_cap.TestStoreCapabilitiesChecking,
                           test_cinder_base.TestCinderStoreBase):

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

        fake_sc = [{'endpoints': [{'publicURL': 'http://foo/public_url'}],
                    'endpoints_links': [],
                    'name': 'cinder',
                    'type': 'volumev3'}]
        self.context = mock.MagicMock(service_catalog=fake_sc,
                                      user_id='fake_user',
                                      auth_token='fake_token',
                                      project_id='fake_project')
        self.hash_algo = 'sha256'
        self.fake_admin_context = mock.MagicMock()
        self.fake_admin_context.elevated.return_value = mock.MagicMock(
            service_catalog=fake_sc,
            user_id='admin_user',
            auth_token='admin_token',
            project_id='admin_project')
        cinder._reset_cinder_session()
        self.config(cinder_mount_point_base=None, group='cinder1')
        self.volume_id = str(uuid.uuid4())
        specs = {'scheme': 'cinder',
                 'volume_id': self.volume_id}
        self.location = cinder.StoreLocation(specs, self.conf,
                                             backend_group='cinder1')

    def test_location_url_prefix_is_set(self):
        self.assertEqual("cinder://cinder1", self.store.url_prefix)

    def test_get_cinderclient_with_user_overriden(self):
        self._test_get_cinderclient_with_user_overriden(group='cinder1')

    def test_get_cinderclient_with_user_overriden_and_region(self):
        self._test_get_cinderclient_with_user_overriden_and_region(
            group='cinder1')

    def test_get_cinderclient_with_api_insecure(self):
        self._test_get_cinderclient_with_api_insecure(group='cinder1')

    def test_get_cinderclient_with_ca_certificates(self):
        self._test_get_cinderclient_with_ca_certificates(group='cinder1')

    def test_get_cinderclient_legacy_update(self):
        fake_endpoint = 'http://cinder.openstack.example.com/v2/fake_project'
        self.config(cinder_endpoint_template=fake_endpoint, group='cinder1')
        cc = self.store.get_cinderclient(self.context)
        self.assertEqual(self.context.auth_token,
                         cc.client.auth.token)
        self.assertEqual(fake_endpoint, cc.client.auth.endpoint)

    def test_open_cinder_volume_multipath_enabled(self):
        self.config(cinder_use_multipath=True, group='cinder1')
        self._test_open_cinder_volume('wb', 'rw', None,
                                      multipath_supported=True)

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
                          mock.MagicMock(service_catalog=None))

        self.store._check_context(mock.MagicMock(service_catalog='fake'))

    def test_configure_add_valid_type(self):
        self.config(cinder_volume_type='some_type',
                    group=self.store.backend_group)
        self._test_configure_add_valid_type()

    def test_configure_add_invalid_type(self):
        # setting cinder_volume_type to non-existent value will log a
        # warning
        self.config(cinder_volume_type='some_random_type',
                    group=self.store.backend_group)
        self._test_configure_add_invalid_type()

    def test_configure_add_cinder_service_down(self):

        def fake_volume_type_check(name):
            raise cinder.cinder_exception.ClientException(code=503)

        self.config(cinder_volume_type='some_type',
                    group=self.store.backend_group)
        with mock.patch.object(self.store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(
                volume_types=mock.MagicMock(
                    find=fake_volume_type_check))
            # We handle the ClientException to pass so no exception is raised
            # in this case
            self.store.configure_add()

    def test_configure_add_authorization_failed(self):

        def fake_volume_type_check(name):
            raise cinder.exceptions.AuthorizationFailure(code=401)

        self.config(cinder_volume_type='some_type',
                    group=self.store.backend_group)
        with mock.patch.object(self.store, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = mock.MagicMock(
                volume_types=mock.MagicMock(
                    find=fake_volume_type_check))
            # Anything apart from invalid volume type or cinder service
            # down will raise an exception
            self.assertRaises(cinder.exceptions.AuthorizationFailure,
                              self.store.configure_add)

    def test_is_image_associated_with_store(self):
        with mock.patch.object(self.store, 'get_cinderclient') as mocked_cc:
            mock_default = mock.MagicMock()
            # The 'name' attribute is set separately since 'name' is a property
            # of MagicMock and it can't be set during initialization of
            # MagicMock object
            mock_default.name = 'some_type'
            mocked_cc.return_value = mock.MagicMock(
                volumes=mock.MagicMock(
                    get=lambda volume_id: mock.MagicMock(
                        volume_type='some_type')),
                volume_types=mock.MagicMock(
                    default=lambda: mock_default))
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
            mocked_cc.return_value.volume_types = mock.MagicMock(
                default=lambda: {'name': 'random_type'})
            type_match = self.store.is_image_associated_with_store(
                self.context, fake_vol_id)
            self.assertFalse(type_match)
            # When the Image-Volume is not found
            mocked_cc.return_value.volumes.get = mock.MagicMock(
                side_effect=cinder.cinder_exception.NotFound(code=404))
            with mock.patch.object(cinder, 'LOG') as mock_log:
                type_match = self.store.is_image_associated_with_store(
                    self.context, fake_vol_id)
                mock_log.warning.assert_called_with(
                    "Image-Volume %s not found. If you have "
                    "upgraded your environment from single store "
                    "to multi store, transfer all your "
                    "Image-Volumes from user projects to service "
                    "project." % fake_vol_id)
            self.assertFalse(type_match)

    def test_cinder_get(self):
        self._test_cinder_get(is_multi_store=True)

    def test_cinder_get_size(self):
        self._test_cinder_get_size(is_multi_store=True)

    def test_cinder_get_size_with_metadata(self):
        self._test_cinder_get_size_with_metadata(is_multi_store=True)

    def test_cinder_add(self):
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        volume_file = io.BytesIO()
        self._test_cinder_add(fake_volume, volume_file, is_multi_store=True)

    def test_cinder_add_with_verifier(self):
        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        volume_file = io.BytesIO()
        verifier = mock.MagicMock()
        self._test_cinder_add(fake_volume, volume_file, 1, verifier,
                              is_multi_store=True)
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
                              self._test_cinder_add, fake_volume, volume_file,
                              is_multi_store=True)
        fake_volume.delete.assert_called_once_with()

    def test_cinder_add_different_backend(self):
        self.store = cinder.Store(self.conf, backend="cinder2")
        self.store.configure()
        self.register_store_backend_schemes(self.store, 'cinder', 'cinder2')

        fake_volume = mock.MagicMock(id=str(uuid.uuid4()),
                                     status='available',
                                     size=1)
        volume_file = io.BytesIO()
        self._test_cinder_add(fake_volume, volume_file, backend="cinder2",
                              is_multi_store=True)

    def test_cinder_add_extend(self):
        self._test_cinder_add_extend(is_multi_store=True)

    def test_cinder_add_extend_online(self):
        self._test_cinder_add_extend(is_multi_store=True, online=True)

    def test_cinder_delete(self):
        self._test_cinder_delete(is_multi_store=True)

    def test_set_url_prefix(self):
        self.assertEqual('cinder://cinder1', self.store._url_prefix)

    def test_get_uri(self):
        expected_uri = 'cinder://cinder1/%s' % self.volume_id
        self._test_get_uri(expected_uri)

    def test_parse_uri_valid(self):
        expected_uri = 'cinder://cinder1/%s' % self.volume_id
        self.location.parse_uri(expected_uri)

    def test_parse_uri_invalid(self):
        uri = 'cinder://cinder1/%s' % 'fake_volume'
        self._test_parse_uri_invalid(uri)

    def test_get_root_helper(self):
        self._test_get_root_helper(group='cinder1')

    def test_get_cinderclient_cinder_endpoint_template(self):
        self._test_get_cinderclient_cinder_endpoint_template(
            group='cinder1')
