# Copyright 2014 OpenStack Foundation
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

import mock

from glance_store._drivers.swift import connection_manager
from glance_store._drivers.swift import store as swift_store
from glance_store import exceptions
from glance_store.tests import base


class TestConnectionManager(base.StoreBaseTest):
    def setUp(self):
        super(TestConnectionManager, self).setUp()
        self.client = mock.MagicMock()
        self.client.session.get_auth_headers.return_value = {
            connection_manager.SwiftConnectionManager.AUTH_HEADER_NAME:
                "fake_token"}

        self.location = mock.create_autospec(swift_store.StoreLocation)
        self.context = mock.MagicMock()
        self.conf = mock.MagicMock()

    def prepare_store(self, multi_tenant=False):
        if multi_tenant:
            store = mock.create_autospec(swift_store.MultiTenantStore,
                                         conf=self.conf)
        else:
            store = mock.create_autospec(swift_store.SingleTenantStore,
                                         service_type="swift",
                                         endpoint_type="internal",
                                         region=None,
                                         conf=self.conf,
                                         auth_version='3')

        store.backend_group = None
        store.init_client.return_value = self.client
        return store

    def test_basic_single_tenant_cm_init(self):
        store = self.prepare_store()
        manager = connection_manager.SingleTenantConnectionManager(
            store=store,
            store_location=self.location
        )
        store.init_client.assert_called_once_with(self.location, None)
        self.client.session.get_endpoint.assert_called_once_with(
            service_type=store.service_type,
            interface=store.endpoint_type,
            region_name=store.region
        )
        store.get_store_connection.assert_called_once_with(
            "fake_token", manager.storage_url
        )

    def test_basic_multi_tenant_cm_init(self):
        store = self.prepare_store(multi_tenant=True)
        manager = connection_manager.MultiTenantConnectionManager(
            store=store,
            store_location=self.location,
            context=self.context
        )
        store.get_store_connection.assert_called_once_with(
            self.context.auth_token, manager.storage_url)

    def test_basis_multi_tenant_no_context(self):
        store = self.prepare_store(multi_tenant=True)
        self.assertRaises(exceptions.BadStoreConfiguration,
                          connection_manager.MultiTenantConnectionManager,
                          store=store, store_location=self.location)

    def test_multi_tenant_client_cm_with_client_creation_fails(self):
        store = self.prepare_store(multi_tenant=True)
        store.init_client.side_effect = [Exception]
        manager = connection_manager.MultiTenantConnectionManager(
            store=store,
            store_location=self.location,
            context=self.context,
            allow_reauth=True
        )
        store.init_client.assert_called_once_with(self.location,
                                                  self.context)
        store.get_store_connection.assert_called_once_with(
            self.context.auth_token, manager.storage_url)
        self.assertFalse(manager.allow_reauth)

    def test_multi_tenant_client_cm_with_no_expiration(self):
        store = self.prepare_store(multi_tenant=True)
        manager = connection_manager.MultiTenantConnectionManager(
            store=store,
            store_location=self.location,
            context=self.context,
            allow_reauth=True
        )
        store.init_client.assert_called_once_with(self.location,
                                                  self.context)
        # return the same connection because it should not be expired
        auth_ref = mock.MagicMock()
        self.client.session.auth.auth_ref = auth_ref
        auth_ref.will_expire_soon.return_value = False
        manager.get_connection()
        # check that we don't update connection
        store.get_store_connection.assert_called_once_with("fake_token",
                                                           manager.storage_url)
        self.client.session.get_auth_headers.assert_called_once_with()

    def test_multi_tenant_client_cm_with_expiration(self):
        store = self.prepare_store(multi_tenant=True)
        manager = connection_manager.MultiTenantConnectionManager(
            store=store,
            store_location=self.location,
            context=self.context,
            allow_reauth=True
        )
        store.init_client.assert_called_once_with(self.location,
                                                  self.context)
        # return the same connection because it should not be expired
        auth_ref = mock.MagicMock()
        self.client.session.auth.get_auth_ref.return_value = auth_ref
        auth_ref.will_expire_soon.return_value = True
        manager.get_connection()
        # check that we don't update connection
        self.assertEqual(2, store.get_store_connection.call_count)
        self.assertEqual(2, self.client.session.get_auth_headers.call_count)

    def test_single_tenant_client_cm_with_no_expiration(self):
        store = self.prepare_store()
        manager = connection_manager.SingleTenantConnectionManager(
            store=store,
            store_location=self.location,
            allow_reauth=True
        )
        store.init_client.assert_called_once_with(self.location, None)
        self.client.session.get_endpoint.assert_called_once_with(
            service_type=store.service_type,
            interface=store.endpoint_type,
            region_name=store.region
        )
        # return the same connection because it should not be expired
        auth_ref = mock.MagicMock()
        self.client.session.auth.auth_ref = auth_ref
        auth_ref.will_expire_soon.return_value = False
        manager.get_connection()
        # check that we don't update connection
        store.get_store_connection.assert_called_once_with("fake_token",
                                                           manager.storage_url)
        self.client.session.get_auth_headers.assert_called_once_with()

    def test_single_tenant_client_cm_with_expiration(self):
        store = self.prepare_store()
        manager = connection_manager.SingleTenantConnectionManager(
            store=store,
            store_location=self.location,
            allow_reauth=True
        )
        store.init_client.assert_called_once_with(self.location, None)
        self.client.session.get_endpoint.assert_called_once_with(
            service_type=store.service_type,
            interface=store.endpoint_type,
            region_name=store.region
        )
        # return the same connection because it should not be expired
        auth_ref = mock.MagicMock()
        self.client.session.auth.get_auth_ref.return_value = auth_ref
        auth_ref.will_expire_soon.return_value = True
        manager.get_connection()
        # check that we don't update connection
        self.assertEqual(2, store.get_store_connection.call_count)
        self.assertEqual(2, self.client.session.get_auth_headers.call_count)
