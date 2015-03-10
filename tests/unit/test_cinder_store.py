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

import mock

from oslo_utils import units

import glance_store
from glance_store._drivers import cinder
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from tests.unit import test_store_capabilities


class FakeObject(object):
    def __init__(self, **kwargs):
        for name, value in kwargs.iteritems():
            setattr(self, name, value)


class TestCinderStore(base.StoreBaseTest,
                      test_store_capabilities.TestStoreCapabilitiesChecking):

    def setUp(self):
        super(TestCinderStore, self).setUp()
        self.store = cinder.Store(self.conf)
        self.store.configure()
        self.register_store_schemes(self.store, 'cinder')

    def test_cinder_configure_add(self):
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._check_context, None)

        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._check_context,
                          FakeObject(service_catalog=None))

        self.store._check_context(FakeObject(service_catalog='fake'))

    def test_cinder_get_size(self):
        fake_client = FakeObject(auth_token=None, management_url=None)
        fake_volumes = {'12345678-9012-3455-6789-012345678901':
                        FakeObject(size=5)}

        with mock.patch.object(cinder, 'get_cinderclient') as mocked_cc:
            mocked_cc.return_value = FakeObject(client=fake_client,
                                                volumes=fake_volumes)

            fake_sc = [{u'endpoints': [{u'publicURL': u'foo_public_url'}],
                        u'endpoints_links': [],
                        u'name': u'cinder',
                        u'type': u'volume'}]
            fake_context = FakeObject(service_catalog=fake_sc,
                                      user='fake_uer',
                                      auth_tok='fake_token',
                                      tenant='fake_tenant')

            uri = 'cinder://%s' % fake_volumes.keys()[0]
            loc = location.get_location_from_uri(uri, conf=self.conf)
            image_size = self.store.get_size(loc, context=fake_context)
            self.assertEqual(image_size,
                             fake_volumes.values()[0].size * units.Gi)

    def test_cinder_delete_raise_error(self):
        uri = 'cinder://12345678-9012-3455-6789-012345678901'
        loc = location.get_location_from_uri(uri, conf=self.conf)
        self.assertRaises(exceptions.StoreDeleteNotSupported,
                          self.store.delete, loc)
        self.assertRaises(exceptions.StoreDeleteNotSupported,
                          glance_store.delete_from_backend, uri, {})

    def test_cinder_add_raise_error(self):
        self.assertRaises(exceptions.StoreAddDisabled,
                          self.store.add, None, None, None, None)
        self.assertRaises(exceptions.StoreAddDisabled,
                          glance_store.add_to_backend, None, None,
                          None, None, 'cinder')
