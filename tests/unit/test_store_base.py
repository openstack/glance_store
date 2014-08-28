# Copyright 2011-2013 OpenStack Foundation
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

import glance_store as store
from glance_store import driver
from glance_store.openstack.common.gettextutils import _
from glance_store.tests import base


class TestStoreBase(base.StoreBaseTest):

    def setUp(self):
        super(TestStoreBase, self).setUp()
        self.config(default_store='file', group='glance_store')

    def test_exception_to_unicode(self):
        class FakeException(Exception):
            def __str__(self):
                raise UnicodeError()

        exc = Exception('error message')
        ret = driver._exception_to_unicode(exc)
        self.assertIsInstance(ret, unicode)
        self.assertEqual(ret, 'error message')

        exc = Exception('\xa5 error message')
        ret = driver._exception_to_unicode(exc)
        self.assertIsInstance(ret, unicode)
        self.assertEqual(ret, ' error message')

        exc = FakeException('\xa5 error message')
        ret = driver._exception_to_unicode(exc)
        self.assertIsInstance(ret, unicode)
        self.assertEqual(ret, _("Caught '%(exception)s' exception.") %
                         {'exception': 'FakeException'})

    def test_create_store_exclude_unconfigurable_drivers(self):
        self.config(stores=["no_conf", "file"], group='glance_store')
        count = store.create_stores(self.conf)
        self.assertEqual(count, 1)
