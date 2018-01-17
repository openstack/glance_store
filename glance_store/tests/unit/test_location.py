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

from glance_store import exceptions
from glance_store import location
from glance_store.tests import base


class TestStoreLocation(base.StoreBaseTest):

    def setUp(self):
        super(TestStoreLocation, self).setUp()

    def test_scheme_validation(self):
        valid_schemas = ("file://", "http://")
        correct_uri = "file://test"
        location.StoreLocation.validate_schemas(correct_uri, valid_schemas)
        incorrect_uri = "fake://test"
        self.assertRaises(exceptions.BadStoreUri,
                          location.StoreLocation.validate_schemas,
                          incorrect_uri, valid_schemas)
