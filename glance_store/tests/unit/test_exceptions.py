# Copyright 2015 OpenStack Foundation
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
from oslotest import base

import glance_store


class TestExceptions(base.BaseTestCase):
    """Test routines in glance_store.common.utils."""
    def test_backend_exception(self):
        msg = glance_store.BackendException()
        self.assertIn('', str(msg))

    def test_unsupported_backend_exception(self):
        msg = glance_store.UnsupportedBackend()
        self.assertIn('', str(msg))

    def test_redirect_exception(self):
        # Just checks imports work ok
        glance_store.RedirectException(url='http://localhost')

    def test_exception_no_message(self):
        msg = glance_store.NotFound()
        self.assertIn('Image %(image)s not found', str(msg))

    def test_exception_not_found_with_image(self):
        msg = glance_store.NotFound(image='123')
        self.assertIn('Image 123 not found', str(msg))

    def test_exception_with_message(self):
        msg = glance_store.NotFound('Some message')
        self.assertIn('Some message', str(msg))

    def test_exception_with_kwargs(self):
        msg = glance_store.NotFound('Message: %(foo)s', foo='bar')
        self.assertIn('Message: bar', str(msg))
