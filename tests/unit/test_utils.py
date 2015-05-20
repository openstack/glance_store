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

from oslotest import base
import six

from glance_store.common import utils


class TestUtils(base.BaseTestCase):
    """Test routines in glance_store.common.utils."""

    def test_exception_to_str(self):
        class FakeException(Exception):
            def __str__(self):
                raise UnicodeError()

        ret = utils.exception_to_str(Exception('error message'))
        self.assertEqual(ret, 'error message')

        ret = utils.exception_to_str(FakeException('\xa5 error message'))
        self.assertEqual(ret, "Caught '%(exception)s' exception." %
                         {'exception': 'FakeException'})

    def test_exception_to_str_ignore(self):
        if six.PY3:
            # On Python 3, exception messages are unicode strings, they are not
            # decoded from an encoding and so it's not possible to test the
            # "ignore" error handler
            self.skipTest("test specific to Python 2")
        ret = utils.exception_to_str(Exception('\xa5 error message'))
        self.assertEqual(ret, ' error message')
