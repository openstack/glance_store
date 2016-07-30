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


import logging
import shutil
import tempfile

from oslo_config import cfg

from glance_store.tests.functional import base

CONF = cfg.CONF

logging.basicConfig()


class TestFilesystem(base.BaseFunctionalTests):

    def __init__(self, *args, **kwargs):
        super(TestFilesystem, self).__init__('file', *args, **kwargs)

    def setUp(self):
        self.tmp_image_dir = tempfile.mkdtemp(prefix='glance_store_')
        CONF.set_override('filesystem_store_datadir',
                          self.tmp_image_dir,
                          group='glance_store')
        super(TestFilesystem, self).setUp()

    def tearDown(self):
        shutil.rmtree(self.tmp_image_dir)
        super(TestFilesystem, self).tearDown()
