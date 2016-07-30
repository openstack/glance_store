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
import random
import time

from oslo_config import cfg
import swiftclient

from glance_store.tests.functional import base

CONF = cfg.CONF

logging.basicConfig()


class TestSwift(base.BaseFunctionalTests):

    def __init__(self, *args, **kwargs):
        super(TestSwift, self).__init__('swift', *args, **kwargs)

        self.auth = self.config.get('admin', 'auth_address')
        user = self.config.get('admin', 'user')
        self.key = self.config.get('admin', 'key')
        self.region = self.config.get('admin', 'region')

        self.tenant, self.username = user.split(':')

        CONF.set_override('swift_store_user',
                          user,
                          group='glance_store')
        CONF.set_override('swift_store_auth_address',
                          self.auth,
                          group='glance_store')
        CONF.set_override('swift_store_key',
                          self.key,
                          group='glance_store')
        CONF.set_override('swift_store_create_container_on_put',
                          True,
                          group='glance_store')
        CONF.set_override('swift_store_region',
                          self.region,
                          group='glance_store')
        CONF.set_override('swift_store_create_container_on_put',
                          True,
                          group='glance_store')

    def setUp(self):
        self.container = ("glance_store_container_" +
                          str(int(random.random() * 1000)))

        CONF.set_override('swift_store_container',
                          self.container,
                          group='glance_store')

        super(TestSwift, self).setUp()

    def tearDown(self):
        for x in range(1, 4):
            time.sleep(x)
            try:
                swift = swiftclient.client.Connection(auth_version='2',
                                                      user=self.username,
                                                      key=self.key,
                                                      tenant_name=self.tenant,
                                                      authurl=self.auth)
                _, objects = swift.get_container(self.container)
                for obj in objects:
                    swift.delete_object(self.container, obj.get('name'))
                swift.delete_container(self.container)
            except Exception:
                if x < 3:
                    pass
                else:
                    raise
            else:
                break
        super(TestSwift, self).tearDown()
