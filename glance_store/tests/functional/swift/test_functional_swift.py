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

from keystoneauth1.identity import v3
from keystoneauth1 import session
from oslo_config import cfg
import swiftclient

from glance_store.tests.functional import base

CONF = cfg.CONF

logging.basicConfig()


class TestSwift(base.BaseFunctionalTests):

    def __init__(self, *args, **kwargs):
        super(TestSwift, self).__init__('swift', *args, **kwargs)

        CONF.set_override('swift_store_user',
                          '{1}:{0}'.format(self.username, self.project_name),
                          group='glance_store')
        CONF.set_override('swift_store_auth_address',
                          self.auth_url,
                          group='glance_store')
        CONF.set_override('swift_store_auth_version',
                          self.keystone_version,
                          group='glance_store')
        CONF.set_override('swift_store_key',
                          self.password,
                          group='glance_store')
        CONF.set_override('swift_store_region',
                          self.region_name,
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
        auth = v3.Password(auth_url=self.auth_url,
                           username=self.username,
                           password=self.password,
                           project_name=self.project_name,
                           user_domain_id=self.user_domain_id,
                           project_domain_id=self.project_domain_id)
        sess = session.Session(auth=auth)
        swift = swiftclient.client.Connection(session=sess)

        for x in range(1, 4):
            time.sleep(x)
            try:
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
