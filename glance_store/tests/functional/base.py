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

import io
from os import environ

import glance_store
import os_client_config
from oslo_config import cfg
import testtools

CONF = cfg.CONF

UUID1 = '961973d8-3360-4364-919e-2c197825dbb4'
UUID2 = 'e03cf3b1-3070-4497-a37d-9703edfb615b'
UUID3 = '0d7f89b2-e236-45e9-b081-561cd3102e92'
UUID4 = '165e9681-ea56-46b0-a84c-f148c752ef8b'
IMAGE_BITS = b'I am a bootable image, I promise'


class Base(testtools.TestCase):

    def __init__(self, driver_name, *args, **kwargs):
        super(Base, self).__init__(*args, **kwargs)
        self.driver_name = driver_name

        # check whether a particular cloud should be used
        cloud = environ.get('OS_TEST_GLANCE_STORE_FUNC_TEST_CLOUD',
                            'devstack-admin')
        creds = os_client_config.OpenStackConfig().get_one_cloud(
            cloud=cloud)
        auth = creds.get_auth_args()
        self.username = auth["username"]
        self.password = auth["password"]
        self.project_name = auth["project_name"]
        self.user_domain_id = auth["user_domain_id"]
        self.project_domain_id = auth["project_domain_id"]
        self.keystone_version = creds.get_api_version('identity')
        self.cinder_version = creds.get_api_version('volume')
        self.region_name = creds.get_region_name()
        # auth_url in devstack clouds.yaml is unversioned
        if auth["auth_url"].endswith('/v3'):
            self.auth_url = auth["auth_url"]
        else:
            self.auth_url = '{}/v3'.format(auth["auth_url"])

        # finally, load the configuration options
        glance_store.register_opts(CONF)

    def setUp(self):
        super(Base, self).setUp()

        CONF.set_override('stores', [self.driver_name], group='glance_store')
        CONF.set_override('default_store',
                          self.driver_name,
                          group='glance_store'
                          )
        glance_store.create_stores()
        self.store = glance_store.backend._load_store(CONF, self.driver_name)
        self.store.configure()


class BaseFunctionalTests(Base):

    def test_add(self):
        image_file = io.BytesIO(IMAGE_BITS)
        loc, written, _, _ = self.store.add(UUID1, image_file, len(IMAGE_BITS))
        self.assertEqual(len(IMAGE_BITS), written)

    def test_delete(self):
        image_file = io.BytesIO(IMAGE_BITS)
        loc, written, _, _ = self.store.add(UUID2, image_file, len(IMAGE_BITS))
        location = glance_store.location.get_location_from_uri(loc)

        self.store.delete(location)

    def test_get_size(self):
        image_file = io.BytesIO(IMAGE_BITS)
        loc, written, _, _ = self.store.add(UUID3, image_file, len(IMAGE_BITS))
        location = glance_store.location.get_location_from_uri(loc)

        size = self.store.get_size(location)
        self.assertEqual(len(IMAGE_BITS), size)

    def test_get(self):
        image_file = io.BytesIO(IMAGE_BITS)
        loc, written, _, _ = self.store.add(UUID3, image_file, len(IMAGE_BITS))
        location = glance_store.location.get_location_from_uri(loc)

        image, size = self.store.get(location)

        self.assertEqual(len(IMAGE_BITS), size)

        data = b''
        for chunk in image:
            data += chunk

        self.assertEqual(IMAGE_BITS, data)
