# Copyright 2011 OpenStack Foundation
# Copyright 2014 Red Hat, Inc
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

import os
import shutil

import fixtures
from oslo_config import cfg
from oslotest import base

import glance_store as store
from glance_store import location


class StoreBaseTest(base.BaseTestCase):

    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    def setUp(self):
        super(StoreBaseTest, self).setUp()
        self.conf = self._CONF
        self.conf(args=[])
        store.register_opts(self.conf)
        self.config(stores=[])

        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_MAP = {}

        store.create_stores(self.conf)
        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_MAP', dict())
        self.test_dir = self.useFixture(fixtures.TempDir()).path
        self.addCleanup(self.conf.reset)

    def copy_data_file(self, file_name, dst_dir):
        src_file_name = os.path.join('glance_store/tests/etc', file_name)
        shutil.copy(src_file_name, dst_dir)
        dst_file_name = os.path.join(dst_dir, file_name)
        return dst_file_name

    def config(self, **kw):
        """Override some configuration values.

        The keyword arguments are the names of configuration options to
        override and their values.

        If a group argument is supplied, the overrides are applied to
        the specified configuration option group.

        All overrides are automatically cleared at the end of the current
        test by the fixtures cleanup process.
        """
        group = kw.pop('group', 'glance_store')
        for k, v in kw.items():
            self.conf.set_override(k, v, group)

    def register_store_schemes(self, store, store_entry):
        schemes = store.get_schemes()
        scheme_map = {}

        loc_cls = store.get_store_location_class()
        for scheme in schemes:
            scheme_map[scheme] = {
                'store': store,
                'location_class': loc_cls,
                'store_entry': store_entry
            }
        location.register_scheme_map(scheme_map)


class MultiStoreBaseTest(base.BaseTestCase):

    def copy_data_file(self, file_name, dst_dir):
        src_file_name = os.path.join('glance_store/tests/etc', file_name)
        shutil.copy(src_file_name, dst_dir)
        dst_file_name = os.path.join(dst_dir, file_name)
        return dst_file_name

    def config(self, **kw):
        """Override some configuration values.

        The keyword arguments are the names of configuration options to
        override and their values.

        If a group argument is supplied, the overrides are applied to
        the specified configuration option group.

        All overrides are automatically cleared at the end of the current
        test by the fixtures cleanup process.
        """
        group = kw.pop('group', None)
        for k, v in kw.items():
            if group:
                self.conf.set_override(k, v, group)
            else:
                self.conf.set_override(k, v)

    def register_store_backend_schemes(self, store, store_entry,
                                       store_identifier):
        schemes = store.get_schemes()
        scheme_map = {}

        loc_cls = store.get_store_location_class()
        for scheme in schemes:
            scheme_map[scheme] = {}
            scheme_map[scheme][store_identifier] = {
                'store': store,
                'location_class': loc_cls,
                'store_entry': store_entry
            }
        location.register_scheme_backend_map(scheme_map)
