# Copyright 2026 OpenStack Foundation
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

import importlib.metadata
from unittest import mock

from oslo_config import cfg
from oslotest import base

from glance_store import multi_backend


class TestRegisterStoreOpts(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.conf = cfg.ConfigOpts()
        self.conf([])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))

    def _register(self, enabled_backends, reserved_stores=None):
        self.conf.set_override('enabled_backends', enabled_backends)
        with mock.patch.object(multi_backend, '_load_multi_store',
                               wraps=multi_backend._load_multi_store) as m:
            multi_backend.register_store_opts(
                self.conf, reserved_stores=reserved_stores)
        return m

    def test_only_configured_drivers_are_loaded(self):
        m = self._register({'fast': 'file', 'cheap': 'file', 'web': 'http'})

        self.assertEqual(
            sorted(['file', 'file', 'http']),
            sorted(c.args[1] for c in m.call_args_list))
        self.assertIn('filesystem_store_datadir', self.conf.fast)
        self.assertIn('filesystem_store_datadir', self.conf.cheap)
        self.assertIn('http_proxy_information', self.conf.web)

    def test_unconfigured_drivers_are_not_imported(self):
        loaded = []
        orig_load = importlib.metadata.EntryPoint.load

        def load(ep):
            loaded.append(ep.name)
            return orig_load(ep)

        with mock.patch.object(importlib.metadata.EntryPoint, 'load', load):
            self._register({'fast': 'file'})

        self.assertEqual(['file'], loaded)

    def test_unknown_store_type_is_skipped(self):
        self._register({'fast': 'file', 'bogus': 'no-such-store'})

        self.assertIn('filesystem_store_datadir', self.conf.fast)
        self.assertRaises(cfg.NoSuchOptError, getattr, self.conf, 'bogus')

    def test_reserved_stores_are_registered(self):
        self._register({'fast': 'file'},
                       reserved_stores={'os_glance_staging_store': 'file'})

        self.assertIn('filesystem_store_datadir',
                      self.conf.os_glance_staging_store)
