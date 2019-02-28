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

import pkg_resources
from testtools import matchers

from glance_store import backend
from glance_store.tests import base


def load_entry_point(entry_point, verify_requirements=False):
    """Load an entry-point without requiring dependencies."""
    resolve = getattr(entry_point, 'resolve', None)
    require = getattr(entry_point, 'require', None)
    if resolve is not None and require is not None:
        if verify_requirements:
            entry_point.require()
        return entry_point.resolve()
    else:
        return entry_point.load(require=verify_requirements)


class OptsTestCase(base.StoreBaseTest):

    def _check_opt_groups(self, opt_list, expected_opt_groups):
        self.assertThat(opt_list, matchers.HasLength(len(expected_opt_groups)))

        groups = [g for (g, _l) in opt_list]
        self.assertThat(groups, matchers.HasLength(len(expected_opt_groups)))

        for idx, group in enumerate(groups):
            self.assertEqual(expected_opt_groups[idx], group)

    def _check_opt_names(self, opt_list, expected_opt_names):
        opt_names = [o.name for (g, l) in opt_list for o in l]
        self.assertThat(opt_names, matchers.HasLength(len(expected_opt_names)))

        for opt in opt_names:
            self.assertIn(opt, expected_opt_names)

    def _test_entry_point(self, namespace,
                          expected_opt_groups, expected_opt_names):
        opt_list = None
        for ep in pkg_resources.iter_entry_points('oslo.config.opts'):
            if ep.name == namespace:
                list_fn = load_entry_point(ep)
                opt_list = list_fn()
                break

        self.assertIsNotNone(opt_list)

        self._check_opt_groups(opt_list, expected_opt_groups)
        self._check_opt_names(opt_list, expected_opt_names)

    def test_list_api_opts(self):
        opt_list = backend._list_opts()
        expected_opt_groups = ['glance_store', 'glance_store']
        expected_opt_names = [
            'default_store',
            'stores',
            'store_capabilities_update_min_interval',
            'cinder_api_insecure',
            'cinder_ca_certificates_file',
            'cinder_catalog_info',
            'cinder_endpoint_template',
            'cinder_http_retries',
            'cinder_os_region_name',
            'cinder_state_transition_timeout',
            'cinder_store_auth_address',
            'cinder_store_user_name',
            'cinder_store_password',
            'cinder_store_project_name',
            'cinder_volume_type',
            'default_swift_reference',
            'https_insecure',
            'filesystem_store_chunk_size',
            'filesystem_store_datadir',
            'filesystem_store_datadirs',
            'filesystem_store_file_perm',
            'filesystem_store_metadata_file',
            'http_proxy_information',
            'https_ca_certificates_file',
            'rbd_store_ceph_conf',
            'rbd_store_chunk_size',
            'rbd_store_pool',
            'rbd_store_user',
            'rados_connect_timeout',
            'rootwrap_config',
            'swift_store_expire_soon_interval',
            'sheepdog_store_address',
            'sheepdog_store_chunk_size',
            'sheepdog_store_port',
            'swift_store_admin_tenants',
            'swift_store_auth_address',
            'swift_store_cacert',
            'swift_store_auth_insecure',
            'swift_store_auth_version',
            'swift_store_config_file',
            'swift_store_container',
            'swift_store_create_container_on_put',
            'swift_store_endpoint',
            'swift_store_endpoint_type',
            'swift_store_key',
            'swift_store_large_object_chunk_size',
            'swift_store_large_object_size',
            'swift_store_multi_tenant',
            'swift_store_multiple_containers_seed',
            'swift_store_region',
            'swift_store_retry_get_count',
            'swift_store_service_type',
            'swift_store_ssl_compression',
            'swift_store_use_trusts',
            'swift_store_user',
            'swift_buffer_on_upload',
            'swift_upload_buffer_dir',
            'vmware_insecure',
            'vmware_ca_file',
            'vmware_api_retry_count',
            'vmware_datastores',
            'vmware_server_host',
            'vmware_server_password',
            'vmware_server_username',
            'vmware_store_image_dir',
            'vmware_task_poll_interval'
        ]

        self._check_opt_groups(opt_list, expected_opt_groups)
        self._check_opt_names(opt_list, expected_opt_names)
        self._test_entry_point('glance.store',
                               expected_opt_groups, expected_opt_names)
