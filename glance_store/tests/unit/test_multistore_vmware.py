# Copyright 2018 RedHat Inc.
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

"""Tests the Multiple VMware Datastore backend store"""

from unittest import mock
import uuid

from oslo_config import cfg
from oslo_utils import units
from oslo_vmware.objects import datacenter as oslo_datacenter
from oslo_vmware.objects import datastore as oslo_datastore

import glance_store as store
import glance_store._drivers.vmware_datastore as vm_store
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities
from glance_store.tests.unit import test_vmware_store_base as vmware_base

FAKE_UUID = str(uuid.uuid4())

FIVE_KB = 5 * units.Ki

VMWARE_DS = {
    'debug': True,
    'vmware_server_host': '127.0.0.1',
    'vmware_server_username': 'username',
    'vmware_server_password': 'password',
    'vmware_store_image_dir': '/openstack_glance',
    'vmware_insecure': 'True',
    'vmware_datastores': ['a:b:0'],
}


def format_location(host_ip, folder_name, image_id, datastores):
    """
    Helper method that returns a VMware Datastore store URI given
    the component pieces.
    """
    scheme = 'vsphere'
    (datacenter_path, datastore_name, weight) = datastores[0].split(':')
    return ("%s://%s/folder%s/%s?dcPath=%s&dsName=%s"
            % (scheme, host_ip, folder_name,
               image_id, datacenter_path, datastore_name))


def fake_datastore_obj(*args, **kwargs):
    dc_obj = oslo_datacenter.Datacenter(ref='fake-ref',
                                        name='fake-name')
    dc_obj.path = args[0]
    return oslo_datastore.Datastore(ref='fake-ref',
                                    datacenter=dc_obj,
                                    name=args[1])


class TestMultiStore(base.MultiStoreBaseTest,
                     vmware_base.TestVMwareStoreBase,
                     test_store_capabilities.TestStoreCapabilitiesChecking):
    # NOTE(flaper87): temporary until we
    # can move to a fully-local lib.
    # (Swift store's fault)
    _CONF = cfg.ConfigOpts()

    @mock.patch.object(vm_store.Store, '_get_datastore')
    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def setUp(self, mock_api_session, mock_get_datastore):
        """Establish a clean test environment."""
        super(TestMultiStore, self).setUp()

        # Set class attributes for multistore and backend
        self.multistore = True
        self.backend = 'vmware1'

        enabled_backends = {
            "vmware1": "vmware",
            "vmware2": "vmware"
        }
        self.hash_algo = 'sha256'
        self.conf = self._CONF
        self.conf(args=[])
        self.conf.register_opt(cfg.DictOpt('enabled_backends'))
        self.config(enabled_backends=enabled_backends)
        store.register_store_opts(self.conf)
        self.config(default_backend='vmware1', group='glance_store')

        # set vmware related config options
        self.config(group='vmware1',
                    vmware_server_username='admin',
                    vmware_server_password='admin',
                    vmware_server_host='127.0.0.1',
                    vmware_insecure='True',
                    vmware_datastores=['a:b:0'],
                    vmware_store_image_dir='/openstack_glance')

        self.config(group='vmware2',
                    vmware_server_username='admin',
                    vmware_server_password='admin',
                    vmware_server_host='127.0.0.1',
                    vmware_insecure='True',
                    vmware_datastores=['a:b:1'],
                    vmware_store_image_dir='/openstack_glance_1')
        # Ensure stores + locations cleared
        location.SCHEME_TO_CLS_BACKEND_MAP = {}
        store.create_multi_stores(self.conf)

        self.addCleanup(setattr, location, 'SCHEME_TO_CLS_BACKEND_MAP',
                        dict())
        self.addCleanup(self.conf.reset)

        vm_store.Store.CHUNKSIZE = 2

        mock_get_datastore.side_effect = fake_datastore_obj

        self.store = vm_store.Store(self.conf, backend="vmware1")
        self.store.configure()

    def _mock_http_connection(self):
        return mock.patch('http.client.HTTPConnection')

    def test_location_url_prefix_is_set(self):
        """Test that the location URL prefix is set correctly."""
        expected_url_prefix = "vsphere://127.0.0.1/openstack_glance"
        self.assertEqual(expected_url_prefix, self.store.url_prefix)

    def test_get(self):
        """Test a "normal" retrieval of an image in chunks."""
        self._test_get()

    def test_get_random_access(self):
        """Test a "normal" retrieval of an image in chunks."""
        # First add an image...
        self._test_get_random_access()

    def test_get_non_existing(self):
        """Test trying to retrieve a file that doesn't exist raises error."""
        self._test_get_non_existing()

    def test_get_non_existing_identifier(self):
        """Test trying to retrieve a store that doesn't exist raises error."""
        self.assertRaises(exceptions.UnknownScheme,
                          location.get_location_from_uri_and_backend,
                          "vsphere:///127.0.0.1/non-existing",
                          'vmware3', conf=self.conf)

    def test_add(self):
        """Test that we can add an image via the VMware backend."""
        self._test_add()

    def test_add_size_zero(self):
        """
        Test that when specifying size zero for the image to add,
        the actual size of the image is returned.
        """
        self._test_add_size_zero()

    def test_add_with_verifier(self):
        """Test that the verifier is passed to the _Reader during add."""
        self._test_add_with_verifier()

    def test_add_with_verifier_size_zero(self):
        """Test that the verifier is passed to the _ChunkReader during add."""
        self._test_add_with_verifier_size_zero()

    def test_delete(self):
        """Test we can delete an existing image in the VMware store."""
        self._test_delete()

    def test_delete_non_existing(self):
        """
        Test that trying to delete an image that doesn't exist raises an error
        """
        self._test_delete_non_existing()

    def test_get_size(self):
        """
        Test we can get the size of an existing image in the VMware store
        """
        self._test_get_size()

    def test_get_size_non_existing(self):
        """
        Test that trying to retrieve an image size that doesn't exist
        raises an error
        """
        self._test_get_size_non_existing()

    def test_reader_full(self):
        """Test the reader reads full content correctly."""
        self._test_reader_full()

    def test_reader_partial(self):
        """Test the reader reads partial content correctly."""
        self._test_reader_partial()

    def test_reader_with_verifier(self):
        """Test the reader works with verifier."""
        self._test_reader_with_verifier()

    def test_sanity_check_multiple_datastores(self):
        """Test sanity check with multiple datastores."""
        self.config(group='vmware1', vmware_api_retry_count=1)
        self.config(group='vmware1', vmware_task_poll_interval=1)
        self.config(group='vmware1', vmware_datastores=['a:b:0', 'a:d:0'])
        try:
            self.store._sanity_check()
        except exceptions.BadStoreConfiguration:
            self.fail()

    def test_parse_datastore_info_and_weight_less_opts(self):
        """Test parsing datastore with less options."""
        self._test_parse_datastore_info_and_weight_less_opts()

    def test_parse_datastore_info_and_weight_invalid_weight(self):
        """Test parsing datastore with invalid weight."""
        self._test_parse_datastore_info_and_weight_invalid_weight()

    def test_parse_datastore_info_and_weight_empty_opts(self):
        """Test parsing datastore with empty options."""
        self._test_parse_datastore_info_and_weight_empty_opts()

    def test_parse_datastore_info_and_weight(self):
        """Test parsing datastore with valid options."""
        self._test_parse_datastore_info_and_weight()

    def test_parse_datastore_info_and_weight_default_weight(self):
        """Test parsing datastore with default weight."""
        self._test_parse_datastore_info_and_weight_default_weight()

    def test_unexpected_status(self):
        """Test handling of unexpected HTTP status."""
        self._test_unexpected_status()

    def test_unexpected_status_no_response_body(self):
        """Test handling of unexpected HTTP status with no response body."""
        self._test_unexpected_status_no_response_body()

    def test_reset_session(self):
        """Test resetting the session."""
        self._test_reset_session()

    def test_build_vim_cookie_header_active(self):
        """Test building VIM cookie header with active session."""
        self._test_build_vim_cookie_header_active()

    def test_build_vim_cookie_header_expired(self):
        """Test building VIM cookie header with expired session."""
        self._test_build_vim_cookie_header_expired()

    def test_build_vim_cookie_header_expired_noverify(self):
        """Test building VIM cookie header with expired session no verify."""
        self._test_build_vim_cookie_header_expired_noverify()

    def test_add_ioerror(self):
        """Test handling of IOError during add."""
        self._test_add_ioerror()

    def test_qs_sort_with_literal_question_mark(self):
        """Test URL sorting with literal question mark."""
        self._test_qs_sort_with_literal_question_mark()

    def test_build_datastore_weighted_map(self):
        """Test building datastore weighted map."""
        self._test_build_datastore_weighted_map()

    def test_build_datastore_weighted_map_equal_weight(self):
        """Test building datastore weighted map with equal weights."""
        self._test_build_datastore_weighted_map_equal_weight()

    def test_build_datastore_weighted_map_empty_list(self):
        """Test building datastore weighted map with empty list."""
        self._test_build_datastore_weighted_map_empty_list()

    def test_select_datastore_insufficient_freespace(self):
        """Test selecting datastore with insufficient free space."""
        self._test_select_datastore_insufficient_freespace()

    def test_select_datastore_insufficient_fs_one_ds(self):
        """Test selecting datastore with less free space on one datastore."""
        self._test_select_datastore_insufficient_fs_one_ds()

    def test_select_datastore_equal_freespace(self):
        """Test selecting datastore with equal free space."""
        self._test_select_datastore_equal_freespace()

    def test_select_datastore_contention(self):
        """Test selecting datastore with contention."""
        self._test_select_datastore_contention()

    def test_select_datastore_empty_list(self):
        """Test selecting datastore with empty list."""
        self._test_select_datastore_empty_list()

    def test_get_datacenter_ref(self):
        """Test getting datacenter reference."""
        self._test_get_datacenter_ref()

    def test_http_get_redirect(self):
        """Test HTTP GET with redirects."""
        self._test_http_get_redirect()

    def test_http_get_max_redirects(self):
        """Test HTTP GET with max redirects exceeded."""
        self._test_http_get_max_redirects()

    def test_http_get_redirect_invalid(self):
        """Test HTTP GET with invalid redirect."""
        self._test_http_get_redirect_invalid()
