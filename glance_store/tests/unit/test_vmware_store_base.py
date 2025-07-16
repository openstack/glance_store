# Copyright 2025 RedHat Inc.
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

import hashlib
import io
from unittest import mock
import uuid

from oslo_utils import units
from oslo_vmware import api
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware.objects import datacenter as oslo_datacenter
from oslo_vmware.objects import datastore as oslo_datastore

import glance_store._drivers.vmware_datastore as vm_store
from glance_store import exceptions
from glance_store import location
from glance_store.tests import utils


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


class TestVMwareStoreBase(object):

    def _test_get(self):
        """Test a "normal" retrieval of an image in chunks."""
        expected_image_size = 31
        expected_returns = ['I am a teapot, short and stout\n']
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                "vsphere://127.0.0.1/folder/openstack_glance/%s"
                "?dsName=ds1&dcPath=dc1" % FAKE_UUID, self.backend,
                conf=self.conf)
        else:
            loc = location.get_location_from_uri(
                "vsphere://127.0.0.1/folder/openstack_glance/%s"
                "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response()
            (image_file, image_size) = self.store.get(loc)
        self.assertEqual(expected_image_size, image_size)
        chunks = [c for c in image_file]
        self.assertEqual(expected_returns, chunks)

    def _test_get_random_access(self):
        """Test a "normal" retrieval of an image in chunks."""
        expected_image_size = 31
        expected_returns = ['I am a teapot, short and stout\n']
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                "vsphere://127.0.0.1/folder/openstack_glance/%s"
                "?dsName=ds1&dcPath=dc1" % FAKE_UUID, self.backend,
                conf=self.conf)
        else:
            loc = location.get_location_from_uri(
                "vsphere://127.0.0.1/folder/openstack_glance/%s"
                "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response()
            (image_file, image_size) = self.store.get(loc)
        self.assertEqual(expected_image_size, image_size)
        chunks = [c for c in image_file]
        self.assertEqual(expected_returns, chunks)

    def _test_get_non_existing(self):
        """
        Test that trying to retrieve an image that doesn't exist
        raises an error
        """
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                "vsphere://127.0.0.1/folder/openstack_glance/%s?"
                "dsName=ds1&dcPath=dc1" % FAKE_UUID,
                self.backend, conf=self.conf)
        else:
            loc = location.get_location_from_uri(
                "vsphere://127.0.0.1/folder/openstack_glan"
                "ce/%s?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response(status_code=404)
            self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def _test_add(self):
        """Test that we can add an image via the VMware backend."""
        with mock.patch.object(
                vm_store.Store, '_build_vim_cookie_header') as fake_cookie:
            with mock.patch.object(
                    vm_store.Store,
                    'select_datastore') as fake_select_ds:
                with mock.patch.object(vm_store._Reader, 'size') as fake_size:
                    fake_select_ds.return_value = self.store.datastores[0][0]
                    expected_image_id = str(uuid.uuid4())
                    expected_size = FIVE_KB
                    expected_contents = b"*" * expected_size
                    hash_code = hashlib.md5(
                        expected_contents, usedforsecurity=False)
                    expected_checksum = hash_code.hexdigest()
                    sha256_code = hashlib.sha256(expected_contents)
                    expected_multihash = sha256_code.hexdigest()
                    fake_size.__get__ = mock.Mock(return_value=expected_size)
                    expected_cookie_val = 'vmware_soap_session=fake-uuid'
                    fake_cookie.return_value = expected_cookie_val
                    expected_headers = {'Content-Length': str(expected_size),
                                        'Cookie': expected_cookie_val}
                    with mock.patch('hashlib.md5') as md5:
                        with mock.patch('hashlib.new') as fake_new:
                            md5.return_value = hash_code
                            fake_new.return_value = sha256_code
                            expected_location = format_location(
                                VMWARE_DS['vmware_server_host'],
                                VMWARE_DS['vmware_store_image_dir'],
                                expected_image_id,
                                VMWARE_DS['vmware_datastores'])
                            image = io.BytesIO(expected_contents)
                            with mock.patch(
                                    'requests.Session.request') as HttpConn:
                                HttpConn.return_value = utils.fake_response()
                                if self.multistore:
                                    loc, size, cs, md = self.store.add(
                                        expected_image_id, image,
                                        expected_size)
                                    self.assertEqual(self.backend, md['store'])
                                else:
                                    loc, size, cs, hash, _ = self.store.add(
                                        expected_image_id, image,
                                        expected_size, self.hash_algo)
                                    self.assertEqual(expected_multihash, hash)
                                _, kwargs = HttpConn.call_args
                                self.assertEqual(expected_headers,
                                                 kwargs['headers'])

                    self.assertEqual(
                        utils.sort_url_by_qs_keys(expected_location),
                        utils.sort_url_by_qs_keys(loc))
                    self.assertEqual(expected_size, size)
                    self.assertEqual(expected_checksum, cs)

    def _test_add_size_zero(self):
        """
        Test that when specifying size zero for the image to add,
        the actual size of the image is returned.
        """
        with mock.patch.object(
                vm_store.Store, 'select_datastore') as fake_select_ds:
            with mock.patch.object(vm_store._Reader, 'size') as fake_size:
                fake_select_ds.return_value = self.store.datastores[0][0]
                expected_image_id = str(uuid.uuid4())
                expected_size = FIVE_KB
                expected_contents = b"*" * expected_size
                hash_code = hashlib.md5(
                    expected_contents, usedforsecurity=False)
                expected_checksum = hash_code.hexdigest()
                sha256_code = hashlib.sha256(expected_contents)
                expected_multihash = sha256_code.hexdigest()
                fake_size.__get__ = mock.Mock(return_value=expected_size)
                with mock.patch('hashlib.md5') as md5:
                    with mock.patch('hashlib.new') as fake_new:
                        md5.return_value = hash_code
                        fake_new.return_value = sha256_code
                        expected_location = format_location(
                            VMWARE_DS['vmware_server_host'],
                            VMWARE_DS['vmware_store_image_dir'],
                            expected_image_id,
                            VMWARE_DS['vmware_datastores'])
                        image = io.BytesIO(expected_contents)
                        with mock.patch(
                                'requests.Session.request') as HttpConn:
                            HttpConn.return_value = utils.fake_response()
                            if self.multistore:
                                loc, size, cs, md = self.store.add(
                                    expected_image_id, image, 0)
                                self.assertEqual(self.backend, md['store'])
                            else:
                                loc, size, cs, hash, _ = self.store.add(
                                    expected_image_id, image, 0,
                                    self.hash_algo)
                                self.assertEqual(expected_multihash, hash)

                self.assertEqual(utils.sort_url_by_qs_keys(expected_location),
                                 utils.sort_url_by_qs_keys(loc))
                self.assertEqual(expected_size, size)
                self.assertEqual(expected_checksum, cs)

    def _test_add_with_verifier(self):
        """Test that the verifier is passed to the _Reader during add."""
        verifier = mock.MagicMock(name='mock_verifier')
        with mock.patch.object(
                vm_store.Store, 'select_datastore'):
            with mock.patch(
                    'glance_store._drivers.vmware_datastore._Reader') as fr:
                image_id = str(uuid.uuid4())
                size = FIVE_KB
                contents = b"*" * size
                image = io.BytesIO(contents)
                with mock.patch('requests.Session.request') as HttpConn:
                    HttpConn.return_value = utils.fake_response()
                    self.store.add(image_id, image, size, self.hash_algo,
                                   verifier=verifier)

                fr.assert_called_with(image, self.hash_algo, verifier)

    def _test_add_with_verifier_size_zero(self):
        """Test that the verifier is passed to the _ChunkReader during add."""
        verifier = mock.MagicMock(name='mock_verifier')
        with mock.patch.object(
                vm_store.Store, 'select_datastore'):
            with mock.patch(
                    'glance_store._drivers.vmware_datastore._Reader') as fr:
                image_id = str(uuid.uuid4())
                size = FIVE_KB
                contents = b"*" * size
                image = io.BytesIO(contents)
                with mock.patch('requests.Session.request') as HttpConn:
                    HttpConn.return_value = utils.fake_response()
                    self.store.add(image_id, image, 0, self.hash_algo,
                                   verifier=verifier)

                fr.assert_called_with(image, self.hash_algo, verifier)

    def _test_delete(self):
        """Test we can delete an existing image in the VMware store."""
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                "vsphere://127.0.0.1/folder/openstack_glance/%s?"
                "dsName=ds1&dcPath=dc1" % FAKE_UUID,
                self.backend, conf=self.conf)
        else:
            loc = location.get_location_from_uri(
                "vsphere://127.0.0.1/folder/openstack_glance/%s?"
                "dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response()
            vm_store.Store._service_content = mock.Mock()
            self.store.delete(loc)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response(status_code=404)
            self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def _test_delete_non_existing(self):
        """
        Test that trying to delete an image that doesn't exist raises an error
        """
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                "vsphere://127.0.0.1/folder/openstack_glance/%s?"
                "dsName=ds1&dcPath=dc1" % FAKE_UUID,
                self.backend, conf=self.conf)
        else:
            loc = location.get_location_from_uri(
                "vsphere://127.0.0.1/folder/openstack_glance/%s?"
                "dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch.object(self.store.session,
                               'wait_for_task') as mock_task:
            mock_task.side_effect = vmware_exceptions.FileNotFoundException
            self.assertRaises(exceptions.NotFound, self.store.delete, loc)

    def _test_get_size(self):
        """
        Test we can get the size of an existing image in the VMware store
        """
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                "vsphere://127.0.0.1/folder/openstack_glance/%s?"
                "dsName=ds1&dcPath=dc1" % FAKE_UUID,
                self.backend, conf=self.conf)
        else:
            loc = location.get_location_from_uri(
                "vsphere://127.0.0.1/folder/openstack_glance/%s"
                "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response()
            image_size = self.store.get_size(loc)
        self.assertEqual(image_size, 31)

    def _test_get_size_non_existing(self):
        """
        Test that trying to retrieve an image size that doesn't exist
        raises an error
        """
        if self.multistore:
            loc = location.get_location_from_uri_and_backend(
                "vsphere://127.0.0.1/folder/openstack_glance/%s?"
                "dsName=ds1&dcPath=dc1" % FAKE_UUID,
                self.backend, conf=self.conf)
        else:
            loc = location.get_location_from_uri(
                "vsphere://127.0.0.1/folder/openstack_glan"
                "ce/%s?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response(status_code=404)
            self.assertRaises(exceptions.NotFound, self.store.get_size, loc)

    def _test_reader_full(self):
        """Test the reader reads full content correctly."""
        content = b'XXX'
        image = io.BytesIO(content)
        expected_checksum = hashlib.md5(content,
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(content).hexdigest()
        reader = vm_store._Reader(image, self.hash_algo)
        ret = reader.read()
        self.assertEqual(content, ret)
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertEqual(expected_multihash, reader.os_hash_value.hexdigest())
        self.assertEqual(len(content), reader.size)

    def _test_reader_partial(self):
        """Test the reader reads partial content correctly."""
        content = b'XXX'
        image = io.BytesIO(content)
        expected_checksum = hashlib.md5(b'X',
                                        usedforsecurity=False).hexdigest()
        expected_multihash = hashlib.sha256(b'X').hexdigest()
        reader = vm_store._Reader(image, self.hash_algo)
        ret = reader.read(1)
        self.assertEqual(b'X', ret)
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertEqual(expected_multihash, reader.os_hash_value.hexdigest())
        self.assertEqual(1, reader.size)

    def _test_reader_with_verifier(self):
        """Test the reader works with verifier."""
        content = b'XXX'
        image = io.BytesIO(content)
        verifier = mock.MagicMock(name='mock_verifier')
        reader = vm_store._Reader(image, self.hash_algo, verifier)
        reader.read()
        verifier.update.assert_called_with(content)

    def _test_sanity_check_api_retry_count(self):
        """Test that sanity check raises if api_retry_count is <= 0."""
        self.store.conf.glance_store.vmware_api_retry_count = -1
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._sanity_check)
        self.store.conf.glance_store.vmware_api_retry_count = 0
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._sanity_check)
        self.store.conf.glance_store.vmware_api_retry_count = 1
        try:
            self.store._sanity_check()
        except exceptions.BadStoreConfiguration:
            self.fail()

    def _test_sanity_check_task_poll_interval(self):
        """Test that sanity check raises if task_poll_interval is <= 0."""
        self.store.conf.glance_store.vmware_task_poll_interval = -1
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._sanity_check)
        self.store.conf.glance_store.vmware_task_poll_interval = 0
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._sanity_check)
        self.store.conf.glance_store.vmware_task_poll_interval = 1
        try:
            self.store._sanity_check()
        except exceptions.BadStoreConfiguration:
            self.fail()

    def _test_sanity_check_multiple_datastores(self):
        """Test sanity check with multiple datastores."""
        self.store.conf.glance_store.vmware_api_retry_count = 1
        self.store.conf.glance_store.vmware_task_poll_interval = 1
        self.store.conf.glance_store.vmware_datastores = ['a:b:0', 'a:d:0']
        try:
            self.store._sanity_check()
        except exceptions.BadStoreConfiguration:
            self.fail()

    def _test_parse_datastore_info_and_weight_less_opts(self):
        """Test parsing datastore with less options."""
        datastore = 'a'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._parse_datastore_info_and_weight,
                          datastore)

    def _test_parse_datastore_info_and_weight_invalid_weight(self):
        """Test parsing datastore with invalid weight."""
        datastore = 'a:b:c'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._parse_datastore_info_and_weight,
                          datastore)

    def _test_parse_datastore_info_and_weight_empty_opts(self):
        """Test parsing datastore with empty options."""
        datastore = 'a: :0'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._parse_datastore_info_and_weight,
                          datastore)
        datastore = ':b:0'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._parse_datastore_info_and_weight,
                          datastore)

    def _test_parse_datastore_info_and_weight(self):
        """Test parsing datastore with valid options."""
        datastore = 'a:b:100'
        parts = self.store._parse_datastore_info_and_weight(datastore)
        self.assertEqual('a', parts[0])
        self.assertEqual('b', parts[1])
        self.assertEqual(100, parts[2])

    def _test_parse_datastore_info_and_weight_default_weight(self):
        """Test parsing datastore with default weight."""
        datastore = 'a:b'
        parts = self.store._parse_datastore_info_and_weight(datastore)
        self.assertEqual('a', parts[0])
        self.assertEqual('b', parts[1])
        self.assertEqual(0, parts[2])

    def _test_unexpected_status(self):
        """Test handling of unexpected HTTP status."""
        with mock.patch.object(
                vm_store.Store, 'select_datastore'):
            with mock.patch.object(
                    api, 'VMwareAPISession'):
                expected_image_id = str(uuid.uuid4())
                expected_size = FIVE_KB
                expected_contents = b"*" * expected_size
                image = io.BytesIO(expected_contents)
                self.session = mock.Mock()
                with mock.patch('requests.Session.request') as HttpConn:
                    HttpConn.return_value = utils.fake_response(
                        status_code=401)
                    if self.multistore:
                        self.assertRaises(exceptions.BackendException,
                                          self.store.add,
                                          expected_image_id, image,
                                          expected_size)
                    else:
                        self.assertRaises(exceptions.BackendException,
                                          self.store.add,
                                          expected_image_id, image,
                                          expected_size, self.hash_algo)

    def _test_unexpected_status_no_response_body(self):
        """Test handling of unexpected HTTP status with no response body."""
        with mock.patch.object(
                vm_store.Store, 'select_datastore'):
            with mock.patch.object(
                    api, 'VMwareAPISession'):
                expected_image_id = str(uuid.uuid4())
                expected_size = FIVE_KB
                expected_contents = b"*" * expected_size
                image = io.BytesIO(expected_contents)
                self.session = mock.Mock()
                with mock.patch('http.client.HTTPConnection') as HttpConn:
                    HttpConn.return_value = utils.fake_response(
                        status_code=500, no_response_body=True)
                    if self.multistore:
                        self.assertRaises(exceptions.BackendException,
                                          self.store.add,
                                          expected_image_id, image,
                                          expected_size)
                    else:
                        self.assertRaises(exceptions.BackendException,
                                          self.store.add,
                                          expected_image_id, image,
                                          expected_size, self.hash_algo)

    def _test_reset_session(self):
        """Test resetting the session."""
        with mock.patch.object(api, 'VMwareAPISession') as mock_api_session:
            self.store.reset_session()
            self.assertTrue(mock_api_session.called)

    def _test_build_vim_cookie_header_active(self):
        """Test building VIM cookie header with active session."""
        with mock.patch.object(api, 'VMwareAPISession') as mock_api_session:
            self.store.session.is_current_session_active = mock.Mock()
            self.store.session.is_current_session_active.return_value = True
            self.store._build_vim_cookie_header(True)
            self.assertFalse(mock_api_session.called)

    def _test_build_vim_cookie_header_expired(self):
        """Test building VIM cookie header with expired session."""
        with mock.patch.object(api, 'VMwareAPISession') as mock_api_session:
            self.store.session.is_current_session_active = mock.Mock()
            self.store.session.is_current_session_active.return_value = False
            self.store._build_vim_cookie_header(True)
            self.assertTrue(mock_api_session.called)

    def _test_build_vim_cookie_header_expired_noverify(self):
        """Test building VIM cookie header with expired session no verify."""
        with mock.patch.object(api, 'VMwareAPISession') as mock_api_session:
            self.store.session.is_current_session_active = mock.Mock()
            self.store.session.is_current_session_active.return_value = False
            self.store._build_vim_cookie_header()
            self.assertFalse(mock_api_session.called)

    def _test_add_ioerror(self):
        """Test handling of IOError during add."""
        with mock.patch.object(
                vm_store.Store, 'select_datastore') as mock_select_ds:
            with mock.patch.object(
                    api, 'VMwareAPISession'):
                mock_select_ds.return_value = self.store.datastores[0][0]
                expected_image_id = str(uuid.uuid4())
                expected_size = FIVE_KB
                expected_contents = b"*" * expected_size
                image = io.BytesIO(expected_contents)
                self.session = mock.Mock()
                with mock.patch('requests.Session.request') as HttpConn:
                    HttpConn.request.side_effect = IOError
                    if self.multistore:
                        self.assertRaises(exceptions.BackendException,
                                          self.store.add,
                                          expected_image_id, image,
                                          expected_size)
                    else:
                        self.assertRaises(exceptions.BackendException,
                                          self.store.add,
                                          expected_image_id, image,
                                          expected_size, self.hash_algo)

    def _test_qs_sort_with_literal_question_mark(self):
        """Test URL sorting with literal question mark."""
        url = 'scheme://example.com/path?key2=val2&key1=val1?sort=true'
        exp_url = 'scheme://example.com/path?key1=val1%3Fsort%3Dtrue&key2=val2'
        self.assertEqual(exp_url,
                         utils.sort_url_by_qs_keys(url))

    def _test_build_datastore_weighted_map(self):
        """Test building datastore weighted map."""
        with mock.patch.object(
                vm_store.Store, '_get_datastore') as mock_ds_obj:
            with mock.patch.object(
                    api, 'VMwareAPISession'):
                datastores = ['a:b:100', 'c:d:100', 'e:f:200']
                mock_ds_obj.side_effect = fake_datastore_obj
                ret = self.store._build_datastore_weighted_map(datastores)
                ds = ret[200]
                self.assertEqual('e', ds[0].datacenter.path)
                self.assertEqual('f', ds[0].name)
                ds = ret[100]
                self.assertEqual(2, len(ds))

    def _test_build_datastore_weighted_map_equal_weight(self):
        """Test building datastore weighted map with equal weights."""
        with mock.patch.object(
                vm_store.Store, '_get_datastore') as mock_ds_obj:
            with mock.patch.object(
                    api, 'VMwareAPISession'):
                datastores = ['a:b:200', 'a:b:200']
                mock_ds_obj.side_effect = fake_datastore_obj
                ret = self.store._build_datastore_weighted_map(datastores)
                ds = ret[200]
                self.assertEqual(2, len(ds))

    def _test_build_datastore_weighted_map_empty_list(self):
        """Test building datastore weighted map with empty list."""
        with mock.patch.object(
                vm_store.Store, '_get_datastore'):
            with mock.patch.object(
                    api, 'VMwareAPISession'):
                datastores = []
                ret = self.store._build_datastore_weighted_map(datastores)
                self.assertEqual({}, ret)

    def _test_select_datastore_insufficient_freespace(self):
        """Test selecting datastore with insufficient free space."""
        with mock.patch.object(
                vm_store.Store, '_get_datastore'):
            with mock.patch.object(
                    vm_store.Store, '_get_freespace') as mock_get_freespace:
                datastores = ['a:b:100', 'c:d:100', 'e:f:200']
                image_size = 10
                self.store.datastores = (
                    self.store._build_datastore_weighted_map(datastores))
                freespaces = [5, 5, 5]

                def fake_get_fp(*args, **kwargs):
                    return freespaces.pop(0)
                mock_get_freespace.side_effect = fake_get_fp
                self.assertRaises(exceptions.StorageFull,
                                  self.store.select_datastore, image_size)

    def _test_select_datastore_insufficient_fs_one_ds(self):
        """Test selecting datastore with less free space on one datastore."""
        with mock.patch.object(
                vm_store.Store, '_get_datastore'):
            with mock.patch.object(
                    vm_store.Store, '_get_freespace') as mock_get_freespace:
                datastores = ['a:b:100']
                image_size = 10
                self.store.datastores = (
                    self.store._build_datastore_weighted_map(datastores))
                freespaces = [5]

                def fake_get_fp(*args, **kwargs):
                    return freespaces.pop(0)
                mock_get_freespace.side_effect = fake_get_fp
                self.assertRaises(exceptions.StorageFull,
                                  self.store.select_datastore, image_size)

    def _test_select_datastore_equal_freespace(self):
        """Test selecting datastore with equal free space."""
        with mock.patch.object(
                vm_store.Store, '_get_datastore') as mock_ds_obj:
            with mock.patch.object(
                    vm_store.Store, '_get_freespace') as mock_get_freespace:
                datastores = ['a:b:100', 'c:d:100', 'e:f:200']
                image_size = 10
                mock_ds_obj.side_effect = fake_datastore_obj
                self.store.datastores = (
                    self.store._build_datastore_weighted_map(datastores))
                freespaces = [11, 11, 11]

                def fake_get_fp(*args, **kwargs):
                    return freespaces.pop(0)
                mock_get_freespace.side_effect = fake_get_fp

                ds = self.store.select_datastore(image_size)
                self.assertEqual('e', ds.datacenter.path)
                self.assertEqual('f', ds.name)

    def _test_select_datastore_contention(self):
        """Test selecting datastore with contention."""
        with mock.patch.object(
                vm_store.Store, '_get_datastore') as mock_ds_obj:
            with mock.patch.object(
                    vm_store.Store, '_get_freespace') as mock_get_freespace:
                datastores = ['a:b:100', 'c:d:100', 'e:f:200']
                image_size = 10
                mock_ds_obj.side_effect = fake_datastore_obj
                self.store.datastores = (
                    self.store._build_datastore_weighted_map(datastores))
                freespaces = [5, 11, 12]

                def fake_get_fp(*args, **kwargs):
                    return freespaces.pop(0)
                mock_get_freespace.side_effect = fake_get_fp
                ds = self.store.select_datastore(image_size)
                self.assertEqual('c', ds.datacenter.path)
                self.assertEqual('d', ds.name)

    def _test_select_datastore_empty_list(self):
        """Test selecting datastore with empty list."""
        datastores = []
        self.store.datastores = (
            self.store._build_datastore_weighted_map(datastores))
        self.assertRaises(exceptions.StorageFull,
                          self.store.select_datastore, 10)

    def _test_get_datacenter_ref(self):
        """Test getting datacenter reference."""
        with mock.patch(
                'oslo_vmware.api.VMwareAPISession'):
            datacenter_path = 'Datacenter1'
            self.store._get_datacenter(datacenter_path)
            self.store.session.invoke_api.assert_called_with(
                self.store.session.vim,
                'FindByInventoryPath',
                self.store.session.vim.service_content.searchIndex,
                inventoryPath=datacenter_path)

    def _test_http_get_redirect(self):
        """Test HTTP GET with redirects."""
        with mock.patch(
                'oslo_vmware.api.VMwareAPISession'):
            # Add two layers of redirects to the response stack, which will
            # return the default 200 OK with the expected data after resolving
            # both redirects.
            red1 = {"location": "https://example.com?dsName=ds1&dcPath=dc1"}
            red2 = {"location": "https://example.com?dsName=ds2&dcPath=dc2"}
            responses = [utils.fake_response(),
                         utils.fake_response(status_code=302, headers=red1),
                         utils.fake_response(status_code=301, headers=red2)]

            def getresponse(*args, **kwargs):
                return responses.pop()

            expected_image_size = 31
            expected_returns = ['I am a teapot, short and stout\n']
            if self.multistore:
                loc = location.get_location_from_uri_and_backend(
                    "vsphere://127.0.0.1/folder/openstack_glance/%s"
                    "?dsName=ds1&dcPath=dc1" % FAKE_UUID, self.backend,
                    conf=self.conf)
            else:
                loc = location.get_location_from_uri(
                    "vsphere://127.0.0.1/folder/openstack_glance/%s"
                    "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
            with mock.patch('requests.Session.request') as HttpConn:
                HttpConn.side_effect = getresponse
                (image_file, image_size) = self.store.get(loc)
            self.assertEqual(expected_image_size, image_size)
            chunks = [c for c in image_file]
            self.assertEqual(expected_returns, chunks)

    def _test_http_get_max_redirects(self):
        """Test HTTP GET with max redirects exceeded."""
        with mock.patch(
                'oslo_vmware.api.VMwareAPISession'):
            red = {"location": "https://example.com?dsName=ds1&dcPath=dc1"}
            responses = ([utils.fake_response(status_code=302, headers=red)]
                         * (vm_store.MAX_REDIRECTS + 1))

            def getresponse(*args, **kwargs):
                return responses.pop()

            if self.multistore:
                loc = location.get_location_from_uri_and_backend(
                    "vsphere://127.0.0.1/folder/openstack_glance/%s?"
                    "dsName=ds1&dcPath=dc1" % FAKE_UUID,
                    self.backend, conf=self.conf)
            else:
                loc = location.get_location_from_uri(
                    "vsphere://127.0.0.1/folder/openstack_glance/%s"
                    "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
            with mock.patch('requests.Session.request') as HttpConn:
                HttpConn.side_effect = getresponse
                self.assertRaises(exceptions.MaxRedirectsExceeded,
                                  self.store.get, loc)

    def _test_http_get_redirect_invalid(self):
        """Test HTTP GET with invalid redirect."""
        with mock.patch(
                'oslo_vmware.api.VMwareAPISession'):
            red = {"location": "https://example.com?dsName=ds1&dcPath=dc1"}

            if self.multistore:
                loc = location.get_location_from_uri_and_backend(
                    "vsphere://127.0.0.1/folder/openstack_glance/%s"
                    "?dsName=ds1&dcPath=dc1" % FAKE_UUID, self.backend,
                    conf=self.conf)
            else:
                loc = location.get_location_from_uri(
                    "vsphere://127.0.0.1/folder/openstack_glance/%s"
                    "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
            with mock.patch('requests.Session.request') as HttpConn:
                HttpConn.return_value = utils.fake_response(status_code=307,
                                                            headers=red)
                self.assertRaises(exceptions.BadStoreUri, self.store.get, loc)
