# Copyright 2014 OpenStack, LLC
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

"""Tests the VMware Datastore backend store"""

import hashlib
import uuid

import mock
from oslo_utils import units
from oslo_vmware import api
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware.objects import datacenter as oslo_datacenter
from oslo_vmware.objects import datastore as oslo_datastore
import six

import glance_store._drivers.vmware_datastore as vm_store
from glance_store import backend
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities
from glance_store.tests import utils


FAKE_UUID = str(uuid.uuid4())

FIVE_KB = 5 * units.Ki

VMWARE_DS = {
    'debug': True,
    'known_stores': ['vmware_datastore'],
    'default_store': 'vsphere',
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


class TestStore(base.StoreBaseTest,
                test_store_capabilities.TestStoreCapabilitiesChecking):

    @mock.patch.object(vm_store.Store, '_get_datastore')
    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def setUp(self, mock_api_session, mock_get_datastore):
        """Establish a clean test environment."""
        super(TestStore, self).setUp()

        vm_store.Store.CHUNKSIZE = 2
        default_store = VMWARE_DS['default_store']
        self.config(default_store=default_store, stores=['vmware'])
        backend.register_opts(self.conf)
        self.config(group='glance_store',
                    vmware_server_username='admin',
                    vmware_server_password='admin',
                    vmware_server_host=VMWARE_DS['vmware_server_host'],
                    vmware_insecure=VMWARE_DS['vmware_insecure'],
                    vmware_datastores=VMWARE_DS['vmware_datastores'])

        mock_get_datastore.side_effect = fake_datastore_obj
        backend.create_stores(self.conf)

        self.store = backend.get_store_from_scheme('vsphere')

        self.store.store_image_dir = (
            VMWARE_DS['vmware_store_image_dir'])

        self.hash_algo = 'sha256'

    def _mock_http_connection(self):
        return mock.patch('six.moves.http_client.HTTPConnection')

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_get(self, mock_api_session):
        """Test a "normal" retrieval of an image in chunks."""
        expected_image_size = 31
        expected_returns = ['I am a teapot, short and stout\n']
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response()
            (image_file, image_size) = self.store.get(loc)
        self.assertEqual(expected_image_size, image_size)
        chunks = [c for c in image_file]
        self.assertEqual(expected_returns, chunks)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_get_non_existing(self, mock_api_session):
        """
        Test that trying to retrieve an image that doesn't exist
        raises an error
        """
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glan"
            "ce/%s?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response(status_code=404)
            self.assertRaises(exceptions.NotFound, self.store.get, loc)

    @mock.patch.object(vm_store.Store, '_build_vim_cookie_header')
    @mock.patch.object(vm_store.Store, 'select_datastore')
    @mock.patch.object(vm_store._Reader, 'size')
    @mock.patch.object(api, 'VMwareAPISession')
    def test_add(self, fake_api_session, fake_size, fake_select_datastore,
                 fake_cookie):
        """Test that we can add an image via the VMware backend."""
        fake_select_datastore.return_value = self.store.datastores[0][0]
        expected_image_id = str(uuid.uuid4())
        expected_size = FIVE_KB
        expected_contents = b"*" * expected_size
        hash_code = hashlib.md5(expected_contents)
        expected_checksum = hash_code.hexdigest()
        sha256_code = hashlib.sha256(expected_contents)
        expected_multihash = sha256_code.hexdigest()
        fake_size.__get__ = mock.Mock(return_value=expected_size)
        expected_cookie = 'vmware_soap_session=fake-uuid'
        fake_cookie.return_value = expected_cookie
        expected_headers = {'Content-Length': six.text_type(expected_size),
                            'Cookie': expected_cookie}
        with mock.patch('hashlib.md5') as md5:
            with mock.patch('hashlib.new') as fake_new:
                md5.return_value = hash_code
                fake_new.return_value = sha256_code
                expected_location = format_location(
                    VMWARE_DS['vmware_server_host'],
                    VMWARE_DS['vmware_store_image_dir'],
                    expected_image_id,
                    VMWARE_DS['vmware_datastores'])
                image = six.BytesIO(expected_contents)
                with mock.patch('requests.Session.request') as HttpConn:
                    HttpConn.return_value = utils.fake_response()
                    location, size, checksum, multihash, _ = self.store.add(
                        expected_image_id, image, expected_size,
                        self.hash_algo)
                    _, kwargs = HttpConn.call_args
                    self.assertEqual(expected_headers, kwargs['headers'])
        self.assertEqual(utils.sort_url_by_qs_keys(expected_location),
                         utils.sort_url_by_qs_keys(location))
        self.assertEqual(expected_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

    @mock.patch.object(vm_store.Store, 'select_datastore')
    @mock.patch.object(vm_store._Reader, 'size')
    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_add_size_zero(self, mock_api_session, fake_size,
                           fake_select_datastore):
        """
        Test that when specifying size zero for the image to add,
        the actual size of the image is returned.
        """
        fake_select_datastore.return_value = self.store.datastores[0][0]
        expected_image_id = str(uuid.uuid4())
        expected_size = FIVE_KB
        expected_contents = b"*" * expected_size
        hash_code = hashlib.md5(expected_contents)
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
                image = six.BytesIO(expected_contents)
                with mock.patch('requests.Session.request') as HttpConn:
                    HttpConn.return_value = utils.fake_response()
                    location, size, checksum, multihash, _ = self.store.add(
                        expected_image_id, image, 0, self.hash_algo)
        self.assertEqual(utils.sort_url_by_qs_keys(expected_location),
                         utils.sort_url_by_qs_keys(location))
        self.assertEqual(expected_size, size)
        self.assertEqual(expected_checksum, checksum)
        self.assertEqual(expected_multihash, multihash)

    @mock.patch.object(vm_store.Store, 'select_datastore')
    @mock.patch('glance_store._drivers.vmware_datastore._Reader')
    def test_add_with_verifier(self, fake_reader, fake_select_datastore):
        """Test that the verifier is passed to the _Reader during add."""
        verifier = mock.MagicMock(name='mock_verifier')
        image_id = str(uuid.uuid4())
        size = FIVE_KB
        contents = b"*" * size
        image = six.BytesIO(contents)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response()
            self.store.add(image_id, image, size, self.hash_algo,
                           verifier=verifier)

        fake_reader.assert_called_with(image, self.hash_algo, verifier)

    @mock.patch.object(vm_store.Store, 'select_datastore')
    @mock.patch('glance_store._drivers.vmware_datastore._Reader')
    def test_add_with_verifier_size_zero(self, fake_reader, fake_select_ds):
        """Test that the verifier is passed to the _ChunkReader during add."""
        verifier = mock.MagicMock(name='mock_verifier')
        image_id = str(uuid.uuid4())
        size = FIVE_KB
        contents = b"*" * size
        image = six.BytesIO(contents)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response()
            self.store.add(image_id, image, 0, self.hash_algo,
                           verifier=verifier)

        fake_reader.assert_called_with(image, self.hash_algo, verifier)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_delete(self, mock_api_session):
        """Test we can delete an existing image in the VMware store."""
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

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_delete_non_existing(self, mock_api_session):
        """
        Test that trying to delete an image that doesn't exist raises an error
        """
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glance/%s?"
            "dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch.object(self.store.session,
                               'wait_for_task') as mock_task:
            mock_task.side_effect = vmware_exceptions.FileNotFoundException
            self.assertRaises(exceptions.NotFound, self.store.delete, loc)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_get_size(self, mock_api_session):
        """
        Test we can get the size of an existing image in the VMware store
        """
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response()
            image_size = self.store.get_size(loc)
        self.assertEqual(image_size, 31)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_get_size_non_existing(self, mock_api_session):
        """
        Test that trying to retrieve an image size that doesn't exist
        raises an error
        """
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glan"
            "ce/%s?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response(status_code=404)
            self.assertRaises(exceptions.NotFound, self.store.get_size, loc)

    def test_reader_full(self):
        content = b'XXX'
        image = six.BytesIO(content)
        expected_checksum = hashlib.md5(content).hexdigest()
        expected_multihash = hashlib.sha256(content).hexdigest()
        reader = vm_store._Reader(image, self.hash_algo)
        ret = reader.read()
        self.assertEqual(content, ret)
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertEqual(expected_multihash, reader.os_hash_value.hexdigest())
        self.assertEqual(len(content), reader.size)

    def test_reader_partial(self):
        content = b'XXX'
        image = six.BytesIO(content)
        expected_checksum = hashlib.md5(b'X').hexdigest()
        expected_multihash = hashlib.sha256(b'X').hexdigest()
        reader = vm_store._Reader(image, self.hash_algo)
        ret = reader.read(1)
        self.assertEqual(b'X', ret)
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertEqual(expected_multihash, reader.os_hash_value.hexdigest())
        self.assertEqual(1, reader.size)

    def test_reader_with_verifier(self):
        content = b'XXX'
        image = six.BytesIO(content)
        verifier = mock.MagicMock(name='mock_verifier')
        reader = vm_store._Reader(image, self.hash_algo, verifier)
        reader.read()
        verifier.update.assert_called_with(content)

    def test_sanity_check_api_retry_count(self):
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

    def test_sanity_check_task_poll_interval(self):
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

    def test_sanity_check_multiple_datastores(self):
        self.store.conf.glance_store.vmware_api_retry_count = 1
        self.store.conf.glance_store.vmware_task_poll_interval = 1
        self.store.conf.glance_store.vmware_datastores = ['a:b:0', 'a:d:0']
        try:
            self.store._sanity_check()
        except exceptions.BadStoreConfiguration:
            self.fail()

    def test_parse_datastore_info_and_weight_less_opts(self):
        datastore = 'a'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._parse_datastore_info_and_weight,
                          datastore)

    def test_parse_datastore_info_and_weight_invalid_weight(self):
        datastore = 'a:b:c'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._parse_datastore_info_and_weight,
                          datastore)

    def test_parse_datastore_info_and_weight_empty_opts(self):
        datastore = 'a: :0'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._parse_datastore_info_and_weight,
                          datastore)
        datastore = ':b:0'
        self.assertRaises(exceptions.BadStoreConfiguration,
                          self.store._parse_datastore_info_and_weight,
                          datastore)

    def test_parse_datastore_info_and_weight(self):
        datastore = 'a:b:100'
        parts = self.store._parse_datastore_info_and_weight(datastore)
        self.assertEqual('a', parts[0])
        self.assertEqual('b', parts[1])
        self.assertEqual(100, parts[2])

    def test_parse_datastore_info_and_weight_default_weight(self):
        datastore = 'a:b'
        parts = self.store._parse_datastore_info_and_weight(datastore)
        self.assertEqual('a', parts[0])
        self.assertEqual('b', parts[1])
        self.assertEqual(0, parts[2])

    @mock.patch.object(vm_store.Store, 'select_datastore')
    @mock.patch.object(api, 'VMwareAPISession')
    def test_unexpected_status(self, mock_api_session, mock_select_datastore):
        expected_image_id = str(uuid.uuid4())
        expected_size = FIVE_KB
        expected_contents = b"*" * expected_size
        image = six.BytesIO(expected_contents)
        self.session = mock.Mock()
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response(status_code=401)
            self.assertRaises(exceptions.BackendException,
                              self.store.add,
                              expected_image_id, image, expected_size,
                              self.hash_algo)

    @mock.patch.object(vm_store.Store, 'select_datastore')
    @mock.patch.object(api, 'VMwareAPISession')
    def test_unexpected_status_no_response_body(self, mock_api_session,
                                                mock_select_datastore):
        expected_image_id = str(uuid.uuid4())
        expected_size = FIVE_KB
        expected_contents = b"*" * expected_size
        image = six.BytesIO(expected_contents)
        self.session = mock.Mock()
        with self._mock_http_connection() as HttpConn:
            HttpConn.return_value = utils.fake_response(status_code=500,
                                                        no_response_body=True)
            self.assertRaises(exceptions.BackendException,
                              self.store.add,
                              expected_image_id, image, expected_size,
                              self.hash_algo)

    @mock.patch.object(api, 'VMwareAPISession')
    def test_reset_session(self, mock_api_session):
        self.store.reset_session()
        self.assertTrue(mock_api_session.called)

    @mock.patch.object(api, 'VMwareAPISession')
    def test_build_vim_cookie_header_active(self, mock_api_session):
        self.store.session.is_current_session_active = mock.Mock()
        self.store.session.is_current_session_active.return_value = True
        self.store._build_vim_cookie_header(True)
        self.assertFalse(mock_api_session.called)

    @mock.patch.object(api, 'VMwareAPISession')
    def test_build_vim_cookie_header_expired(self, mock_api_session):
        self.store.session.is_current_session_active = mock.Mock()
        self.store.session.is_current_session_active.return_value = False
        self.store._build_vim_cookie_header(True)
        self.assertTrue(mock_api_session.called)

    @mock.patch.object(api, 'VMwareAPISession')
    def test_build_vim_cookie_header_expired_noverify(self, mock_api_session):
        self.store.session.is_current_session_active = mock.Mock()
        self.store.session.is_current_session_active.return_value = False
        self.store._build_vim_cookie_header()
        self.assertFalse(mock_api_session.called)

    @mock.patch.object(vm_store.Store, 'select_datastore')
    @mock.patch.object(api, 'VMwareAPISession')
    def test_add_ioerror(self, mock_api_session, mock_select_datastore):
        mock_select_datastore.return_value = self.store.datastores[0][0]
        expected_image_id = str(uuid.uuid4())
        expected_size = FIVE_KB
        expected_contents = b"*" * expected_size
        image = six.BytesIO(expected_contents)
        self.session = mock.Mock()
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.request.side_effect = IOError
            self.assertRaises(exceptions.BackendException,
                              self.store.add,
                              expected_image_id, image, expected_size,
                              self.hash_algo)

    def test_qs_sort_with_literal_question_mark(self):
        url = 'scheme://example.com/path?key2=val2&key1=val1?sort=true'
        exp_url = 'scheme://example.com/path?key1=val1%3Fsort%3Dtrue&key2=val2'
        self.assertEqual(exp_url,
                         utils.sort_url_by_qs_keys(url))

    @mock.patch.object(vm_store.Store, '_get_datastore')
    @mock.patch.object(api, 'VMwareAPISession')
    def test_build_datastore_weighted_map(self, mock_api_session, mock_ds_obj):
        datastores = ['a:b:100', 'c:d:100', 'e:f:200']
        mock_ds_obj.side_effect = fake_datastore_obj
        ret = self.store._build_datastore_weighted_map(datastores)
        ds = ret[200]
        self.assertEqual('e', ds[0].datacenter.path)
        self.assertEqual('f', ds[0].name)
        ds = ret[100]
        self.assertEqual(2, len(ds))

    @mock.patch.object(vm_store.Store, '_get_datastore')
    @mock.patch.object(api, 'VMwareAPISession')
    def test_build_datastore_weighted_map_equal_weight(self, mock_api_session,
                                                       mock_ds_obj):
        datastores = ['a:b:200', 'a:b:200']
        mock_ds_obj.side_effect = fake_datastore_obj
        ret = self.store._build_datastore_weighted_map(datastores)
        ds = ret[200]
        self.assertEqual(2, len(ds))

    @mock.patch.object(vm_store.Store, '_get_datastore')
    @mock.patch.object(api, 'VMwareAPISession')
    def test_build_datastore_weighted_map_empty_list(self, mock_api_session,
                                                     mock_ds_ref):
        datastores = []
        ret = self.store._build_datastore_weighted_map(datastores)
        self.assertEqual({}, ret)

    @mock.patch.object(vm_store.Store, '_get_datastore')
    @mock.patch.object(vm_store.Store, '_get_freespace')
    def test_select_datastore_insufficient_freespace(self, mock_get_freespace,
                                                     mock_ds_ref):
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

    @mock.patch.object(vm_store.Store, '_get_datastore')
    @mock.patch.object(vm_store.Store, '_get_freespace')
    def test_select_datastore_insufficient_fs_one_ds(self, mock_get_freespace,
                                                     mock_ds_ref):
        # Tests if fs is updated with just one datastore.
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

    @mock.patch.object(vm_store.Store, '_get_datastore')
    @mock.patch.object(vm_store.Store, '_get_freespace')
    def test_select_datastore_equal_freespace(self, mock_get_freespace,
                                              mock_ds_obj):
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

    @mock.patch.object(vm_store.Store, '_get_datastore')
    @mock.patch.object(vm_store.Store, '_get_freespace')
    def test_select_datastore_contention(self, mock_get_freespace,
                                         mock_ds_obj):
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

    def test_select_datastore_empty_list(self):
        datastores = []
        self.store.datastores = (
            self.store._build_datastore_weighted_map(datastores))
        self.assertRaises(exceptions.StorageFull,
                          self.store.select_datastore, 10)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_get_datacenter_ref(self, mock_api_session):
        datacenter_path = 'Datacenter1'
        self.store._get_datacenter(datacenter_path)
        self.store.session.invoke_api.assert_called_with(
            self.store.session.vim,
            'FindByInventoryPath',
            self.store.session.vim.service_content.searchIndex,
            inventoryPath=datacenter_path)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_http_get_redirect(self, mock_api_session):
        # Add two layers of redirects to the response stack, which will
        # return the default 200 OK with the expected data after resolving
        # both redirects.
        redirect1 = {"location": "https://example.com?dsName=ds1&dcPath=dc1"}
        redirect2 = {"location": "https://example.com?dsName=ds2&dcPath=dc2"}
        responses = [utils.fake_response(),
                     utils.fake_response(status_code=302, headers=redirect1),
                     utils.fake_response(status_code=301, headers=redirect2)]

        def getresponse(*args, **kwargs):
            return responses.pop()

        expected_image_size = 31
        expected_returns = ['I am a teapot, short and stout\n']
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.side_effect = getresponse
            (image_file, image_size) = self.store.get(loc)
        self.assertEqual(expected_image_size, image_size)
        chunks = [c for c in image_file]
        self.assertEqual(expected_returns, chunks)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_http_get_max_redirects(self, mock_api_session):
        redirect = {"location": "https://example.com?dsName=ds1&dcPath=dc1"}
        responses = ([utils.fake_response(status_code=302, headers=redirect)]
                     * (vm_store.MAX_REDIRECTS + 1))

        def getresponse(*args, **kwargs):
            return responses.pop()

        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.side_effect = getresponse
            self.assertRaises(exceptions.MaxRedirectsExceeded, self.store.get,
                              loc)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_http_get_redirect_invalid(self, mock_api_session):
        redirect = {"location": "https://example.com?dsName=ds1&dcPath=dc1"}

        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response(status_code=307,
                                                        headers=redirect)
            self.assertRaises(exceptions.BadStoreUri, self.store.get, loc)
