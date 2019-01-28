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

import hashlib
import uuid

import mock
from oslo_config import cfg
from oslo_utils import units
from oslo_vmware import api
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware.objects import datacenter as oslo_datacenter
from oslo_vmware.objects import datastore as oslo_datastore
import six

import glance_store as store
import glance_store._drivers.vmware_datastore as vm_store
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests.unit import test_store_capabilities
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


class TestMultiStore(base.MultiStoreBaseTest,
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
        return mock.patch('six.moves.http_client.HTTPConnection')

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_get(self, mock_api_session):
        """Test a "normal" retrieval of an image in chunks."""
        expected_image_size = 31
        expected_returns = ['I am a teapot, short and stout\n']
        loc = location.get_location_from_uri_and_backend(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, "vmware1", conf=self.conf)
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
        loc = location.get_location_from_uri_and_backend(
            "vsphere://127.0.0.1/folder/openstack_glan"
            "ce/%s?dsName=ds1&dcPath=dc1" % FAKE_UUID, "vmware1",
            conf=self.conf)
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
        fake_size.__get__ = mock.Mock(return_value=expected_size)
        expected_cookie = 'vmware_soap_session=fake-uuid'
        fake_cookie.return_value = expected_cookie
        expected_headers = {'Content-Length': six.text_type(expected_size),
                            'Cookie': expected_cookie}
        with mock.patch('hashlib.md5') as md5:
            md5.return_value = hash_code
            expected_location = format_location(
                VMWARE_DS['vmware_server_host'],
                VMWARE_DS['vmware_store_image_dir'],
                expected_image_id,
                VMWARE_DS['vmware_datastores'])
            image = six.BytesIO(expected_contents)
            with mock.patch('requests.Session.request') as HttpConn:
                HttpConn.return_value = utils.fake_response()
                location, size, checksum, metadata = self.store.add(
                    expected_image_id, image, expected_size)
                _, kwargs = HttpConn.call_args
                self.assertEqual(expected_headers, kwargs['headers'])
                self.assertEqual("vmware1", metadata["backend"])

        self.assertEqual(utils.sort_url_by_qs_keys(expected_location),
                         utils.sort_url_by_qs_keys(location))
        self.assertEqual(expected_size, size)
        self.assertEqual(expected_checksum, checksum)

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
        fake_size.__get__ = mock.Mock(return_value=expected_size)
        with mock.patch('hashlib.md5') as md5:
            md5.return_value = hash_code
            expected_location = format_location(
                VMWARE_DS['vmware_server_host'],
                VMWARE_DS['vmware_store_image_dir'],
                expected_image_id,
                VMWARE_DS['vmware_datastores'])
            image = six.BytesIO(expected_contents)
            with mock.patch('requests.Session.request') as HttpConn:
                HttpConn.return_value = utils.fake_response()
                location, size, checksum, metadata = self.store.add(
                    expected_image_id, image, 0)
                self.assertEqual("vmware1", metadata["backend"])

        self.assertEqual(utils.sort_url_by_qs_keys(expected_location),
                         utils.sort_url_by_qs_keys(location))
        self.assertEqual(expected_size, size)
        self.assertEqual(expected_checksum, checksum)

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
            location, size, checksum, multihash, metadata = self.store.add(
                image_id, image, size, self.hash_algo, verifier=verifier)
            self.assertEqual("vmware1", metadata["backend"])

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
            location, size, checksum, multihash, metadata = self.store.add(
                image_id, image, 0, self.hash_algo, verifier=verifier)
            self.assertEqual("vmware1", metadata["backend"])

        fake_reader.assert_called_with(image, self.hash_algo, verifier)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_delete(self, mock_api_session):
        """Test we can delete an existing image in the VMware store."""
        loc = location.get_location_from_uri_and_backend(
            "vsphere://127.0.0.1/folder/openstack_glance/%s?"
            "dsName=ds1&dcPath=dc1" % FAKE_UUID, "vmware1", conf=self.conf)
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
        loc = location.get_location_from_uri_and_backend(
            "vsphere://127.0.0.1/folder/openstack_glance/%s?"
            "dsName=ds1&dcPath=dc1" % FAKE_UUID,
            "vmware1", conf=self.conf)
        with mock.patch.object(self.store.session,
                               'wait_for_task') as mock_task:
            mock_task.side_effect = vmware_exceptions.FileNotFoundException
            self.assertRaises(exceptions.NotFound, self.store.delete, loc)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_get_size(self, mock_api_session):
        """
        Test we can get the size of an existing image in the VMware store
        """
        loc = location.get_location_from_uri_and_backend(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, "vmware1", conf=self.conf)
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
        loc = location.get_location_from_uri_and_backend(
            "vsphere://127.0.0.1/folder/openstack_glan"
            "ce/%s?dsName=ds1&dcPath=dc1" % FAKE_UUID,
            "vmware1", conf=self.conf)
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

    def test_sanity_check_multiple_datastores(self):
        self.config(group='vmware1', vmware_api_retry_count=1)
        self.config(group='vmware1', vmware_task_poll_interval=1)
        self.config(group='vmware1', vmware_datastores=['a:b:0', 'a:d:0'])
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
                              expected_image_id, image, expected_size)

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
                              expected_image_id, image, expected_size)

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
                              expected_image_id, image, expected_size)

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
        loc = location.get_location_from_uri_and_backend(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, "vmware1", conf=self.conf)
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

        loc = location.get_location_from_uri_and_backend(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, "vmware1", conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.side_effect = getresponse
            self.assertRaises(exceptions.MaxRedirectsExceeded, self.store.get,
                              loc)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_http_get_redirect_invalid(self, mock_api_session):
        redirect = {"location": "https://example.com?dsName=ds1&dcPath=dc1"}

        loc = location.get_location_from_uri_and_backend(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, "vmware1", conf=self.conf)
        with mock.patch('requests.Session.request') as HttpConn:
            HttpConn.return_value = utils.fake_response(status_code=307,
                                                        headers=redirect)
            self.assertRaises(exceptions.BadStoreUri, self.store.get, loc)
