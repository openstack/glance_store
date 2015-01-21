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
from oslo.vmware import api
from oslo_utils import units
import six

import glance_store._drivers.vmware_datastore as vm_store
from glance_store import backend
from glance_store import exceptions
from glance_store import location
from glance_store.tests import base
from glance_store.tests import utils
from tests.unit import test_store_capabilities


FAKE_UUID = str(uuid.uuid4())

FIVE_KB = 5 * units.Ki

VMWARE_DS = {
    'verbose': True,
    'debug': True,
    'known_stores': ['vmware_datastore'],
    'default_store': 'vsphere',
    'vmware_server_host': '127.0.0.1',
    'vmware_server_username': 'username',
    'vmware_server_password': 'password',
    'vmware_datacenter_path': 'dc1',
    'vmware_datastore_name': 'ds1',
    'vmware_store_image_dir': '/openstack_glance',
    'vmware_api_insecure': 'True',
}


def format_location(host_ip, folder_name,
                    image_id, datacenter_path, datastore_name):
    """
    Helper method that returns a VMware Datastore store URI given
    the component pieces.
    """
    scheme = 'vsphere'
    return ("%s://%s/folder%s/%s?dcPath=%s&dsName=%s"
            % (scheme, host_ip, folder_name,
               image_id, datacenter_path, datastore_name))


class FakeHTTPConnection(object):

    def __init__(self, status=200, *args, **kwargs):
        self.status = status
        pass

    def getresponse(self):
        return utils.FakeHTTPResponse(status=self.status)

    def request(self, *_args, **_kwargs):
        pass

    def close(self):
        pass


class TestStore(base.StoreBaseTest,
                test_store_capabilities.TestStoreCapabilitiesChecking):

    @mock.patch('oslo.vmware.api.VMwareAPISession', autospec=True)
    def setUp(self, mock_session):
        """Establish a clean test environment."""
        super(TestStore, self).setUp()

        vm_store.Store.CHUNKSIZE = 2
        self.config(default_store='vmware', stores=['vmware'])
        backend.register_opts(self.conf)
        self.config(group='glance_store',
                    vmware_server_username='admin',
                    vmware_server_password='admin',
                    vmware_server_host=VMWARE_DS['vmware_server_host'],
                    vmware_api_insecure=VMWARE_DS['vmware_api_insecure'],
                    vmware_datastore_name=VMWARE_DS['vmware_datastore_name'],
                    vmware_datacenter_path=VMWARE_DS['vmware_datacenter_path'])

        backend.create_stores(self.conf)

        self.store = backend.get_store_from_scheme('vsphere')

        self.store.store_image_dir = (
            VMWARE_DS['vmware_store_image_dir'])

    def test_get(self):
        """Test a "normal" retrieval of an image in chunks."""
        expected_image_size = 31
        expected_returns = ['I am a teapot, short and stout\n']
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('httplib.HTTPConnection') as HttpConn:
            HttpConn.return_value = FakeHTTPConnection()
            (image_file, image_size) = self.store.get(loc)
        self.assertEqual(image_size, expected_image_size)
        chunks = [c for c in image_file]
        self.assertEqual(expected_returns, chunks)

    def test_get_non_existing(self):
        """
        Test that trying to retrieve an image that doesn't exist
        raises an error
        """
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glan"
            "ce/%s?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('httplib.HTTPConnection') as HttpConn:
            HttpConn.return_value = FakeHTTPConnection(status=404)
            self.assertRaises(exceptions.NotFound, self.store.get, loc)

    @mock.patch.object(vm_store._Reader, 'size')
    def test_add(self, fake_size):
        """Test that we can add an image via the VMware backend."""
        expected_image_id = str(uuid.uuid4())
        expected_size = FIVE_KB
        expected_contents = "*" * expected_size
        hash_code = hashlib.md5(expected_contents)
        expected_checksum = hash_code.hexdigest()
        fake_size.__get__ = mock.Mock(return_value=expected_size)
        with mock.patch('hashlib.md5') as md5:
            md5.return_value = hash_code
            expected_location = format_location(
                VMWARE_DS['vmware_server_host'],
                VMWARE_DS['vmware_store_image_dir'],
                expected_image_id,
                VMWARE_DS['vmware_datacenter_path'],
                VMWARE_DS['vmware_datastore_name'])
            image = six.StringIO(expected_contents)
            with mock.patch('httplib.HTTPConnection') as HttpConn:
                HttpConn.return_value = FakeHTTPConnection()
                location, size, checksum, _ = self.store.add(expected_image_id,
                                                             image,
                                                             expected_size)
        self.assertEqual(utils.sort_url_by_qs_keys(expected_location),
                         utils.sort_url_by_qs_keys(location))
        self.assertEqual(expected_size, size)
        self.assertEqual(expected_checksum, checksum)

    @mock.patch.object(vm_store._Reader, 'size')
    def test_add_size_zero(self, fake_size):
        """
        Test that when specifying size zero for the image to add,
        the actual size of the image is returned.
        """
        expected_image_id = str(uuid.uuid4())
        expected_size = FIVE_KB
        expected_contents = "*" * expected_size
        hash_code = hashlib.md5(expected_contents)
        expected_checksum = hash_code.hexdigest()
        fake_size.__get__ = mock.Mock(return_value=expected_size)
        with mock.patch('hashlib.md5') as md5:
            md5.return_value = hash_code
            expected_location = format_location(
                VMWARE_DS['vmware_server_host'],
                VMWARE_DS['vmware_store_image_dir'],
                expected_image_id,
                VMWARE_DS['vmware_datacenter_path'],
                VMWARE_DS['vmware_datastore_name'])
            image = six.StringIO(expected_contents)
            with mock.patch('httplib.HTTPConnection') as HttpConn:
                HttpConn.return_value = FakeHTTPConnection()
                location, size, checksum, _ = self.store.add(expected_image_id,
                                                             image, 0)
        self.assertEqual(utils.sort_url_by_qs_keys(expected_location),
                         utils.sort_url_by_qs_keys(location))
        self.assertEqual(expected_size, size)
        self.assertEqual(expected_checksum, checksum)

    def test_delete(self):
        """Test we can delete an existing image in the VMware store."""
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glance/%s?"
            "dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('httplib.HTTPConnection') as HttpConn:
            HttpConn.return_value = FakeHTTPConnection()
            vm_store.Store._service_content = mock.Mock()
            self.store.delete(loc)
        with mock.patch('httplib.HTTPConnection') as HttpConn:
            HttpConn.return_value = FakeHTTPConnection(status=404)
            self.assertRaises(exceptions.NotFound, self.store.get, loc)

    def test_get_size(self):
        """
        Test we can get the size of an existing image in the VMware store
        """
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glance/%s"
            "?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('httplib.HTTPConnection') as HttpConn:
            HttpConn.return_value = FakeHTTPConnection()
            image_size = self.store.get_size(loc)
        self.assertEqual(image_size, 31)

    def test_get_size_non_existing(self):
        """
        Test that trying to retrieve an image size that doesn't exist
        raises an error
        """
        loc = location.get_location_from_uri(
            "vsphere://127.0.0.1/folder/openstack_glan"
            "ce/%s?dsName=ds1&dcPath=dc1" % FAKE_UUID, conf=self.conf)
        with mock.patch('httplib.HTTPConnection') as HttpConn:
            HttpConn.return_value = FakeHTTPConnection(status=404)
            self.assertRaises(exceptions.NotFound, self.store.get_size, loc)

    def test_reader_full(self):
        content = 'XXX'
        image = six.StringIO(content)
        expected_checksum = hashlib.md5(content).hexdigest()
        reader = vm_store._Reader(image)
        ret = reader.read()
        self.assertEqual(content, ret)
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertEqual(len(content), reader.size)

    def test_reader_partial(self):
        content = 'XXX'
        image = six.StringIO(content)
        expected_checksum = hashlib.md5('X').hexdigest()
        reader = vm_store._Reader(image)
        ret = reader.read(1)
        self.assertEqual('X', ret)
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertEqual(1, reader.size)

    def test_chunkreader_image_fits_in_blocksize(self):
        """
        Test that the image file reader returns the expected chunk of data
        when the block size is larger than the image.
        """
        content = 'XXX'
        image = six.StringIO(content)
        expected_checksum = hashlib.md5(content).hexdigest()
        reader = vm_store._ChunkReader(image)
        ret = reader.read()
        expected_chunk = '%x\r\n%s\r\n' % (len(content), content)
        last_chunk = '0\r\n\r\n'
        self.assertEqual('%s%s' % (expected_chunk, last_chunk), ret)
        self.assertEqual(image.len, reader.size)
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertTrue(reader.closed)
        ret = reader.read()
        self.assertEqual(image.len, reader.size)
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertTrue(reader.closed)
        self.assertEqual('', ret)

    def test_chunkreader_image_larger_blocksize(self):
        """
        Test that the image file reader returns the expected chunks when
        the block size specified is smaller than the image.
        """
        content = 'XXX'
        image = six.StringIO(content)
        expected_checksum = hashlib.md5(content).hexdigest()
        last_chunk = '0\r\n\r\n'
        reader = vm_store._ChunkReader(image, blocksize=1)
        ret = reader.read()
        expected_chunk = '1\r\nX\r\n'
        self.assertEqual('%s%s%s%s' % (expected_chunk, expected_chunk,
                                       expected_chunk, last_chunk), ret)
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertEqual(image.len, reader.size)
        self.assertTrue(reader.closed)

    def test_chunkreader_size(self):
        """Test that the image reader takes into account the specified size."""
        content = 'XXX'
        image = six.StringIO(content)
        expected_checksum = hashlib.md5(content).hexdigest()
        reader = vm_store._ChunkReader(image, blocksize=1)
        ret = reader.read(size=3)
        self.assertEqual('1\r\n', ret)
        ret = reader.read(size=1)
        self.assertEqual('X', ret)
        ret = reader.read()
        self.assertEqual(expected_checksum, reader.checksum.hexdigest())
        self.assertEqual(image.len, reader.size)
        self.assertTrue(reader.closed)

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

    @mock.patch.object(api, 'VMwareAPISession')
    def test_unexpected_status(self, mock_api_session):
        expected_image_id = str(uuid.uuid4())
        expected_size = FIVE_KB
        expected_contents = "*" * expected_size
        image = six.StringIO(expected_contents)
        self.session = mock.Mock()
        with mock.patch('httplib.HTTPConnection') as HttpConn:
            HttpConn.return_value = FakeHTTPConnection(status=401)
            self.assertRaises(exceptions.BackendException,
                              self.store.add,
                              expected_image_id, image, expected_size)

    @mock.patch.object(api, 'VMwareAPISession')
    def test_reset_session(self, mock_api_session):
        self.store.reset_session(force=False)
        self.assertFalse(mock_api_session.called)
        self.store.reset_session()
        self.assertFalse(mock_api_session.called)
        self.store.reset_session(force=True)
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

    @mock.patch.object(api, 'VMwareAPISession')
    def test_add_ioerror(self, mock_api_session):
        expected_image_id = str(uuid.uuid4())
        expected_size = FIVE_KB
        expected_contents = "*" * expected_size
        image = six.StringIO(expected_contents)
        self.session = mock.Mock()
        with mock.patch('httplib.HTTPConnection') as HttpConn:
            HttpConn.request.side_effect = IOError
            self.assertRaises(exceptions.BackendException,
                              self.store.add,
                              expected_image_id, image, expected_size)

    def test_qs_sort_with_literal_question_mark(self):
        url = 'scheme://example.com/path?key2=val2&key1=val1?sort=true'
        exp_url = 'scheme://example.com/path?key1=val1%3Fsort%3Dtrue&key2=val2'
        self.assertEqual(exp_url,
                         utils.sort_url_by_qs_keys(url))
