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

"""Storage backend for VMware Datastore"""

import hashlib
import httplib
import logging
import os
import socket

from oslo_config import cfg
from oslo_utils import excutils
from oslo_utils import units
from oslo_vmware import api
from oslo_vmware import constants
import oslo_vmware.exceptions as vexc
from oslo_vmware.objects import datacenter as oslo_datacenter
from oslo_vmware.objects import datastore as oslo_datastore
from oslo_vmware import vim_util

import six
# NOTE(jokke): simplified transition to py3, behaves like py2 xrange
from six.moves import range
import six.moves.urllib.parse as urlparse

import glance_store
from glance_store import capabilities
from glance_store import exceptions
from glance_store.i18n import _
from glance_store.i18n import _LE
from glance_store import location


LOG = logging.getLogger(__name__)

MAX_REDIRECTS = 5
DEFAULT_STORE_IMAGE_DIR = '/openstack_glance'
DS_URL_PREFIX = '/folder'
STORE_SCHEME = 'vsphere'

# check that datacenter/datastore combination is valid
_datastore_info_valid = False

_VMWARE_OPTS = [
    cfg.StrOpt('vmware_server_host',
               help=_('ESX/ESXi or vCenter Server target system. '
                      'The server value can be an IP address or a DNS name.')),
    cfg.StrOpt('vmware_server_username',
               help=_('Username for authenticating with '
                      'VMware ESX/VC server.')),
    cfg.StrOpt('vmware_server_password',
               help=_('Password for authenticating with '
                      'VMware ESX/VC server.'),
               secret=True),
    cfg.StrOpt('vmware_datacenter_path',
               default=constants.ESX_DATACENTER_PATH,
               help=_('DEPRECATED. Inventory path to a datacenter. '
                      'If the vmware_server_host specified is an ESX/ESXi, '
                      'the vmware_datacenter_path is optional. If specified, '
                      'it should be "ha-datacenter". This option is '
                      'deprecated in favor of vmware_datastores and will be '
                      'removed in the Liberty release.'),
               deprecated_for_removal=True),
    cfg.StrOpt('vmware_datastore_name',
               help=_('DEPRECATED. Datastore associated with the datacenter. '
                      'This option is deprecated in favor of '
                      'vmware_datastores and will be removed in the Liberty '
                      'release.'),
               deprecated_for_removal=True),
    cfg.IntOpt('vmware_api_retry_count',
               default=10,
               help=_('Number of times VMware ESX/VC server API must be '
                      'retried upon connection related issues.')),
    cfg.IntOpt('vmware_task_poll_interval',
               default=5,
               help=_('The interval used for polling remote tasks '
                      'invoked on VMware ESX/VC server.')),
    cfg.StrOpt('vmware_store_image_dir',
               default=DEFAULT_STORE_IMAGE_DIR,
               help=_('The name of the directory where the glance images '
                      'will be stored in the VMware datastore.')),
    cfg.BoolOpt('vmware_api_insecure',
                default=False,
                help=_('Allow to perform insecure SSL requests to ESX/VC.')),
    cfg.MultiStrOpt(
        'vmware_datastores',
        help=_(
            'A list of datastores where the image can be stored. This option '
            'may be specified multiple times for specifying multiple '
            'datastores. Either one of vmware_datastore_name or '
            'vmware_datastores is required. The datastore name should be '
            'specified after its datacenter path, seperated by ":". An '
            'optional weight may be given after the datastore name, seperated '
            'again by ":". Thus, the required format becomes '
            '<datacenter_path>:<datastore_name>:<optional_weight>. When '
            'adding an image, the datastore with highest weight will be '
            'selected, unless there is not enough free space available in '
            'cases where the image size is already known. If no weight is '
            'given, it is assumed to be zero and the directory will be '
            'considered for selection last. If multiple datastores have the '
            'same weight, then the one with the most free space available is '
            'selected.'))]


def is_valid_ipv6(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except Exception:
        return False


def http_response_iterator(conn, response, size):
    """Return an iterator for a file-like object.

    :param conn: HTTP(S) Connection
    :param response: httplib.HTTPResponse object
    :param size: Chunk size to iterate with
    """
    try:
        chunk = response.read(size)
        while chunk:
            yield chunk
            chunk = response.read(size)
    finally:
        conn.close()


class _Reader(object):

    def __init__(self, data):
        self._size = 0
        self.data = data
        self.checksum = hashlib.md5()

    def read(self, size=None):
        result = self.data.read(size)
        self._size += len(result)
        self.checksum.update(result)
        return result

    @property
    def size(self):
        return self._size


class _ChunkReader(_Reader):

    def __init__(self, data, blocksize=8192):
        self.blocksize = blocksize
        self.current_chunk = ""
        self.closed = False
        super(_ChunkReader, self).__init__(data)

    def read(self, size=None):
        ret = ""
        while size is None or size >= len(self.current_chunk):
            ret += self.current_chunk
            if size is not None:
                size -= len(self.current_chunk)
            if self.closed:
                self.current_chunk = ""
                break
            self._get_chunk()
        else:
            ret += self.current_chunk[:size]
            self.current_chunk = self.current_chunk[size:]
        return ret

    def _get_chunk(self):
        if not self.closed:
            chunk = self.data.read(self.blocksize)
            chunk_len = len(chunk)
            self._size += chunk_len
            self.checksum.update(chunk)
            if chunk:
                self.current_chunk = '%x\r\n%s\r\n' % (chunk_len, chunk)
            else:
                self.current_chunk = '0\r\n\r\n'
                self.closed = True


class StoreLocation(location.StoreLocation):
    """Class describing an VMware URI.

    An VMware URI can look like any of the following:
    vsphere://server_host/folder/file_path?dcPath=dc_path&dsName=ds_name
    """

    def __init__(self, store_specs, conf):
        super(StoreLocation, self).__init__(store_specs, conf)
        self.datacenter_path = None
        self.datastore_name = None

    def process_specs(self):
        self.scheme = self.specs.get('scheme', STORE_SCHEME)
        self.server_host = self.specs.get('server_host')
        self.path = os.path.join(DS_URL_PREFIX,
                                 self.specs.get('image_dir').strip('/'),
                                 self.specs.get('image_id'))
        self.datacenter_path = self.specs.get('datacenter_path')
        self.datstore_name = self.specs.get('datastore_name')
        param_list = {'dsName': self.datstore_name}
        if self.datacenter_path:
            param_list['dcPath'] = self.datacenter_path
        self.query = urlparse.urlencode(param_list)

    def get_uri(self):
        if is_valid_ipv6(self.server_host):
            base_url = '%s://[%s]%s' % (self.scheme,
                                        self.server_host, self.path)
        else:
            base_url = '%s://%s%s' % (self.scheme,
                                      self.server_host, self.path)

        return '%s?%s' % (base_url, self.query)

    # NOTE(flaper87): Commenting out for now, it's probably better to do
    # it during image add/get. This validation relies on a config param
    # which doesn't make sense to have in the StoreLocation instance.
    # def _is_valid_path(self, path):
    #    sdir = self.conf.glance_store.vmware_store_image_dir.strip('/')
    #    return path.startswith(os.path.join(DS_URL_PREFIX, sdir))

    def parse_uri(self, uri):
        if not uri.startswith('%s://' % STORE_SCHEME):
            reason = (_("URI %(uri)s must start with %(scheme)s://") %
                      {'uri': uri, 'scheme': STORE_SCHEME})
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)
        (self.scheme, self.server_host,
         path, params, query, fragment) = urlparse.urlparse(uri)
        if not query:
            path, query = path.split('?')

        self.path = path
        self.query = query
        # NOTE(flaper87): Read comment on `_is_valid_path`
        # reason = 'Badly formed VMware datastore URI %(uri)s.' % {'uri': uri}
        # LOG.debug(reason)
        # raise exceptions.BadStoreUri(reason)
        parts = urlparse.parse_qs(self.query)
        dc_path = parts.get('dcPath')
        if dc_path:
            self.datacenter_path = dc_path[0]
        ds_name = parts.get('dsName')
        if ds_name:
            self.datastore_name = ds_name[0]


class Store(glance_store.Store):
    """An implementation of the VMware datastore adapter."""

    _CAPABILITIES = (capabilities.BitMasks.RW_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)
    OPTIONS = _VMWARE_OPTS
    WRITE_CHUNKSIZE = units.Mi
    # FIXME(arnaud): re-visit this code once the store API is cleaned up.
    _VMW_SESSION = None

    def __init__(self, conf):
        super(Store, self).__init__(conf)
        self.datastores = {}

    def reset_session(self, force=False):
        if Store._VMW_SESSION is None or force:
            Store._VMW_SESSION = api.VMwareAPISession(
                self.server_host, self.server_username, self.server_password,
                self.api_retry_count, self.tpoll_interval)
        return Store._VMW_SESSION

    session = property(reset_session)

    def get_schemes(self):
        return (STORE_SCHEME,)

    def _sanity_check(self):
        if self.conf.glance_store.vmware_api_retry_count <= 0:
            msg = _('vmware_api_retry_count should be greater than zero')
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=msg)

        if self.conf.glance_store.vmware_task_poll_interval <= 0:
            msg = _('vmware_task_poll_interval should be greater than zero')
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=msg)

        if not (self.conf.glance_store.vmware_datastore_name
                or self.conf.glance_store.vmware_datastores):
            msg = (_("Specify at least 'vmware_datastore_name' or "
                     "'vmware_datastores' option"))
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=msg)

        if (self.conf.glance_store.vmware_datastore_name and
                self.conf.glance_store.vmware_datastores):
            msg = (_("Specify either 'vmware_datastore_name' or "
                     "'vmware_datastores' option"))
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=msg)

    def configure(self):
        self._sanity_check()
        self.scheme = STORE_SCHEME
        self.server_host = self._option_get('vmware_server_host')
        self.server_username = self._option_get('vmware_server_username')
        self.server_password = self._option_get('vmware_server_password')
        self.api_retry_count = self.conf.glance_store.vmware_api_retry_count
        self.tpoll_interval = self.conf.glance_store.vmware_task_poll_interval
        self.api_insecure = self.conf.glance_store.vmware_api_insecure
        super(Store, self).configure()

    def _get_datacenter(self, datacenter_path):
        search_index_moref = self.session.vim.service_content.searchIndex
        dc_moref = self.session.invoke_api(
            self.session.vim,
            'FindByInventoryPath',
            search_index_moref,
            inventoryPath=datacenter_path)
        dc_name = datacenter_path.rsplit('/', 1)[-1]
        # TODO(sabari): Add datacenter_path attribute in oslo.vmware
        dc_obj = oslo_datacenter.Datacenter(ref=dc_moref, name=dc_name)
        dc_obj.path = datacenter_path
        return dc_obj

    def _get_datastore(self, datacenter_path, datastore_name):
        dc_obj = self._get_datacenter(datacenter_path)
        datastore_ret = self.session.invoke_api(
            vim_util, 'get_object_property', self.session.vim, dc_obj.ref,
            'datastore')
        if datastore_ret:
            datastore_refs = datastore_ret.ManagedObjectReference
            for ds_ref in datastore_refs:
                ds_obj = oslo_datastore.get_datastore_by_ref(self.session,
                                                             ds_ref)
                if ds_obj.name == datastore_name:
                    ds_obj.datacenter = dc_obj
                    return ds_obj

    def _get_freespace(self, ds_obj):
        # TODO(sabari): Move this function into oslo_vmware's datastore object.
        return self.session.invoke_api(
            vim_util, 'get_object_property', self.session.vim, ds_obj.ref,
            'summary.freeSpace')

    def _parse_datastore_info_and_weight(self, datastore):
        weight = 0
        parts = map(lambda x: x.strip(), datastore.rsplit(":", 2))
        if len(parts) < 2:
            msg = _('vmware_datastores format must be '
                    'datacenter_path:datastore_name:weight or '
                    'datacenter_path:datastore_name')
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=msg)
        if len(parts) == 3 and parts[2]:
            weight = parts[2]
            if not weight.isdigit():
                msg = (_('Invalid weight value %(weight)s in '
                         'vmware_datastores configuration') %
                       {'weight': weight})
                LOG.exception(msg)
                raise exceptions.BadStoreConfiguration(
                    store_name="vmware_datastore", reason=msg)
        datacenter_path, datastore_name = parts[0], parts[1]
        if not datacenter_path or not datastore_name:
            msg = _('Invalid datacenter_path or datastore_name specified '
                    'in vmware_datastores configuration')
            LOG.exception(msg)
            raise exceptions.BadStoreConfiguration(
                store_name="vmware_datastore", reason=msg)
        return datacenter_path, datastore_name, weight

    def _build_datastore_weighted_map(self, datastores):
        """Build an ordered map where the key is a weight and the value is a
        Datastore object.

        :param: a list of datastores in the format
                datacenter_path:datastore_name:weight
        :return: a map with key-value <weight>:<Datastore>
        """
        ds_map = {}
        for ds in datastores:
            dc_path, name, weight = self._parse_datastore_info_and_weight(ds)
            # Fetch the server side reference.
            ds_obj = self._get_datastore(dc_path, name)
            if not ds_obj:
                msg = (_("Could not find datastore %(ds_name)s "
                         "in datacenter %(dc_path)s")
                       % {'ds_name': name,
                          'dc_path': dc_path})
                LOG.error(msg)
                raise exceptions.BadStoreConfiguration(
                    store_name='vmware_datastore', reason=msg)
            ds_map.setdefault(int(weight), []).append(ds_obj)
        return ds_map

    def configure_add(self):
        if self.conf.glance_store.vmware_datastores:
            datastores = self.conf.glance_store.vmware_datastores
        else:
            # Backwards compatibility for vmware_datastore_name and
            # vmware_datacenter_path.
            datacenter_path = self.conf.glance_store.vmware_datacenter_path
            datastore_name = self._option_get('vmware_datastore_name')
            datastores = ['%s:%s:%s' % (datacenter_path, datastore_name, 0)]

        self.datastores = self._build_datastore_weighted_map(datastores)
        self.store_image_dir = self.conf.glance_store.vmware_store_image_dir

    def select_datastore(self, image_size):
        """Select a datastore with free space larger than image size."""
        for k, v in sorted(six.iteritems(self.datastores), reverse=True):
            max_ds = None
            max_fs = 0
            for ds in v:
                # Update with current freespace
                ds.freespace = self._get_freespace(ds)
                if ds.freespace > max_fs:
                    max_ds = ds
                    max_fs = ds.freespace
            if max_ds and max_ds.freespace >= image_size:
                return max_ds
        msg = _LE("No datastore found with enough free space to contain an "
                  "image of size %d") % image_size
        LOG.error(msg)
        raise exceptions.StorageFull()

    def _option_get(self, param):
        result = getattr(self.conf.glance_store, param)
        if not result:
            reason = (_("Could not find %(param)s in configuration "
                        "options.") % {'param': param})
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=reason)
        return result

    def _build_vim_cookie_header(self, verify_session=False):
        """Build ESX host session cookie header."""
        if verify_session and not self.session.is_current_session_active():
            self.reset_session(force=True)
        vim_cookies = self.session.vim.client.options.transport.cookiejar
        if len(list(vim_cookies)) > 0:
            cookie = list(vim_cookies)[0]
            return cookie.name + '=' + cookie.value

    @capabilities.check
    def add(self, image_id, image_file, image_size, context=None):
        """Stores an image file with supplied identifier to the backend
        storage system and returns a tuple containing information
        about the stored image.

        :param image_id: The opaque image identifier
        :param image_file: The image data to write, as a file-like object
        :param image_size: The size of the image data to write, in bytes
        :retval tuple of URL in backing store, bytes written, checksum
                and a dictionary with storage system specific information
        :raises `glance.common.exceptions.Duplicate` if the image already
                existed
                `glance.common.exceptions.UnexpectedStatus` if the upload
                request returned an unexpected status. The expected responses
                are 201 Created and 200 OK.
        """
        ds = self.select_datastore(image_size)
        if image_size > 0:
            headers = {'Content-Length': image_size}
            image_file = _Reader(image_file)
        else:
            # NOTE (arnaud): use chunk encoding when the image is still being
            # generated by the server (ex: stream optimized disks generated by
            # Nova).
            headers = {'Transfer-Encoding': 'chunked'}
            image_file = _ChunkReader(image_file)
        loc = StoreLocation({'scheme': self.scheme,
                             'server_host': self.server_host,
                             'image_dir': self.store_image_dir,
                             'datacenter_path': ds.datacenter.path,
                             'datastore_name': ds.name,
                             'image_id': image_id}, self.conf)
        # NOTE(arnaud): use a decorator when the config is not tied to self
        cookie = self._build_vim_cookie_header(True)
        headers = dict(headers.items() + {'Cookie': cookie}.items())
        conn_class = self._get_http_conn_class()
        conn = conn_class(loc.server_host)
        url = urlparse.quote('%s?%s' % (loc.path, loc.query))
        try:
            conn.request('PUT', url, image_file, headers)
        except IOError as e:
            # When a session is not authenticated, the socket is closed by
            # the server after sending the response. httplib has an open
            # issue with https that raises Broken Pipe
            # error instead of returning the response.
            # See http://bugs.python.org/issue16062. Here, we log the error
            # and continue to look into the response.
            msg = _LE('Communication error sending http %(method)s request'
                      'to the url %(url)s.\n'
                      'Got IOError %(e)s') % {'method': 'PUT',
                                              'url': url,
                                              'e': e}
            LOG.error(msg)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to upload content of image '
                                  '%(image)s'), {'image': image_id})
        res = conn.getresponse()
        if res.status == httplib.CONFLICT:
            raise exceptions.Duplicate(_("Image file %(image_id)s already "
                                         "exists!") %
                                       {'image_id': image_id})

        if res.status not in (httplib.CREATED, httplib.OK):
            msg = (_LE('Failed to upload content of image %(image)s. '
                       'The request returned an unexpected status: %(status)s.'
                       '\nThe response body:\n%(body)s') %
                   {'image': image_id,
                    'status': res.status,
                    'body': res.body})
            LOG.error(msg)
            raise exceptions.BackendException(msg)

        return (loc.get_uri(), image_file.size,
                image_file.checksum.hexdigest(), {})

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        conn, resp, content_length = self._query(location, 'GET')
        iterator = http_response_iterator(conn, resp, self.READ_CHUNKSIZE)

        class ResponseIndexable(glance_store.Indexable):

            def another(self):
                try:
                    return self.wrapped.next()
                except StopIteration:
                    return ''

        return (ResponseIndexable(iterator, content_length), content_length)

    def get_size(self, location, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        return self._query(location, 'HEAD')[2]

    @capabilities.check
    def delete(self, location, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :location `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()
        :raises NotFound if image does not exist
        """
        file_path = '[%s] %s' % (
            location.store_location.datastore_name,
            location.store_location.path[len(DS_URL_PREFIX):])
        dc_obj = self._get_datacenter(location.store_location.datacenter_path)
        delete_task = self.session.invoke_api(
            self.session.vim,
            'DeleteDatastoreFile_Task',
            self.session.vim.service_content.fileManager,
            name=file_path,
            datacenter=dc_obj.ref)
        try:
            self.session.wait_for_task(delete_task)
        except vexc.FileNotFoundException:
            msg = _('Image file %s not found') % file_path
            LOG.warn(msg)
            raise exceptions.NotFound(message=msg)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to delete image %(image)s '
                                  'content.') % {'image': location.image_id})

    def _query(self, location, method, depth=0):
        if depth > MAX_REDIRECTS:
            msg = ("The HTTP URL exceeded %(max_redirects)s maximum "
                   "redirects.", {'max_redirects': MAX_REDIRECTS})
            LOG.debug(msg)
            raise exceptions.MaxRedirectsExceeded(redirects=MAX_REDIRECTS)
        loc = location.store_location
        # NOTE(arnaud): use a decorator when the config is not tied to self
        for i in range(self.api_retry_count + 1):
            cookie = self._build_vim_cookie_header()
            headers = {'Cookie': cookie}
            try:
                conn = self._get_http_conn(method, loc, headers)
                resp = conn.getresponse()
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE('Failed to access image %(image)s '
                                      'content.') % {'image':
                                                     location.image_id})
            if resp.status >= 400:
                if resp.status == httplib.UNAUTHORIZED:
                    self.reset_session(force=True)
                    continue
                if resp.status == httplib.NOT_FOUND:
                    reason = _('VMware datastore could not find image at URI.')
                    LOG.info(reason)
                    raise exceptions.NotFound(message=reason)
                msg = ('HTTP request returned a %(status)s status code.'
                       % {'status': resp.status})
                LOG.debug(msg)
                raise exceptions.BadStoreUri(msg)
            break
        location_header = resp.getheader('location')
        if location_header:
            if resp.status not in (301, 302):
                reason = (_("The HTTP URL %(path)s attempted to redirect "
                            "with an invalid %(status)s status code.")
                          % {'path': loc.path, 'status': resp.status})
                LOG.info(reason)
                raise exceptions.BadStoreUri(message=reason)
            location_class = glance_store.location.Location
            new_loc = location_class(location.store_name,
                                     location.store_location.__class__,
                                     uri=location_header,
                                     image_id=location.image_id,
                                     store_specs=location.store_specs)
            return self._query(new_loc, method, depth + 1)
        content_length = int(resp.getheader('content-length', 0))

        return (conn, resp, content_length)

    def _get_http_conn(self, method, loc, headers, content=None):
        conn_class = self._get_http_conn_class()
        conn = conn_class(loc.server_host)
        url = urlparse.quote('%s?%s' % (loc.path, loc.query))
        conn.request(method, url, content, headers)

        return conn

    def _get_http_conn_class(self):
        if self.api_insecure:
            return httplib.HTTPConnection
        return httplib.HTTPSConnection
