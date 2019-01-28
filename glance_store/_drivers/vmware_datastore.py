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
import logging
import os

from oslo_config import cfg
from oslo_utils import excutils
from oslo_utils import netutils
from oslo_utils import units
try:
    from oslo_vmware import api
    import oslo_vmware.exceptions as vexc
    from oslo_vmware.objects import datacenter as oslo_datacenter
    from oslo_vmware.objects import datastore as oslo_datastore
    from oslo_vmware import vim_util
except ImportError:
    api = None

from six.moves import urllib
import six.moves.urllib.parse as urlparse

import requests
from requests import adapters
from requests.packages.urllib3.util import retry
import six
# NOTE(jokke): simplified transition to py3, behaves like py2 xrange
from six.moves import range

import glance_store
from glance_store import capabilities
from glance_store.common import utils
from glance_store import exceptions
from glance_store.i18n import _, _LE
from glance_store import location


LOG = logging.getLogger(__name__)

CHUNKSIZE = 1024 * 64  # 64kB
MAX_REDIRECTS = 5
DEFAULT_STORE_IMAGE_DIR = '/openstack_glance'
DS_URL_PREFIX = '/folder'
STORE_SCHEME = 'vsphere'

_VMWARE_OPTS = [
    cfg.HostAddressOpt('vmware_server_host',
                       sample_default='127.0.0.1',
                       help="""
Address of the ESX/ESXi or vCenter Server target system.

This configuration option sets the address of the ESX/ESXi or vCenter
Server target system. This option is required when using the VMware
storage backend. The address can contain an IP address (127.0.0.1) or
a DNS name (www.my-domain.com).

Possible Values:
    * A valid IPv4 or IPv6 address
    * A valid DNS name

Related options:
    * vmware_server_username
    * vmware_server_password

"""),
    cfg.StrOpt('vmware_server_username',
               sample_default='root',
               help="""
Server username.

This configuration option takes the username for authenticating with
the VMware ESX/ESXi or vCenter Server. This option is required when
using the VMware storage backend.

Possible Values:
    * Any string that is the username for a user with appropriate
      privileges

Related options:
    * vmware_server_host
    * vmware_server_password

"""),
    cfg.StrOpt('vmware_server_password',
               sample_default='vmware',
               help="""
Server password.

This configuration option takes the password for authenticating with
the VMware ESX/ESXi or vCenter Server. This option is required when
using the VMware storage backend.

Possible Values:
    * Any string that is a password corresponding to the username
      specified using the "vmware_server_username" option

Related options:
    * vmware_server_host
    * vmware_server_username

""",
               secret=True),
    cfg.IntOpt('vmware_api_retry_count',
               default=10,
               min=1,
               help="""
The number of VMware API retries.

This configuration option specifies the number of times the VMware
ESX/VC server API must be retried upon connection related issues or
server API call overload. It is not possible to specify 'retry
forever'.

Possible Values:
    * Any positive integer value

Related options:
    * None

"""),
    cfg.IntOpt('vmware_task_poll_interval',
               default=5,
               min=1,
               help="""
Interval in seconds used for polling remote tasks invoked on VMware
ESX/VC server.

This configuration option takes in the sleep time in seconds for polling an
on-going async task as part of the VMWare ESX/VC server API call.

Possible Values:
    * Any positive integer value

Related options:
    * None

"""),
    cfg.StrOpt('vmware_store_image_dir',
               default=DEFAULT_STORE_IMAGE_DIR,
               help="""
The directory where the glance images will be stored in the datastore.

This configuration option specifies the path to the directory where the
glance images will be stored in the VMware datastore. If this option
is not set,  the default directory where the glance images are stored
is openstack_glance.

Possible Values:
    * Any string that is a valid path to a directory

Related options:
    * None

"""),
    cfg.BoolOpt('vmware_insecure',
                default=False,
                deprecated_name='vmware_api_insecure',
                help="""
Set verification of the ESX/vCenter server certificate.

This configuration option takes a boolean value to determine
whether or not to verify the ESX/vCenter server certificate. If this
option is set to True, the ESX/vCenter server certificate is not
verified. If this option is set to False, then the default CA
truststore is used for verification.

This option is ignored if the "vmware_ca_file" option is set. In that
case, the ESX/vCenter server certificate will then be verified using
the file specified using the "vmware_ca_file" option .

Possible Values:
    * True
    * False

Related options:
    * vmware_ca_file

"""),
    cfg.StrOpt('vmware_ca_file',
               sample_default='/etc/ssl/certs/ca-certificates.crt',
               help="""
Absolute path to the CA bundle file.

This configuration option enables the operator to use a custom
Cerificate Authority File to verify the ESX/vCenter certificate.

If this option is set, the "vmware_insecure" option will be ignored
and the CA file specified will be used to authenticate the ESX/vCenter
server certificate and establish a secure connection to the server.

Possible Values:
    * Any string that is a valid absolute path to a CA file

Related options:
    * vmware_insecure

"""),
    cfg.MultiStrOpt(
        'vmware_datastores',
        help="""
The datastores where the image can be stored.

This configuration option specifies the datastores where the image can
be stored in the VMWare store backend. This option may be specified
multiple times for specifying multiple datastores. The datastore name
should be specified after its datacenter path, separated by ":". An
optional weight may be given after the datastore name, separated again
by ":" to specify the priority. Thus, the required format becomes
<datacenter_path>:<datastore_name>:<optional_weight>.

When adding an image, the datastore with highest weight will be
selected, unless there is not enough free space available in cases
where the image size is already known. If no weight is given, it is
assumed to be zero and the directory will be considered for selection
last. If multiple datastores have the same weight, then the one with
the most free space available is selected.

Possible Values:
    * Any string of the format:
      <datacenter_path>:<datastore_name>:<optional_weight>

Related options:
   * None

""")]


def http_response_iterator(conn, response, size):
    """Return an iterator for a file-like object.

    :param conn: HTTP(S) Connection
    :param response: http_client.HTTPResponse object
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

    def __init__(self, data, hashing_algo, verifier=None):
        self._size = 0
        self.data = data
        self.checksum = hashlib.md5()
        self.os_hash_value = hashlib.new(str(hashing_algo))
        self.verifier = verifier

    def read(self, size=None):
        result = self.data.read(size)
        self._size += len(result)
        self.checksum.update(result)
        self.os_hash_value.update(result)
        if self.verifier:
            self.verifier.update(result)
        return result

    @property
    def size(self):
        return self._size


class StoreLocation(location.StoreLocation):
    """Class describing an VMware URI.

    An VMware URI can look like any of the following:
    vsphere://server_host/folder/file_path?dcPath=dc_path&dsName=ds_name
    """

    def __init__(self, store_specs, conf, backend_group=None):
        super(StoreLocation, self).__init__(store_specs, conf,
                                            backend_group=backend_group)
        self.datacenter_path = None
        self.datastore_name = None
        self.backend_group = backend_group

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
        self.query = urllib.parse.urlencode(param_list)

    def get_uri(self):
        if netutils.is_valid_ipv6(self.server_host):
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
        self.validate_schemas(uri, valid_schemas=('%s://' % STORE_SCHEME,))
        (self.scheme, self.server_host,
         path, params, query, fragment) = urllib.parse.urlparse(uri)
        if not query:
            path, query = path.split('?')

        self.path = path
        self.query = query
        # NOTE(flaper87): Read comment on `_is_valid_path`
        # reason = 'Badly formed VMware datastore URI %(uri)s.' % {'uri': uri}
        # LOG.debug(reason)
        # raise exceptions.BadStoreUri(reason)
        parts = urllib.parse.parse_qs(self.query)
        dc_path = parts.get('dcPath')
        if dc_path:
            self.datacenter_path = dc_path[0]
        ds_name = parts.get('dsName')
        if ds_name:
            self.datastore_name = ds_name[0]

    @property
    def https_url(self):
        """
        Creates a https url that can be used to upload/download data from a
        vmware store.
        """
        parsed_url = urlparse.urlparse(self.get_uri())
        new_url = parsed_url._replace(scheme='https')
        return urlparse.urlunparse(new_url)


class Store(glance_store.Store):
    """An implementation of the VMware datastore adapter."""

    _CAPABILITIES = (capabilities.BitMasks.RW_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)
    OPTIONS = _VMWARE_OPTS
    WRITE_CHUNKSIZE = units.Mi

    def __init__(self, conf, backend=None):
        super(Store, self).__init__(conf, backend=backend)
        self.datastores = {}

    def reset_session(self):
        self.session = api.VMwareAPISession(
            self.server_host, self.server_username, self.server_password,
            self.api_retry_count, self.tpoll_interval,
            cacert=self.ca_file,
            insecure=self.api_insecure)
        return self.session

    def get_schemes(self):
        return (STORE_SCHEME,)

    def _sanity_check(self):
        if self.backend_group:
            store_conf = getattr(self.conf, self.backend_group)
        else:
            store_conf = self.conf.glance_store

        if store_conf.vmware_api_retry_count <= 0:
            msg = _('vmware_api_retry_count should be greater than zero')
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=msg)

        if store_conf.vmware_task_poll_interval <= 0:
            msg = _('vmware_task_poll_interval should be greater than zero')
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=msg)

    def configure(self, re_raise_bsc=False):
        self._sanity_check()
        self.scheme = STORE_SCHEME
        self.server_host = self._option_get('vmware_server_host')
        self.server_username = self._option_get('vmware_server_username')
        self.server_password = self._option_get('vmware_server_password')

        if self.backend_group:
            store_conf = getattr(self.conf, self.backend_group)
        else:
            store_conf = self.conf.glance_store

        self.api_retry_count = store_conf.vmware_api_retry_count
        self.tpoll_interval = store_conf.vmware_task_poll_interval
        self.ca_file = store_conf.vmware_ca_file
        self.api_insecure = store_conf.vmware_insecure
        if api is None:
            msg = _("Missing dependencies: oslo_vmware")
            raise exceptions.BadStoreConfiguration(
                store_name="vmware_datastore", reason=msg)
        self.session = self.reset_session()
        super(Store, self).configure(re_raise_bsc=re_raise_bsc)

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
        parts = [part.strip() for part in datastore.rsplit(":", 2)]
        if len(parts) < 2:
            msg = _('vmware_datastores format must be '
                    'datacenter_path:datastore_name:weight or '
                    'datacenter_path:datastore_name')
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=msg)
        if len(parts) == 3 and parts[2]:
            try:
                weight = int(parts[2])
            except ValueError:
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
            ds_map.setdefault(weight, []).append(ds_obj)
        return ds_map

    def configure_add(self):
        datastores = self._option_get('vmware_datastores')
        self.datastores = self._build_datastore_weighted_map(datastores)

        if self.backend_group:
            store_conf = getattr(self.conf, self.backend_group)
        else:
            store_conf = self.conf.glance_store

        self.store_image_dir = store_conf.vmware_store_image_dir

    def select_datastore(self, image_size):
        """Select a datastore with free space larger than image size."""
        for k, v in sorted(self.datastores.items(), reverse=True):
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
        if self.backend_group:
            store_conf = getattr(self.conf, self.backend_group)
        else:
            store_conf = self.conf.glance_store

        result = getattr(store_conf, param)
        if not result:
            reason = (_("Could not find %(param)s in configuration "
                        "options.") % {'param': param})
            raise exceptions.BadStoreConfiguration(
                store_name='vmware_datastore', reason=reason)
        return result

    def _build_vim_cookie_header(self, verify_session=False):
        """Build ESX host session cookie header."""
        if verify_session and not self.session.is_current_session_active():
            self.reset_session()
        vim_cookies = self.session.vim.client.options.transport.cookiejar
        if len(list(vim_cookies)) > 0:
            cookie = list(vim_cookies)[0]
            return cookie.name + '=' + cookie.value

    @glance_store.driver.back_compat_add
    @capabilities.check
    def add(self, image_id, image_file, image_size, hashing_algo, context=None,
            verifier=None):
        """Stores an image file with supplied identifier to the backend
        storage system and returns a tuple containing information
        about the stored image.

        :param image_id: The opaque image identifier
        :param image_file: The image data to write, as a file-like object
        :param image_size: The size of the image data to write, in bytes
        :param hashing_algo: A hashlib algorithm identifier (string)
        :param context: A context object
        :param verifier: An object used to verify signatures for images

        :returns: tuple of: (1) URL in backing store, (2) bytes written,
                  (3) checksum, (4) multihash value, and (5) a dictionary
                  with storage system specific information
        :raises: `glance_store.exceptions.Duplicate` if the image already
                 exists
        :raises: `glance.common.exceptions.UnexpectedStatus` if the upload
                 request returned an unexpected status. The expected responses
                 are 201 Created and 200 OK.
        """
        ds = self.select_datastore(image_size)
        image_file = _Reader(image_file, hashing_algo, verifier)
        headers = {}
        if image_size > 0:
            headers.update({'Content-Length': six.text_type(image_size)})
            data = image_file
        else:
            data = utils.chunkiter(image_file, CHUNKSIZE)
        loc = StoreLocation({'scheme': self.scheme,
                             'server_host': self.server_host,
                             'image_dir': self.store_image_dir,
                             'datacenter_path': ds.datacenter.path,
                             'datastore_name': ds.name,
                             'image_id': image_id}, self.conf,
                            backend_group=self.backend_group)
        # NOTE(arnaud): use a decorator when the config is not tied to self
        cookie = self._build_vim_cookie_header(True)
        headers = dict(headers)
        headers.update({'Cookie': cookie})
        session = new_session(self.api_insecure, self.ca_file)

        url = loc.https_url
        try:
            response = session.put(url, data=data, headers=headers)
        except IOError as e:
            # TODO(sigmavirus24): Figure out what the new exception type would
            # be in requests.
            # When a session is not authenticated, the socket is closed by
            # the server after sending the response. http_client has an open
            # issue with https that raises Broken Pipe
            # error instead of returning the response.
            # See http://bugs.python.org/issue16062. Here, we log the error
            # and continue to look into the response.
            msg = _LE('Communication error sending http %(method)s request '
                      'to the url %(url)s.\n'
                      'Got IOError %(e)s') % {'method': 'PUT',
                                              'url': url,
                                              'e': e}
            LOG.error(msg)
            raise exceptions.BackendException(msg)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to upload content of image '
                                  '%(image)s'), {'image': image_id})

        res = response.raw
        if res.status == requests.codes.conflict:
            raise exceptions.Duplicate(_("Image file %(image_id)s already "
                                         "exists!") %
                                       {'image_id': image_id})

        if res.status not in (requests.codes.created, requests.codes.ok):
            msg = (_LE('Failed to upload content of image %(image)s. '
                       'The request returned an unexpected status: %(status)s.'
                       '\nThe response body:\n%(body)s') %
                   {'image': image_id,
                    'status': res.status,
                    'body': getattr(res, 'body', None)})
            LOG.error(msg)
            raise exceptions.BackendException(msg)

        metadata = {}
        if self.backend_group:
            metadata['backend'] = u"%s" % self.backend_group

        return (loc.get_uri(),
                image_file.size,
                image_file.checksum.hexdigest(),
                image_file.os_hash_value.hexdigest(),
                metadata)

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
                    return next(self.wrapped)
                except StopIteration:
                    return ''

        return (ResponseIndexable(iterator, content_length), content_length)

    def get_size(self, location, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        conn = None
        try:
            conn, resp, size = self._query(location, 'HEAD')
            return size
        finally:
            # NOTE(sabari): Close the connection as the request was made with
            # stream=True.
            if conn is not None:
                conn.close()

    @capabilities.check
    def delete(self, location, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :param location: `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()
        :raises: NotFound if image does not exist
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
            LOG.warning(msg)
            raise exceptions.NotFound(message=msg)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to delete image %(image)s '
                                  'content.') % {'image': location.image_id})

    def _query(self, location, method):
        session = new_session(self.api_insecure, self.ca_file)
        loc = location.store_location
        redirects_followed = 0
        # TODO(sabari): The redirect logic was added to handle cases when the
        # backend redirects http url's to https. But the store never makes a
        # http request and hence this can be safely removed.
        while redirects_followed < MAX_REDIRECTS:
            conn, resp = self._retry_request(session, method, location)

            # NOTE(sigmavirus24): _retry_request handles 4xx and 5xx errors so
            # if the response is not a redirect, we can return early.
            if not conn.is_redirect:
                break

            redirects_followed += 1

            location_header = conn.headers.get('location')
            if location_header:
                if resp.status not in (301, 302):
                    reason = (_("The HTTP URL %(path)s attempted to redirect "
                                "with an invalid %(status)s status code.")
                              % {'path': loc.path, 'status': resp.status})
                    LOG.info(reason)
                    raise exceptions.BadStoreUri(message=reason)
                conn.close()
                location = self._new_location(location, location_header)
        else:
            # NOTE(sigmavirus24): We exceeded the maximum number of redirects
            msg = ("The HTTP URL exceeded %(max_redirects)s maximum "
                   "redirects.", {'max_redirects': MAX_REDIRECTS})
            LOG.debug(msg)
            raise exceptions.MaxRedirectsExceeded(redirects=MAX_REDIRECTS)

        content_length = int(resp.getheader('content-length', 0))

        return (conn, resp, content_length)

    def _retry_request(self, session, method, location):
        loc = location.store_location
        # NOTE(arnaud): use a decorator when the config is not tied to self
        for i in range(self.api_retry_count + 1):
            cookie = self._build_vim_cookie_header()
            headers = {'Cookie': cookie}
            conn = session.request(method, loc.https_url, headers=headers,
                                   stream=True)
            resp = conn.raw

            if resp.status >= 400:
                if resp.status == requests.codes.unauthorized:
                    self.reset_session()
                    continue
                if resp.status == requests.codes.not_found:
                    reason = _('VMware datastore could not find image at URI.')
                    LOG.info(reason)
                    raise exceptions.NotFound(message=reason)
                msg = ('HTTP request returned a %(status)s status code.'
                       % {'status': resp.status})
                LOG.debug(msg)
                raise exceptions.BadStoreUri(msg)
            break
        return conn, resp

    def _new_location(self, old_location, url):
        store_name = old_location.store_name
        store_class = old_location.store_location.__class__
        image_id = old_location.image_id
        store_specs = old_location.store_specs
        # Note(sabari): The redirect url will have a scheme 'http(s)', but the
        # store only accepts url with scheme 'vsphere'. Thus, replacing with
        # store's scheme.
        parsed_url = urlparse.urlparse(url)
        new_url = parsed_url._replace(scheme='vsphere')
        vsphere_url = urlparse.urlunparse(new_url)
        return glance_store.location.Location(store_name,
                                              store_class,
                                              self.conf,
                                              uri=vsphere_url,
                                              image_id=image_id,
                                              store_specs=store_specs,
                                              backend=self.backend_group)


def new_session(insecure=False, ca_file=None, total_retries=None):
    session = requests.Session()
    if total_retries is not None:
        http_adapter = adapters.HTTPAdapter(
            max_retries=retry.Retry(total=total_retries))
        https_adapter = adapters.HTTPAdapter(
            max_retries=retry.Retry(total=total_retries))
        session.mount('http://', http_adapter)
        session.mount('https://', https_adapter)
    session.verify = ca_file if ca_file else not insecure
    return session
