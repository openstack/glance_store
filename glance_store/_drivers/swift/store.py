# Copyright 2010-2011 OpenStack Foundation
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

"""Storage backend for SWIFT"""

import hashlib
import httplib
import logging
import math

from oslo_config import cfg
from oslo_utils import excutils
from oslo_utils import units
import six
import six.moves.urllib.parse as urlparse
import swiftclient
import urllib

import glance_store
from glance_store._drivers.swift import utils as sutils
from glance_store import capabilities
from glance_store.common import auth
from glance_store.common import utils as cutils
from glance_store import driver
from glance_store import exceptions
from glance_store import i18n
from glance_store import location


_ = i18n._
LOG = logging.getLogger(__name__)
_LI = i18n._LI

DEFAULT_CONTAINER = 'glance'
DEFAULT_LARGE_OBJECT_SIZE = 5 * units.Ki  # 5GB
DEFAULT_LARGE_OBJECT_CHUNK_SIZE = 200  # 200M
ONE_MB = units.k * units.Ki  # Here we used the mixed meaning of MB

_SWIFT_OPTS = [
    cfg.StrOpt('swift_store_auth_version', default='2',
               help=_('Version of the authentication service to use. '
                      'Valid versions are 2 for keystone and 1 for swauth '
                      'and rackspace. (deprecated)')),
    cfg.BoolOpt('swift_store_auth_insecure', default=False,
                help=_('If True, swiftclient won\'t check for a valid SSL '
                       'certificate when authenticating.')),
    cfg.StrOpt('swift_store_cacert',
               help=_('A string giving the CA certificate file to use in '
                      'SSL connections for verifying certs.')),
    cfg.StrOpt('swift_store_region',
               help=_('The region of the swift endpoint to be used for '
                      'single tenant. This setting is only necessary if the '
                      'tenant has multiple swift endpoints.')),
    cfg.StrOpt('swift_store_endpoint',
               default=None,
               help=_('If set, the configured endpoint will be used. If '
                      'None, the storage url from the auth response will be '
                      'used.')),
    cfg.StrOpt('swift_store_endpoint_type', default='publicURL',
               help=_('A string giving the endpoint type of the swift '
                      'service to use (publicURL, adminURL or internalURL). '
                      'This setting is only used if swift_store_auth_version '
                      'is 2.')),
    cfg.StrOpt('swift_store_service_type', default='object-store',
               help=_('A string giving the service type of the swift service '
                      'to use. This setting is only used if '
                      'swift_store_auth_version is 2.')),
    cfg.StrOpt('swift_store_container',
               default=DEFAULT_CONTAINER,
               help=_('Container within the account that the account should '
                      'use for storing images in Swift when using single '
                      'container mode. In multiple container mode, this will '
                      'be the prefix for all containers.')),
    cfg.IntOpt('swift_store_large_object_size',
               default=DEFAULT_LARGE_OBJECT_SIZE,
               help=_('The size, in MB, that Glance will start chunking image '
                      'files and do a large object manifest in Swift.')),
    cfg.IntOpt('swift_store_large_object_chunk_size',
               default=DEFAULT_LARGE_OBJECT_CHUNK_SIZE,
               help=_('The amount of data written to a temporary '
                      'disk buffer during the process of chunking '
                      'the image file.')),
    cfg.BoolOpt('swift_store_create_container_on_put', default=False,
                help=_('A boolean value that determines if we create the '
                       'container if it does not exist.')),
    cfg.BoolOpt('swift_store_multi_tenant', default=False,
                help=_('If set to True, enables multi-tenant storage '
                       'mode which causes Glance images to be stored in '
                       'tenant specific Swift accounts.')),
    cfg.IntOpt('swift_store_multiple_containers_seed',
               default=0,
               help=_('When set to 0, a single-tenant store will only use one '
                      'container to store all images. When set to an integer '
                      'value between 1 and 32, a single-tenant store will use '
                      'multiple containers to store images, and this value '
                      'will determine how many containers are created.'
                      'Used only when swift_store_multi_tenant is disabled. '
                      'The total number of containers that will be used is '
                      'equal to 16^N, so if this config option is set to 2, '
                      'then 16^2=256 containers will be used to store images.'
                      )),
    cfg.ListOpt('swift_store_admin_tenants', default=[],
                help=_('A list of tenants that will be granted read/write '
                       'access on all Swift containers created by Glance in '
                       'multi-tenant mode.')),
    cfg.BoolOpt('swift_store_ssl_compression', default=True,
                help=_('If set to False, disables SSL layer compression of '
                       'https swift requests. Setting to False may improve '
                       'performance for images which are already in a '
                       'compressed format, eg qcow2.')),
    cfg.IntOpt('swift_store_retry_get_count', default=0,
               help=_('The number of times a Swift download will be retried '
                      'before the request fails.'))
]


def swift_retry_iter(resp_iter, length, store, location, context):
    length = length if length else (resp_iter.len
                                    if hasattr(resp_iter, 'len') else 0)
    retries = 0
    bytes_read = 0

    while retries <= store.conf.glance_store.swift_store_retry_get_count:
        try:
            for chunk in resp_iter:
                yield chunk
                bytes_read += len(chunk)
        except swiftclient.ClientException as e:
            LOG.warn(_("Swift exception raised %s") %
                     cutils.exception_to_str(e))

        if bytes_read != length:
            if retries == store.conf.glance_store.swift_store_retry_get_count:
                # terminate silently and let higher level decide
                LOG.error(_("Stopping Swift retries after %d "
                            "attempts") % retries)
                break
            else:
                retries += 1
                glance_conf = store.conf.glance_store
                retry_count = glance_conf.swift_store_retry_get_count
                LOG.info(_("Retrying Swift connection "
                           "(%(retries)d/%(max_retries)d) with "
                           "range=%(start)d-%(end)d") %
                         {'retries': retries,
                          'max_retries': retry_count,
                          'start': bytes_read,
                          'end': length})
                (_resp_headers, resp_iter) = store._get_object(location, None,
                                                               bytes_read,
                                                               context=context)
        else:
            break


class StoreLocation(location.StoreLocation):

    """
    Class describing a Swift URI. A Swift URI can look like any of
    the following:

        swift://user:pass@authurl.com/container/obj-id
        swift://account:user:pass@authurl.com/container/obj-id
        swift+http://user:pass@authurl.com/container/obj-id
        swift+https://user:pass@authurl.com/container/obj-id

    When using multi-tenant a URI might look like this (a storage URL):

        swift+https://example.com/container/obj-id

    The swift+http:// URIs indicate there is an HTTP authentication URL.
    The default for Swift is an HTTPS authentication URL, so swift:// and
    swift+https:// are the same...
    """

    def process_specs(self):
        self.scheme = self.specs.get('scheme', 'swift+https')
        self.user = self.specs.get('user')
        self.key = self.specs.get('key')
        self.auth_or_store_url = self.specs.get('auth_or_store_url')
        self.container = self.specs.get('container')
        self.obj = self.specs.get('obj')

    def _get_credstring(self):
        if self.user and self.key:
            return '%s:%s' % (urllib.quote(self.user), urllib.quote(self.key))
        return ''

    def get_uri(self, credentials_included=True):
        auth_or_store_url = self.auth_or_store_url
        if auth_or_store_url.startswith('http://'):
            auth_or_store_url = auth_or_store_url[len('http://'):]
        elif auth_or_store_url.startswith('https://'):
            auth_or_store_url = auth_or_store_url[len('https://'):]

        credstring = self._get_credstring()
        auth_or_store_url = auth_or_store_url.strip('/')
        container = self.container.strip('/')
        obj = self.obj.strip('/')

        if not credentials_included:
            # Used only in case of an add
            # Get the current store from config
            store = self.conf.glance_store.default_swift_reference

            return '%s://%s/%s/%s' % ('swift+config', store, container, obj)
        if self.scheme == 'swift+config':
            if self.ssl_enabled:
                self.scheme = 'swift+https'
            else:
                self.scheme = 'swift+http'
        if credstring != '':
            credstring = "%s@" % credstring
        return '%s://%s%s/%s/%s' % (self.scheme, credstring, auth_or_store_url,
                                    container, obj)

    def _get_conf_value_from_account_ref(self, netloc):
        try:
            ref_params = sutils.SwiftParams(self.conf).params
            self.user = ref_params[netloc]['user']
            self.key = ref_params[netloc]['key']
            netloc = ref_params[netloc]['auth_address']
            self.ssl_enabled = True
            if netloc != '':
                if netloc.startswith('http://'):
                    self.ssl_enabled = False
                    netloc = netloc[len('http://'):]
                elif netloc.startswith('https://'):
                    netloc = netloc[len('https://'):]
        except KeyError:
            reason = _("Badly formed Swift URI. Credentials not found for "
                       "account reference")
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)
        return netloc

    def _form_uri_parts(self, netloc, path):
        if netloc != '':
            # > Python 2.6.1
            if '@' in netloc:
                creds, netloc = netloc.split('@')
            else:
                creds = None
        else:
            # Python 2.6.1 compat
            # see lp659445 and Python issue7904
            if '@' in path:
                creds, path = path.split('@')
            else:
                creds = None
            netloc = path[0:path.find('/')].strip('/')
            path = path[path.find('/'):].strip('/')
        if creds:
            cred_parts = creds.split(':')
            if len(cred_parts) < 2:
                reason = _("Badly formed credentials in Swift URI.")
                LOG.info(reason)
                raise exceptions.BadStoreUri(message=reason)
            key = cred_parts.pop()
            user = ':'.join(cred_parts)
            creds = urllib.unquote(creds)
            try:
                self.user, self.key = creds.rsplit(':', 1)
            except exceptions.BadStoreConfiguration:
                self.user = urllib.unquote(user)
                self.key = urllib.unquote(key)
        else:
            self.user = None
            self.key = None
        return netloc, path

    def _form_auth_or_store_url(self, netloc, path):
        path_parts = path.split('/')
        try:
            self.obj = path_parts.pop()
            self.container = path_parts.pop()
            if not netloc.startswith('http'):
                # push hostname back into the remaining to build full authurl
                path_parts.insert(0, netloc)
                self.auth_or_store_url = '/'.join(path_parts)
        except IndexError:
            reason = _("Badly formed Swift URI.")
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)

    def parse_uri(self, uri):
        """
        Parse URLs. This method fixes an issue where credentials specified
        in the URL are interpreted differently in Python 2.6.1+ than prior
        versions of Python. It also deals with the peculiarity that new-style
        Swift URIs have where a username can contain a ':', like so:

            swift://account:user:pass@authurl.com/container/obj
            and for system created locations with account reference
            swift+config://account_reference/container/obj
        """
        # Make sure that URIs that contain multiple schemes, such as:
        # swift://user:pass@http://authurl.com/v1/container/obj
        # are immediately rejected.
        if uri.count('://') != 1:
            reason = _("URI cannot contain more than one occurrence "
                       "of a scheme. If you have specified a URI like "
                       "swift://user:pass@http://authurl.com/v1/container/obj"
                       ", you need to change it to use the "
                       "swift+http:// scheme, like so: "
                       "swift+http://user:pass@authurl.com/v1/container/obj")
            LOG.info(_LI("Invalid store URI: %(reason)s"), {'reason': reason})
            raise exceptions.BadStoreUri(message=reason)

        pieces = urlparse.urlparse(uri)
        assert pieces.scheme in ('swift', 'swift+http', 'swift+https',
                                 'swift+config')

        self.scheme = pieces.scheme
        netloc = pieces.netloc
        path = pieces.path.lstrip('/')

        # NOTE(Sridevi): Fix to map the account reference to the
        # corresponding configuration value
        if self.scheme == 'swift+config':
            netloc = self._get_conf_value_from_account_ref(netloc)
        else:
            netloc, path = self._form_uri_parts(netloc, path)

        self._form_auth_or_store_url(netloc, path)

    @property
    def swift_url(self):
        """
        Creates a fully-qualified auth address that the Swift client library
        can use. The scheme for the auth_address is determined using the scheme
        included in the `location` field.

        HTTPS is assumed, unless 'swift+http' is specified.
        """
        if self.auth_or_store_url.startswith('http'):
            return self.auth_or_store_url
        else:
            if self.scheme == 'swift+config':
                if self.ssl_enabled:
                    self.scheme = 'swift+https'
                else:
                    self.scheme = 'swift+http'
            if self.scheme in ('swift+https', 'swift'):
                auth_scheme = 'https://'
            else:
                auth_scheme = 'http://'

            return ''.join([auth_scheme, self.auth_or_store_url])


def Store(conf):
    try:
        conf.register_opts(_SWIFT_OPTS + sutils.swift_opts,
                           group='glance_store')
    except cfg.DuplicateOptError:
        pass

    if conf.glance_store.swift_store_multi_tenant:
        return MultiTenantStore(conf)
    return SingleTenantStore(conf)

Store.OPTIONS = _SWIFT_OPTS + sutils.swift_opts


def _is_slo(slo_header):
    if (slo_header is not None and isinstance(slo_header, six.string_types)
            and slo_header.lower() == 'true'):
        return True

    return False


class BaseStore(driver.Store):

    _CAPABILITIES = capabilities.BitMasks.RW_ACCESS
    CHUNKSIZE = 65536
    OPTIONS = _SWIFT_OPTS + sutils.swift_opts

    def get_schemes(self):
        return ('swift+https', 'swift', 'swift+http', 'swift+config')

    def configure(self):
        glance_conf = self.conf.glance_store
        _obj_size = self._option_get('swift_store_large_object_size')
        self.large_object_size = _obj_size * ONE_MB
        _chunk_size = self._option_get('swift_store_large_object_chunk_size')
        self.large_object_chunk_size = _chunk_size * ONE_MB
        self.admin_tenants = glance_conf.swift_store_admin_tenants
        self.region = glance_conf.swift_store_region
        self.service_type = glance_conf.swift_store_service_type
        self.conf_endpoint = glance_conf.swift_store_endpoint
        self.endpoint_type = glance_conf.swift_store_endpoint_type
        self.insecure = glance_conf.swift_store_auth_insecure
        self.ssl_compression = glance_conf.swift_store_ssl_compression
        self.cacert = glance_conf.swift_store_cacert
        super(BaseStore, self).configure()

    def _get_object(self, location, connection=None, start=None, context=None):
        if not connection:
            connection = self.get_connection(location, context=context)
        headers = {}
        if start is not None:
            bytes_range = 'bytes=%d-' % start
            headers = {'Range': bytes_range}

        try:
            resp_headers, resp_body = connection.get_object(
                container=location.container, obj=location.obj,
                resp_chunk_size=self.CHUNKSIZE, headers=headers)
        except swiftclient.ClientException as e:
            if e.http_status == httplib.NOT_FOUND:
                msg = _("Swift could not find object %s.") % location.obj
                LOG.warn(msg)
                raise exceptions.NotFound(message=msg)
            else:
                raise

        return (resp_headers, resp_body)

    @capabilities.check
    def get(self, location, connection=None,
            offset=0, chunk_size=None, context=None):
        location = location.store_location
        (resp_headers, resp_body) = self._get_object(location, connection,
                                                     context=context)

        class ResponseIndexable(glance_store.Indexable):
            def another(self):
                try:
                    return self.wrapped.next()
                except StopIteration:
                    return ''

        length = int(resp_headers.get('content-length', 0))
        if self.conf.glance_store.swift_store_retry_get_count > 0:
            resp_body = swift_retry_iter(resp_body, length,
                                         self, location, context)
        return (ResponseIndexable(resp_body, length), length)

    def get_size(self, location, connection=None, context=None):
        location = location.store_location
        if not connection:
            connection = self.get_connection(location, context=context)
        try:
            resp_headers = connection.head_object(
                container=location.container, obj=location.obj)
            return int(resp_headers.get('content-length', 0))
        except Exception:
            return 0

    def _option_get(self, param):
        result = getattr(self.conf.glance_store, param)
        if not result:
            reason = (_("Could not find %(param)s in configuration options.")
                      % param)
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name="swift",
                                                   reason=reason)
        return result

    def _delete_stale_chunks(self, connection, container, chunk_list):
        for chunk in chunk_list:
            LOG.debug("Deleting chunk %s" % chunk)
            try:
                connection.delete_object(container, chunk)
            except Exception:
                msg = _("Failed to delete orphaned chunk "
                        "%(container)s/%(chunk)s")
                LOG.exception(msg % {'container': container,
                                     'chunk': chunk})

    @capabilities.check
    def add(self, image_id, image_file, image_size,
            connection=None, context=None):
        location = self.create_location(image_id, context=context)
        if not connection:
            connection = self.get_connection(location, context=context)

        self._create_container_if_missing(location.container, connection)

        LOG.debug("Adding image object '%(obj_name)s' "
                  "to Swift" % dict(obj_name=location.obj))
        try:
            if image_size > 0 and image_size < self.large_object_size:
                # Image size is known, and is less than large_object_size.
                # Send to Swift with regular PUT.
                obj_etag = connection.put_object(location.container,
                                                 location.obj, image_file,
                                                 content_length=image_size)
            else:
                # Write the image into Swift in chunks.
                chunk_id = 1
                if image_size > 0:
                    total_chunks = str(int(
                        math.ceil(float(image_size) /
                                  float(self.large_object_chunk_size))))
                else:
                    # image_size == 0 is when we don't know the size
                    # of the image. This can occur with older clients
                    # that don't inspect the payload size.
                    LOG.debug("Cannot determine image size. Adding as a "
                              "segmented object to Swift.")
                    total_chunks = '?'

                checksum = hashlib.md5()
                written_chunks = []
                combined_chunks_size = 0
                while True:
                    chunk_size = self.large_object_chunk_size
                    if image_size == 0:
                        content_length = None
                    else:
                        left = image_size - combined_chunks_size
                        if left == 0:
                            break
                        if chunk_size > left:
                            chunk_size = left
                        content_length = chunk_size

                    chunk_name = "%s-%05d" % (location.obj, chunk_id)
                    reader = ChunkReader(image_file, checksum, chunk_size)
                    try:
                        chunk_etag = connection.put_object(
                            location.container, chunk_name, reader,
                            content_length=content_length)
                        written_chunks.append(chunk_name)
                    except Exception:
                        # Delete orphaned segments from swift backend
                        with excutils.save_and_reraise_exception():
                            LOG.exception(_("Error during chunked upload to "
                                            "backend, deleting stale chunks"))
                            self._delete_stale_chunks(connection,
                                                      location.container,
                                                      written_chunks)

                    bytes_read = reader.bytes_read
                    msg = ("Wrote chunk %(chunk_name)s (%(chunk_id)d/"
                           "%(total_chunks)s) of length %(bytes_read)d "
                           "to Swift returning MD5 of content: "
                           "%(chunk_etag)s" %
                           {'chunk_name': chunk_name,
                            'chunk_id': chunk_id,
                            'total_chunks': total_chunks,
                            'bytes_read': bytes_read,
                            'chunk_etag': chunk_etag})
                    LOG.debug(msg)

                    if bytes_read == 0:
                        # Delete the last chunk, because it's of zero size.
                        # This will happen if size == 0.
                        LOG.debug("Deleting final zero-length chunk")
                        connection.delete_object(location.container,
                                                 chunk_name)
                        break

                    chunk_id += 1
                    combined_chunks_size += bytes_read

                # In the case we have been given an unknown image size,
                # set the size to the total size of the combined chunks.
                if image_size == 0:
                    image_size = combined_chunks_size

                # Now we write the object manifest and return the
                # manifest's etag...
                manifest = "%s/%s-" % (location.container, location.obj)
                headers = {'ETag': hashlib.md5("").hexdigest(),
                           'X-Object-Manifest': manifest}

                # The ETag returned for the manifest is actually the
                # MD5 hash of the concatenated checksums of the strings
                # of each chunk...so we ignore this result in favour of
                # the MD5 of the entire image file contents, so that
                # users can verify the image file contents accordingly
                connection.put_object(location.container, location.obj,
                                      None, headers=headers)
                obj_etag = checksum.hexdigest()

            # NOTE: We return the user and key here! Have to because
            # location is used by the API server to return the actual
            # image data. We *really* should consider NOT returning
            # the location attribute from GET /images/<ID> and
            # GET /images/details
            if sutils.is_multiple_swift_store_accounts_enabled(self.conf):
                include_creds = False
            else:
                include_creds = True

            return (location.get_uri(credentials_included=include_creds),
                    image_size, obj_etag, {})
        except swiftclient.ClientException as e:
            if e.http_status == httplib.CONFLICT:
                msg = _("Swift already has an image at this location")
                raise exceptions.Duplicate(message=msg)

            msg = (_(u"Failed to add object to Swift.\n"
                     "Got error from Swift: %s.") % cutils.exception_to_str(e))
            LOG.error(msg)
            raise glance_store.BackendException(msg)

    @capabilities.check
    def delete(self, location, connection=None, context=None):
        location = location.store_location
        if not connection:
            connection = self.get_connection(location, context=context)

        try:
            # We request the manifest for the object. If one exists,
            # that means the object was uploaded in chunks/segments,
            # and we need to delete all the chunks as well as the
            # manifest.
            dlo_manifest = None
            slo_manifest = None
            try:
                headers = connection.head_object(
                    location.container, location.obj)
                dlo_manifest = headers.get('x-object-manifest')
                slo_manifest = headers.get('x-static-large-object')
            except swiftclient.ClientException as e:
                if e.http_status != httplib.NOT_FOUND:
                    raise

            if _is_slo(slo_manifest):
                # Delete the manifest as well as the segments
                query_string = 'multipart-manifest=delete'
                connection.delete_object(location.container, location.obj,
                                         query_string=query_string)
                return

            if dlo_manifest:
                # Delete all the chunks before the object manifest itself
                obj_container, obj_prefix = dlo_manifest.split('/', 1)
                segments = connection.get_container(
                    obj_container, prefix=obj_prefix)[1]
                for segment in segments:
                    # TODO(jaypipes): This would be an easy area to parallelize
                    # since we're simply sending off parallelizable requests
                    # to Swift to delete stuff. It's not like we're going to
                    # be hogging up network or file I/O here...
                    try:
                        connection.delete_object(obj_container,
                                                 segment['name'])
                    except swiftclient.ClientException as e:
                        msg = _('Unable to delete segment %(segment_name)s')
                        msg = msg % {'segment_name': segment['name']}
                        LOG.exception(msg)

            # Delete object (or, in segmented case, the manifest)
            connection.delete_object(location.container, location.obj)

        except swiftclient.ClientException as e:
            if e.http_status == httplib.NOT_FOUND:
                msg = _("Swift could not find image at URI.")
                raise exceptions.NotFound(message=msg)
            else:
                raise

    def _create_container_if_missing(self, container, connection):
        """
        Creates a missing container in Swift if the
        ``swift_store_create_container_on_put`` option is set.

        :param container: Name of container to create
        :param connection: Connection to swift service
        """
        try:
            connection.head_container(container)
        except swiftclient.ClientException as e:
            if e.http_status == httplib.NOT_FOUND:
                if self.conf.glance_store.swift_store_create_container_on_put:
                    try:
                        msg = (_LI("Creating swift container %(container)s") %
                               {'container': container})
                        LOG.info(msg)
                        connection.put_container(container)
                    except swiftclient.ClientException as e:
                        msg = (_("Failed to add container to Swift.\n"
                                 "Got error from Swift: %s.") %
                               cutils.exception_to_str(e))
                        raise glance_store.BackendException(msg)
                else:
                    msg = (_("The container %(container)s does not exist in "
                             "Swift. Please set the "
                             "swift_store_create_container_on_put option "
                             "to add container to Swift automatically.") %
                           {'container': container})
                    raise glance_store.BackendException(msg)
            else:
                raise

    def get_connection(self, location, context=None):
        raise NotImplementedError()

    def create_location(self, image_id, context=None):
        raise NotImplementedError()


class SingleTenantStore(BaseStore):
    EXAMPLE_URL = "swift://<USER>:<KEY>@<AUTH_ADDRESS>/<CONTAINER>/<FILE>"

    def __init__(self, conf):
        super(SingleTenantStore, self).__init__(conf)
        self.ref_params = sutils.SwiftParams(self.conf).params

    def configure(self):
        super(SingleTenantStore, self).configure()
        self.auth_version = self._option_get('swift_store_auth_version')

    def configure_add(self):
        default_ref = self.conf.glance_store.default_swift_reference
        default_swift_reference = self.ref_params.get(default_ref)
        if default_swift_reference:
            self.auth_address = default_swift_reference.get('auth_address')
        if (not default_swift_reference) or (not self.auth_address):
            reason = _("A value for swift_store_auth_address is required.")
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(message=reason)

        if self.auth_address.startswith('http://'):
            self.scheme = 'swift+http'
        else:
            self.scheme = 'swift+https'
        self.container = self.conf.glance_store.swift_store_container
        self.user = default_swift_reference.get('user')
        self.key = default_swift_reference.get('key')

        if not (self.user or self.key):
            reason = _("A value for swift_store_ref_params is required.")
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name="swift",
                                                   reason=reason)

    def create_location(self, image_id, context=None):
        container_name = self.get_container_name(image_id, self.container)
        specs = {'scheme': self.scheme,
                 'container': container_name,
                 'obj': str(image_id),
                 'auth_or_store_url': self.auth_address,
                 'user': self.user,
                 'key': self.key}
        return StoreLocation(specs, self.conf)

    def get_container_name(self, image_id, default_image_container):
        """
        Returns appropriate container name depending upon value of
        ``swift_store_multiple_containers_seed``. In single-container mode,
        which is a seed value of 0, simply returns default_image_container.
        In multiple-container mode, returns default_image_container as the
        prefix plus a suffix determined by the multiple container seed

        examples:
            single-container mode:  'glance'
            multiple-container mode: 'glance_3a1' for image uuid 3A1xxxxxxx...

        :param image_id: UUID of image
        :param default_image_container: container name from
               ``swift_store_container``
        """
        seed_num_chars = \
            self.conf.glance_store.swift_store_multiple_containers_seed
        if seed_num_chars is None \
                or seed_num_chars < 0 or seed_num_chars > 32:
            reason = _("An integer value between 0 and 32 is required for"
                       " swift_store_multiple_containers_seed.")
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name="swift",
                                                   reason=reason)
        elif seed_num_chars > 0:
            image_id = str(image_id).lower()

            num_dashes = image_id[:seed_num_chars].count('-')
            num_chars = seed_num_chars + num_dashes
            name_suffix = image_id[:num_chars]
            new_container_name = default_image_container + '_' + name_suffix
            return new_container_name
        else:
            return default_image_container

    def get_connection(self, location, context=None):
        if not location.user:
            reason = _("Location is missing user:password information.")
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)

        auth_url = location.swift_url
        if not auth_url.endswith('/'):
            auth_url += '/'

        if self.auth_version == '2':
            try:
                tenant_name, user = location.user.split(':')
            except ValueError:
                reason = (_("Badly formed tenant:user '%(user)s' in "
                            "Swift URI") % {'user': location.user})
                LOG.info(reason)
                raise exceptions.BadStoreUri(message=reason)
        else:
            tenant_name = None
            user = location.user

        os_options = {}
        if self.region:
            os_options['region_name'] = self.region
        os_options['endpoint_type'] = self.endpoint_type
        os_options['service_type'] = self.service_type

        return swiftclient.Connection(
            auth_url, user, location.key, preauthurl=self.conf_endpoint,
            insecure=self.insecure, tenant_name=tenant_name,
            auth_version=self.auth_version, os_options=os_options,
            ssl_compression=self.ssl_compression, cacert=self.cacert)


class MultiTenantStore(BaseStore):
    EXAMPLE_URL = "swift://<SWIFT_URL>/<CONTAINER>/<FILE>"

    def _get_endpoint(self, context):
        self.container = self.conf.glance_store.swift_store_container
        if context is None:
            reason = _("Multi-tenant Swift storage requires a context.")
            raise exceptions.BadStoreConfiguration(store_name="swift",
                                                   reason=reason)
        if context.service_catalog is None:
            reason = _("Multi-tenant Swift storage requires "
                       "a service catalog.")
            raise exceptions.BadStoreConfiguration(store_name="swift",
                                                   reason=reason)
        self.storage_url = self.conf_endpoint
        if not self.storage_url:
            self.storage_url = auth.get_endpoint(
                context.service_catalog, service_type=self.service_type,
                endpoint_region=self.region, endpoint_type=self.endpoint_type)

        if self.storage_url.startswith('http://'):
            self.scheme = 'swift+http'
        else:
            self.scheme = 'swift+https'

        return self.storage_url

    def delete(self, location, connection=None, context=None):
        if not connection:
            connection = self.get_connection(location.store_location,
                                             context=context)
        super(MultiTenantStore, self).delete(location, connection)
        connection.delete_container(location.store_location.container)

    def set_acls(self, location, public=False, read_tenants=None,
                 write_tenants=None, connection=None, context=None):
        location = location.store_location
        if not connection:
            connection = self.get_connection(location, context=context)

        if read_tenants is None:
            read_tenants = []
        if write_tenants is None:
            write_tenants = []

        headers = {}
        if public:
            headers['X-Container-Read'] = "*:*"
        elif read_tenants:
            headers['X-Container-Read'] = ','.join('%s:*' % i
                                                   for i in read_tenants)
        else:
            headers['X-Container-Read'] = ''

        write_tenants.extend(self.admin_tenants)
        if write_tenants:
            headers['X-Container-Write'] = ','.join('%s:*' % i
                                                    for i in write_tenants)
        else:
            headers['X-Container-Write'] = ''

        try:
            connection.post_container(location.container, headers=headers)
        except swiftclient.ClientException as e:
            if e.http_status == httplib.NOT_FOUND:
                msg = _("Swift could not find image at URI.")
                raise exceptions.NotFound(message=msg)
            else:
                raise

    def create_location(self, image_id, context=None):
        ep = self._get_endpoint(context)
        specs = {'scheme': self.scheme,
                 'container': self.container + '_' + str(image_id),
                 'obj': str(image_id),
                 'auth_or_store_url': ep}
        return StoreLocation(specs, self.conf)

    def get_connection(self, location, context=None):
        return swiftclient.Connection(
            None, context.user, None,
            preauthurl=location.swift_url,
            preauthtoken=context.auth_token,
            tenant_name=context.tenant,
            auth_version='2', insecure=self.insecure,
            ssl_compression=self.ssl_compression,
            cacert=self.cacert)


class ChunkReader(object):
    def __init__(self, fd, checksum, total):
        self.fd = fd
        self.checksum = checksum
        self.total = total
        self.bytes_read = 0

    def read(self, i):
        left = self.total - self.bytes_read
        if i > left:
            i = left
        result = self.fd.read(i)
        self.bytes_read += len(result)
        self.checksum.update(result)
        return result
