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
import logging
import math

from keystoneauth1.access import service_catalog as keystone_sc
from keystoneauth1 import identity as ks_identity
from keystoneauth1 import session as ks_session
from keystoneclient.v3 import client as ks_client
from oslo_config import cfg
from oslo_utils import encodeutils
from oslo_utils import excutils
from oslo_utils import units
import six
from six.moves import http_client
from six.moves import urllib
try:
    import swiftclient
except ImportError:
    swiftclient = None

import glance_store
from glance_store._drivers.swift import buffered
from glance_store._drivers.swift import connection_manager
from glance_store._drivers.swift import utils as sutils
from glance_store import capabilities
from glance_store import driver
from glance_store import exceptions
from glance_store.i18n import _, _LE, _LI
from glance_store import location


LOG = logging.getLogger(__name__)

DEFAULT_CONTAINER = 'glance'
DEFAULT_LARGE_OBJECT_SIZE = 5 * units.Ki  # 5GB
DEFAULT_LARGE_OBJECT_CHUNK_SIZE = 200  # 200M
ONE_MB = units.k * units.Ki  # Here we used the mixed meaning of MB

_SWIFT_OPTS = [
    cfg.BoolOpt('swift_store_auth_insecure', default=False,
                help="""
Set verification of the server certificate.

This boolean determines whether or not to verify the server
certificate. If this option is set to True, swiftclient won't check
for a valid SSL certificate when authenticating. If the option is set
to False, then the default CA truststore is used for verification.

Possible values:
    * True
    * False

Related options:
    * swift_store_cacert

"""),
    cfg.StrOpt('swift_store_cacert',
               sample_default='/etc/ssl/certs/ca-certificates.crt',
               help="""
Path to the CA bundle file.

This configuration option enables the operator to specify the path to
a custom Certificate Authority file for SSL verification when
connecting to Swift.

Possible values:
    * A valid path to a CA file

Related options:
    * swift_store_auth_insecure

"""),
    cfg.StrOpt('swift_store_region',
               sample_default='RegionTwo',
               help="""
The region of Swift endpoint to use by Glance.

Provide a string value representing a Swift region where Glance
can connect to for image storage. By default, there is no region
set.

When Glance uses Swift as the storage backend to store images
for a specific tenant that has multiple endpoints, setting of a
Swift region with ``swift_store_region`` allows Glance to connect
to Swift in the specified region as opposed to a single region
connectivity.

This option can be configured for both single-tenant and
multi-tenant storage.

NOTE: Setting the region with ``swift_store_region`` is
tenant-specific and is necessary ``only if`` the tenant has
multiple endpoints across different regions.

Possible values:
    * A string value representing a valid Swift region.

Related Options:
    * None

"""),
    cfg.StrOpt('swift_store_endpoint',
               sample_default="""\
https://swift.openstack.example.org/v1/path_not_including_container\
_name\
""",
               help="""
The URL endpoint to use for Swift backend storage.

Provide a string value representing the URL endpoint to use for
storing Glance images in Swift store. By default, an endpoint
is not set and the storage URL returned by ``auth`` is used.
Setting an endpoint with ``swift_store_endpoint`` overrides the
storage URL and is used for Glance image storage.

NOTE: The URL should include the path up to, but excluding the
container. The location of an object is obtained by appending
the container and object to the configured URL.

Possible values:
    * String value representing a valid URL path up to a Swift container

Related Options:
    * None

"""),
    cfg.StrOpt('swift_store_endpoint_type', default='publicURL',
               choices=('publicURL', 'adminURL', 'internalURL'),
               help="""
Endpoint Type of Swift service.

This string value indicates the endpoint type to use to fetch the
Swift endpoint. The endpoint type determines the actions the user will
be allowed to perform, for instance, reading and writing to the Store.
This setting is only used if swift_store_auth_version is greater than
1.

Possible values:
    * publicURL
    * adminURL
    * internalURL

Related options:
    * swift_store_endpoint

"""),
    cfg.StrOpt('swift_store_service_type',
               default='object-store',
               help="""
Type of Swift service to use.

Provide a string value representing the service type to use for
storing images while using Swift backend storage. The default
service type is set to ``object-store``.

NOTE: If ``swift_store_auth_version`` is set to 2, the value for
this configuration option needs to be ``object-store``. If using
a higher version of Keystone or a different auth scheme, this
option may be modified.

Possible values:
    * A string representing a valid service type for Swift storage.

Related Options:
    * None

"""),
    cfg.StrOpt('swift_store_container',
               default=DEFAULT_CONTAINER,
               help="""
Name of single container to store images/name prefix for multiple containers

When a single container is being used to store images, this configuration
option indicates the container within the Glance account to be used for
storing all images. When multiple containers are used to store images, this
will be the name prefix for all containers. Usage of single/multiple
containers can be controlled using the configuration option
``swift_store_multiple_containers_seed``.

When using multiple containers, the containers will be named after the value
set for this configuration option with the first N chars of the image UUID
as the suffix delimited by an underscore (where N is specified by
``swift_store_multiple_containers_seed``).

Example: if the seed is set to 3 and swift_store_container = ``glance``, then
an image with UUID ``fdae39a1-bac5-4238-aba4-69bcc726e848`` would be placed in
the container ``glance_fda``. All dashes in the UUID are included when
creating the container name but do not count toward the character limit, so
when N=10 the container name would be ``glance_fdae39a1-ba.``

Possible values:
    * If using single container, this configuration option can be any string
      that is a valid swift container name in Glance's Swift account
    * If using multiple containers, this configuration option can be any
      string as long as it satisfies the container naming rules enforced by
      Swift. The value of ``swift_store_multiple_containers_seed`` should be
      taken into account as well.

Related options:
    * ``swift_store_multiple_containers_seed``
    * ``swift_store_multi_tenant``
    * ``swift_store_create_container_on_put``

"""),
    cfg.IntOpt('swift_store_large_object_size',
               default=DEFAULT_LARGE_OBJECT_SIZE, min=1,
               help="""
The size threshold, in MB, after which Glance will start segmenting image data.

Swift has an upper limit on the size of a single uploaded object. By default,
this is 5GB. To upload objects bigger than this limit, objects are segmented
into multiple smaller objects that are tied together with a manifest file.
For more detail, refer to
https://docs.openstack.org/swift/latest/overview_large_objects.html

This configuration option specifies the size threshold over which the Swift
driver will start segmenting image data into multiple smaller files.
Currently, the Swift driver only supports creating Dynamic Large Objects.

NOTE: This should be set by taking into account the large object limit
enforced by the Swift cluster in consideration.

Possible values:
    * A positive integer that is less than or equal to the large object limit
      enforced by the Swift cluster in consideration.

Related options:
    * ``swift_store_large_object_chunk_size``

"""),
    cfg.IntOpt('swift_store_large_object_chunk_size',
               default=DEFAULT_LARGE_OBJECT_CHUNK_SIZE, min=1,
               help="""
The maximum size, in MB, of the segments when image data is segmented.

When image data is segmented to upload images that are larger than the limit
enforced by the Swift cluster, image data is broken into segments that are no
bigger than the size specified by this configuration option.
Refer to ``swift_store_large_object_size`` for more detail.

For example: if ``swift_store_large_object_size`` is 5GB and
``swift_store_large_object_chunk_size`` is 1GB, an image of size 6.2GB will be
segmented into 7 segments where the first six segments will be 1GB in size and
the seventh segment will be 0.2GB.

Possible values:
    * A positive integer that is less than or equal to the large object limit
      enforced by Swift cluster in consideration.

Related options:
    * ``swift_store_large_object_size``

"""),
    cfg.BoolOpt('swift_store_create_container_on_put', default=False,
                help="""
Create container, if it doesn't already exist, when uploading image.

At the time of uploading an image, if the corresponding container doesn't
exist, it will be created provided this configuration option is set to True.
By default, it won't be created. This behavior is applicable for both single
and multiple containers mode.

Possible values:
    * True
    * False

Related options:
    * None

"""),
    cfg.BoolOpt('swift_store_multi_tenant', default=False,
                help="""
Store images in tenant's Swift account.

This enables multi-tenant storage mode which causes Glance images to be stored
in tenant specific Swift accounts. If this is disabled, Glance stores all
images in its own account. More details multi-tenant store can be found at
https://wiki.openstack.org/wiki/GlanceSwiftTenantSpecificStorage

NOTE: If using multi-tenant swift store, please make sure
that you do not set a swift configuration file with the
'swift_store_config_file' option.

Possible values:
    * True
    * False

Related options:
    * swift_store_config_file

"""),
    cfg.IntOpt('swift_store_multiple_containers_seed',
               default=0, min=0, max=32,
               help="""
Seed indicating the number of containers to use for storing images.

When using a single-tenant store, images can be stored in one or more than one
containers. When set to 0, all images will be stored in one single container.
When set to an integer value between 1 and 32, multiple containers will be
used to store images. This configuration option will determine how many
containers are created. The total number of containers that will be used is
equal to 16^N, so if this config option is set to 2, then 16^2=256 containers
will be used to store images.

Please refer to ``swift_store_container`` for more detail on the naming
convention. More detail about using multiple containers can be found at
https://specs.openstack.org/openstack/glance-specs/specs/kilo/swift-store-multiple-containers.html

NOTE: This is used only when swift_store_multi_tenant is disabled.

Possible values:
    * A non-negative integer less than or equal to 32

Related options:
    * ``swift_store_container``
    * ``swift_store_multi_tenant``
    * ``swift_store_create_container_on_put``

"""),
    cfg.ListOpt('swift_store_admin_tenants', default=[],
                help="""
List of tenants that will be granted admin access.

This is a list of tenants that will be granted read/write access on
all Swift containers created by Glance in multi-tenant mode. The
default value is an empty list.

Possible values:
    * A comma separated list of strings representing UUIDs of Keystone
      projects/tenants

Related options:
    * None

"""),
    cfg.BoolOpt('swift_store_ssl_compression',
                default=True,
                help="""
SSL layer compression for HTTPS Swift requests.

Provide a boolean value to determine whether or not to compress
HTTPS Swift requests for images at the SSL layer. By default,
compression is enabled.

When using Swift as the backend store for Glance image storage,
SSL layer compression of HTTPS Swift requests can be set using
this option. If set to False, SSL layer compression of HTTPS
Swift requests is disabled. Disabling this option may improve
performance for images which are already in a compressed format,
for example, qcow2.

Possible values:
    * True
    * False

Related Options:
    * None

"""),
    cfg.IntOpt('swift_store_retry_get_count',
               default=0,
               min=0,
               help="""
The number of times a Swift download will be retried before the
request fails.

Provide an integer value representing the number of times an image
download must be retried before erroring out. The default value is
zero (no retry on a failed image download). When set to a positive
integer value, ``swift_store_retry_get_count`` ensures that the
download is attempted this many more times upon a download failure
before sending an error message.

Possible values:
    * Zero
    * Positive integer value

Related Options:
    * None

"""),
    cfg.IntOpt('swift_store_expire_soon_interval',
               min=0,
               default=60,
               help="""
Time in seconds defining the size of the window in which a new
token may be requested before the current token is due to expire.

Typically, the Swift storage driver fetches a new token upon the
expiration of the current token to ensure continued access to
Swift. However, some Swift transactions (like uploading image
segments) may not recover well if the token expires on the fly.

Hence, by fetching a new token before the current token expiration,
we make sure that the token does not expire or is close to expiry
before a transaction is attempted. By default, the Swift storage
driver requests for a new token 60 seconds or less before the
current token expiration.

Possible values:
    * Zero
    * Positive integer value

Related Options:
    * None

"""),
    cfg.BoolOpt('swift_store_use_trusts',
                default=True,
                help="""
Use trusts for multi-tenant Swift store.

This option instructs the Swift store to create a trust for each
add/get request when the multi-tenant store is in use. Using trusts
allows the Swift store to avoid problems that can be caused by an
authentication token expiring during the upload or download of data.

By default, ``swift_store_use_trusts`` is set to ``True``(use of
trusts is enabled). If set to ``False``, a user token is used for
the Swift connection instead, eliminating the overhead of trust
creation.

NOTE: This option is considered only when
``swift_store_multi_tenant`` is set to ``True``

Possible values:
    * True
    * False

Related options:
    * swift_store_multi_tenant

"""),
    cfg.BoolOpt('swift_buffer_on_upload',
                default=False,
                help="""
Buffer image segments before upload to Swift.

Provide a boolean value to indicate whether or not Glance should
buffer image data to disk while uploading to swift. This enables
Glance to resume uploads on error.

NOTES:
When enabling this option, one should take great care as this
increases disk usage on the API node. Be aware that depending
upon how the file system is configured, the disk space used
for buffering may decrease the actual disk space available for
the glance image cache.  Disk utilization will cap according to
the following equation:
(``swift_store_large_object_chunk_size`` * ``workers`` * 1000)

Possible values:
    * True
    * False

Related options:
    * swift_upload_buffer_dir

"""),
]


def swift_retry_iter(resp_iter, length, store, location, manager):
    if not length and isinstance(resp_iter, six.BytesIO):
        if six.PY3:
            # On Python 3, io.BytesIO does not have a len attribute, instead
            # go the end using seek to get the size of the file
            pos = resp_iter.tell()
            resp_iter.seek(0, 2)
            length = resp_iter.tell()
            resp_iter.seek(pos)
        else:
            # On Python 2, StringIO has a len attribute
            length = resp_iter.len

    length = length if length else (resp_iter.len
                                    if hasattr(resp_iter, 'len') else 0)
    retries = 0
    bytes_read = 0

    if store.backend_group:
        rcount = getattr(store.conf,
                         store.backend_group).swift_store_retry_get_count
    else:
        rcount = store.conf.glance_store.swift_store_retry_get_count

    while retries <= rcount:
        try:
            for chunk in resp_iter:
                yield chunk
                bytes_read += len(chunk)
        except swiftclient.ClientException as e:
            LOG.warning("Swift exception raised %s"
                        % encodeutils.exception_to_unicode(e))

        if bytes_read != length:
            if retries == rcount:
                # terminate silently and let higher level decide
                LOG.error(_LE("Stopping Swift retries after %d "
                              "attempts") % retries)
                break
            else:
                retries += 1
                LOG.info(_LI("Retrying Swift connection "
                             "(%(retries)d/%(max_retries)d) with "
                             "range=%(start)d-%(end)d"),
                         {'retries': retries,
                          'max_retries': rcount,
                          'start': bytes_read,
                          'end': length})
                (_resp_headers, resp_iter) = store._get_object(location,
                                                               manager,
                                                               bytes_read)
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
            return '%s:%s' % (urllib.parse.quote(self.user),
                              urllib.parse.quote(self.key))
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
            if self.backend_group:
                store = getattr(self.conf,
                                self.backend_group).default_swift_reference
            else:
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
            ref_params = sutils.SwiftParams(
                self.conf, backend=self.backend_group).params
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
            creds = urllib.parse.unquote(creds)
            try:
                self.user, self.key = creds.rsplit(':', 1)
            except exceptions.BadStoreConfiguration:
                self.user = urllib.parse.unquote(user)
                self.key = urllib.parse.unquote(key)
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

        pieces = urllib.parse.urlparse(uri)
        self.validate_schemas(uri, valid_schemas=(
            'swift://', 'swift+http://', 'swift+https://', 'swift+config://'))

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


def Store(conf, backend=None):
    group = 'glance_store'
    if backend:
        group = backend
        multi_tenant = getattr(conf, backend).swift_store_multi_tenant
        default_store = conf.glance_store.default_backend
    else:
        default_store = conf.glance_store.default_store
        multi_tenant = conf.glance_store.swift_store_multi_tenant

    # NOTE(dharinic): Multi-tenant store cannot work with swift config
    if multi_tenant:
        if (default_store == 'swift+config' or
                sutils.is_multiple_swift_store_accounts_enabled(
                    conf, backend=backend)):
            msg = _("Swift multi-tenant store cannot be configured to "
                    "work with swift+config. The options "
                    "'swift_store_multi_tenant' and "
                    "'swift_store_config_file' are mutually exclusive. "
                    "If you inted to use multi-tenant swift store, please "
                    "make sure that you have not set a swift configuration "
                    "file with the 'swift_store_config_file' option.")
            raise exceptions.BadStoreConfiguration(store_name="swift",
                                                   reason=msg)
    try:
        conf.register_opts(_SWIFT_OPTS + sutils.swift_opts +
                           buffered.BUFFERING_OPTS, group=group)
    except cfg.DuplicateOptError:
        pass

    if multi_tenant:
        return MultiTenantStore(conf, backend=backend)
    return SingleTenantStore(conf, backend=backend)

Store.OPTIONS = _SWIFT_OPTS + sutils.swift_opts + buffered.BUFFERING_OPTS


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

    def configure(self, re_raise_bsc=False):
        if self.backend_group:
            glance_conf = getattr(self.conf, self.backend_group)
        else:
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
        if swiftclient is None:
            msg = _("Missing dependency python_swiftclient.")
            raise exceptions.BadStoreConfiguration(store_name="swift",
                                                   reason=msg)

        if glance_conf.swift_buffer_on_upload:
            buffer_dir = glance_conf.swift_upload_buffer_dir
            if buffered.validate_buffering(buffer_dir):
                self.reader_class = buffered.BufferedReader
        else:
            self.reader_class = ChunkReader

        super(BaseStore, self).configure(re_raise_bsc=re_raise_bsc)

    def _get_object(self, location, manager, start=None):
        headers = {}
        if start is not None:
            bytes_range = 'bytes=%d-' % start
            headers = {'Range': bytes_range}

        try:
            resp_headers, resp_body = manager.get_connection().get_object(
                location.container, location.obj,
                resp_chunk_size=self.CHUNKSIZE, headers=headers)
        except swiftclient.ClientException as e:
            if e.http_status == http_client.NOT_FOUND:
                msg = _("Swift could not find object %s.") % location.obj
                LOG.warning(msg)
                raise exceptions.NotFound(message=msg)
            else:
                raise

        return (resp_headers, resp_body)

    @capabilities.check
    def get(self, location, connection=None,
            offset=0, chunk_size=None, context=None):
        if self.backend_group:
            glance_conf = getattr(self.conf, self.backend_group)
        else:
            glance_conf = self.conf.glance_store

        location = location.store_location
        # initialize manager to receive valid connections
        allow_retry = glance_conf.swift_store_retry_get_count > 0
        with self.get_manager(location, context,
                              allow_reauth=allow_retry) as manager:
            (resp_headers, resp_body) = self._get_object(location,
                                                         manager=manager)

            class ResponseIndexable(glance_store.Indexable):
                def another(self):
                    try:
                        return next(self.wrapped)
                    except StopIteration:
                        return ''

            length = int(resp_headers.get('content-length', 0))
            if allow_retry:
                resp_body = swift_retry_iter(resp_body, length,
                                             self, location, manager=manager)
            return ResponseIndexable(resp_body, length), length

    def get_size(self, location, connection=None, context=None):
        location = location.store_location
        if not connection:
            connection = self.get_connection(location, context=context)
        try:
            resp_headers = connection.head_object(
                location.container, location.obj)
            return int(resp_headers.get('content-length', 0))
        except Exception:
            return 0

    def _option_get(self, param):
        if self.backend_group:
            result = getattr(getattr(self.conf, self.backend_group), param)
        else:
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

    @driver.back_compat_add
    @capabilities.check
    def add(self, image_id, image_file, image_size, hashing_algo,
            context=None, verifier=None):
        """
        Stores an image file with supplied identifier to the backend
        storage system and returns a tuple containing information
        about the stored image.

        :param image_id: The opaque image identifier
        :param image_file: The image data to write, as a file-like object
        :param image_size: The size of the image data to write, in bytes
        :param hashing_algo: A hashlib algorithm identifier (string)
        :param verifier: An object used to verify signatures for images

        :returns: tuple of URL in backing store, bytes written, checksum,
                multihash value, and a dictionary with storage system
                specific information
        :raises: `glance_store.exceptions.Duplicate` if something already
                exists at this location
        """
        os_hash_value = hashlib.new(str(hashing_algo))
        location = self.create_location(image_id, context=context)
        # initialize a manager with re-auth if image need to be splitted
        need_chunks = (image_size == 0) or (
            image_size >= self.large_object_size)
        with self.get_manager(location, context,
                              allow_reauth=need_chunks) as manager:

            self._create_container_if_missing(location.container,
                                              manager.get_connection())

            LOG.debug("Adding image object '%(obj_name)s' "
                      "to Swift" % dict(obj_name=location.obj))
            try:
                if not need_chunks:
                    # Image size is known, and is less than large_object_size.
                    # Send to Swift with regular PUT.
                    checksum = hashlib.md5()
                    reader = ChunkReader(image_file, checksum,
                                         os_hash_value, image_size,
                                         verifier=verifier)
                    obj_etag = manager.get_connection().put_object(
                        location.container, location.obj,
                        reader, content_length=image_size)
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
                        LOG.debug("Cannot determine image size because it is "
                                  "either not provided in the request or "
                                  "chunked-transfer encoding is used. "
                                  "Adding image as a segmented object to "
                                  "Swift.")
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

                        with self.reader_class(
                                image_file, checksum, os_hash_value,
                                chunk_size, verifier,
                                backend_group=self.backend_group) as reader:
                            if reader.is_zero_size is True:
                                LOG.debug('Not writing zero-length chunk.')
                                break

                            try:
                                chunk_etag = \
                                    manager.get_connection().put_object(
                                        location.container,
                                        chunk_name, reader,
                                        content_length=content_length)
                                written_chunks.append(chunk_name)
                            except Exception:
                                # Delete orphaned segments from swift backend
                                with excutils.save_and_reraise_exception():
                                    LOG.error(_("Error during chunked upload "
                                                "to backend, deleting stale "
                                                "chunks."))
                                    self._delete_stale_chunks(
                                        manager.get_connection(),
                                        location.container,
                                        written_chunks)

                            bytes_read = reader.bytes_read
                            msg = ("Wrote chunk %(chunk_name)s (%(chunk_id)d/"
                                   "%(total_chunks)s) of length %(bytes_read)"
                                   "d to Swift returning MD5 of content: "
                                   "%(chunk_etag)s" %
                                   {'chunk_name': chunk_name,
                                    'chunk_id': chunk_id,
                                    'total_chunks': total_chunks,
                                    'bytes_read': bytes_read,
                                    'chunk_etag': chunk_etag})
                            LOG.debug(msg)

                        chunk_id += 1
                        combined_chunks_size += bytes_read
                    # In the case we have been given an unknown image size,
                    # set the size to the total size of the combined chunks.
                    if image_size == 0:
                        image_size = combined_chunks_size

                    # Now we write the object manifest in X-Object-Manifest
                    # header as defined for Dynamic Large Objects (DLO) Mode.
                    # This request does not include ETag as PUT request has not
                    # actual content that we need to verify.
                    manifest = "%s/%s-" % (location.container, location.obj)
                    headers = {'X-Object-Manifest': manifest}

                    # The ETag returned for the manifest is actually the
                    # MD5 hash of the concatenated checksums of the strings
                    # of each chunk...so we ignore this result in favour of
                    # the MD5 of the entire image file contents, so that
                    # users can verify the image file contents accordingly
                    manager.get_connection().put_object(location.container,
                                                        location.obj,
                                                        None, headers=headers)
                    obj_etag = checksum.hexdigest()

                # NOTE: We return the user and key here! Have to because
                # location is used by the API server to return the actual
                # image data. We *really* should consider NOT returning
                # the location attribute from GET /images/<ID> and
                # GET /images/details
                if sutils.is_multiple_swift_store_accounts_enabled(
                        self.conf, backend=self.backend_group):
                    include_creds = False
                else:
                    include_creds = True

                metadata = {}
                if self.backend_group:
                    metadata['backend'] = u"%s" % self.backend_group

                return (location.get_uri(credentials_included=include_creds),
                        image_size, obj_etag, os_hash_value.hexdigest(),
                        metadata)
            except swiftclient.ClientException as e:
                if e.http_status == http_client.CONFLICT:
                    msg = _("Swift already has an image at this location")
                    raise exceptions.Duplicate(message=msg)

                msg = (_(u"Failed to add object to Swift.\n"
                         "Got error from Swift: %s.")
                       % encodeutils.exception_to_unicode(e))
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
                if e.http_status != http_client.NOT_FOUND:
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
            if e.http_status == http_client.NOT_FOUND:
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
        if self.backend_group:
            store_conf = getattr(self.conf, self.backend_group)
        else:
            store_conf = self.conf.glance_store
        try:
            connection.head_container(container)
        except swiftclient.ClientException as e:
            if e.http_status == http_client.NOT_FOUND:
                if store_conf.swift_store_create_container_on_put:
                    try:
                        msg = (_LI("Creating swift container %(container)s") %
                               {'container': container})
                        LOG.info(msg)
                        connection.put_container(container)
                    except swiftclient.ClientException as e:
                        msg = (_("Failed to add container to Swift.\n"
                                 "Got error from Swift: %s.")
                               % encodeutils.exception_to_unicode(e))
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

    def init_client(self, location, context=None):
        """Initialize and return client to authorize against keystone

        The method invariant is the following: it always returns Keystone
        client that can be used to receive fresh token in any time. Otherwise
        it raises appropriate exception.
        :param location: swift location data
        :param context: user context (it is not required if user grants are
        specified for single tenant store)
        :return correctly initialized keystone client
        """
        raise NotImplementedError()

    def get_store_connection(self, auth_token, storage_url):
        """Get initialized swift connection

        :param auth_token: auth token
        :param storage_url: swift storage url
        :return: swiftclient connection that allows to request container and
                 others
        """
        # initialize a connection
        return swiftclient.Connection(
            preauthurl=storage_url,
            preauthtoken=auth_token,
            insecure=self.insecure,
            ssl_compression=self.ssl_compression,
            cacert=self.cacert)

    def get_manager(self, store_location, context=None, allow_reauth=False):
        """Return appropriate connection manager for store

        The method detects store type (singletenant or multitenant) and returns
        appropriate connection manager (singletenant or multitenant) that
        allows to request swiftclient connections.

        :param store_location: StoreLocation object that define image location
        :param context: user context
        :param allow_reauth: defines if we allow re-authentication when user
            token is expired and refresh swift connection

        :return: connection manager for store
        """
        msg = _("There is no Connection Manager implemented for %s class.")
        raise NotImplementedError(msg % self.__class__.__name__)


class SingleTenantStore(BaseStore):
    EXAMPLE_URL = "swift://<USER>:<KEY>@<AUTH_ADDRESS>/<CONTAINER>/<FILE>"

    def __init__(self, conf, backend=None):
        super(SingleTenantStore, self).__init__(conf, backend=backend)
        self.backend_group = backend
        self.ref_params = sutils.SwiftParams(self.conf,
                                             backend=backend).params

    def configure(self, re_raise_bsc=False):
        # set configuration before super so configure_add can override
        self.auth_version = self._option_get('swift_store_auth_version')
        self.user_domain_id = None
        self.user_domain_name = None
        self.project_domain_id = None
        self.project_domain_name = None

        super(SingleTenantStore, self).configure(re_raise_bsc=re_raise_bsc)

    def configure_add(self):
        if self.backend_group:
            default_ref = getattr(self.conf,
                                  self.backend_group).default_swift_reference
            self.container = getattr(self.conf,
                                     self.backend_group).swift_store_container
        else:
            default_ref = self.conf.glance_store.default_swift_reference
            self.container = self.conf.glance_store.swift_store_container

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

        self.auth_version = default_swift_reference.get('auth_version')
        self.user = default_swift_reference.get('user')
        self.key = default_swift_reference.get('key')
        self.user_domain_id = default_swift_reference.get('user_domain_id')
        self.user_domain_name = default_swift_reference.get('user_domain_name')
        self.project_domain_id = default_swift_reference.get(
            'project_domain_id')
        self.project_domain_name = default_swift_reference.get(
            'project_domain_name')

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
        return StoreLocation(specs, self.conf,
                             backend_group=self.backend_group)

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
        if self.backend_group:
            seed_num_chars = getattr(
                self.conf,
                self.backend_group).swift_store_multiple_containers_seed
        else:
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

        if self.auth_version in ('2', '3'):
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
        if self.user_domain_id:
            os_options['user_domain_id'] = self.user_domain_id
        if self.user_domain_name:
            os_options['user_domain_name'] = self.user_domain_name
        if self.project_domain_id:
            os_options['project_domain_id'] = self.project_domain_id
        if self.project_domain_name:
            os_options['project_domain_name'] = self.project_domain_name

        return swiftclient.Connection(
            auth_url, user, location.key, preauthurl=self.conf_endpoint,
            insecure=self.insecure, tenant_name=tenant_name,
            auth_version=self.auth_version, os_options=os_options,
            ssl_compression=self.ssl_compression, cacert=self.cacert)

    def init_client(self, location, context=None):
        """Initialize keystone client with swift service user credentials"""
        # prepare swift admin credentials
        if not location.user:
            reason = _("Location is missing user:password information.")
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)

        auth_url = location.swift_url
        if not auth_url.endswith('/'):
            auth_url += '/'

        try:
            tenant_name, user = location.user.split(':')
        except ValueError:
            reason = (_("Badly formed tenant:user '%(user)s' in "
                        "Swift URI") % {'user': location.user})
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)

        # initialize a keystone plugin for swift admin with creds
        password = ks_identity.V3Password(
            auth_url=auth_url,
            username=user,
            password=location.key,
            project_name=tenant_name,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name)

        sess = ks_session.Session(auth=password, verify=not self.insecure)
        return ks_client.Client(session=sess)

    def get_manager(self, store_location, context=None, allow_reauth=False):
        return connection_manager.SingleTenantConnectionManager(self,
                                                                store_location,
                                                                context,
                                                                allow_reauth)


class MultiTenantStore(BaseStore):
    EXAMPLE_URL = "swift://<SWIFT_URL>/<CONTAINER>/<FILE>"

    def _get_endpoint(self, context):
        if self.backend_group:
            self.container = getattr(self.conf,
                                     self.backend_group).swift_store_container
        else:
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
            catalog = keystone_sc.ServiceCatalogV2(context.service_catalog)
            self.storage_url = catalog.url_for(service_type=self.service_type,
                                               region_name=self.region,
                                               interface=self.endpoint_type)

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
            if e.http_status == http_client.NOT_FOUND:
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
        return StoreLocation(specs, self.conf,
                             backend_group=self.backend_group)

    def get_connection(self, location, context=None):
        return swiftclient.Connection(
            preauthurl=location.swift_url,
            preauthtoken=context.auth_token,
            insecure=self.insecure,
            ssl_compression=self.ssl_compression,
            cacert=self.cacert)

    def init_client(self, location, context=None):
        # read client parameters from config files
        ref_params = sutils.SwiftParams(self.conf,
                                        backend=self.backend_group).params
        if self.backend_group:
            default_ref = getattr(self.conf,
                                  self.backend_group).default_swift_reference
        else:
            default_ref = self.conf.glance_store.default_swift_reference

        default_swift_reference = ref_params.get(default_ref)
        if not default_swift_reference:
            reason = _("default_swift_reference %s is "
                       "required."), default_ref
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(message=reason)

        auth_address = default_swift_reference.get('auth_address')
        user = default_swift_reference.get('user')
        key = default_swift_reference.get('key')
        user_domain_id = default_swift_reference.get('user_domain_id')
        user_domain_name = default_swift_reference.get('user_domain_name')
        project_domain_id = default_swift_reference.get('project_domain_id')
        project_domain_name = default_swift_reference.get(
            'project_domain_name')

        # create client for multitenant user(trustor)
        trustor_auth = ks_identity.V3Token(auth_url=auth_address,
                                           token=context.auth_token,
                                           project_id=context.tenant)
        trustor_sess = ks_session.Session(auth=trustor_auth,
                                          verify=not self.insecure)
        trustor_client = ks_client.Client(session=trustor_sess)
        auth_ref = trustor_client.session.auth.get_auth_ref(trustor_sess)
        roles = [t['name'] for t in auth_ref['roles']]

        # create client for trustee - glance user specified in swift config
        tenant_name, user = user.split(':')
        password = ks_identity.V3Password(
            auth_url=auth_address,
            username=user,
            password=key,
            project_name=tenant_name,
            user_domain_id=user_domain_id,
            user_domain_name=user_domain_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name)
        trustee_sess = ks_session.Session(auth=password,
                                          verify=not self.insecure)
        trustee_client = ks_client.Client(session=trustee_sess)

        # request glance user id - we will use it as trustee user
        trustee_user_id = trustee_client.session.get_user_id()

        # create trust for trustee user
        trust_id = trustor_client.trusts.create(
            trustee_user=trustee_user_id, trustor_user=context.user,
            project=context.tenant, impersonation=True,
            role_names=roles
        ).id
        # initialize a new client with trust and trustee credentials
        # create client for glance trustee user
        client_password = ks_identity.V3Password(
            auth_url=auth_address,
            username=user,
            password=key,
            trust_id=trust_id,
            user_domain_id=user_domain_id,
            user_domain_name=user_domain_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name
        )
        # now we can authenticate against KS
        # as trustee of user who provided token
        client_sess = ks_session.Session(auth=client_password,
                                         verify=not self.insecure)
        return ks_client.Client(session=client_sess)

    def get_manager(self, store_location, context=None, allow_reauth=False):
        # if global toggle is turned off then do not allow re-authentication
        # with trusts
        if self.backend_group:
            use_trusts = getattr(self.conf,
                                 self.backend_group).swift_store_use_trusts
        else:
            use_trusts = self.conf.glance_store.swift_store_use_trusts

        if not use_trusts:
            allow_reauth = False

        return connection_manager.MultiTenantConnectionManager(self,
                                                               store_location,
                                                               context,
                                                               allow_reauth)


class ChunkReader(object):
    def __init__(self, fd, checksum, os_hash_value, total, verifier=None,
                 backend_group=None):
        self.fd = fd
        self.checksum = checksum
        self.os_hash_value = os_hash_value
        self.total = total
        self.verifier = verifier
        self.backend_group = backend_group
        self.bytes_read = 0
        self.is_zero_size = False
        self.byteone = fd.read(1)
        if len(self.byteone) == 0:
            self.is_zero_size = True

    def do_read(self, i):
        if self.bytes_read == 0 and i > 0 and self.byteone is not None:
            return self.byteone + self.fd.read(i - 1)
        else:
            return self.fd.read(i)

    def read(self, i):
        left = self.total - self.bytes_read
        if i > left:
            i = left

        # Note(rosmaita): under some circumstances in py3, a zero-byte
        # read results in a non-byte value that then causes a "unicode
        # objects must be encoded before hashing" error when we do the
        # hash computations below.  (At least that seems to be what's
        # happening in testing.)  So just fake a zero-byte read and let
        # the current execution path continue.
        # See https://bugs.launchpad.net/glance-store/+bug/1805332
        # TODO(rosmaita): find what in the execution path is returning
        # a native string instead of bytes and fix it.
        if i == 0:
            result = b''
        else:
            result = self.do_read(i)

        self.bytes_read += len(result)
        self.checksum.update(result)
        self.os_hash_value.update(result)
        if self.verifier:
            self.verifier.update(result)
        return result

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass
