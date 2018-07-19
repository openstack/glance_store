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

"""Storage backend for Cinder"""

import contextlib
import errno
import hashlib
import logging
import math
import os
import shlex
import socket
import time

from keystoneauth1.access import service_catalog as keystone_sc
from keystoneauth1 import exceptions as keystone_exc
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_utils import units

from glance_store import capabilities
from glance_store.common import utils
import glance_store.driver
from glance_store import exceptions
from glance_store.i18n import _, _LE, _LI
import glance_store.location

try:
    from cinderclient import exceptions as cinder_exception
    from cinderclient.v2 import client as cinderclient
    from os_brick.initiator import connector
    from oslo_privsep import priv_context
except ImportError:
    cinder_exception = None
    cinderclient = None
    connector = None
    priv_context = None


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

_CINDER_OPTS = [
    cfg.StrOpt('cinder_catalog_info',
               default='volumev2::publicURL',
               help="""
Information to match when looking for cinder in the service catalog.

When the ``cinder_endpoint_template`` is not set and any of
``cinder_store_auth_address``, ``cinder_store_user_name``,
``cinder_store_project_name``, ``cinder_store_password`` is not set,
cinder store uses this information to lookup cinder endpoint from the service
catalog in the current context. ``cinder_os_region_name``, if set, is taken
into consideration to fetch the appropriate endpoint.

The service catalog can be listed by the ``openstack catalog list`` command.

Possible values:
    * A string of of the following form:
      ``<service_type>:<service_name>:<interface>``
      At least ``service_type`` and ``interface`` should be specified.
      ``service_name`` can be omitted.

Related options:
    * cinder_os_region_name
    * cinder_endpoint_template
    * cinder_store_auth_address
    * cinder_store_user_name
    * cinder_store_project_name
    * cinder_store_password

"""),
    cfg.StrOpt('cinder_endpoint_template',
               default=None,
               help="""
Override service catalog lookup with template for cinder endpoint.

When this option is set, this value is used to generate cinder endpoint,
instead of looking up from the service catalog.
This value is ignored if ``cinder_store_auth_address``,
``cinder_store_user_name``, ``cinder_store_project_name``, and
``cinder_store_password`` are specified.

If this configuration option is set, ``cinder_catalog_info`` will be ignored.

Possible values:
    * URL template string for cinder endpoint, where ``%%(tenant)s`` is
      replaced with the current tenant (project) name.
      For example: ``http://cinder.openstack.example.org/v2/%%(tenant)s``

Related options:
    * cinder_store_auth_address
    * cinder_store_user_name
    * cinder_store_project_name
    * cinder_store_password
    * cinder_catalog_info

"""),
    cfg.StrOpt('cinder_os_region_name', deprecated_name='os_region_name',
               default=None,
               help="""
Region name to lookup cinder service from the service catalog.

This is used only when ``cinder_catalog_info`` is used for determining the
endpoint. If set, the lookup for cinder endpoint by this node is filtered to
the specified region. It is useful when multiple regions are listed in the
catalog. If this is not set, the endpoint is looked up from every region.

Possible values:
    * A string that is a valid region name.

Related options:
    * cinder_catalog_info

"""),
    cfg.StrOpt('cinder_ca_certificates_file',
               help="""
Location of a CA certificates file used for cinder client requests.

The specified CA certificates file, if set, is used to verify cinder
connections via HTTPS endpoint. If the endpoint is HTTP, this value is ignored.
``cinder_api_insecure`` must be set to ``True`` to enable the verification.

Possible values:
    * Path to a ca certificates file

Related options:
    * cinder_api_insecure

"""),
    cfg.IntOpt('cinder_http_retries',
               min=0,
               default=3,
               help="""
Number of cinderclient retries on failed http calls.

When a call failed by any errors, cinderclient will retry the call up to the
specified times after sleeping a few seconds.

Possible values:
    * A positive integer

Related options:
    * None

"""),
    cfg.IntOpt('cinder_state_transition_timeout',
               min=0,
               default=300,
               help="""
Time period, in seconds, to wait for a cinder volume transition to
complete.

When the cinder volume is created, deleted, or attached to the glance node to
read/write the volume data, the volume's state is changed. For example, the
newly created volume status changes from ``creating`` to ``available`` after
the creation process is completed. This specifies the maximum time to wait for
the status change. If a timeout occurs while waiting, or the status is changed
to an unexpected value (e.g. `error``), the image creation fails.

Possible values:
    * A positive integer

Related options:
    * None

"""),
    cfg.BoolOpt('cinder_api_insecure',
                default=False,
                help="""
Allow to perform insecure SSL requests to cinder.

If this option is set to True, HTTPS endpoint connection is verified using the
CA certificates file specified by ``cinder_ca_certificates_file`` option.

Possible values:
    * True
    * False

Related options:
    * cinder_ca_certificates_file

"""),
    cfg.StrOpt('cinder_store_auth_address',
               default=None,
               help="""
The address where the cinder authentication service is listening.

When all of ``cinder_store_auth_address``, ``cinder_store_user_name``,
``cinder_store_project_name``, and ``cinder_store_password`` options are
specified, the specified values are always used for the authentication.
This is useful to hide the image volumes from users by storing them in a
project/tenant specific to the image service. It also enables users to share
the image volume among other projects under the control of glance's ACL.

If either of these options are not set, the cinder endpoint is looked up
from the service catalog, and current context's user and project are used.

Possible values:
    * A valid authentication service address, for example:
      ``http://openstack.example.org/identity/v2.0``

Related options:
    * cinder_store_user_name
    * cinder_store_password
    * cinder_store_project_name

"""),
    cfg.StrOpt('cinder_store_user_name',
               default=None,
               help="""
User name to authenticate against cinder.

This must be used with all the following related options. If any of these are
not specified, the user of the current context is used.

Possible values:
    * A valid user name

Related options:
    * cinder_store_auth_address
    * cinder_store_password
    * cinder_store_project_name

"""),
    cfg.StrOpt('cinder_store_password', secret=True,
               help="""
Password for the user authenticating against cinder.

This must be used with all the following related options. If any of these are
not specified, the user of the current context is used.

Possible values:
    * A valid password for the user specified by ``cinder_store_user_name``

Related options:
    * cinder_store_auth_address
    * cinder_store_user_name
    * cinder_store_project_name

"""),
    cfg.StrOpt('cinder_store_project_name',
               default=None,
               help="""
Project name where the image volume is stored in cinder.

If this configuration option is not set, the project in current context is
used.

This must be used with all the following related options. If any of these are
not specified, the project of the current context is used.

Possible values:
    * A valid project name

Related options:
    * ``cinder_store_auth_address``
    * ``cinder_store_user_name``
    * ``cinder_store_password``

"""),
    cfg.StrOpt('rootwrap_config',
               default='/etc/glance/rootwrap.conf',
               help="""
Path to the rootwrap configuration file to use for running commands as root.

The cinder store requires root privileges to operate the image volumes (for
connecting to iSCSI/FC volumes and reading/writing the volume data, etc.).
The configuration file should allow the required commands by cinder store and
os-brick library.

Possible values:
    * Path to the rootwrap config file

Related options:
    * None

"""),
    cfg.StrOpt('cinder_volume_type',
               default=None,
               help="""
Volume type that will be used for volume creation in cinder.

Some cinder backends can have several volume types to optimize storage usage.
Adding this option allows an operator to choose a specific volume type
in cinder that can be optimized for images.

If this is not set, then the default volume type specified in the cinder
configuration will be used for volume creation.

Possible values:
    * A valid volume type from cinder

Related options:
    * None

"""),
]


def get_root_helper(backend=None):
    if backend:
        rootwrap = getattr(CONF, backend).rootwrap_config
    else:
        rootwrap = CONF.glance_store.rootwrap_config

    return 'sudo glance-rootwrap %s' % rootwrap


def is_user_overriden(conf, backend=None):
    if backend:
        store_conf = getattr(conf, backend)
    else:
        store_conf = conf.glance_store

    return all([store_conf.get('cinder_store_' + key)
                for key in ['user_name', 'password',
                            'project_name', 'auth_address']])


def get_cinderclient(conf, context=None, backend=None):
    if backend:
        glance_store = getattr(conf, backend)
    else:
        glance_store = conf.glance_store

    user_overriden = is_user_overriden(conf, backend=backend)
    if user_overriden:
        username = glance_store.cinder_store_user_name
        password = glance_store.cinder_store_password
        project = glance_store.cinder_store_project_name
        url = glance_store.cinder_store_auth_address
    else:
        username = context.user
        password = context.auth_token
        project = context.tenant

        if glance_store.cinder_endpoint_template:
            url = glance_store.cinder_endpoint_template % context.to_dict()
        else:
            info = glance_store.cinder_catalog_info
            service_type, service_name, interface = info.split(':')
            try:
                catalog = keystone_sc.ServiceCatalogV2(context.service_catalog)
                url = catalog.url_for(
                    region_name=glance_store.cinder_os_region_name,
                    service_type=service_type,
                    service_name=service_name,
                    interface=interface)
            except keystone_exc.EndpointNotFound:
                reason = _("Failed to find Cinder from a service catalog.")
                raise exceptions.BadStoreConfiguration(store_name="cinder",
                                                       reason=reason)

    c = cinderclient.Client(username,
                            password,
                            project,
                            auth_url=url,
                            region_name=glance_store.cinder_os_region_name,
                            insecure=glance_store.cinder_api_insecure,
                            retries=glance_store.cinder_http_retries,
                            cacert=glance_store.cinder_ca_certificates_file)

    LOG.debug('Cinderclient connection created for user %(user)s using URL: '
              '%(url)s.', {'user': username, 'url': url})

    # noauth extracts user_id:project_id from auth_token
    if not user_overriden:
        c.client.auth_token = context.auth_token or '%s:%s' % (username,
                                                               project)
    c.client.management_url = url
    return c


class StoreLocation(glance_store.location.StoreLocation):

    """Class describing a Cinder URI."""

    def process_specs(self):
        self.scheme = self.specs.get('scheme', 'cinder')
        self.volume_id = self.specs.get('volume_id')

    def get_uri(self):
        return "cinder://%s" % self.volume_id

    def parse_uri(self, uri):
        self.validate_schemas(uri, valid_schemas=('cinder://',))

        self.scheme = 'cinder'
        self.volume_id = uri[9:]

        if not utils.is_uuid_like(self.volume_id):
            reason = _("URI contains invalid volume ID")
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)


@contextlib.contextmanager
def temporary_chown(path, backend=None):
    owner_uid = os.getuid()
    orig_uid = os.stat(path).st_uid

    if orig_uid != owner_uid:
        processutils.execute('chown', owner_uid, path,
                             run_as_root=True,
                             root_helper=get_root_helper(backend=backend))
    try:
        yield
    finally:
        if orig_uid != owner_uid:
            processutils.execute('chown', orig_uid, path,
                                 run_as_root=True,
                                 root_helper=get_root_helper(backend=backend))


class Store(glance_store.driver.Store):

    """Cinder backend store adapter."""

    _CAPABILITIES = (capabilities.BitMasks.READ_RANDOM |
                     capabilities.BitMasks.WRITE_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)
    OPTIONS = _CINDER_OPTS
    EXAMPLE_URL = "cinder://<VOLUME_ID>"

    def __init__(self, *args, **kargs):
        super(Store, self).__init__(*args, **kargs)

    def get_schemes(self):
        return ('cinder',)

    def _check_context(self, context, require_tenant=False):
        user_overriden = is_user_overriden(self.conf,
                                           backend=self.backend_group)
        if user_overriden and not require_tenant:
            return
        if context is None:
            reason = _("Cinder storage requires a context.")
            raise exceptions.BadStoreConfiguration(store_name="cinder",
                                                   reason=reason)
        if not user_overriden and context.service_catalog is None:
            reason = _("Cinder storage requires a service catalog.")
            raise exceptions.BadStoreConfiguration(store_name="cinder",
                                                   reason=reason)

    def _wait_volume_status(self, volume, status_transition, status_expected):
        max_recheck_wait = 15
        if self.backend_group:
            timeout = getattr(
                self.conf, self.backend_group).cinder_state_transition_timeout
        else:
            timeout = self.conf.glance_store.cinder_state_transition_timeout

        volume = volume.manager.get(volume.id)
        tries = 0
        elapsed = 0
        while volume.status == status_transition:
            if elapsed >= timeout:
                msg = (_('Timeout while waiting while volume %(volume_id)s '
                         'status is %(status)s.')
                       % {'volume_id': volume.id, 'status': status_transition})
                LOG.error(msg)
                raise exceptions.BackendException(msg)

            wait = min(0.5 * 2 ** tries, max_recheck_wait)
            time.sleep(wait)
            tries += 1
            elapsed += wait
            volume = volume.manager.get(volume.id)
        if volume.status != status_expected:
            msg = (_('The status of volume %(volume_id)s is unexpected: '
                     'status = %(status)s, expected = %(expected)s.')
                   % {'volume_id': volume.id, 'status': volume.status,
                      'expected': status_expected})
            LOG.error(msg)
            raise exceptions.BackendException(msg)
        return volume

    @contextlib.contextmanager
    def _open_cinder_volume(self, client, volume, mode):
        attach_mode = 'rw' if mode == 'wb' else 'ro'
        device = None
        root_helper = get_root_helper(backend=self.backend_group)
        priv_context.init(root_helper=shlex.split(root_helper))
        host = socket.gethostname()
        properties = connector.get_connector_properties(root_helper, host,
                                                        False, False)

        try:
            volume.reserve(volume)
        except cinder_exception.ClientException as e:
            msg = (_('Failed to reserve volume %(volume_id)s: %(error)s')
                   % {'volume_id': volume.id, 'error': e})
            LOG.error(msg)
            raise exceptions.BackendException(msg)

        try:
            connection_info = volume.initialize_connection(volume, properties)
            conn = connector.InitiatorConnector.factory(
                connection_info['driver_volume_type'], root_helper,
                conn=connection_info)
            device = conn.connect_volume(connection_info['data'])
            volume.attach(None, 'glance_store', attach_mode, host_name=host)
            volume = self._wait_volume_status(volume, 'attaching', 'in-use')
            if (connection_info['driver_volume_type'] == 'rbd' and
               not conn.do_local_attach):
                yield device['path']
            else:
                with temporary_chown(device['path'],
                                     backend=self.backend_group), \
                        open(device['path'], mode) as f:
                    yield f
        except Exception:
            LOG.exception(_LE('Exception while accessing to cinder volume '
                              '%(volume_id)s.'), {'volume_id': volume.id})
            raise
        finally:
            if volume.status == 'in-use':
                volume.begin_detaching(volume)
            elif volume.status == 'attaching':
                volume.unreserve(volume)

            if device:
                try:
                    conn.disconnect_volume(connection_info['data'], device)
                except Exception:
                    LOG.exception(_LE('Failed to disconnect volume '
                                      '%(volume_id)s.'),
                                  {'volume_id': volume.id})

            try:
                volume.terminate_connection(volume, properties)
            except Exception:
                LOG.exception(_LE('Failed to terminate connection of volume '
                                  '%(volume_id)s.'), {'volume_id': volume.id})

            try:
                client.volumes.detach(volume)
            except Exception:
                LOG.exception(_LE('Failed to detach volume %(volume_id)s.'),
                              {'volume_id': volume.id})

    def _cinder_volume_data_iterator(self, client, volume, max_size, offset=0,
                                     chunk_size=None, partial_length=None):
        chunk_size = chunk_size if chunk_size else self.READ_CHUNKSIZE
        partial = partial_length is not None
        with self._open_cinder_volume(client, volume, 'rb') as fp:
            if offset:
                fp.seek(offset)
                max_size -= offset
            while True:
                if partial:
                    size = min(chunk_size, partial_length, max_size)
                else:
                    size = min(chunk_size, max_size)

                chunk = fp.read(size)
                if chunk:
                    yield chunk
                    max_size -= len(chunk)
                    if max_size <= 0:
                        break
                    if partial:
                        partial_length -= len(chunk)
                        if partial_length <= 0:
                            break
                else:
                    break

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :param offset: offset to start reading
        :param chunk_size: size to read, or None to get all the image
        :param context: Request context
        :raises: `glance_store.exceptions.NotFound` if image does not exist
        """

        loc = location.store_location
        self._check_context(context)
        try:
            client = get_cinderclient(self.conf, context,
                                      backend=self.backend_group)
            volume = client.volumes.get(loc.volume_id)
            size = int(volume.metadata.get('image_size',
                                           volume.size * units.Gi))
            iterator = self._cinder_volume_data_iterator(
                client, volume, size, offset=offset,
                chunk_size=self.READ_CHUNKSIZE, partial_length=chunk_size)
            return (iterator, chunk_size or size)
        except cinder_exception.NotFound:
            reason = _("Failed to get image size due to "
                       "volume can not be found: %s") % loc.volume_id
            LOG.error(reason)
            raise exceptions.NotFound(reason)
        except cinder_exception.ClientException as e:
            msg = (_('Failed to get image volume %(volume_id)s: %(error)s')
                   % {'volume_id': loc.volume_id, 'error': e})
            LOG.error(msg)
            raise exceptions.BackendException(msg)

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file and returns the image size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :raises: `glance_store.exceptions.NotFound` if image does not exist
        :rtype: int
        """

        loc = location.store_location

        try:
            self._check_context(context)
            volume = get_cinderclient(
                self.conf, context,
                backend=self.backend_group).volumes.get(loc.volume_id)
            return int(volume.metadata.get('image_size',
                                           volume.size * units.Gi))
        except cinder_exception.NotFound:
            raise exceptions.NotFound(image=loc.volume_id)
        except Exception:
            LOG.exception(_LE("Failed to get image size due to "
                              "internal error."))
            return 0

    @glance_store.driver.back_compat_add
    @capabilities.check
    def add(self, image_id, image_file, image_size, hashing_algo, context=None,
            verifier=None):
        """
        Stores an image file with supplied identifier to the backend
        storage system and returns a tuple containing information
        about the stored image.

        :param image_id: The opaque image identifier
        :param image_file: The image data to write, as a file-like object
        :param image_size: The size of the image data to write, in bytes
        :param hashing_algo: A hashlib algorithm identifier (string)
        :param context: The request context
        :param verifier: An object used to verify signatures for images

        :returns: tuple of: (1) URL in backing store, (2) bytes written,
                  (3) checksum, (4) multihash value, and (5) a dictionary
                  with storage system specific information
        :raises: `glance_store.exceptions.Duplicate` if the image already
                 exists
        """

        self._check_context(context, require_tenant=True)
        client = get_cinderclient(self.conf, context,
                                  backend=self.backend_group)
        os_hash_value = hashlib.new(str(hashing_algo))
        checksum = hashlib.md5()
        bytes_written = 0
        size_gb = int(math.ceil(float(image_size) / units.Gi))
        if size_gb == 0:
            size_gb = 1
        name = "image-%s" % image_id
        owner = context.tenant
        metadata = {'glance_image_id': image_id,
                    'image_size': str(image_size),
                    'image_owner': owner}

        if self.backend_group:
            volume_type = getattr(self.conf,
                                  self.backend_group).cinder_volume_type
        else:
            volume_type = self.conf.glance_store.cinder_volume_type

        LOG.debug('Creating a new volume: image_size=%d size_gb=%d type=%s',
                  image_size, size_gb, volume_type or 'None')
        if image_size == 0:
            LOG.info(_LI("Since image size is zero, we will be doing "
                         "resize-before-write for each GB which "
                         "will be considerably slower than normal."))
        volume = client.volumes.create(size_gb, name=name, metadata=metadata,
                                       volume_type=volume_type)
        volume = self._wait_volume_status(volume, 'creating', 'available')
        size_gb = volume.size

        failed = True
        need_extend = True
        buf = None
        try:
            while need_extend:
                with self._open_cinder_volume(client, volume, 'wb') as f:
                    f.seek(bytes_written)
                    if buf:
                        f.write(buf)
                        bytes_written += len(buf)
                    while True:
                        buf = image_file.read(self.WRITE_CHUNKSIZE)
                        if not buf:
                            need_extend = False
                            break
                        os_hash_value.update(buf)
                        checksum.update(buf)
                        if verifier:
                            verifier.update(buf)
                        if (bytes_written + len(buf) > size_gb * units.Gi and
                                image_size == 0):
                            break
                        f.write(buf)
                        bytes_written += len(buf)

                if need_extend:
                    size_gb += 1
                    LOG.debug("Extending volume %(volume_id)s to %(size)s GB.",
                              {'volume_id': volume.id, 'size': size_gb})
                    volume.extend(volume, size_gb)
                    try:
                        volume = self._wait_volume_status(volume,
                                                          'extending',
                                                          'available')
                        size_gb = volume.size
                    except exceptions.BackendException:
                        raise exceptions.StorageFull()

            failed = False
        except IOError as e:
            # Convert IOError reasons to Glance Store exceptions
            errors = {errno.EFBIG: exceptions.StorageFull(),
                      errno.ENOSPC: exceptions.StorageFull(),
                      errno.EACCES: exceptions.StorageWriteDenied()}
            raise errors.get(e.errno, e)
        finally:
            if failed:
                LOG.error(_LE("Failed to write to volume %(volume_id)s."),
                          {'volume_id': volume.id})
                try:
                    volume.delete()
                except Exception:
                    LOG.exception(_LE('Failed to delete of volume '
                                      '%(volume_id)s.'),
                                  {'volume_id': volume.id})

        if image_size == 0:
            metadata.update({'image_size': str(bytes_written)})
            volume.update_all_metadata(metadata)
        volume.update_readonly_flag(volume, True)

        hash_hex = os_hash_value.hexdigest()
        checksum_hex = checksum.hexdigest()

        LOG.debug("Wrote %(bytes_written)d bytes to volume %(volume_id)s "
                  "with checksum %(checksum_hex)s.",
                  {'bytes_written': bytes_written,
                   'volume_id': volume.id,
                   'checksum_hex': checksum_hex})

        image_metadata = {}
        if self.backend_group:
            image_metadata['backend'] = u"%s" % self.backend_group

        return ('cinder://%s' % volume.id,
                bytes_written,
                checksum_hex,
                hash_hex,
                image_metadata)

    @capabilities.check
    def delete(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :param location: `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()

        :raises: NotFound if image does not exist
        :raises: Forbidden if cannot delete because of permissions
        """
        loc = location.store_location
        self._check_context(context)
        try:
            volume = get_cinderclient(
                self.conf, context,
                backend=self.backend_group).volumes.get(loc.volume_id)
            volume.delete()
        except cinder_exception.NotFound:
            raise exceptions.NotFound(image=loc.volume_id)
        except cinder_exception.ClientException as e:
            msg = (_('Failed to delete volume %(volume_id)s: %(error)s') %
                   {'volume_id': loc.volume_id, 'error': e})
            raise exceptions.BackendException(msg)
