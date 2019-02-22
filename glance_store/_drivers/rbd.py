# Copyright 2010-2011 Josh Durgin
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

"""Storage backend for RBD
   (RADOS (Reliable Autonomic Distributed Object Store) Block Device)"""
from __future__ import absolute_import
from __future__ import with_statement

import contextlib
import hashlib
import logging
import math

from oslo_config import cfg
from oslo_utils import encodeutils
from oslo_utils import units
from six.moves import urllib

from glance_store import capabilities
from glance_store.common import utils
from glance_store import driver
from glance_store import exceptions
from glance_store.i18n import _, _LE, _LI
from glance_store import location

try:
    import rados
    import rbd
except ImportError:
    rados = None
    rbd = None

DEFAULT_POOL = 'images'
DEFAULT_CONFFILE = '/etc/ceph/ceph.conf'
DEFAULT_USER = None    # let librados decide based on the Ceph conf file
DEFAULT_CHUNKSIZE = 8  # in MiB
DEFAULT_SNAPNAME = 'snap'

LOG = logging.getLogger(__name__)

_RBD_OPTS = [
    cfg.IntOpt('rbd_store_chunk_size', default=DEFAULT_CHUNKSIZE,
               min=1,
               help="""
Size, in megabytes, to chunk RADOS images into.

Provide an integer value representing the size in megabytes to chunk
Glance images into. The default chunk size is 8 megabytes. For optimal
performance, the value should be a power of two.

When Ceph's RBD object storage system is used as the storage backend
for storing Glance images, the images are chunked into objects of the
size set using this option. These chunked objects are then stored
across the distributed block data store to use for Glance.

Possible Values:
    * Any positive integer value

Related options:
    * None

"""),
    cfg.StrOpt('rbd_store_pool', default=DEFAULT_POOL,
               help="""
RADOS pool in which images are stored.

When RBD is used as the storage backend for storing Glance images, the
images are stored by means of logical grouping of the objects (chunks
of images) into a ``pool``. Each pool is defined with the number of
placement groups it can contain. The default pool that is used is
'images'.

More information on the RBD storage backend can be found here:
http://ceph.com/planet/how-data-is-stored-in-ceph-cluster/

Possible Values:
    * A valid pool name

Related options:
    * None

"""),
    cfg.StrOpt('rbd_store_user', default=DEFAULT_USER,
               help="""
RADOS user to authenticate as.

This configuration option takes in the RADOS user to authenticate as.
This is only needed when RADOS authentication is enabled and is
applicable only if the user is using Cephx authentication. If the
value for this option is not set by the user or is set to None, a
default value will be chosen, which will be based on the client.
section in rbd_store_ceph_conf.

Possible Values:
    * A valid RADOS user

Related options:
    * rbd_store_ceph_conf

"""),
    cfg.StrOpt('rbd_store_ceph_conf', default=DEFAULT_CONFFILE,
               help="""
Ceph configuration file path.

This configuration option takes in the path to the Ceph configuration
file to be used. If the value for this option is not set by the user
or is set to None, librados will locate the default configuration file
which is located at /etc/ceph/ceph.conf. If using Cephx
authentication, this file should include a reference to the right
keyring in a client.<USER> section

Possible Values:
    * A valid path to a configuration file

Related options:
    * rbd_store_user

"""),
    cfg.IntOpt('rados_connect_timeout', default=0,
               help="""
Timeout value for connecting to Ceph cluster.

This configuration option takes in the timeout value in seconds used
when connecting to the Ceph cluster i.e. it sets the time to wait for
glance-api before closing the connection. This prevents glance-api
hangups during the connection to RBD. If the value for this option
is set to less than or equal to 0, no timeout is set and the default
librados value is used.

Possible Values:
    * Any integer value

Related options:
    * None

"""),
]


class StoreLocation(location.StoreLocation):
    """
    Class describing a RBD URI. This is of the form:

        rbd://image

        or

        rbd://fsid/pool/image/snapshot
    """

    def process_specs(self):
        # convert to ascii since librbd doesn't handle unicode
        for key, value in self.specs.items():
            self.specs[key] = str(value)
        self.fsid = self.specs.get('fsid')
        self.pool = self.specs.get('pool')
        self.image = self.specs.get('image')
        self.snapshot = self.specs.get('snapshot')

    def get_uri(self):
        if self.fsid and self.pool and self.snapshot:
            # ensure nothing contains / or any other url-unsafe character
            safe_fsid = urllib.parse.quote(self.fsid, '')
            safe_pool = urllib.parse.quote(self.pool, '')
            safe_image = urllib.parse.quote(self.image, '')
            safe_snapshot = urllib.parse.quote(self.snapshot, '')
            return "rbd://%s/%s/%s/%s" % (safe_fsid, safe_pool,
                                          safe_image, safe_snapshot)
        else:
            return "rbd://%s" % self.image

    def parse_uri(self, uri):
        prefix = 'rbd://'
        self.validate_schemas(uri, valid_schemas=(prefix,))
        # convert to ascii since librbd doesn't handle unicode
        try:
            ascii_uri = str(uri)
        except UnicodeError:
            reason = _('URI contains non-ascii characters')
            msg = _LI("Invalid URI: %s") % reason

            LOG.info(msg)
            raise exceptions.BadStoreUri(message=reason)
        pieces = ascii_uri[len(prefix):].split('/')
        if len(pieces) == 1:
            self.fsid, self.pool, self.image, self.snapshot = \
                (None, None, pieces[0], None)
        elif len(pieces) == 4:
            self.fsid, self.pool, self.image, self.snapshot = \
                map(urllib.parse.unquote, pieces)
        else:
            reason = _('URI must have exactly 1 or 4 components')
            msg = _LI("Invalid URI: %s") % reason

            LOG.info(msg)
            raise exceptions.BadStoreUri(message=reason)
        if any(map(lambda p: p == '', pieces)):
            reason = _('URI cannot contain empty components')
            msg = _LI("Invalid URI: %s") % reason

            LOG.info(msg)
            raise exceptions.BadStoreUri(message=reason)


class ImageIterator(object):
    """
    Reads data from an RBD image, one chunk at a time.
    """

    def __init__(self, pool, name, snapshot, store, chunk_size=None):
        self.pool = pool or store.pool
        self.name = name
        self.snapshot = snapshot
        self.user = store.user
        self.conf_file = store.conf_file
        self.chunk_size = chunk_size or store.READ_CHUNKSIZE
        self.store = store

    def __iter__(self):
        try:
            with self.store.get_connection(conffile=self.conf_file,
                                           rados_id=self.user) as conn:
                with conn.open_ioctx(self.pool) as ioctx:
                    with rbd.Image(ioctx, self.name,
                                   snapshot=self.snapshot) as image:
                        size = image.size()
                        bytes_left = size
                        while bytes_left > 0:
                            length = min(self.chunk_size, bytes_left)
                            data = image.read(size - bytes_left, length)
                            bytes_left -= len(data)
                            yield data
                        return
        except rbd.ImageNotFound:
            raise exceptions.NotFound(
                _('RBD image %s does not exist') % self.name)


class Store(driver.Store):
    """An implementation of the RBD backend adapter."""

    _CAPABILITIES = capabilities.BitMasks.RW_ACCESS
    OPTIONS = _RBD_OPTS

    EXAMPLE_URL = "rbd://<FSID>/<POOL>/<IMAGE>/<SNAP>"

    def get_schemes(self):
        return ('rbd',)

    @contextlib.contextmanager
    def get_connection(self, conffile, rados_id):
        client = rados.Rados(conffile=conffile, rados_id=rados_id)

        try:
            client.connect(timeout=self.connect_timeout)
        except rados.Error:
            msg = _LE("Error connecting to ceph cluster.")
            LOG.exception(msg)
            raise exceptions.BackendException()
        try:
            yield client
        finally:
            client.shutdown()

    def configure_add(self):
        """
        Configure the Store to use the stored configuration options
        Any store that needs special configuration should implement
        this method. If the store was not able to successfully configure
        itself, it should raise `exceptions.BadStoreConfiguration`
        """
        try:
            if self.backend_group:
                chunk = getattr(self.conf,
                                self.backend_group).rbd_store_chunk_size
                pool = getattr(self.conf, self.backend_group).rbd_store_pool
                user = getattr(self.conf, self.backend_group).rbd_store_user
                conf_file = getattr(self.conf,
                                    self.backend_group).rbd_store_ceph_conf
                connect_timeout = getattr(
                    self.conf, self.backend_group).rados_connect_timeout
            else:
                chunk = self.conf.glance_store.rbd_store_chunk_size
                pool = self.conf.glance_store.rbd_store_pool
                user = self.conf.glance_store.rbd_store_user
                conf_file = self.conf.glance_store.rbd_store_ceph_conf
                connect_timeout = self.conf.glance_store.rados_connect_timeout

            self.chunk_size = chunk * units.Mi
            self.READ_CHUNKSIZE = self.chunk_size
            self.WRITE_CHUNKSIZE = self.READ_CHUNKSIZE

            # these must not be unicode since they will be passed to a
            # non-unicode-aware C library
            self.pool = str(pool)
            self.user = str(user)
            self.conf_file = str(conf_file)
            self.connect_timeout = connect_timeout
        except cfg.ConfigFileValueError as e:
            reason = _("Error in store configuration: %s") % e
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name='rbd',
                                                   reason=reason)

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :raises: `glance_store.exceptions.NotFound` if image does not exist
        """
        loc = location.store_location
        return (ImageIterator(loc.pool, loc.image, loc.snapshot, self),
                self.get_size(location))

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :raises: `glance_store.exceptions.NotFound` if image does not exist
        """
        loc = location.store_location
        # if there is a pool specific in the location, use it; otherwise
        # we fall back to the default pool specified in the config
        target_pool = loc.pool or self.pool
        with self.get_connection(conffile=self.conf_file,
                                 rados_id=self.user) as conn:
            with conn.open_ioctx(target_pool) as ioctx:
                try:
                    with rbd.Image(ioctx, loc.image,
                                   snapshot=loc.snapshot) as image:
                        img_info = image.stat()
                        return img_info['size']
                except rbd.ImageNotFound:
                    msg = _('RBD image %s does not exist') % loc.get_uri()
                    LOG.debug(msg)
                    raise exceptions.NotFound(msg)

    def _create_image(self, fsid, conn, ioctx, image_name,
                      size, order, context=None):
        """
        Create an rbd image. If librbd supports it,
        make it a cloneable snapshot, so that copy-on-write
        volumes can be created from it.

        :param image_name: Image's name

        :returns: `glance_store.rbd.StoreLocation` object
        """
        librbd = rbd.RBD()
        features = conn.conf_get('rbd_default_features')
        if ((features is None) or (int(features) == 0)):
            features = rbd.RBD_FEATURE_LAYERING
        librbd.create(ioctx, image_name, size, order, old_format=False,
                      features=int(features))
        return StoreLocation({
            'fsid': fsid,
            'pool': self.pool,
            'image': image_name,
            'snapshot': DEFAULT_SNAPNAME,
        }, self.conf)

    def _delete_image(self, target_pool, image_name,
                      snapshot_name=None, context=None):
        """
        Delete RBD image and snapshot.

        :param image_name: Image's name
        :param snapshot_name: Image snapshot's name

        :raises: NotFound if image does not exist;
                InUseByStore if image is in use or snapshot unprotect failed
        """
        with self.get_connection(conffile=self.conf_file,
                                 rados_id=self.user) as conn:
            with conn.open_ioctx(target_pool) as ioctx:
                try:
                    # First remove snapshot.
                    if snapshot_name is not None:
                        with rbd.Image(ioctx, image_name) as image:
                            try:
                                self._unprotect_snapshot(image, snapshot_name)
                                image.remove_snap(snapshot_name)
                            except rbd.ImageNotFound as exc:
                                msg = (_("Snap Operating Exception "
                                         "%(snap_exc)s "
                                         "Snapshot does not exist.") %
                                       {'snap_exc': exc})
                                LOG.debug(msg)
                            except rbd.ImageBusy as exc:
                                log_msg = (_LE("Snap Operating Exception "
                                               "%(snap_exc)s "
                                               "Snapshot is in use.") %
                                           {'snap_exc': exc})
                                LOG.error(log_msg)
                                raise exceptions.InUseByStore()

                    # Then delete image.
                    rbd.RBD().remove(ioctx, image_name)
                except rbd.ImageHasSnapshots:
                    log_msg = (_LE("Remove image %(img_name)s failed. "
                                   "It has snapshot(s) left.") %
                               {'img_name': image_name})
                    LOG.error(log_msg)
                    raise exceptions.HasSnapshot()
                except rbd.ImageBusy:
                    log_msg = (_LE("Remove image %(img_name)s failed. "
                                   "It is in use.") %
                               {'img_name': image_name})
                    LOG.error(log_msg)
                    raise exceptions.InUseByStore()
                except rbd.ImageNotFound:
                    msg = _("RBD image %s does not exist") % image_name
                    raise exceptions.NotFound(message=msg)

    def _unprotect_snapshot(self, image, snap_name):
        try:
            image.unprotect_snap(snap_name)
        except rbd.InvalidArgument:
            # NOTE(slaweq): if snapshot was unprotected already, rbd library
            # raises InvalidArgument exception without any "clear" message.
            # Such exception is not dangerous for us so it will be just logged
            LOG.debug("Snapshot %s is unprotected already" % snap_name)

    @driver.back_compat_add
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
        :param context: A context object
        :param verifier: An object used to verify signatures for images

        :returns: tuple of: (1) URL in backing store, (2) bytes written,
                  (3) checksum, (4) multihash value, and (5) a dictionary
                  with storage system specific information
        :raises: `glance_store.exceptions.Duplicate` if the image already
                 exists
        """
        checksum = hashlib.md5()
        os_hash_value = hashlib.new(str(hashing_algo))
        image_name = str(image_id)
        with self.get_connection(conffile=self.conf_file,
                                 rados_id=self.user) as conn:
            fsid = None
            if hasattr(conn, 'get_fsid'):
                # Librados's get_fsid is represented as binary
                # in py3 instead of str as it is in py2.
                # This is causing problems with ceph.
                # Decode binary to str fixes these issues.
                # Fix with encodeutils.safe_decode CAN BE REMOVED
                # after librados's fix will be stable.
                #
                # More informations:
                # https://bugs.launchpad.net/glance-store/+bug/1816721
                # https://bugs.launchpad.net/cinder/+bug/1816468
                # https://tracker.ceph.com/issues/38381
                fsid = encodeutils.safe_decode(conn.get_fsid())
            with conn.open_ioctx(self.pool) as ioctx:
                order = int(math.log(self.WRITE_CHUNKSIZE, 2))
                LOG.debug('creating image %s with order %d and size %d',
                          image_name, order, image_size)
                if image_size == 0:
                    LOG.warning(_("since image size is zero we will be doing "
                                  "resize-before-write for each chunk which "
                                  "will be considerably slower than normal"))

                try:
                    loc = self._create_image(fsid, conn, ioctx, image_name,
                                             image_size, order)
                except rbd.ImageExists:
                    msg = _('RBD image %s already exists') % image_id
                    raise exceptions.Duplicate(message=msg)

                try:
                    with rbd.Image(ioctx, image_name) as image:
                        bytes_written = 0
                        offset = 0
                        chunks = utils.chunkreadable(image_file,
                                                     self.WRITE_CHUNKSIZE)
                        for chunk in chunks:
                            # If the image size provided is zero we need to do
                            # a resize for the amount we are writing. This will
                            # be slower so setting a higher chunk size may
                            # speed things up a bit.
                            if image_size == 0:
                                chunk_length = len(chunk)
                                length = offset + chunk_length
                                bytes_written += chunk_length
                                LOG.debug(_("resizing image to %s KiB") %
                                          (length / units.Ki))
                                image.resize(length)
                            LOG.debug(_("writing chunk at offset %s") %
                                      (offset))
                            offset += image.write(chunk, offset)
                            os_hash_value.update(chunk)
                            checksum.update(chunk)
                            if verifier:
                                verifier.update(chunk)
                        if loc.snapshot:
                            image.create_snap(loc.snapshot)
                            image.protect_snap(loc.snapshot)
                except rbd.NoSpace:
                    log_msg = (_LE("Failed to store image %(img_name)s "
                                   "insufficient space available") %
                               {'img_name': image_name})
                    LOG.error(log_msg)

                    # Delete image if one was created
                    try:
                        target_pool = loc.pool or self.pool
                        self._delete_image(target_pool, loc.image,
                                           loc.snapshot)
                    except exceptions.NotFound:
                        pass

                    raise exceptions.StorageFull(message=log_msg)
                except Exception as exc:
                    log_msg = (_LE("Failed to store image %(img_name)s "
                                   "Store Exception %(store_exc)s") %
                               {'img_name': image_name,
                                'store_exc': exc})
                    LOG.error(log_msg)

                    # Delete image if one was created
                    try:
                        target_pool = loc.pool or self.pool
                        self._delete_image(target_pool, loc.image,
                                           loc.snapshot)
                    except exceptions.NotFound:
                        pass

                    raise exc

        # Make sure we send back the image size whether provided or inferred.
        if image_size == 0:
            image_size = bytes_written

        # Add store backend information to location metadata
        metadata = {}
        if self.backend_group:
            metadata['backend'] = u"%s" % self.backend_group

        return (loc.get_uri(),
                image_size,
                checksum.hexdigest(),
                os_hash_value.hexdigest(),
                metadata)

    @capabilities.check
    def delete(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete.

        :param location: `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()

        :raises: NotFound if image does not exist;
                InUseByStore if image is in use or snapshot unprotect failed
        """
        loc = location.store_location
        target_pool = loc.pool or self.pool
        self._delete_image(target_pool, loc.image, loc.snapshot)
