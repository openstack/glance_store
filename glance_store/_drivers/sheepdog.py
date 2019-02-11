# Copyright 2013 Taobao Inc.
# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

"""Storage backend for Sheepdog storage system"""

import hashlib
import logging
import six

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_utils import excutils
from oslo_utils import units

import glance_store
from glance_store import capabilities
from glance_store.common import utils
import glance_store.driver
from glance_store import exceptions
from glance_store.i18n import _
import glance_store.location


LOG = logging.getLogger(__name__)

DEFAULT_ADDR = '127.0.0.1'
DEFAULT_PORT = 7000
DEFAULT_CHUNKSIZE = 64  # in MiB

_SHEEPDOG_OPTS = [
    cfg.IntOpt('sheepdog_store_chunk_size',
               min=1,
               default=DEFAULT_CHUNKSIZE,
               help="""
Chunk size for images to be stored in Sheepdog data store.

Provide an integer value representing the size in mebibyte
(1048576 bytes) to chunk Glance images into. The default
chunk size is 64 mebibytes.

When using Sheepdog distributed storage system, the images are
chunked into objects of this size and then stored across the
distributed data store to use for Glance.

Chunk sizes, if a power of two, help avoid fragmentation and
enable improved performance.

Possible values:
    * Positive integer value representing size in mebibytes.

Related Options:
    * None

"""),
    cfg.PortOpt('sheepdog_store_port',
                default=DEFAULT_PORT,
                help="""
Port number on which the sheep daemon will listen.

Provide an integer value representing a valid port number on
which you want the Sheepdog daemon to listen on. The default
port is 7000.

The Sheepdog daemon, also called 'sheep', manages the storage
in the distributed cluster by writing objects across the storage
network. It identifies and acts on the messages it receives on
the port number set using ``sheepdog_store_port`` option to store
chunks of Glance images.

Possible values:
    * A valid port number (0 to 65535)

Related Options:
    * sheepdog_store_address

"""),
    cfg.HostAddressOpt('sheepdog_store_address',
                       default=DEFAULT_ADDR,
                       help="""
Address to bind the Sheepdog daemon to.

Provide a string value representing the address to bind the
Sheepdog daemon to. The default address set for the 'sheep'
is 127.0.0.1.

The Sheepdog daemon, also called 'sheep', manages the storage
in the distributed cluster by writing objects across the storage
network. It identifies and acts on the messages directed to the
address set using ``sheepdog_store_address`` option to store
chunks of Glance images.

Possible values:
    * A valid IPv4 address
    * A valid IPv6 address
    * A valid hostname

Related Options:
    * sheepdog_store_port

"""),
]


class SheepdogImage(object):
    """Class describing an image stored in Sheepdog storage."""

    def __init__(self, addr, port, name, chunk_size):
        self.addr = addr
        self.port = port
        self.name = name
        self.chunk_size = chunk_size

    def _run_command(self, command, data, *params):
        cmd = ['collie', 'vdi']
        cmd.extend(command.split(' '))
        cmd.extend(['-a', self.addr, '-p', self.port, self.name])
        cmd.extend(params)

        try:
            return processutils.execute(
                *cmd, process_input=data)[0]
        except processutils.ProcessExecutionError as exc:
            LOG.error(exc)
            raise glance_store.BackendException(exc)

    def get_size(self):
        """
        Return the size of the this image

        Sheepdog Usage: collie vdi list -r -a address -p port image
        """
        out = self._run_command("list -r", None)
        return int(out.split(' ')[3])

    def read(self, offset, count):
        """
        Read up to 'count' bytes from this image starting at 'offset' and
        return the data.

        Sheepdog Usage: collie vdi read -a address -p port image offset len
        """
        return self._run_command("read", None, str(offset), str(count))

    def write(self, data, offset, count):
        """
        Write up to 'count' bytes from the data to this image starting at
        'offset'

        Sheepdog Usage: collie vdi write -a address -p port image offset len
        """
        self._run_command("write", data, str(offset), str(count))

    def create(self, size):
        """
        Create this image in the Sheepdog cluster with size 'size'.

        Sheepdog Usage: collie vdi create -a address -p port image size
        """
        if not isinstance(size, (six.integer_types, float)):
            raise exceptions.Forbidden("Size is not a number")
        self._run_command("create", None, str(size))

    def resize(self, size):
        """Resize this image in the Sheepdog cluster with size 'size'.

        Sheepdog Usage: collie vdi create -a address -p port image size
        """
        self._run_command("resize", None, str(size))

    def delete(self):
        """
        Delete this image in the Sheepdog cluster

        Sheepdog Usage: collie vdi delete -a address -p port image
        """
        self._run_command("delete", None)

    def exist(self):
        """
        Check if this image exists in the Sheepdog cluster via 'list' command

        Sheepdog Usage: collie vdi list -r -a address -p port image
        """
        out = self._run_command("list -r", None)
        if not out:
            return False
        else:
            return True


class StoreLocation(glance_store.location.StoreLocation):
    """
    Class describing a Sheepdog URI. This is of the form:

        sheepdog://addr:port:image

    """

    def process_specs(self):
        self.image = self.specs.get('image')
        self.addr = self.specs.get('addr')
        self.port = self.specs.get('port')

    def get_uri(self):
        return "sheepdog://%(addr)s:%(port)d:%(image)s" % {
            'addr': self.addr,
            'port': self.port,
            'image': self.image}

    def parse_uri(self, uri):
        valid_schema = 'sheepdog://'
        self.validate_schemas(uri, valid_schemas=(valid_schema,))
        pieces = uri[len(valid_schema):].split(':')
        if len(pieces) == 3:
            self.image = pieces[2]
            self.port = int(pieces[1])
            self.addr = pieces[0]
        # This is used for backwards compatibility.
        else:
            if self.backend_group:
                store_conf = getattr(self.conf, self.backend_group)
            else:
                store_conf = self.conf.glance_store

            self.image = pieces[0]
            self.port = store_conf.sheepdog_store_port
            self.addr = store_conf.sheepdog_store_address


class ImageIterator(object):
    """
    Reads data from an Sheepdog image, one chunk at a time.
    """

    def __init__(self, image):
        self.image = image

    def __iter__(self):
        image = self.image
        total = left = image.get_size()
        while left > 0:
            length = min(image.chunk_size, left)
            data = image.read(total - left, length)
            left -= len(data)
            yield data
        return


class Store(glance_store.driver.Store):
    """Sheepdog backend adapter."""

    _CAPABILITIES = (capabilities.BitMasks.RW_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)
    OPTIONS = _SHEEPDOG_OPTS
    EXAMPLE_URL = "sheepdog://addr:port:image"

    def get_schemes(self):
        return ('sheepdog',)

    def configure_add(self):
        """
        Configure the Store to use the stored configuration options
        Any store that needs special configuration should implement
        this method. If the store was not able to successfully configure
        itself, it should raise `exceptions.BadStoreConfiguration`
        """
        if self.backend_group:
            store_conf = getattr(self.conf, self.backend_group)
        else:
            store_conf = self.conf.glance_store

        try:
            chunk_size = store_conf.sheepdog_store_chunk_size
            self.chunk_size = chunk_size * units.Mi
            self.READ_CHUNKSIZE = self.chunk_size
            self.WRITE_CHUNKSIZE = self.READ_CHUNKSIZE

            self.addr = store_conf.sheepdog_store_address
            self.port = store_conf.sheepdog_store_port
        except cfg.ConfigFileValueError as e:
            reason = _("Error in store configuration: %s") % e
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name='sheepdog',
                                                   reason=reason)

        try:
            processutils.execute("collie")
        except processutils.ProcessExecutionError as exc:
            reason = _("Error in store configuration: %s") % exc
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name='sheepdog',
                                                   reason=reason)

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a generator for reading
        the image file

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :raises: `glance_store.exceptions.NotFound` if image does not exist
        """

        loc = location.store_location
        image = SheepdogImage(loc.addr, loc.port, loc.image,
                              self.READ_CHUNKSIZE)
        if not image.exist():
            raise exceptions.NotFound(_("Sheepdog image %s does not exist")
                                      % image.name)
        return (ImageIterator(image), image.get_size())

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
        image = SheepdogImage(loc.addr, loc.port, loc.image,
                              self.READ_CHUNKSIZE)
        if not image.exist():
            raise exceptions.NotFound(_("Sheepdog image %s does not exist")
                                      % image.name)
        return image.get_size()

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
        :param context: A context object
        :param verifier: An object used to verify signatures for images

        :returns: tuple of: (1) URL in backing store, (2) bytes written,
                  (3) checksum, (4) multihash value, and (5) a dictionary
                  with storage system specific information
        :raises: `glance_store.exceptions.Duplicate` if the image already
                 exists
        """

        image = SheepdogImage(self.addr, self.port, image_id,
                              self.WRITE_CHUNKSIZE)
        if image.exist():
            raise exceptions.Duplicate(_("Sheepdog image %s already exists")
                                       % image_id)

        location = StoreLocation({
            'image': image_id,
            'addr': self.addr,
            'port': self.port
        }, self.conf, backend_group=self.backend_group)

        image.create(image_size)

        try:
            offset = 0
            os_hash_value = hashlib.new(str(hashing_algo))
            checksum = hashlib.md5()
            chunks = utils.chunkreadable(image_file, self.WRITE_CHUNKSIZE)
            for chunk in chunks:
                chunk_length = len(chunk)
                # If the image size provided is zero we need to do
                # a resize for the amount we are writing. This will
                # be slower so setting a higher chunk size may
                # speed things up a bit.
                if image_size == 0:
                    image.resize(offset + chunk_length)
                image.write(chunk, offset, chunk_length)
                offset += chunk_length
                os_hash_value.update(chunk)
                checksum.update(chunk)
                if verifier:
                    verifier.update(chunk)
        except Exception:
            # Note(zhiyan): clean up already received data when
            # error occurs such as ImageSizeLimitExceeded exceptions.
            with excutils.save_and_reraise_exception():
                image.delete()

        metadata = {}
        if self.backend_group:
            metadata['backend'] = u"%s" % self.backend_group

        return (location.get_uri(),
                offset,
                checksum.hexdigest(),
                os_hash_value.hexdigest(),
                metadata)

    @capabilities.check
    def delete(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :param location: `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()

        :raises: NotFound if image does not exist
        """

        loc = location.store_location
        image = SheepdogImage(loc.addr, loc.port, loc.image,
                              self.WRITE_CHUNKSIZE)
        if not image.exist():
            raise exceptions.NotFound(_("Sheepdog image %s does not exist") %
                                      loc.image)
        image.delete()
