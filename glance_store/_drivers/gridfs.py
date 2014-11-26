# Copyright 2013 Red Hat, Inc
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

"""Storage backend for GridFS"""
from __future__ import absolute_import

import logging
import urlparse

from oslo_config import cfg
from oslo_utils import excutils

from glance_store import capabilities
import glance_store.driver
from glance_store import exceptions
from glance_store.i18n import _
import glance_store.location

try:
    import gridfs
    import gridfs.errors
    import pymongo
    import pymongo.uri_parser as uri_parser
except ImportError:
    pymongo = None

LOG = logging.getLogger(__name__)

_GRIDFS_OPTS = [
    cfg.StrOpt('mongodb_store_uri',
               help="Hostname or IP address of the instance to connect to, "
                    "or a mongodb URI, or a list of hostnames / mongodb URIs. "
                    "If host is an IPv6 literal it must be enclosed "
                    "in '[' and ']' characters following the RFC2732 "
                    "URL syntax (e.g. '[::1]' for localhost)"),
    cfg.StrOpt('mongodb_store_db', default=None, help='Database to use'),
]


class StoreLocation(glance_store.location.StoreLocation):
    """
    Class describing an gridfs URI:

        gridfs://<IMAGE_ID>

    Connection information has been consciously omitted for
    security reasons, since this location will be stored in glance's
    database and can be queried from outside.

    Note(flaper87): Make connection info available if user wants so
    by adding a new configuration parameter `mongdb_store_insecure`.
    """

    def get_uri(self):
        return "gridfs://%s" % self.specs.get("image_id")

    def parse_uri(self, uri):
        """
        This method should fix any issue with the passed URI. Right now,
        it just sets image_id value in the specs dict.

        :param uri: Current set URI
        """
        parsed = urlparse.urlparse(uri)
        assert parsed.scheme in ('gridfs',)
        self.specs["image_id"] = parsed.netloc


class Store(glance_store.driver.Store):
    """GridFS adapter"""

    _CAPABILITIES = capabilities.BitMasks.RW_ACCESS
    OPTIONS = _GRIDFS_OPTS
    EXAMPLE_URL = "gridfs://<IMAGE_ID>"

    def __init__(self, *args, **kwargs):
        LOG.warn('The gridfs store has been deprecated and it\'ll be removed '
                 'in future versions of this library. Please, consider '
                 'maintaining it yourself or adopting a different store.')
        super(Store, self).__init__(*args, **kwargs)

    def get_schemes(self):
        return ('gridfs',)

    def configure_add(self):
        """
        Configure the Store to use the stored configuration options
        Any store that needs special configuration should implement
        this method. If the store was not able to successfully configure
        itself, it should raise `exceptions.BadStoreConfiguration`
        """
        if pymongo is None:
            msg = _("Missing dependencies: pymongo")
            raise exceptions.BadStoreConfiguration(store_name="gridfs",
                                                   reason=msg)

        self.mongodb_uri = self._option_get('mongodb_store_uri')

        parsed = uri_parser.parse_uri(self.mongodb_uri)
        self.mongodb_db = self._option_get('mongodb_store_db') or \
            parsed.get("database")

        self.mongodb = pymongo.MongoClient(self.mongodb_uri)
        self.fs = gridfs.GridFS(self.mongodb[self.mongodb_db])

    def _option_get(self, param):
        result = getattr(self.conf.glance_store, param)
        if not result:
            reason = (_("Could not find %(param)s in configuration "
                        "options.") % {'param': param})
            LOG.debug(reason)
            raise exceptions.BadStoreConfiguration(store_name="gridfs",
                                                   reason=reason)
        return result

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :raises `glance_store.exceptions.NotFound` if image does not exist
        """
        image = self._get_file(location)
        return (image, image.length)

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the image_size (or 0
        if unavailable)

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        try:
            key = self._get_file(location)
            return key.length
        except Exception:
            return 0

    def _get_file(self, location):
        store_location = location
        if isinstance(location, glance_store.location.Location):
            store_location = location.store_location
        try:

            parsed = urlparse.urlparse(store_location.get_uri())
            return self.fs.get(parsed.netloc)
        except gridfs.errors.NoFile:
            msg = _("Could not find %s image in GridFS") % \
                store_location.get_uri()
            LOG.debug(msg)
            raise exceptions.NotFound(msg)

    @capabilities.check
    def add(self, image_id, image_file, image_size, context=None):
        """
        Stores an image file with supplied identifier to the backend
        storage system and returns a tuple containing information
        about the stored image.

        :param image_id: The opaque image identifier
        :param image_file: The image data to write, as a file-like object
        :param image_size: The size of the image data to write, in bytes

        :retval tuple of URL in backing store, bytes written, checksum
                and a dictionary with storage system specific information
        :raises `glance_store.exceptions.Duplicate` if the image already
                existed
        """
        loc = StoreLocation({'image_id': image_id}, self.conf)

        if self.fs.exists(image_id):
            raise exceptions.Duplicate(_("GridFS already has an image at "
                                         "location %s") % loc.get_uri())

        LOG.debug(_("Adding a new image to GridFS with "
                    "id %(iid)s and size %(size)s")
                  % dict(iid=image_id, size=image_size))

        try:
            self.fs.put(image_file, _id=image_id)
            image = self._get_file(loc)
        except Exception:
            # Note(zhiyan): clean up already received data when
            # error occurs such as ImageSizeLimitExceeded exception.
            with excutils.save_and_reraise_exception():
                self.fs.delete(image_id)

        LOG.debug(_("Uploaded image %(iid)s, "
                    "md5 %(md)s, length %(len)s to GridFS") %
                  dict(iid=image._id, md=image.md5, len=image.length))

        return (loc.get_uri(), image.length, image.md5, {})

    @capabilities.check
    def delete(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :location `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()

        :raises NotFound if image does not exist
        """
        image = self._get_file(location)
        self.fs.delete(image._id)
        LOG.debug("Deleted image %s from GridFS")
