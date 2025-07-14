# Copyright 2011 OpenStack Foundation
# Copyright 2012 RedHat Inc.
# Copyright 2018 Verizon Wireless
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

"""Base class for all storage backends"""

from functools import wraps
import logging

from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import units

from glance_store import capabilities
from glance_store import exceptions
from glance_store.i18n import _

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
SHARED_CONF_GROUP = 'backend_defaults'

_MULTI_BACKEND_OPTS = [
    cfg.StrOpt('store_description',
               help=_("""
This option will be used to provide a constructive information about
the store backend to end users. Using /v2/stores-info call user can
seek more information on all available backends.

""")),
    cfg.IntOpt('weight',
               help=_("""
This option is used to define a relative weight for this store over
any others that are configured. The actual value of the weight is meaningless
and only serves to provide a "sort order" compared to others. Any stores
with the same weight will be treated as equivalent.
"""),
               default=0),
]


class Store(capabilities.StoreCapability):

    OPTIONS = None
    MULTI_BACKEND_OPTIONS = _MULTI_BACKEND_OPTS
    READ_CHUNKSIZE = 4 * units.Mi  # 4M
    WRITE_CHUNKSIZE = READ_CHUNKSIZE

    def __init__(self, conf, backend=None):
        """
        Initialize the Store
        """

        super(Store, self).__init__()

        self.conf = conf
        self.backend_group = backend
        self.store_location_class = None
        self._url_prefix = None

        try:
            if self.OPTIONS is not None:
                group = 'glance_store'
                if self.backend_group:
                    group = self.backend_group
                    if self.MULTI_BACKEND_OPTIONS is not None:
                        self.conf.register_opts(
                            self.MULTI_BACKEND_OPTIONS, group=group)

                self.conf.register_opts(self.OPTIONS, group=group)
                self.conf.register_opts(self.OPTIONS, group=SHARED_CONF_GROUP)
        except cfg.DuplicateOptError:
            pass

    @property
    def url_prefix(self):
        return self._url_prefix

    @property
    def weight(self):
        if self.backend_group is None:
            # NOTE(danms): A backend with no config group can not have a
            # weight set, so just return the default
            return 0
        else:
            return getattr(self.conf, self.backend_group).weight

    def configure(self, re_raise_bsc=False):
        """
        Configure the store to use the stored configuration options
        and initialize capabilities based on current configuration.

        Any store that needs special configuration should implement
        this method.
        """

        try:
            self.configure_add()
        except exceptions.BadStoreConfiguration as e:
            self.unset_capabilities(capabilities.BitMasks.WRITE_ACCESS)
            msg = _("Failed to configure store correctly: %s "
                    "Disabling add method.") % e
            LOG.warning(msg)
            if re_raise_bsc:
                raise
        finally:
            self.update_capabilities()

    def get_schemes(self):
        """
        Returns a tuple of schemes which this store can handle.
        """
        raise NotImplementedError

    def get_store_location_class(self):
        """
        Returns the store location class that is used by this store.
        """
        if not self.store_location_class:
            class_name = "%s.StoreLocation" % (self.__module__)
            LOG.debug("Late loading location class %s", class_name)
            self.store_location_class = importutils.import_class(class_name)
        return self.store_location_class

    def configure_add(self):
        """
        This is like `configure` except that it's specifically for
        configuring the store to accept objects.

        If the store was not able to successfully configure
        itself, it should raise `exceptions.BadStoreConfiguration`.
        """
        # NOTE(flaper87): This should probably go away

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :raises: `glance.exceptions.NotFound` if image does not exist
        """
        raise NotImplementedError

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :raises: `glance_store.exceptions.NotFound` if image does not exist
        """
        raise NotImplementedError

    # NOTE(rosmaita): use the @glance_store.driver.back_compat_add
    # annotation on implementions for backward compatibility with
    # pre-0.26.0 add().  Need backcompat because pre-0.26.0 returned
    # a 4 tuple, this returns a 5-tuple
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
        :param context: A context object
        :param verifier: An object used to verify signatures for images

        :returns: tuple of: (1) URL in backing store, (2) bytes written,
                  (3) checksum, (4) multihash value, and (5) a dictionary
                  with storage system specific information
        :raises: `glance_store.exceptions.Duplicate` if the image already
                 exists
        """
        raise NotImplementedError

    @capabilities.check
    def delete(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :param location: `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()
        :raises: `glance_store.exceptions.NotFound` if image does not exist
        """
        raise NotImplementedError

    def set_acls(self, location, public=False, read_tenants=None,
                 write_tenants=None, context=None):
        """
        Sets the read and write access control list for an image in the
        backend store.

        :param location: `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()
        :param public: A boolean indicating whether the image should be public.
        :param read_tenants: A list of tenant strings which should be granted
                      read access for an image.
        :param write_tenants: A list of tenant strings which should be granted
                      write access for an image.
        """
        raise NotImplementedError


def back_compat_add(store_add_fun):
    """
    Provides backward compatibility for the 0.26.0+ Store.add() function.
    In 0.26.0, the 'hashing_algo' parameter is introduced and Store.add()
    returns a 5-tuple containing a computed 'multihash' value.

    This wrapper behaves as follows:

    If no hashing_algo identifier is supplied as an argument, the response
    is the pre-0.26.0 4-tuple of::

    (backend_url, bytes_written, checksum, metadata_dict)

    If a hashing_algo is supplied, the response is a 5-tuple::

    (backend_url, bytes_written, checksum, multihash, metadata_dict)

    The wrapper detects the presence of a 'hashing_algo' argument both
    by examining named arguments and positionally.
    """

    @wraps(store_add_fun)
    def add_adapter(*args, **kwargs):
        """
        Wrapper for the store 'add' function.  If no hashing_algo identifier
        is supplied, the response is the pre-0.25.0 4-tuple of::

        (backend_url, bytes_written, checksum, metadata_dict)

        If a hashing_algo is supplied, the response is a 5-tuple::

        (backend_url, bytes_written, checksum, multihash, metadata_dict)
        """
        # strategy: assume this until we determine otherwise
        back_compat_required = True

        # specify info about 0.26.0 Store.add() call (can't introspect
        # this because the add method is wrapped by the capabilities
        # check)
        p_algo = 4
        max_args = 7

        num_args = len(args)
        num_kwargs = len(kwargs)

        if num_args + num_kwargs == max_args:
            # everything is present, including hashing_algo
            back_compat_required = False
        elif ('hashing_algo' in kwargs or
              (num_args >= p_algo + 1 and isinstance(args[p_algo], str))):
            # there is a hashing_algo argument present
            back_compat_required = False
        else:
            # this is a pre-0.26.0-style call, so let's figure out
            # whether to insert the hashing_algo in the args or kwargs
            if kwargs and 'image_' in ''.join(kwargs):
                # if any of the image_* is named, everything after it
                # must be named as well, so slap the algo into kwargs
                kwargs['hashing_algo'] = 'md5'
            else:
                args = args[:p_algo] + ('md5',) + args[p_algo:]

        # business time
        (backend_url,
         bytes_written,
         checksum,
         multihash,
         metadata_dict) = store_add_fun(*args, **kwargs)

        if back_compat_required:
            return (backend_url, bytes_written, checksum, metadata_dict)

        return (backend_url, bytes_written, checksum, multihash,
                metadata_dict)

    return add_adapter


class BackendGroupConfiguration(object):

    def __init__(self, store_opts, config_group=None, conf=None):
        """Initialize configuration.

        This takes care of grafting the implementation's config
        values into the config group and shared defaults. We will try to
        pull values from the specified 'config_group', but fall back to
        defaults from the SHARED_CONF_GROUP.
        """
        self.config_group = config_group
        self.conf = conf or CONF

        # set the local conf so that __call__'s know what to use
        self._ensure_config_values(store_opts)
        self.backend_conf = self.conf._get(self.config_group)
        self.shared_backend_conf = self.conf._get(SHARED_CONF_GROUP)

    def _safe_register(self, opt, group):
        try:
            CONF.register_opt(opt, group=group)
        except cfg.DuplicateOptError:
            pass  # If it's already registered ignore it

    def _ensure_config_values(self, store_opts):
        """Register the options in the shared group.

        When we go to get a config option we will try the backend specific
        group first and fall back to the shared group. We override the default
        from all the config options for the backend group so we can know if it
        was set or not.
        """
        for opt in store_opts:
            self._safe_register(opt, SHARED_CONF_GROUP)
            # Assuming they aren't the same groups, graft on the options into
            # the backend group and override its default value.
            if self.config_group != SHARED_CONF_GROUP:
                self._safe_register(opt, self.config_group)
                self.conf.set_default(opt.name, None, group=self.config_group)

    def append_config_values(self, store_opts):
        self._ensure_config_values(store_opts)

    def set_default(self, opt_name, default):
        self.conf.set_default(opt_name, default, group=SHARED_CONF_GROUP)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __getattr__(self, opt_name):
        # Don't use self.X to avoid reentrant call to __getattr__()
        backend_conf = object.__getattribute__(self, 'backend_conf')
        opt_value = getattr(backend_conf, opt_name)
        if opt_value is None:
            shared_conf = object.__getattribute__(self, 'shared_backend_conf')
            opt_value = getattr(shared_conf, opt_name)
        return opt_value
