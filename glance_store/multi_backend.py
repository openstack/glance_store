# Copyright 2018 RedHat Inc.
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

import copy
import hashlib
import logging

from oslo_config import cfg
from oslo_utils import encodeutils
from oslo_utils import units
from stevedore import driver
from stevedore import extension

from glance_store import capabilities
from glance_store import exceptions
from glance_store.i18n import _
from glance_store import location


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

_STORE_OPTS = [
    cfg.StrOpt('default_backend',
               help=_("""
The store identifier for the default backend in which data will be
stored.

The value must be defined as one of the keys in the dict defined
by the ``enabled_backends`` configuration option in the DEFAULT
configuration group.

If a value is not defined for this option:

* the consuming service may refuse to start
* store_add calls that do not specify a specific backend will
  raise a ``glance_store.exceptions.UnknownScheme`` exception

Related Options:
    * enabled_backends

""")),
]

FS_CONF_DATADIR_HELP = """
Directory of which the reserved store {} uses.

Possible values:
    * A valid path to a directory

Refer to [glance_store]/filesystem store config opts for more details.
"""

FS_CONF_CHUNKSIZE_HELP = """
Chunk size, in bytes to be used by reserved store {}.

The chunk size used when reading or writing image files. Raising this value
may improve the throughput but it may also slightly increase the memory usage
when handling a large number of requests.

Possible Values:
    * Any positive integer value

"""


_STORE_CFG_GROUP = 'glance_store'
_RESERVED_STORES = {}


def _list_config_opts():
    # NOTE(abhishekk): This separated approach could list
    # store options before all driver ones, which easier
    # to generate sampe config file.
    driver_opts = _list_driver_opts()
    sample_opts = [(_STORE_CFG_GROUP, _STORE_OPTS)]
    for store_entry in driver_opts:
        # NOTE(abhishekk): Do not include no_conf store
        if store_entry == "no_conf":
            continue
        sample_opts.append((store_entry, driver_opts[store_entry]))

    return sample_opts


def _list_driver_opts():
    driver_opts = {}
    mgr = extension.ExtensionManager('glance_store.drivers')
    # NOTE(zhiyan): Handle available drivers entry_points provided
    # NOTE(nikhil): Return a sorted list of drivers to ensure that the sample
    # configuration files generated by oslo config generator retain the order
    # in which the config opts appear across different runs. If this order of
    # config opts is not preserved, some downstream packagers may see a long
    # diff of the changes though not relevant as only order has changed. See
    # some more details at bug 1619487.
    drivers = sorted([ext.name for ext in mgr])
    handled_drivers = []  # Used to handle backwards-compatible entries
    for store_entry in drivers:
        driver_cls = _load_multi_store(None, store_entry, False)
        if driver_cls and driver_cls not in handled_drivers:
            if getattr(driver_cls, 'OPTIONS', None) is not None:
                driver_opts[store_entry] = driver_cls.OPTIONS
            handled_drivers.append(driver_cls)

    # NOTE(zhiyan): This separated approach could list
    # store options before all driver ones, which easier
    # to read and configure by operator.
    return driver_opts


def register_store_opts(conf, reserved_stores=None):
    LOG.debug("Registering options for group %s", _STORE_CFG_GROUP)
    conf.register_opts(_STORE_OPTS, group=_STORE_CFG_GROUP)

    configured_backends = copy.deepcopy(conf.enabled_backends)
    if reserved_stores:
        conf.enabled_backends.update(reserved_stores)
        for key in reserved_stores.keys():
            fs_conf_template = [
                cfg.StrOpt('filesystem_store_datadir',
                           default='/var/lib/glance/{}'.format(key),
                           help=FS_CONF_DATADIR_HELP.format(key)),
                cfg.MultiStrOpt('filesystem_store_datadirs',
                                help="""Not used"""),
                cfg.StrOpt('filesystem_store_metadata_file',
                           help="""Not used"""),
                cfg.IntOpt('filesystem_store_file_perm',
                           default=0,
                           help="""Not used"""),
                cfg.IntOpt('filesystem_store_chunk_size',
                           default=64 * units.Ki,
                           min=1,
                           help=FS_CONF_CHUNKSIZE_HELP.format(key)),
                cfg.BoolOpt('filesystem_thin_provisioning',
                            default=False,
                            help="""Not used""")]
            LOG.debug("Registering options for reserved store: {}".format(key))
            conf.register_opts(fs_conf_template, group=key)

    driver_opts = _list_driver_opts()
    for backend in configured_backends:
        for opt_list in driver_opts:
            if configured_backends[backend] not in opt_list:
                continue

            LOG.debug("Registering options for group %s", backend)
            conf.register_opts(driver_opts[opt_list], group=backend)


def _load_multi_store(conf, store_entry,
                      invoke_load=True,
                      backend=None):
    if backend:
        invoke_args = [conf, backend]
    else:
        invoke_args = [conf]
    try:
        LOG.debug("Attempting to import store %s", store_entry)
        mgr = driver.DriverManager('glance_store.drivers',
                                   store_entry,
                                   invoke_args=invoke_args,
                                   invoke_on_load=invoke_load)
        return mgr.driver
    except RuntimeError as e:
        LOG.warning("Failed to load driver %(driver)s. The "
                    "driver will be disabled", dict(driver=str([driver, e])))


def _load_multi_stores(conf, reserved_stores=None):
    enabled_backends = conf.enabled_backends
    if reserved_stores:
        enabled_backends.update(reserved_stores)
        _RESERVED_STORES.update(reserved_stores)

    for backend, store_entry in enabled_backends.items():
        try:
            # FIXME(flaper87): Don't hide BadStoreConfiguration
            # exceptions. These exceptions should be propagated
            # to the user of the library.
            store_instance = _load_multi_store(conf, store_entry,
                                               backend=backend)

            if not store_instance:
                continue

            yield (store_entry, store_instance, backend)

        except exceptions.BadStoreConfiguration:
            continue


def create_multi_stores(conf=CONF, reserved_stores=None):
    """
    Registers all store modules and all schemes from the given configuration
    object.

    :param conf: A oslo_config (or compatible) object
    :param reserved_stores: A list of stores for the consuming service's
                            internal use.  The list must be the same
                            format as the ``enabled_backends`` configuration
                            setting.  The default value is None
    :return: The number of stores configured
    :raises: ``glance_store.exceptions.BackendException``

    *Configuring Multiple Backends*

    The backends to be configured are expected to be found in the
    ``enabled_backends`` configuration variable in the DEFAULT group
    of the object.  The format for the variable is a dictionary of
    key:value pairs where the key is an arbitrary store identifier
    and the value is the store type identifier for the store.

    The type identifiers must be defined in the  ``[entry points]``
    section of the glance_store ``setup.cfg`` file as values for
    the ``glance_store.drivers`` configuration.  (See the default
    ``setup.cfg`` file for an example.)  The store type identifiers
    for the currently supported drivers are already defined in the file.

    Thus an example value for ``enabled_backends`` is::

        {'store_one': 'http', 'store_two': 'file', 'store_three': 'rbd'}

    The ``reserved_stores`` parameter, if included, must have the same
    format.  There is no difference between the ``enabled_backends`` and
    ``reserved_stores`` from the glance_store point of view: the reserved
    stores are a convenience for the consuming service, which may wish
    to handle the two sets of stores differently.

    *The Default Store*

    If you wish to set a default store, its store identifier should be
    defined as the value of the ``default_backend`` configuration option
    in the ``glance_store`` group of the ``conf`` parameter.  The store
    identifier, or course, should be specified as one of the keys in the
    ``enabled_backends`` dict.  It is recommended that a default store
    be set.

    *Configuring Individual Backends*

    To configure each store mentioned in the ``enabled_backends``
    configuration option, you must define an option group with the
    same name as the store identifier.  The options defined for that
    backend will depend upon the store type; consult the documentation
    for the appropriate backend driver to determine what these are.

    For example, given the ``enabled_backends`` example above, you
    would put the following in the configuration file that loads the
    ``conf`` object::

        [DEFAULT]
        enabled_backends = store_one:rbd,store_two:file,store_three:http

        [store_one]
        store_description = "A human-readable string aimed at end users"
        rbd_store_chunk_size = 8
        rbd_store_pool = images
        rbd_store_user = admin
        rbd_store_ceph_conf = /etc/ceph/ceph.conf

        [store_two]
        store_description = "Human-readable description of this store"
        filesystem_store_datadir = /opt/stack/data/glance/store_two

        [store_three]
        store_description = "A read-only store"
        https_ca_certificates_file = /opt/stack/certs/gs.cert

        [glance_store]
        default_backend = store_two

    The ``store_description`` options may be used by a consuming service.
    As recommended above, this file also defines a default backend.
    """

    store_count = 0
    scheme_map = {}
    for (store_entry, store_instance,
         store_identifier) in _load_multi_stores(
            conf, reserved_stores=reserved_stores):
        try:
            schemes = store_instance.get_schemes()
            store_instance.configure(re_raise_bsc=False)
        except NotImplementedError:
            continue

        if not schemes:
            raise exceptions.BackendException(
                _('Unable to register store %s. No schemes associated '
                  'with it.') % store_entry)
        else:
            LOG.debug("Registering store %s with schemes %s",
                      store_entry, schemes)

            loc_cls = store_instance.get_store_location_class()
            for scheme in schemes:
                if scheme not in scheme_map:
                    scheme_map[scheme] = {}
                scheme_map[scheme][store_identifier] = {
                    'store': store_instance,
                    'location_class': loc_cls,
                    'store_entry': store_entry
                }
                location.register_scheme_backend_map(scheme_map)
                store_count += 1

    return store_count


def verify_store():
    store_id = CONF.glance_store.default_backend
    if not store_id:
        msg = _("'default_backend' config option is not set.")
        raise RuntimeError(msg)

    try:
        get_store_from_store_identifier(store_id)
    except exceptions.UnknownScheme:
        msg = _("Store for identifier %s not found") % store_id
        raise RuntimeError(msg)


def get_store_from_store_identifier(store_identifier):
    """Determine backing store from identifier.

    Given a store identifier, return the appropriate store object
    for handling that scheme.
    """
    scheme_map = {}
    enabled_backends = CONF.enabled_backends
    enabled_backends.update(_RESERVED_STORES)

    try:
        scheme = enabled_backends[store_identifier]
    except KeyError:
        msg = _("Store for identifier %s not found") % store_identifier
        raise exceptions.UnknownScheme(msg)

    if scheme not in location.SCHEME_TO_CLS_BACKEND_MAP:
        raise exceptions.UnknownScheme(scheme=scheme)

    scheme_info = location.SCHEME_TO_CLS_BACKEND_MAP[scheme][store_identifier]
    store = scheme_info['store']

    if not store.is_capable(capabilities.BitMasks.DRIVER_REUSABLE):
        # Driver instance isn't stateless so it can't
        # be reused safely and need recreation.
        store_entry = scheme_info['store_entry']
        store = _load_multi_store(store.conf, store_entry, invoke_load=True,
                                  backend=store_identifier)
        store.configure()
        try:
            loc_cls = store.get_store_location_class()
            for new_scheme in store.get_schemes():
                if new_scheme not in scheme_map:
                    scheme_map[new_scheme] = {}

                scheme_map[new_scheme][store_identifier] = {
                    'store': store,
                    'location_class': loc_cls,
                    'store_entry': store_entry
                }
                location.register_scheme_backend_map(scheme_map)
        except NotImplementedError:
            scheme_info['store'] = store

    return store


def add(conf, image_id, data, size, backend, context=None,
        verifier=None):
    if not backend:
        backend = conf.glance_store.default_backend

    store = get_store_from_store_identifier(backend)
    return store_add_to_backend(image_id, data, size, store, context,
                                verifier)


def add_with_multihash(conf, image_id, data, size, backend, hashing_algo,
                       scheme=None, context=None, verifier=None):
    if not backend:
        backend = conf.glance_store.default_backend

    store = get_store_from_store_identifier(backend)
    return store_add_to_backend_with_multihash(
        image_id, data, size, hashing_algo, store, context, verifier)


def _check_metadata(store, metadata):
    if not isinstance(metadata, dict):
        msg = (_("The storage driver %(driver)s returned invalid "
                 " metadata %(metadata)s. This must be a dictionary type")
               % dict(driver=str(store), metadata=str(metadata)))
        LOG.error(msg)
        raise exceptions.BackendException(msg)
    try:
        check_location_metadata(metadata)
    except exceptions.BackendException as e:
        e_msg = (_("A bad metadata structure was returned from the "
                   "%(driver)s storage driver: %(metadata)s.  %(e)s.") %
                 dict(driver=encodeutils.exception_to_unicode(store),
                      metadata=encodeutils.exception_to_unicode(metadata),
                      e=encodeutils.exception_to_unicode(e)))
        LOG.error(e_msg)
        raise exceptions.BackendException(e_msg)


def store_add_to_backend(image_id, data, size, store, context=None,
                         verifier=None):
    """A wrapper around a call to each stores add() method.

    This gives glance a common place to check the output.

    :param image_id:  The image add to which data is added
    :param data: The data to be stored
    :param size: The length of the data in bytes
    :param store: The store to which the data is being added
    :param context: The request context
    :param verifier: An object used to verify signatures for images
    :param backend: Name of the backend to store the image
    :return: The url location of the file,
             the size amount of data,
             the checksum of the data
             the storage systems metadata dictionary for the location
    """
    (location, size, checksum, metadata) = store.add(image_id,
                                                     data,
                                                     size,
                                                     context=context,
                                                     verifier=verifier)

    if metadata is not None:
        _check_metadata(store, metadata)

    return (location, size, checksum, metadata)


def store_add_to_backend_with_multihash(
        image_id, data, size, hashing_algo, store,
        context=None, verifier=None):
    """
    A wrapper around a call to each store's add() method that requires
    a hashing_algo identifier and returns a 5-tuple including the
    "multihash" computed using the specified hashing_algo.  (This
    is an enhanced version of store_add_to_backend(), which is left
    as-is for backward compatibility.)

    :param image_id:  The image add to which data is added
    :param data: The data to be stored
    :param size: The length of the data in bytes
    :param store: The store to which the data is being added
    :param hashing_algo: A hashlib algorithm identifier (string)
    :param context: The request context
    :param verifier: An object used to verify signatures for images
    :return: The url location of the file,
             the size amount of data,
             the checksum of the data,
             the multihash of the data,
             the storage system's metadata dictionary for the location
    :raises: ``glance_store.exceptions.BackendException``
             ``glance_store.exceptions.UnknownHashingAlgo``
    """

    if hashing_algo not in hashlib.algorithms_available:
        raise exceptions.UnknownHashingAlgo(algo=hashing_algo)

    (location, size, checksum, multihash, metadata) = store.add(
        image_id, data, size, hashing_algo, context=context, verifier=verifier)

    if metadata is not None:
        _check_metadata(store, metadata)

    return (location, size, checksum, multihash, metadata)


def check_location_metadata(val, key=''):
    if isinstance(val, dict):
        for key in val:
            check_location_metadata(val[key], key=key)
    elif isinstance(val, list):
        ndx = 0
        for v in val:
            check_location_metadata(v, key='%s[%d]' % (key, ndx))
            ndx = ndx + 1
    elif not isinstance(val, str):
        raise exceptions.BackendException(_("The image metadata key %(key)s "
                                            "has an invalid type of %(type)s. "
                                            "Only dict, list, and unicode are "
                                            "supported.")
                                          % dict(key=key, type=type(val)))


def delete(uri, backend, context=None):
    """Removes chunks of data from backend specified by uri."""
    if backend:
        loc = location.get_location_from_uri_and_backend(
            uri, backend, conf=CONF)
        store = get_store_from_store_identifier(backend)
        return store.delete(loc, context=context)

    LOG.warning('Backend is not set to image, searching all backends based on '
                'location URI.')

    backends = CONF.enabled_backends
    for backend in backends:
        try:
            if not uri.startswith(backends[backend]):
                continue

            loc = location.get_location_from_uri_and_backend(
                uri, backend, conf=CONF)
            store = get_store_from_store_identifier(backend)
            return store.delete(loc, context=context)
        except (exceptions.NotFound, exceptions.UnknownScheme):
            continue

    raise exceptions.NotFound(_("Image not found in any configured backend"))


def set_acls_for_multi_store(location_uri, backend, public=False,
                             read_tenants=[],
                             write_tenants=None, context=None):

    if write_tenants is None:
        write_tenants = []

    loc = location.get_location_from_uri_and_backend(
        location_uri, backend, conf=CONF)
    store = get_store_from_store_identifier(backend)
    try:
        store.set_acls(loc, public=public,
                       read_tenants=read_tenants,
                       write_tenants=write_tenants,
                       context=context)
    except NotImplementedError:
        LOG.debug("Skipping store.set_acls... not implemented")


def get(uri, backend, offset=0, chunk_size=None, context=None):
    """Yields chunks of data from backend specified by uri."""

    if backend:
        loc = location.get_location_from_uri_and_backend(uri, backend,
                                                         conf=CONF)
        store = get_store_from_store_identifier(backend)

        return store.get(loc, offset=offset,
                         chunk_size=chunk_size,
                         context=context)

    LOG.warning('Backend is not set to image, searching all backends based on '
                'location URI.')

    backends = CONF.enabled_backends
    for backend in backends:
        try:
            if not uri.startswith(backends[backend]):
                continue

            loc = location.get_location_from_uri_and_backend(
                uri, backend, conf=CONF)
            store = get_store_from_store_identifier(backend)
            data, size = store.get(loc, offset=offset,
                                   chunk_size=chunk_size,
                                   context=context)
            if data:
                return data, size
        except (exceptions.NotFound, exceptions.UnknownScheme):
            continue

    raise exceptions.NotFound(_("Image not found in any configured backend"))


def get_known_schemes_for_multi_store():
    """Returns list of known schemes."""
    return location.SCHEME_TO_CLS_BACKEND_MAP.keys()


def get_size_from_uri_and_backend(uri, backend, context=None):
    """Retrieves image size from backend specified by uri."""

    loc = location.get_location_from_uri_and_backend(
        uri, backend, conf=CONF)
    store = get_store_from_store_identifier(backend)
    return store.get_size(loc, context=context)
