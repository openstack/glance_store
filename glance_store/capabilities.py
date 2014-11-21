# Copyright (c) 2015 IBM, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Glance Store capability"""

import logging
import threading
import time

from eventlet import tpool

from glance_store import exceptions
from glance_store import i18n

_LW = i18n._LW
_STORE_CAPABILITES_UPDATE_SCHEDULING_BOOK = {}
_STORE_CAPABILITES_UPDATE_SCHEDULING_LOCK = threading.Lock()
LOG = logging.getLogger(__name__)

# Store capability constants
NONE = 0b00000000
ALL = 0b11111111
READ_ACCESS = 0b00000001
READ_OFFSET = 0b00000011  # Included READ_ACCESS
READ_CHUNK = 0b00000101  # Included READ_ACCESS
READ_RANDOM = 0b00000111  # READ_OFFSET | READ_CHUNK
WRITE_ACCESS = 0b00001000
WRITE_OFFSET = 0b00011000  # Included WRITE_ACCESS
WRITE_CHUNK = 0b00101000  # Included WRITE_ACCESS
WRITE_RANDOM = 0b00111000  # WRITE_OFFSET | WRITE_CHUNK
RW_ACCESS = 0b00001001  # READ_ACCESS | WRITE_ACCESS
RW_OFFSET = 0b00011011  # READ_OFFSET | WRITE_OFFSET
RW_CHUNK = 0b00101101  # READ_CHUNK | WRITE_CHUNK
RW_RANDOM = 0b00111111  # RW_OFFSET | RW_CHUNK
DRIVER_REUSABLE = 0b01000000  # driver is stateless and can be reused safely


class StoreCapability(object):

    def __init__(self):
        # Set static store capabilities base on
        # current driver implementation.
        self._capabilities = getattr(self.__class__, "_CAPABILITIES", 0)

    @property
    def capabilities(self):
        return self._capabilities

    @staticmethod
    def contains(x, y):
        return x & y == y

    def update_capabilities(self):
        """
        Update dynamic storage capabilities based on current
        driver configuration and backend status when needed.

        As a hook, the function will be triggered in two cases:
        calling once after store driver get configured, it was
        used to update dynamic storage capabilities based on
        current driver configuration, or calling when the
        capabilities checking of an operation failed every time,
        this was used to refresh dynamic storage capabilities
        based on backend status then.

        This function shouldn't raise any exception out.
        """
        LOG.debug(("Store %s doesn't support updating dynamic "
                   "storage capabilities. Please overwrite "
                   "'update_capabilities' method of the store to "
                   "implement updating logics if needed.") %
                  self.__class__.__name__)

    def is_capable(self, *capabilities):
        """
        Check if requested capability(s) are supported by
        current driver instance.

        :param capabilities: required capability(s).
        """
        caps = 0

        for cap in capabilities:
            caps |= int(cap)

        return self.contains(self.capabilities, caps)

    def set_capabilities(self, *dynamic_capabilites):
        """
        Set dynamic storage capabilities based on current
        driver configuration and backend status.

        :param dynamic_capabilites: dynamic storage capability(s).
        """
        for cap in dynamic_capabilites:
            self._capabilities |= int(cap)

    def unset_capabilities(self, *dynamic_capabilites):
        """
        Unset dynamic storage capabilities.

        :param dynamic_capabilites: dynamic storage capability(s).
        """
        caps = 0

        for cap in dynamic_capabilites:
            caps |= int(cap)

        # TODO(zhiyan): Cascaded capability removal is
        # skipped currently, we can add it back later
        # when a concrete requirement comes out.
        # For example, when removing READ_ACCESS, all
        # read related capabilities need to be removed
        # together, e.g. READ_RANDOM.

        self._capabilities &= ~caps


def _schedule_capabilities_update(store):
    def _update_capabilities(store, context):
        with context['lock']:
            if context['updating']:
                return
            context['updating'] = True
            try:
                store.update_capabilities()
            except Exception:
                pass
            finally:
                context['updating'] = False
                # NOTE(zhiyan): Update 'latest_update' field
                # in anyway even an exception raised, to
                # prevent call problematic routine cyclically.
                context['latest_update'] = int(time.time())

    global _STORE_CAPABILITES_UPDATE_SCHEDULING_BOOK
    book = _STORE_CAPABILITES_UPDATE_SCHEDULING_BOOK
    if store not in book:
        with _STORE_CAPABILITES_UPDATE_SCHEDULING_LOCK:
            if store not in book:
                book[store] = {'latest_update': int(time.time()),
                               'lock': threading.Lock(),
                               'updating': False}
    else:
        context = book[store]
        # NOTE(zhiyan): We don't need to lock 'latest_update'
        # field for check since time increased one-way only.
        sec = (int(time.time()) - context['latest_update'] -
               store.conf.glance_store.store_capabilities_update_min_interval)
        if sec >= 0:
            if not context['updating']:
                # NOTE(zhiyan): Using a real thread pool instead
                # of green pool due to store capabilities updating
                # probably calls some inevitably blocking code for
                # IO operation on remote or local storage.
                # Eventlet allows operator to uses environment var
                # EVENTLET_THREADPOOL_SIZE to desired pool size.
                tpool.execute(_update_capabilities, store, context)


def check(store_op_fun):

    def op_checker(store, *args, **kwargs):
        # NOTE(zhiyan): Trigger the hook of updating store
        # dynamic capabilities based on current store status.
        if store.conf.glance_store.store_capabilities_update_min_interval > 0:
            _schedule_capabilities_update(store)

        op_cap_map = {
            'get': [READ_ACCESS,
                    READ_OFFSET if kwargs.get('offset') else NONE,
                    READ_CHUNK if kwargs.get('chunk_size') else NONE],
            'add': [WRITE_ACCESS],
            'delete': [WRITE_ACCESS]}

        op_exec_map = {
            'get': (exceptions.StoreRandomGetNotSupported
                    if kwargs.get('offset') or kwargs.get('chunk_size') else
                    exceptions.StoreGetNotSupported),
            'add': exceptions.StoreAddDisabled,
            'delete': exceptions.StoreDeleteNotSupported}

        op = store_op_fun.__name__.lower()

        try:
            req_cap = op_cap_map[op]
        except KeyError:
            LOG.warn(_LW('The capability of operation "%s" '
                         'could not be checked.' % op))
        else:
            if not store.is_capable(*req_cap):
                kwargs.setdefault('offset', 0)
                kwargs.setdefault('chunk_size', None)
                raise op_exec_map[op](**kwargs)

        return store_op_fun(store, *args, **kwargs)

    return op_checker
