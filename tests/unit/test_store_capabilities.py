# Copyright 2014 OpenStack Foundation
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


from glance_store import capabilities as caps
from glance_store.tests import base


class FakeStoreWithStaticCapabilities(caps.StoreCapability):
    _CAPABILITIES = caps.BitMasks.READ_RANDOM | caps.BitMasks.DRIVER_REUSABLE


class FakeStoreWithDynamicCapabilities(caps.StoreCapability):
    def __init__(self, *cap_list):
        super(FakeStoreWithDynamicCapabilities, self).__init__()
        if not cap_list:
            cap_list = [caps.BitMasks.READ_RANDOM,
                        caps.BitMasks.DRIVER_REUSABLE]
        self.set_capabilities(*cap_list)


class FakeStoreWithMixedCapabilities(caps.StoreCapability):
    _CAPABILITIES = caps.BitMasks.READ_RANDOM

    def __init__(self):
        super(FakeStoreWithMixedCapabilities, self).__init__()
        self.set_capabilities(caps.BitMasks.DRIVER_REUSABLE)


class TestStoreCapabilitiesChecking(object):

    def test_store_capabilities_checked_on_io_operations(self):
        self.assertEqual('op_checker', self.store.add.__name__)
        self.assertEqual('op_checker', self.store.get.__name__)
        self.assertEqual('op_checker', self.store.delete.__name__)


class TestStoreCapabilities(base.StoreBaseTest):

    def _verify_store_capabilities(self, store):
        # This function tested is_capable() as well.
        self.assertTrue(store.is_capable(caps.BitMasks.READ_RANDOM))
        self.assertTrue(store.is_capable(caps.BitMasks.DRIVER_REUSABLE))
        self.assertFalse(store.is_capable(caps.BitMasks.WRITE_ACCESS))

    def test_static_capabilities_setup(self):
        self._verify_store_capabilities(FakeStoreWithStaticCapabilities())

    def test_dynamic_capabilities_setup(self):
        self._verify_store_capabilities(FakeStoreWithDynamicCapabilities())

    def test_mixed_capabilities_setup(self):
        self._verify_store_capabilities(FakeStoreWithMixedCapabilities())

    def test_set_unset_capabilities(self):
        store = FakeStoreWithStaticCapabilities()
        self.assertFalse(store.is_capable(caps.BitMasks.WRITE_ACCESS))

        # Set and unset single capability on one time
        store.set_capabilities(caps.BitMasks.WRITE_ACCESS)
        self.assertTrue(store.is_capable(caps.BitMasks.WRITE_ACCESS))
        store.unset_capabilities(caps.BitMasks.WRITE_ACCESS)
        self.assertFalse(store.is_capable(caps.BitMasks.WRITE_ACCESS))

        # Set and unset multiple capabilities on one time
        cap_list = [caps.BitMasks.WRITE_ACCESS, caps.BitMasks.WRITE_OFFSET]
        store.set_capabilities(*cap_list)
        self.assertTrue(store.is_capable(*cap_list))
        store.unset_capabilities(*cap_list)
        self.assertFalse(store.is_capable(*cap_list))

    def test_store_capabilities_property(self):
        store1 = FakeStoreWithDynamicCapabilities()
        self.assertTrue(hasattr(store1, 'capabilities'))
        store2 = FakeStoreWithMixedCapabilities()
        self.assertEqual(store1.capabilities, store2.capabilities)

    def test_cascaded_unset_capabilities(self):
        # Test read capability
        store = FakeStoreWithMixedCapabilities()
        self._verify_store_capabilities(store)
        store.unset_capabilities(caps.BitMasks.READ_ACCESS)
        cap_list = [caps.BitMasks.READ_ACCESS, caps.BitMasks.READ_OFFSET,
                    caps.BitMasks.READ_CHUNK, caps.BitMasks.READ_RANDOM]
        for cap in cap_list:
            # To make sure all of them are unsetted.
            self.assertFalse(store.is_capable(cap))
        self.assertTrue(store.is_capable(caps.BitMasks.DRIVER_REUSABLE))

        # Test write capability
        store = FakeStoreWithDynamicCapabilities(caps.BitMasks.WRITE_RANDOM,
                                                 caps.BitMasks.DRIVER_REUSABLE)
        self.assertTrue(store.is_capable(caps.BitMasks.WRITE_RANDOM))
        self.assertTrue(store.is_capable(caps.BitMasks.DRIVER_REUSABLE))
        store.unset_capabilities(caps.BitMasks.WRITE_ACCESS)
        cap_list = [caps.BitMasks.WRITE_ACCESS, caps.BitMasks.WRITE_OFFSET,
                    caps.BitMasks.WRITE_CHUNK, caps.BitMasks.WRITE_RANDOM]
        for cap in cap_list:
            # To make sure all of them are unsetted.
            self.assertFalse(store.is_capable(cap))
        self.assertTrue(store.is_capable(caps.BitMasks.DRIVER_REUSABLE))


class TestStoreCapabilityConstants(base.StoreBaseTest):

    def test_one_single_capability_own_one_bit(self):
        cap_list = [
            caps.BitMasks.READ_ACCESS,
            caps.BitMasks.WRITE_ACCESS,
            caps.BitMasks.DRIVER_REUSABLE,
        ]
        for cap in cap_list:
            self.assertEqual(1, bin(cap).count('1'))

    def test_combined_capability_bits(self):
        check = caps.StoreCapability.contains
        check(caps.BitMasks.READ_OFFSET, caps.BitMasks.READ_ACCESS)
        check(caps.BitMasks.READ_CHUNK, caps.BitMasks.READ_ACCESS)
        check(caps.BitMasks.READ_RANDOM, caps.BitMasks.READ_CHUNK)
        check(caps.BitMasks.READ_RANDOM, caps.BitMasks.READ_OFFSET)
        check(caps.BitMasks.WRITE_OFFSET, caps.BitMasks.WRITE_ACCESS)
        check(caps.BitMasks.WRITE_CHUNK, caps.BitMasks.WRITE_ACCESS)
        check(caps.BitMasks.WRITE_RANDOM, caps.BitMasks.WRITE_CHUNK)
        check(caps.BitMasks.WRITE_RANDOM, caps.BitMasks.WRITE_OFFSET)
        check(caps.BitMasks.RW_ACCESS, caps.BitMasks.READ_ACCESS)
        check(caps.BitMasks.RW_ACCESS, caps.BitMasks.WRITE_ACCESS)
        check(caps.BitMasks.RW_OFFSET, caps.BitMasks.READ_OFFSET)
        check(caps.BitMasks.RW_OFFSET, caps.BitMasks.WRITE_OFFSET)
        check(caps.BitMasks.RW_CHUNK, caps.BitMasks.READ_CHUNK)
        check(caps.BitMasks.RW_CHUNK, caps.BitMasks.WRITE_CHUNK)
        check(caps.BitMasks.RW_RANDOM, caps.BitMasks.READ_RANDOM)
        check(caps.BitMasks.RW_RANDOM, caps.BitMasks.WRITE_RANDOM)
