#!/bin/bash
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This script is executed inside gate_hook function in devstack gate.

# NOTE(NiallBunting) The store to test is passed in here from the
# project config.
GLANCE_STORE_DRIVER=${1:-swift}

ENABLED_SERVICES+=",key,glance"

case $GLANCE_STORE_DRIVER in
    swift)
        ENABLED_SERVICES+=",s-proxy,s-account,s-container,s-object,"
        ;;
esac

export GLANCE_STORE_DRIVER

export ENABLED_SERVICES

$BASE/new/devstack-gate/devstack-vm-gate.sh
