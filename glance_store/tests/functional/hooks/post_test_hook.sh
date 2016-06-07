#!/bin/bash -xe

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This script is executed inside post_test_hook function in devstack gate.

set -xe

export GLANCE_STORE_DIR="$BASE/new/glance_store"
SCRIPTS_DIR="/usr/os-testr-env/bin/"
GLANCE_STORE_DRIVER=${1:-swift}

function generate_test_logs {
    local path="$1"
    # Compress all $path/*.txt files and move the directories holding those
    # files to /opt/stack/logs. Files with .log suffix have their
    # suffix changed to .txt (so browsers will know to open the compressed
    # files and not download them).
    if [ -d "$path" ]
    then
        sudo find $path -iname "*.log" -type f -exec mv {} {}.txt \; -exec gzip -9 {}.txt \;
        sudo mv $path/* /opt/stack/logs/
    fi
}

function generate_testr_results {
    if [ -f .testrepository/0 ]; then
        # Give job user rights to access tox logs
        sudo -H -u "$owner" chmod o+rw .
        sudo -H -u "$owner" chmod o+rw -R .testrepository

        if [[ -f ".testrepository/0" ]] ; then
            "subunit-1to2" < .testrepository/0 > ./testrepository.subunit
            $SCRIPTS_DIR/subunit2html ./testrepository.subunit testr_results.html
            gzip -9 ./testrepository.subunit
            gzip -9 ./testr_results.html
            sudo mv ./*.gz /opt/stack/logs/
        fi

    fi
}

owner=jenkins

# Get admin credentials
cd $BASE/new/devstack
source openrc admin admin

# Go to the glance_store dir
cd $GLANCE_STORE_DIR

sudo chown -R $owner:stack $GLANCE_STORE_DIR

sudo cp $GLANCE_STORE_DIR/functional_testing.conf.sample $GLANCE_STORE_DIR/functional_testing.conf

# Set admin creds
iniset $GLANCE_STORE_DIR/functional_testing.conf admin key $ADMIN_PASSWORD

# Run tests
echo "Running glance_store functional test suite"
set +e
# Preserve env for OS_ credentials
sudo -E -H -u jenkins tox -e functional-$GLANCE_STORE_DRIVER
EXIT_CODE=$?
set -e

# Collect and parse result
generate_testr_results
exit $EXIT_CODE
