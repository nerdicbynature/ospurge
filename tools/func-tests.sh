#!/usr/bin/env bash
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

# Be strict (but not too much: '-u' doesn't always play nice with devstack)
set -xeo pipefail

# Set this so -x doesn't spam warnings
RC_DIR=$(cd $(dirname "${BASH_SOURCE:-$0}") && pwd)

readonly PROGDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Try to detect whether we run in the OpenStack Gate.
if [[ -d ~stack/devstack ]]; then
    export DEVSTACK_DIR=~stack/devstack
    GATE_RUN=1
else
    export DEVSTACK_DIR=~/devstack
    GATE_RUN=0
fi

#projectname_username
invisible_to_admin_demo_pass=$(cat $DEVSTACK_DIR/accrc/invisible_to_admin/demo | sed -nr 's/.*OS_PASSWORD="(.*)"/\1/p')
admin_admin_pass=$(cat $DEVSTACK_DIR/accrc/admin/admin | sed -nr 's/.*OS_PASSWORD="(.*)"/\1/p')

function assert_compute {
    if [[ $(nova list | wc -l) -lt 5 ]]; then
        echo "Less than one VM, someone cleaned our VM :("
        exit 1
    fi

}

function assert_network {
    # We expect at least 1 "" (free), 1 "compute:",
    # 1 "network:router_interface" and 1 "network:dhcp" ports
    if [[ $(neutron port-list | wc -l) -lt 8 ]]; then
        echo "Less than 4 ports, someone cleaned our ports :("
        exit 1
    fi

    # We expect at least 2 security groups (default + one created by populate)
    if [[ $(openstack security group list | wc -l) -lt 6 ]]; then
        echo "Less than 2 security groups, someone cleaned our sec-groups :("
        exit 1
    fi

    if [[ $(openstack floating ip list | wc -l) -lt 5 ]]; then
        echo "Less than one floating ip, someone cleaned our FIP :("
        exit 1
    fi
}

function assert_volume {
    if [[ ${GATE_RUN} == 1 ]]; then
        # The Cinder backup service is enabled in the Gate.
        if [[ $(openstack volume backup list | wc -l) -lt 5 ]]; then
            echo "Less than one backup, someone cleaned our backup:("
            exit 1
        fi
    else
        if [[ $(openstack volume list | wc -l) -lt 5 ]]; then
            echo "Less than one volume, someone cleaned our volume:("
            exit 1
        fi
    fi
}

########################
# Disable asserts
########################
function test_neutron_disable {
    if [[ $(openstack port list -c Status -f value --device-owner compute:nova --project $demo_project_id | grep -ic 'active' ) -gt 0 ]]; then
        echo "Some of the ports is not disabled yet :)"
        exit 1
    fi
    if [[ $(openstack port list -c Status -f value --device-owner  ''  --project $demo_project_id | grep -ic 'active' ) -gt 0 ]]; then
        echo "Some of the ports is not disabled yet :)"
        exit 1
    fi
    if [[ $(openstack network list --no-share --long -c State -f value --project $demo_project_id | grep -ic 'UP' ) -gt 0 ]]; then
        echo "Some of the networks is not disabled yet :)"
        exit 1
    fi
    for router in $(openstack router list -c ID -f value --project $demo_project_id); do
        if [[ $(openstack router show $router -c admin_state_up -f value | grep -ic 'true' ) -gt 0 ]]; then
            echo "Some of the routers is not disabled yet :)"
            exit 1
        fi
    done
}


function test_cinder_disable {
    if [[ $(openstack volume list --long -c Properties -f value | grep -qvi 'readonly') ]]; then
        echo "Cinder volume is not disabled :)"
        exit 1
    fi
}


function test_glance_disable {
    if [[ $(openstack image list --long -c Project -c Status -f value| grep $demo_project_id | grep -ic 'active' ) -gt 0 ]]; then
        echo "Some of the images is not disabled yet :)"
        exit 1
    fi
}


function test_nova_disable {
    if [[ $(openstack server list -c Status -f value | grep -ic 'active' ) -gt 0 ]]; then
        echo "Some of the servers is not disabled yet :)"
        exit 1
    fi
}


function test_loadbalancer_disable {
    for loadbalancer in $(openstack loadbalancer list -c id -f value --project $demo_project_id); do
        if [[ $(openstack loadbalancer show $loadbalancer -c admin_state_up -f value | grep -ic 'true' ) -gt 0 ]]; then
            echo "Some of the loadbalancers is not disabled yet :)"
            exit 1
        fi
    done
}


function test_swift_disable {
    for container in $(openstack container list -c Name -f value); do
        if [[ $(openstack container show $container -f json |  grep -iq 'read[-_]acl:.*' ) ]]; then
            echo "Some of the containers  is not disabled yet :)"
            exit 1
        fi
        if [[ $(openstack container show $container -f json |  grep -iq 'write[-_]acl:.*' ) ]]; then
            echo "Some of the containers is not disabled yet :)"
            exit 1
        fi
    done
}


########################
### Pre check
########################
source $DEVSTACK_DIR/openrc admin admin
if [[ ! "$(openstack flavor list)" =~ 'm1.nano' ]]; then
    openstack flavor create --id 42 --ram 64 --disk 1 --vcpus 1 m1.nano
fi

# Allow additional test user/projects access the load-balancer service
openstack role add --user demo --project invisible_to_admin load-balancer_member
openstack role add --user alt_demo --project alt_demo load-balancer_member

########################
### Populate
########################
pid=()

(source $DEVSTACK_DIR/openrc admin admin && ${PROGDIR}/populate.sh) &
pid+=($!)

(source $DEVSTACK_DIR/openrc demo demo && ${PROGDIR}/populate.sh) &
pid+=($!)

(source $DEVSTACK_DIR/openrc demo invisible_to_admin && ${PROGDIR}/populate.sh) &
pid+=($!)

(source $DEVSTACK_DIR/openrc alt_demo alt_demo && ${PROGDIR}/populate.sh) &
pid+=($!)

for i in ${!pid[@]}; do
    wait ${pid[i]}
    if [[ $? -ne 0 ]]; then
        echo "One of the 'populate.sh' execution failed."
        exit 1
    fi
    unset "pid[$i]"
done

echo "Done populating. Moving on to cleanup."

########################
# Disable
########################
source $DEVSTACK_DIR/openrc admin admin
demo_project_id=$(openstack project show demo -c id -f value | awk '{print $1}')
source $DEVSTACK_DIR/openrc demo demo
assert_compute && assert_network && assert_volume

tox -e run -- --os-cloud devstack --purge-own-project --verbose --disable-only # disable demo/demo
test_neutron_disable && test_cinder_disable && test_glance_disable \
&& test_nova_disable && test_loadbalancer_disable && test_swift_disable

########################
### Cleanup
########################
source $DEVSTACK_DIR/openrc admin admin
tox -e run -- --os-cloud devstack-admin --purge-own-project --verbose # purges admin/admin

source $DEVSTACK_DIR/openrc demo demo
assert_compute && assert_network && assert_volume

tox -e run -- --os-cloud devstack --purge-own-project --verbose # purges demo/demo

source $DEVSTACK_DIR/openrc demo invisible_to_admin
assert_compute && assert_network && assert_volume

tox -e run -- \
    --os-auth-url http://localhost/identity \
    --os-cacert /opt/stack/data/ca-bundle.pem \
    --os-identity-api-version 3 \
    --os-region-name $OS_REGION_NAME \
    --os-username demo \
    --os-project-name invisible_to_admin \
    --os-password $invisible_to_admin_demo_pass \
    --os-domain-id $OS_PROJECT_DOMAIN_ID \
    --purge-own-project \
    --verbose

source $DEVSTACK_DIR/openrc alt_demo alt_demo
assert_compute && assert_network && assert_volume

source $DEVSTACK_DIR/openrc admin admin
openstack project set --disable alt_demo
tox -e run -- \
    --os-auth-url http://localhost/identity \
    --os-cacert /opt/stack/data/ca-bundle.pem \
    --os-identity-api-version 3 \
    --os-region-name $OS_REGION_NAME \
    --os-username admin \
    --os-project-name admin \
    --os-password $admin_admin_pass \
    --os-domain-id $OS_PROJECT_DOMAIN_ID \
    --purge-project alt_demo \
    --verbose
openstack project set --enable alt_demo



########################
### Final assertion
########################
if [[ $(nova list --all-tenants --minimal | wc -l) -ne 4 ]]; then
    echo "Not all VMs were cleaned up"
    exit 1
fi

if [[ $(neutron port-list | wc -l) -ne 1 ]]; then  # This also checks FIP
    echo "Not all ports were cleaned up"
    exit 1
fi

if [[ ${GATE_RUN} == 1 ]]; then
    # The Cinder backup service is enabled in the Gate.
    if [[ $(openstack volume backup list --all-projects | wc -l) -ne 1 ]]; then
        echo "Not all volume backups were cleaned up"
        exit 1
    fi
else
    if [[ $(openstack volume list --all-projects | wc -l) -ne 1 ]]; then
        echo "Not all volumes were cleaned up"
        exit 1
    fi
fi

if [[ $(openstack zone list --all-projects | wc -l) -ne 1 ]]; then  # This also checks FIP
    echo "Not all zones were cleaned up"
    exit 1
fi

if [[ $(openstack loadbalancer list | wc -l) -ne 1 ]]; then
    echo "Not all loadbalancers were cleaned up"
    exit 1
fi
