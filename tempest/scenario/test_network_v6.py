# Copyright 2014 Cisco Systems, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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
import netaddr
from tempest import config
from tempest.openstack.common import log as logging
from tempest.scenario import manager
from tempest import test


CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestGettingAddress(manager.NetworkScenarioTest):
    """Create network with 2 subnets: IPv4 and IPv6 in a given address mode
    Boot 2 VMs on this network
    Allocate and assign 2 FIP4
    Check that vNIC of server matches port data from OpenStack DB
    Ping4 tenant IPv4 of one VM from another one
    Will do the same with ping6 when available in VM
    """

    @classmethod
    def resource_setup(cls):
        # Create no network resources for these tests.
        cls.set_network_resources()
        super(TestGettingAddress, cls).resource_setup()

    @classmethod
    def check_preconditions(cls):
        if not (CONF.network_feature_enabled.ipv6
                and CONF.network_feature_enabled.ipv6_subnet_attributes):
            raise cls.skipException('IPv6 or its attributes not supported')
        if not (CONF.network.tenant_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        if CONF.baremetal.driver_enabled:
            msg = ('Baremetal does not currently support network isolation')
            raise cls.skipException(msg)

        super(TestGettingAddress, cls).check_preconditions()

    def setUp(self):
        super(TestGettingAddress, self).setUp()
        self.keypair = self.create_keypair()
        self.sec_grp = self._create_security_group(tenant_id=self.tenant_id)
        self.srv_kwargs = {
            'key_name': self.keypair['name'],
            'security_groups': [{'name': self.sec_grp['name']}]}

    def prepare_network(self, address6_mode, n_subnets6=1):
        """Creates network with
         given number of IPv6 subnets in the given mode and
         one IPv4 subnet
         Creates router with ports on all subnets
        """
        self.network = self._create_network(tenant_id=self.tenant_id)
        sub4 = self._create_subnet(network=self.network,
                                   namestart='sub4',
                                   ip_version=4,)

        router = self._get_router(tenant_id=self.tenant_id)
        sub4.add_to_router(router_id=router['id'])
        self.addCleanup(sub4.delete)

        for _ in range(n_subnets6):
            sub6 = self._create_subnet(network=self.network,
                                       namestart='sub6',
                                       ip_version=6,
                                       ipv6_ra_mode=address6_mode,
                                       ipv6_address_mode=address6_mode)

            sub6.add_to_router(router_id=router['id'])
            self.addCleanup(sub6.delete)

    @staticmethod
    def define_server_ips(srv):
        ips = {'4': None, '6': []}
        for net_name, nics in srv['addresses'].iteritems():
            for nic in nics:
                if nic['version'] == 6:
                    ips['6'].append(nic['addr'])
                else:
                    ips['4'] = nic['addr']
        return ips

    def prepare_server(self):
        username = CONF.compute.image_ssh_user

        create_kwargs = self.srv_kwargs
        create_kwargs['networks'] = [{'uuid': self.network.id}]

        srv = self.create_server(create_kwargs=create_kwargs)
        fip = self.create_floating_ip(thing=srv)
        ips = self.define_server_ips(srv=srv)
        ssh = self.get_remote_client(
            server_or_ip=fip.floating_ip_address,
            username=username)
        return ssh, ips

    def _prepare_and_test(self, address6_mode, n_subnets6=1):
        self.prepare_network(address6_mode=address6_mode,
                             n_subnets6=n_subnets6)

        ssh1_4, ips_from_api_1 = self.prepare_server()
        ssh2_4, ips_from_api_2 = self.prepare_server()

        ips_from_ip_1 = ssh1_4.get_ip_list()
        ips_from_ip_2 = ssh2_4.get_ip_list()
        self.assertIn(ips_from_api_1['4'], ips_from_ip_1)
        self.assertIn(ips_from_api_2['4'], ips_from_ip_2)
        for i in range(n_subnets6):
            # v6 should be configured since the image supports it
            self.assertIn(ips_from_api_1['6'][i], ips_from_ip_1)
            self.assertIn(ips_from_api_2['6'][i], ips_from_ip_2)

        result = ssh1_4.ping_host(ips_from_api_2['4'])
        self.assertIn('0% packet loss', result)
        result = ssh2_4.ping_host(ips_from_api_1['4'])
        self.assertIn('0% packet loss', result)

        # Some VM (like cirros) may not have ping6 utility
        result = ssh1_4.exec_command('whereis ping6')
        is_ping6 = False if result == 'ping6:\n' else True
        if is_ping6:
            for i in range(n_subnets6):
                result = ssh1_4.ping_host(ips_from_api_2['6'][i])
                self.assertIn('0% packet loss', result)
                result = ssh2_4.ping_host(ips_from_api_1['6'][i])
                self.assertIn('0% packet loss', result)
        else:
            LOG.warning('Ping6 is not available, skipping')

    @test.services('compute', 'network')
    def test_slaac_from_os(self):
        self._prepare_and_test(address6_mode='slaac')

    @test.services('compute', 'network')
    def test_dhcp6_stateless_from_os(self):
        self._prepare_and_test(address6_mode='dhcpv6-stateless')


class TestGettingMultipleAddresses(TestGettingAddress):
    """Create network with 3 subnets: IPv4 and 2 IPv6 in a given address mode
    Boot 2 VMs on this network
    Allocate and assign 2 FIP4
    Check that vNIC of server matches port data from OpenStack DB
    Ping4 tenant IPv4 of one VM from another one
    Will do the same with ping6 when available in VM
    """

    @test.services('compute', 'network')
    def test_multi_prefix_dhcpv6_stateless(self):
        self._prepare_and_test(address6_mode='dhcpv6-stateless', n_subnets6=2)

    @test.services('compute', 'network')
    def test_multi_prefix_slaac(self):
        self._prepare_and_test(address6_mode='slaac', n_subnets6=2)
