# Copyright 2014 OpenStack LLC.
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
import mock

from infoblox_client import objects
from infoblox_client.tests import base


class TestObjects(base.TestCase):

    def _mock_connector(self, get_object=None, create_object=None):
        connector = mock.Mock()
        connector.get_object.return_value = get_object
        connector.create_object.return_value = create_object
        return connector

    def test_search_network(self):
        connector = self._mock_connector()

        objects.Network.search(connector,
                               network_view='some-view',
                               cidr='192.68.1.0/20')
        connector.get_object.assert_called_once_with(
            'network',
            {'network_view': 'some-view', 'network': '192.68.1.0/20'},
            extattrs=None, force_proxy=False, return_fields=None)

    def test_search_network_v6(self):
        connector = self._mock_connector()

        objects.Network.search(connector,
                               network_view='some-view',
                               cidr='fffe:2312::/64')
        connector.get_object.assert_called_once_with(
            'ipv6network',
            {'network_view': 'some-view', 'network': 'fffe:2312::/64'},
            extattrs=None, force_proxy=False, return_fields=None)

    def test_search_network_with_results(self):
        found = {"_ref": "network/ZG5zLm5ldHdvcmskMTAuMzkuMTEuMC8yNC8w"
                         ":10.39.11.0/24/default",
                 "network_view": 'some-view',
                 "network": '192.68.1.0/20'}
        connector = self._mock_connector(get_object=found)

        network = objects.Network.search(connector,
                                         network_view='some-view',
                                         cidr='192.68.1.0/20')
        connector.get_object.assert_called_once_with(
            'network',
            {'network_view': 'some-view', 'network': '192.68.1.0/20'},
            extattrs=None, force_proxy=False, return_fields=None)
        self.assertEqual('192.68.1.0/20', network.network)
        self.assertEqual('some-view', network.network_view)
        # verify aliased fields works too
        self.assertEqual('192.68.1.0/20', network.cidr)

    def test_create_IP(self):
        ip = objects.IP.create(ip='192.168.1.12', mac='4a:ac:de:12:34:45')
        self.assertIsInstance(ip, objects.IPv4)
        self.assertEqual('192.168.1.12', ip.ip)
        self.assertEqual('192.168.1.12', ip.ipv4addr)
        self.assertEqual('4a:ac:de:12:34:45', ip.mac)
        self.assertEqual(None, ip.configure_for_dhcp)
        self.assertEqual(None, ip.host)

    def test_create_host_record_with_ip(self):
        mock_record = {
            '_ref': 'record:host/ZG5zLmhvc3QkLl9kZWZhdWx0LmNvbS5nbG9iYWwuY22NA'
                    ':test_host_name.testsubnet.cloud.global.com/default',
            'ipv4addrs': [{
                'configure_for_dhcp': False,
                '_ref': 'record:host_ipv4addr/lMmQ3ZjkuM4Zj5Mi00Y2:22.0.0.2/'
                        'test_host_name.testsubnet.cloud.global.com/default',
                'ipv4addr': '22.0.0.2',
                'mac': 'fa:16:3e:29:87:70',
                'host': '2c8f8e97-0d92-4cac-a350-096ff2b79.cloud.global.com'}],
            'extattrs': {
                'Account': {'value': '8a21c40495f04f30a1b2dc6fd1d9ed1a'},
                'Cloud API Owned': {'value': 'True'},
                'VM ID': {'value': 'None'},
                'IP Type': {'value': 'Fixed'},
                'CMP Type': {'value': 'OpenStack'},
                'Port ID': {'value': '136ef9ad-9c88-41ea-9fa6-bd48d8ec789a'},
                'Tenant ID': {'value': '00fd80791dee4112bb538c872b206d4c'}}
        }
        host_record_copy = copy.deepcopy(mock_record)
        connector = self._mock_connector(create_object=host_record_copy)

        ip = objects.IP.create(ip='22.0.0.2', mac='fa:16:3e:29:87:70')
        self.assertIsInstance(ip, objects.IPv4)

        host_record = objects.HostRecord.create(connector,
                                                view='some-dns-view',
                                                ip=[ip])
        ip_dict = {'ipv4addr': '22.0.0.2', 'mac': 'fa:16:3e:29:87:70'}
        connector.create_object.assert_called_once_with(
            'record:host',
            {'view': 'some-dns-view', 'ipv4addrs': [ip_dict]}, [])
        self.assertIsInstance(host_record, objects.HostRecordV4)
        # validate nios reply was parsed correctly
        self.assertEqual(mock_record['_ref'], host_record._ref)
        nios_ip = host_record.ipv4addrs[0]
        self.assertIsInstance(ip, objects.IPv4)
        self.assertEqual(mock_record['ipv4addrs'][0]['mac'], nios_ip.mac)
        self.assertEqual(mock_record['ipv4addrs'][0]['ipv4addr'],
                         nios_ip.ipv4addr)
        self.assertEqual(mock_record['ipv4addrs'][0]['host'],
                         nios_ip.host)
        self.assertEqual(mock_record['ipv4addrs'][0]['configure_for_dhcp'],
                         nios_ip.configure_for_dhcp)
