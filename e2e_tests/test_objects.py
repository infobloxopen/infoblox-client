import os
import unittest

from e2e_tests.connector_facade import E2EConnectorFacade
from infoblox_client.objects import ARecord, DNSZone, AAAARecord, Network, \
    EADefinition, EA, HostRecord, IP


class TestObjectsE2E(unittest.TestCase):
    def setUp(self):
        opts = {
            'host': os.environ['WAPI_HOST'],
            'username': os.environ['WAPI_USER'],
            'password': os.environ['WAPI_PASS'],
        }

        self.connector = E2EConnectorFacade(opts)

    def tearDown(self):
        self.connector.sweep_objects()

    def test_create_alias_a_record(self):
        """Create two A records with different names, but pointing to the same
        ipv4addr"""
        DNSZone.create(self.connector,
                       view='default',
                       fqdn="e2e-test.com")

        alias1, created = ARecord.create_check_exists(
            self.connector,
            view='default',
            ipv4addr="192.168.1.25",
            name='alias1.e2e-test.com',
        )
        self.assertTrue(created)

        alias2, created = ARecord.create_check_exists(
            self.connector,
            view='default',
            ipv4addr="192.168.1.25",
            name='alias2.e2e-test.com',
        )
        self.assertTrue(created)
        self.assertNotEqual(alias1._ref, alias2._ref)

    def test_create_alias_aaaa_record(self):
        """Create two AAAA records with different names, but pointing to the
        same ipv6addr"""
        DNSZone.create(self.connector,
                       view='default',
                       fqdn="e2e-test.com")

        alias1, created = AAAARecord.create_check_exists(
            self.connector,
            view='default',
            ipv6addr="aaaa:bbbb:cccc:dddd::",
            name='alias1.e2e-test.com',
        )
        self.assertTrue(created)

        alias2, created = AAAARecord.create_check_exists(
            self.connector,
            view='default',
            ipv6addr="aaaa:bbbb:cccc:dddd::",
            name='alias2.e2e-test.com',
        )
        self.assertTrue(created)
        self.assertNotEqual(alias1._ref, alias2._ref)

    def test_create_object_check_response(self):
        """Objects returned by create method should contain response field"""
        # When WAPI object is successfully created
        zone = DNSZone.create(self.connector, view='default', fqdn='check_response_zone.com')
        self.assertEqual("Infoblox Object was Created", zone.response)
        # When WAPI object already exists
        zone = DNSZone.create(self.connector, view='default', fqdn='check_response_zone.com')
        self.assertEqual("Infoblox Object already Exists", zone.response)
        # When WAPI object is updated
        zone = DNSZone.create(self.connector, view='default', fqdn='check_response_zone.com',
                              comment="Zone updated", update_if_exists=True, ref=zone.ref)
        self.assertEqual("Infoblox Object was Updated", zone.response)

    def test_fetch_by_ref_when_paging_enabled(self):
        """
        Fetch should explicitly disable paging, when reading object from
        the API by the ref
        """
        # Enable paging for the test connector
        self.connector.paging = True
        zone1 = DNSZone.create(self.connector,
                               view='default',
                               fqdn="e2e-test.com")
        # Fetch DNS zone by ref
        zone2 = DNSZone(self.connector)
        zone2._ref = zone1._ref
        zone2.fetch()
        self.assertEqual(zone1.fqdn, zone2.fqdn)

    def test_update_dns_zone(self):
        """
        Validates if DNS Zone object can be updated

        Related ticket: NIOS-84427
        """
        # Create DNS Zone
        zone = DNSZone.create(self.connector,
                              fqdn="e2e-test-zone.com",
                              view="default")
        # Update DNS zone
        zone.Comment = "Modified"
        zone.update()

    def test_host_record_ea_inheritance(self):
        """
        Checks if EA inheritance for record:host object
        works as expected
        """
        # Create inheritable extensible attribute
        EADefinition.create(
            self.connector,
            name="Test HostRecord EA Inheritance",
            type="STRING",
            flags="I",
        )
        # Create two networks with inheritable
        # extensible attributes
        Network.create(
            self.connector,
            network="192.170.1.0/24",
            network_view="default",
            extattrs=EA({
                "Test HostRecord EA Inheritance": "Expected Value"
            })
        )
        Network.create(
            self.connector,
            network="192.180.1.0/24",
            network_view="default",
            extattrs=EA({
                "Test HostRecord EA Inheritance": "Second Value"
            })
        )

        # Create DNS Zone for the host record
        DNSZone.create(
            self.connector,
            view='default',
            fqdn="e2e-test.com",
        )

        # Create two ips in both networks
        # One IP will be used for EA inheritance
        ip170net = IP.create(
            ip="192.170.1.25",
            mac="00:00:00:00:00:00",
            use_for_ea_inheritance=True,
        )
        ip180net = IP.create(
            ip="192.180.1.25",
            mac="00:00:00:00:00:00",
        )

        hr = HostRecord.create(
            self.connector,
            view="default",
            name="test_host_record_ea_inheritance.e2e-test.com",
            ips=[ip170net, ip180net]
        )

        # Expect host record to inherit EAs from 192.170.1.0/24 network
        self.assertEqual(
            "Expected Value",
            hr.extattrs.ea_dict["Test HostRecord EA Inheritance"]
        )
