import os
import unittest

from e2e_tests.connector_facade import E2EConnectorFacade
from infoblox_client.objects import ARecord, DNSZone, AAAARecord, Csvimporttask


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

    def test_search_csvimporttask(self):
        """
        Test validates if client is able to read Csvimporttask
        """
        Csvimporttask.search(self.connector)
