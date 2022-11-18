===============================
Infoblox Client
===============================

.. image:: https://travis-ci.org/infobloxopen/infoblox-client.svg?branch=master
        :target: https://travis-ci.org/infobloxopen/infoblox-client

.. image:: https://img.shields.io/pypi/v/infoblox-client.svg
        :target: https://pypi.python.org/pypi/infoblox-client

.. image:: https://codecov.io/github/infobloxopen/infoblox-client/coverage.svg?branch=master
        :target: https://codecov.io/github/infobloxopen/infoblox-client?branch=master

.. image:: https://readthedocs.org/projects/infoblox-client/badge/?version=latest
        :target: http://infoblox-client.readthedocs.org/en/latest/?badge=latest

Client for interacting with Infoblox NIOS over WAPI.

* Free software: Apache license
* Documentation: https://infoblox-client.readthedocs.org.

Installation
------------

Install infoblox-client using pip:

::

  pip install infoblox-client

Usage
-----

Configure logger prior to loading infoblox_client to get all debug messages in console:

.. code:: python

  import logging
  logging.basicConfig(level=logging.DEBUG)

Low level API, using connector module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Retrieve list of network views from NIOS:

.. code:: python

  from infoblox_client import connector

  opts = {'host': '192.168.1.10', 'username': 'admin', 'password': 'admin'}
  conn = connector.Connector(opts)
  # get all network_views
  network_views = conn.get_object('networkview')
  # search network by cidr in specific network view
  network = conn.get_object('network', {'network': '100.0.0.0/8', 'network_view': 'default'})


For these request data is returned as list of dicts:

.. code:: python

  network_views:
  [{u'_ref': u'networkview/ZG5zLm5ldHdvcmtfdmlldyQw:default/true',
    u'is_default': True,
    u'name': u'default'}]

  network:
  [{u'_ref': u'network/ZG5zLm5ldHdvcmskMTAwLjAuMC4wLzgvMA:100.0.0.0/8/default',
    u'network': u'100.0.0.0/8',
    u'network_view': u'default'}]

High level API, using objects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Example of creating Network View, Network, DNS View, DNSZone and HostRecord using NIOS objects:

.. code:: python

  from infoblox_client import connector
  from infoblox_client import objects

  opts = {'host': '192.168.1.10', 'username': 'admin', 'password': 'admin'}
  conn = connector.Connector(opts)

Create a network view, and network:

.. code:: python

  nview = objects.NetworkView.create(conn, name='my_view')
  network = objects.Network.create(conn, network_view='my_view', cidr='192.168.1.0/24')

Create a DNS view and zone:

.. code:: python

  view = objects.DNSView.create(conn, network_view='my_view', name='my_dns_view')
  zone = objects.DNSZone.create(conn, view='my_dns_view', fqdn='my_zone.com')

Create a host record:

.. code:: python

  my_ip = objects.IP.create(ip='192.168.1.25', mac='aa:bb:cc:11:22:33')
  hr = objects.HostRecord.create(conn, view='my_dns_view',
                                 name='my_host_record.my_zone.com', ip=my_ip)

Create host record with Extensible Attributes (EA):

.. code:: python

  ea = objects.EA({'Tenant ID': tenantid, 'CMP Type': cmptype,
                   'Cloud API Owned': True})
  host = objects.HostRecord.create(conn, name='new_host', ip=my_ip, extattrs=ea)

Create a host record with inherited Extensible Attributes (EA):

.. code:: python

  my_ip = objects.IP.create(ip='192.168.1.25', mac='aa:bb:cc:11:22:33', use_for_ea_inheritance=True)
  hr = objects.HostRecord.create(conn, view='my_dns_view',
                                 name='my_host_record.my_zone.com', ip=my_ip)

Set the TTL to 30 minutes:

.. code:: python

  hr = objects.HostRecord.create(conn, view='my_dns_view',
                                 name='my_host_record.my_zone.com', ip=my_ip,
                                 ttl = 1800)

Create a new host record, from the next available IP in a CIDR, with a MAC address, and DHCP enabled:

.. code:: python

    next = objects.IPAllocation.next_available_ip_from_cidr('default', '10.0.0.0/24')
    my_ip = objects.IP.create(ip=next, mac='aa:bb:cc:11:22:33', configure_for_dhcp=True)
    host = objects.HostRecord.create(conn, name='some.valid.fqdn', view='Internal', ip=my_ip)

Reply from NIOS is parsed back into objects and contains next data:

.. code:: python

  In [22]: hr
  Out[22]: HostRecordV4: _ref=record:host/ZG5zLmhvc3QkLjQuY29tLm15X3pvbmUubXlfaG9zdF9yZWNvcmQ:my_host_record.my_zone.com/my_dns_view, name=my_host_record.my_zone.com, ipv4addrs=[<infoblox_client.objects.IPv4 object at 0x7f7d6b0fe9d0>], view=my_dns_view


Create a new fixed address, with a MS server DHCP reservation:

.. code:: python

  obj, created = objects.FixedAddress.create_check_exists(connector=conn,
                                                          ip='192.168.100.100',
                                                          mac='aa:bb:cc:11:22:33',
                                                          comment='My DHCP reservation',
                                                          name='My hostname',
                                                          network_view='default',
                                                          ms_server={'_struct': 'msdhcpserver',
                                                                     'ipv4addr': '192.168.0.0'})



High level API, using InfobloxObjectManager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a new fixed address, selecting it from the next available IP in a CIDR:

.. code:: python

  from infoblox_client.object_manager import InfobloxObjectManager

  new_address = InfobloxObjectManager(conn).create_fixed_address_from_cidr(netview='default', mac='aa:bb:cc:11:22:33', cidr='10.0.0.0/24', extattrs=[])

What you get back is a ``FixedAddressV4`` object.

Objects Interface
-----------------

All top level objects support interface for CRUD operations. List of supported objects is defined in next section.

- ``create(cls, connector, check_if_exists=True, update_if_exists=False, **kwargs)``
    Creates object on NIOS side.
    Requires connector passed as the first argument, ``check_if_exists`` and ``update_if_exists`` are optional.
    Object related fields are passed in as kwargs: ``field=value``, ``field2=value2``.

- ``search(cls, connector, return_fields=None, search_extattrs=None, force_proxy=False, **kwargs)``
    Search single object on NIOS side, returns first object that match search criteria.
    Requires connector passed as the first argument.
    ``return_fields`` can be set to retrieve particular fields from NIOS,
    for example ``return_fields=['view', 'name']``.
    If ``return_fields`` is ``[]`` default ``return_fields`` are returned by NIOS side for current ``wapi_version``.
    ``search_extattrs`` is used to filter out results by extensible attributes.
    ``force_proxy`` forces search request to be processed on Grid Master (applies only in cloud environment)

- ``search_all(cls, connector, return_fields=None, search_extattrs=None, force_proxy=False, **kwargs)``
    Search all objects on NIOS side that match search criteria. Returns a list of objects.
    All other options are equal to ``search()``.

- ``update(self)``
    Update the object on NIOS side by pushing changes done in the local object.

- ``delete(self)``
    Deletes the object from NIOS side.

Supported NIOS objects
----------------------
All NIOS Objects are supported in the 0.6.0 verison release. check infoblox_client/objects.py for description of the objects.
Newly supported objects

* ``AAAADtcRecord``
* ``AAAARecord``
* ``AAAASharedRecord``
* ``ADtcRecord``
* ``ADtcRecordBase``
* ``ARecord``
* ``ARecordBase``
* ``ASharedRecord``
* ``ASharedRecordBase``
* ``AdAuthServer``
* ``AdAuthService``
* ``Addressac``
* ``Admingroup``
* ``Adminrole``
* ``Adminuser``
* ``AliasRecord``
* ``Allendpoints``
* ``Allnsgroup``
* ``Allrecords``
* ``Allrpzrecords``
* ``AnyMember``
* ``Approvalworkflow``
* ``Authpolicy``
* ``Awsrte53Task``
* ``Awsrte53Taskgroup``
* ``Awsuser``
* ``BaseObject``
* ``Bfdtemplate``
* ``Bgpas``
* ``Bulkhost``
* ``Bulkhostnametemplate``
* ``CNAMEDtcRecord``
* ``CNAMERecord``
* ``CNAMESharedRecord``
* ``CaaRecord``
* ``Cacertificate``
* ``Capacityreport``
* ``CapacityreportObjectcount``
* ``Captiveportal``
* ``CaptiveportalFile``
* ``CertificateAuthservice``
* ``Changedobject``
* ``CiscoiseEndpoint``
* ``Clientsubnetdomain``
* ``Csvimporttask``
* ``DHCPLease``
* ``DHCPRoamingHost``
* ``DNSView``
* ``DNSZone``
* ``DNSZoneDelegated``
* ``DNSZoneForward``
* ``DbObjects``
* ``Dbsnapshot``
* ``DdnsPrincipalcluster``
* ``DdnsPrincipalclusterGroup``
* ``DeletedObjects``
* ``DhcidRecord``
* ``DhcpOptionDefinition``
* ``DhcpOptionDefinitionV4``
* ``DhcpOptionDefinitionV6``
* ``DhcpOptionSpace``
* ``DhcpOptionSpaceV4``
* ``DhcpOptionSpaceV6``
* ``DhcpStatistics``
* ``Dhcpddns``
* ``Dhcpfailover``
* ``Dhcpmember``
* ``Dhcpoption``
* ``Discovery``
* ``DiscoveryAutoconversionsetting``
* ``DiscoveryCiscoapicconfiguration``
* ``DiscoveryClicredential``
* ``DiscoveryDevice``
* ``DiscoveryDevicecomponent``
* ``DiscoveryDeviceinterface``
* ``DiscoveryDeviceneighbor``
* ``DiscoveryDevicesupportbundle``
* ``DiscoveryDiagnostictask``
* ``DiscoveryGridproperties``
* ``DiscoveryIfaddrinfo``
* ``DiscoveryMemberproperties``
* ``DiscoveryNetworkinfo``
* ``DiscoveryPort``
* ``DiscoveryScaninterface``
* ``DiscoverySeedrouter``
* ``DiscoverySnmp3Credential``
* ``DiscoverySnmpcredential``
* ``DiscoveryStatus``
* ``DiscoveryVlaninfo``
* ``DiscoveryVrf``
* ``DiscoveryVrfmappingrule``
* ``Discoverytask``
* ``Discoverytaskport``
* ``Discoverytaskvserver``
* ``Distributionschedule``
* ``DnameRecord``
* ``Dns64Group``
* ``DnskeyRecord``
* ``Dnsseckey``
* ``Dnssectrustedkey``
* ``DsRecord``
* ``Dtc``
* ``DtcAllrecords``
* ``DtcCertificate``
* ``DtcLbdn``
* ``DtcMonitor``
* ``DtcMonitorHttp``
* ``DtcMonitorIcmp``
* ``DtcMonitorPdp``
* ``DtcMonitorSip``
* ``DtcMonitorSnmp``
* ``DtcMonitorSnmpOid``
* ``DtcMonitorTcp``
* ``DtcObject``
* ``DtcPool``
* ``DtcPoolConsolidatedMonitorHealth``
* ``DtcPoolLink``
* ``DtcServer``
* ``DtcServerLink``
* ``DtcServerMonitor``
* ``DtcTopology``
* ``DtcTopologyLabel``
* ``DtcTopologyRule``
* ``DtcTopologyRuleSource``
* ``DtclbdnRecord``
* ``DxlEndpoint``
* ``DxlEndpointBroker``
* ``EA``
* ``EADefinition``
* ``Exclusionrange``
* ``Exclusionrangetemplate``
* ``ExtensibleattributedefListvalues``
* ``Extserver``
* ``Extsyslogbackupserver``
* ``Fileop``
* ``Filterfingerprint``
* ``Filtermac``
* ``Filternac``
* ``Filteroption``
* ``Filterrelayagent``
* ``Filterrule``
* ``Fingerprint``
* ``FixedAddress``
* ``FixedAddressTemplate``
* ``FixedAddressTemplateV4``
* ``FixedAddressTemplateV6``
* ``FixedAddressV4``
* ``FixedAddressV6``
* ``Forwardingmemberserver``
* ``Ftpuser``
* ``Grid``
* ``GridCloudapi``
* ``GridCloudapiCloudstatistics``
* ``GridCloudapiUser``
* ``GridCloudapiVm``
* ``GridCloudapiVmaddress``
* ``GridDashboard``
* ``GridDhcpproperties``
* ``GridDns``
* ``GridDnsFixedrrsetorderfqdn``
* ``GridFiledistribution``
* ``GridLicensePool``
* ``GridLicensePoolContainer``
* ``GridLicensesubpool``
* ``GridMaxminddbinfo``
* ``GridMemberCloudapi``
* ``GridServicerestartGroup``
* ``GridServicerestartGroupOrder``
* ``GridServicerestartRequest``
* ``GridServicerestartRequestChangedobject``
* ``GridServicerestartStatus``
* ``GridThreatanalytics``
* ``GridThreatprotection``
* ``GridX509Certificate``
* ``GridmemberSoamname``
* ``GridmemberSoaserial``
* ``HostRecord``
* ``HostRecordV4``
* ``HostRecordV6``
* ``Hostnamerewritepolicy``
* ``Hotfix``
* ``HsmAllgroups``
* ``HsmSafenet``
* ``HsmSafenetgroup``
* ``HsmThales``
* ``HsmThalesgroup``
* ``IP``
* ``IPAddress``
* ``IPAllocation``
* ``IPRange``
* ``IPRangeV4``
* ``IPRangeV6``
* ``IPv4``
* ``IPv4Address``
* ``IPv4HostAddress``
* ``IPv6``
* ``IPv6Address``
* ``IPv6HostAddress``
* ``InfobloxObject``
* ``Interface``
* ``IpamStatistics``
* ``Ipv6Networksetting``
* ``Kerberoskey``
* ``LdapAuthService``
* ``LdapEamapping``
* ``LdapServer``
* ``LicenseGridwide``
* ``LocaluserAuthservice``
* ``Logicfilterrule``
* ``Lomnetworkconfig``
* ``Lomuser``
* ``MXRecord``
* ``MXSharedRecord``
* ``Macfilteraddress``
* ``Mastergrid``
* ``Member``
* ``MemberDhcpproperties``
* ``MemberDns``
* ``MemberDnsgluerecordaddr``
* ``MemberDnsip``
* ``MemberFiledistribution``
* ``MemberLicense``
* ``MemberParentalcontrol``
* ``MemberThreatanalytics``
* ``MemberThreatprotection``
* ``Memberserver``
* ``Memberservicecommunication``
* ``Memberservicestatus``
* ``Msdhcpoption``
* ``Msdhcpserver``
* ``Msdnsserver``
* ``Msserver``
* ``MsserverAdsitesDomain``
* ``MsserverAdsitesSite``
* ``MsserverDcnsrecordcreation``
* ``MsserverDhcp``
* ``MsserverDns``
* ``Mssuperscope``
* ``Namedacl``
* ``NaptrDtcRecord``
* ``NaptrRecord``
* ``Natgroup``
* ``Network``
* ``NetworkContainer``
* ``NetworkContainerV4``
* ``NetworkContainerV6``
* ``NetworkDiscovery``
* ``NetworkTemplate``
* ``NetworkTemplateV4``
* ``NetworkTemplateV6``
* ``NetworkV4``
* ``NetworkV6``
* ``NetworkView``
* ``Networkuser``
* ``NetworkviewAssocmember``
* ``Nodeinfo``
* ``NotificationRestEndpoint``
* ``NotificationRestTemplate``
* ``NotificationRestTemplateparameter``
* ``NotificationRule``
* ``NotificationRuleexpressionop``
* ``NsRecord``
* ``Nsec3ParamRecord``
* ``Nsec3Record``
* ``NsecRecord``
* ``Nsgroup``
* ``NsgroupDelegation``
* ``NsgroupForwardingmember``
* ``NsgroupForwardstubserver``
* ``NsgroupStubmember``
* ``Nxdomainrule``
* ``OcspResponder``
* ``Option60Matchrule``
* ``Orderedranges``
* ``Orderedresponsepolicyzones``
* ``Ospf``
* ``OutboundCloudclient``
* ``OutboundCloudclientEvent``
* ``ParentalcontrolAbs``
* ``ParentalcontrolAvp``
* ``ParentalcontrolBlockingpolicy``
* ``ParentalcontrolIpspacediscriminator``
* ``ParentalcontrolMsp``
* ``ParentalcontrolNasgateway``
* ``ParentalcontrolSitemember``
* ``ParentalcontrolSpm``
* ``ParentalcontrolSubscriber``
* ``ParentalcontrolSubscribersite``
* ``Permission``
* ``PtrRecord``
* ``PtrRecordV4``
* ``PtrRecordV6``
* ``RadiusAuthservice``
* ``RadiusServer``
* ``RangeTemplate``
* ``RangeTemplateV4``
* ``RangeTemplateV6``
* ``Rdatasubfield``
* ``Recordnamepolicy``
* ``Remoteddnszone``
* ``Restartservicestatus``
* ``Rir``
* ``RirOrganization``
* ``RpzAIpaddressRecord``
* ``RpzARecord``
* ``RpzAaaaIpaddressRecord``
* ``RpzAaaaRecord``
* ``RpzCnameClientipaddressRecord``
* ``RpzCnameClientipaddressdnRecord``
* ``RpzCnameIpaddressRecord``
* ``RpzCnameIpaddressdnRecord``
* ``RpzCnameRecord``
* ``RpzMxRecord``
* ``RpzNaptrRecord``
* ``RpzPtrRecord``
* ``RpzPtrRecordV4``
* ``RpzPtrRecordV6``
* ``RpzSrvRecord``
* ``RpzTxtRecord``
* ``RrsigRecord``
* ``Ruleset``
* ``SRVDtcRecord``
* ``SRVRecord``
* ``SRVSharedRecord``
* ``SamlAuthservice``
* ``Scavengingtask``
* ``Scheduledtask``
* ``Search``
* ``SettingNetwork``
* ``SettingViewaddress``
* ``SharedNetwork``
* ``SharedNetworkV4``
* ``SharedNetworkV6``
* ``Sharedrecordgroup``
* ``SmartfolderChildren``
* ``SmartfolderGlobal``
* ``SmartfolderGroupby``
* ``SmartfolderPersonal``
* ``SmartfolderQueryitem``
* ``Snmpuser``
* ``Sortlist``
* ``SubObjects``
* ``Superhost``
* ``Superhostchild``
* ``SyslogEndpoint``
* ``SyslogEndpointServers``
* ``Syslogserver``
* ``TXTRecord``
* ``TXTSharedRecord``
* ``TacacsplusAuthservice``
* ``TacacsplusServer``
* ``Taxii``
* ``TaxiiRpzconfig``
* ``Tenant``
* ``Tftpfiledir``
* ``ThreatanalyticsModuleset``
* ``ThreatanalyticsWhitelist``
* ``ThreatinsightCloudclient``
* ``ThreatprotectionGridRule``
* ``ThreatprotectionNatrule``
* ``ThreatprotectionProfile``
* ``ThreatprotectionProfileRule``
* ``ThreatprotectionRule``
* ``ThreatprotectionRulecategory``
* ``ThreatprotectionRuleset``
* ``ThreatprotectionRuletemplate``
* ``ThreatprotectionStatinfo``
* ``ThreatprotectionStatistics``
* ``Thresholdtrap``
* ``TlsaRecord``
* ``Trapnotification``
* ``UnknownRecord``
* ``Updatesdownloadmemberconfig``
* ``Upgradegroup``
* ``UpgradegroupMember``
* ``UpgradegroupSchedule``
* ``Upgradeschedule``
* ``Upgradestatus``
* ``Upgradestep``
* ``Userprofile``
* ``Vdiscoverytask``
* ``Vlan``
* ``Vlanlink``
* ``Vlanrange``
* ``Vlanview``
* ``Vtftpdirmember``
* ``ZoneAuthDiscrepancy``
* ``ZoneRp``
* ``ZoneStub``
* ``Zoneassociation``
* ``Zonenameserver``

Until 0.4.25 this project supported

* ``NetworkView`` for 'networkview'
* ``DNSView`` for 'view'
* ``DNSZone`` for 'zone_auth'
* ``Member`` for 'member'
* ``Network`` (V4 and V6)

  * ``NetworkV4`` for 'network'
  * ``NetworkV6`` for 'ipv6network'

* ``IPRange`` (V4 and V6)

  * ``IPRangeV4`` for 'range'
  * ``IPRangeV6`` for 'ipv6range'

* ``HostRecord`` (V4 and V6)

  * ``HostRecordV4`` for 'record:host'
  * ``HostRecordV6`` for 'record:host'

* ``FixedAddress`` (V4 and V6)

  * ``FixedAddressV4`` for 'fixedaddress'
  * ``FixedAddressV6`` for 'ipv6fixedaddress'

* ``IPAddress`` (V4 and V6)

  * ``IPv4Address`` for 'ipv4address'
  * ``IPv6Address`` for 'ipv6address'

* ``ARecordBase``

  * ``ARecord`` for 'record:a'
  * ``AAAARecord`` for 'record:aaaa'

* ``PtrRecord`` (V4 and V6)

  * ``PtrRecordV4`` for 'record:ptr'
  * ``PtrRecordV6`` for 'record:ptr'

* ``EADefinition`` for 'extensibleattributedef'
* ``CNAMERecord`` for 'record:cname'
* ``MXRecord`` for 'record:mx'


Search by regular expression
----------------------------

Search for partial match is supported only by low-level API for now.
Use '~' with field name to search by regular expressions. Not all
fields support search by regular expression. Refer to wapidoc to find
out complete list of fields that can be searched this way. Examples:

Find all networks that starts with '10.10.':

.. code:: python

  conn = connector.Connector(opts)
  nw = conn.get_object('network', {'network~': '10.10.'})


Find all host records that starts with '10.10.':

.. code:: python

  conn = connector.Connector(opts)
  hr = conn.get_object('record:host', {'ipv4addr~': '10.10.'})


More examples
-------------

Utilizing extensible attributes and searching on them can easily be done with the ``get_object`` function.
The ``default`` field in ``return_fields`` acts like the ``+`` does in WAPI.

 > ``_return_fields+`` Specified list of fields (comma separated) will be returned in addition
 to the basic fields of the object (documented for each object).

This enables you to always get the default values in return, in addition to what you specify whether
you search for a ``network`` or a ``networkcontainer``,
defined as ``place_to_check`` in the code below.


.. code:: python

    from infoblox_client.connector import Connector


    def default_infoblox_connection():
        opts = {'host': '192.168.1.10', 'username': 'admin', 'password': 'admin'}
        conn = Connector(opts)
        return conn

    def search_extensible_attribute(connection, place_to_check: str, extensible_attribute: str, value: str):
        """
        Find extensible attributes.
        :param connection: Infoblox connection
        :param place_to_check: Can be `network`, `networkcontainer` or `record:host` and so on.
        :param extensible_attribute: Which extensible attribute to search for. Can be `CustomerCode`, `Location`
        and so on.
        :param value: The value you want to search for.
        :return: result
        """
        extensible_args = [
            place_to_check,
            {
                f"*{extensible_attribute}:~": value,
            }
        ]
        kwargs = {
            'return_fields': [
                'default',
                'extattrs',
            ]
        }
        result = {"type": f"{place_to_check}", "objects": connection.get_object(*extensible_args, **kwargs)}
        return result

    connection = default_infoblox_connection()

    search_network = search_extensible_attribute(connection, "network", "CustomerCode", "Infoblox")
    # Print the output:
    print(search_network)
    {
      "type": "network",
      "objects": [
        {
          "_ref": "network/ZG5zLmhvc3QkLjQuY29tLm15X3pvbmUubXlfaG9zdF9yZWNvcmQ:192.168.1.1/28/default",
          "comment": "Infoblox Network",
          "extattrs": {
            "CustomerCode": {
              "value": "Infoblox"
            }
          },
          "network": "192.168.1.0/28",
          "network_view": "default"
        }
      ]
    }

    search_host = search_extensible_attribute(connection, "record:host", "CustomerCode", "Infoblox")
    # Print the output:
    print(search_host)
    {
      "type": "record:host",
      "objects": [
        {
          "_ref": "record:host/ZG5zLm5ldHdvcmtfdmlldyQw:InfobloxHost",
          "extattrs": {
            "CustomerCode": {
              "value": "Infoblox"
            }
          },
          "ipv4addrs": [
            {
              "_ref": "record:host_ipv4addr/ZG5zLm5ldHdvcmtfdmlldyQwdvcmtfdmlldyQw:192.168.1.1/InfobloxHost",
              "configure_for_dhcp": false,
              "host": "InfobloxHost",
              "ipv4addr": "192.168.1.1"
            }
          ],
          "name": "InfobloxHost",
          "view": " "
        }
      ]
    }

Features
--------

* TODO
