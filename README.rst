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

::

  import logging
  logging.basicConfig(level=logging.DEBUG)


1. Low level API, using connector module.

Retrieve list of network views from NIOS:

::

  from infoblox_client import connector

  opts = {'host': '192.168.1.10', 'username': 'admin', 'password': 'admin'}
  conn = connector.Connector(opts)
  # get all network_views
  network_views = conn.get_object('networkview')
  # search network by cidr in specific network view
  network = conn.get_object('network', {'network': '100.0.0.0/8', 'network_view': 'default'})


For these request data is returned as list of dicts:

::

  network_views:
  [{u'_ref': u'networkview/ZG5zLm5ldHdvcmtfdmlldyQw:default/true',
    u'is_default': True,
    u'name': u'default'}]

  network:
  [{u'_ref': u'network/ZG5zLm5ldHdvcmskMTAwLjAuMC4wLzgvMA:100.0.0.0/8/default',
    u'network': u'100.0.0.0/8',
    u'network_view': u'default'}]


2. High level API, using objects.

Example of creating Network View, Network, DNS View, DNSZone and HostRecord using NIOS objects:

::

  from infoblox_client import connector
  from infoblox_client import objects

  opts = {'host': '192.168.1.10', 'username': 'admin', 'password': 'admin'}
  conn = connector.Connector(opts)

  nview = objects.NetworkView.create(conn, name='my_view')
  network = objects.Network.create(conn, network_view='my_view', cidr='192.168.1.0/24')

  view = objects.DNSView.create(conn, network_view='my_view', name='my_dns_view')
  zone = objects.DNSZone.create(conn, view='my_dns_view', fqdn='my_zone.com')

  my_ip = objects.IP.create(ip='192.168.1.25', mac='aa:bb:cc:11:22:33')
  hr = objects.HostRecord.create(conn, view='my_dns_view', 
                                 name='my_host_record.my_zone.com', ip=my_ip)
  # Create host record with Extensible Attributes (EA)
  ea = objects.EA({'Tenant ID': tenantid, 'CMP Type': cmptype,
                   'Cloud API Owned': True})
  host = objects.HostRecord.create(conn, name='new_host', ip=my_ip, extattrs=ea)

Reply from NIOS is parsed back into objects and contains next data:

::

  In [22]: hr
  Out[22]: HostRecordV4: _ref=record:host/ZG5zLmhvc3QkLjQuY29tLm15X3pvbmUubXlfaG9zdF9yZWNvcmQ:my_host_record.my_zone.com/my_dns_view, name=my_host_record.my_zone.com, ipv4addrs=[<infoblox_client.objects.IPv4 object at 0x7f7d6b0fe9d0>], view=my_dns_view

Objects Interface
-----------------

All top level objects support interface for CRUD operations. List of supported objects is defined in next section.

- create(cls, connector, check_if_exists=True, update_if_exists=False, \**kwargs)
    Creates object on NIOS side.
    Requires connector passed as the first argument, check_if_exists and update_if_exists are optional.
    Object related fields are passed in as kwargs: field=value, field2=value2.
    
- search(cls, connector, return_fields=None, search_extattrs=None, force_proxy=False, \**kwargs)
    Search single object on NIOS side, returns first object that match search criteria.
    Requires connector passed as the first argument.
    'return_fields' can be set to retrieve particular fields from NIOS,
    for example return_fields=['view', 'name'].
    If 'return_fields' is '[]' default return_fields are returned by NIOS side for current wapi_version.
    'search_extattrs' used to filter out results by extensible attributes.
    'force_proxy' forces search request to be processed on Grid Master (applies only in cloud environment)
    
- search_all(cls, connector, return_fields=None, search_extattrs=None, force_proxy=False, \**kwargs)
    Search all objects on NIOS side that match search cryteria. Returns list of objects.
    All other options are equal to search().

- update(self)
    Update object on NIOS side by pushing changes done in local object.
    
- delete(self)
    Deletes object from NIOS side.

Supported NIOS objects
----------------------

* NetworkView for 'networkview'
* DNSView for 'view'
* DNSZone for 'zone_auth'
* Member for 'member'
* Network (V4 and V6)

  * NetworkV4 for 'network'
  * NetworkV6 for 'ipv6network'
  
* IPRange (V4 and V6)
  
  * IPRangeV4 for 'range'
  * IPRangeV6 for 'ipv6range'
  
* HostRecord (V4 and V6)

  * HostRecordV4 for 'record:host'
  * HostRecordV6 for 'record:host'
  
* FixedAddress (V4 and V6)

  * FixedAddressV4 for 'fixedaddress'
  * FixedAddressV6 for 'ipv6fixedaddress'
  
* IPAddress (V4 and V6)
  
  * IPv4Address for 'ipv4address'
  * IPv6Address for 'ipv6address'
  
* ARecordBase

  * ARecord for 'record:a'
  * AAAARecord for 'record:aaaa'
   
* PtrRecord (V4 and V6)

  * PtrRecordV4 for 'record:ptr'
  * PtrRecordV6 for 'record:ptr'
   
* EADefinition for 'extensibleattributedef'


Search by regular expression
----------------------------

Search for partial match is supported only by low-level API for now.
Use '~' with field name to search by regular expressions. Not all
fields support search by regular expression. Refer to wapidoc to find
out complete list of fields that can be searched this way. Examples:

Find all networks that starts with '10.10.':

::

  conn = connector.Connector(opts)
  nw = conn.get_object('network', {'network~': '10.10.'})


Find all host records that starts with '10.10.':

::

  conn = connector.Connector(opts)
  hr = conn.get_object('record:host', {'ipv4addr~': '10.10.'})

Features
--------

* TODO
