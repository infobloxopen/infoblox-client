===============================
Infoblox Client
===============================

.. image:: https://travis-ci.org/infobloxopen/infoblox-client.svg?branch=master
        :target: https://travis-ci.org/infobloxopen/infoblox-client

.. image:: https://img.shields.io/pypi/v/infoblox-client.svg
        :target: https://pypi.python.org/pypi/infoblox-client

.. image:: https://codecov.io/github/infobloxopen/infoblox-client/coverage.svg?branch=master
        :target: https://codecov.io/github/infobloxopen/infoblox-client?branch=master

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

1. Low level API, using connector module.

Retrieve list of network views from NIOS:

::

  from infoblox_client import connector

  opts = {'host': '192.168.1.10', 'username': 'admin', 'password': 'admin'}
  conn = connector.Connector(opts)
  # get all network_views
  network_views = conn.get_object('networkview')


For this request data is returned as list of dicts:

::

  [{u'_ref': u'networkview/ZG5zLm5ldHdvcmtfdmlldyQw:default/true',
    u'is_default': True,
    u'name': u'default'}]

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

Reply from NIOS is parsed back into objects and contains next data:

::

  In [22]: hr
  Out[22]: HostRecordV4: _ref=record:host/ZG5zLmhvc3QkLjQuY29tLm15X3pvbmUubXlfaG9zdF9yZWNvcmQ:my_host_record.my_zone.com/my_dns_view, name=my_host_record.my_zone.com, ipv4addrs=[<infoblox_client.objects.IPv4 object at 0x7f7d6b0fe9d0>], view=my_dns_view

Features
--------

* TODO
