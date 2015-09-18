# Copyright 2015 Infoblox Inc.
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

import six

from oslo_log import log as logging

from infoblox_client import exceptions as ib_ex
from infoblox_client import utils as ib_utils

LOG = logging.getLogger(__name__)


class InfobloxObject(object):
    """Base class for all Infoblox related objects

    _fields - fields that represents NIOS object (WAPI fields)
    _search_fields - fields that can be used to find object on NIOS side
    _return_fields - fields requested to be returned from NIOS side
         if object is found/created
    _infoblox_type - string representing wapi type of described object
    _remap - dict that maps user faced names into internal
         representation (_fields)
    _custom_field_processing - dict that define rules (lambda) for building
         objects from data returned by NIOS side
    _ip_version - ip version of the object, used to mark version
        specific classes. Value other than None indicates that
        no versioned class lookup needed.
    """
    _fields = []
    _search_fields = []
    _shadow_fields = []
    _return_fields = []
    _infoblox_type = None
    _remap = {}
    _custom_field_processing = {}
    _ip_version = None

    def __new__(cls, connector, **kwargs):
        return super(InfobloxObject,
                     cls).__new__(cls.get_class_from_args(kwargs))

    def __init__(self, connector, **kwargs):
        self.connector = connector
        mapped_args = self._remap_fields(kwargs)
        for field in self._fields + self._shadow_fields:
            if field in mapped_args:
                setattr(self, field, mapped_args[field])
            else:
                # Init all not initialized fields with None
                if not hasattr(self, field):
                    setattr(self, field, None)

    def __getattr__(self, name):
        # Map aliases into real fields
        if name in self._remap:
            return getattr(self, self._remap[name])
        else:
            # Default behaviour
            raise AttributeError

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            for field in self._fields:
                if getattr(self, field) != getattr(other, field):
                    return False
            return True
        return False

    @classmethod
    def from_dict(cls, connector, ip_dict):
        mapping = cls._custom_field_processing
        # Process fields that require building themselves as objects
        for field in mapping:
            if field in ip_dict:
                ip_dict[field] = mapping[field](ip_dict[field])
        return cls(connector, **ip_dict)

    @staticmethod
    def value_to_dict(value):
        return value.to_dict() if hasattr(value, 'to_dict') else value

    def field_to_dict(self, field):
        """Read field value and converts to dict if possible"""
        value = getattr(self, field)
        if isinstance(value, (list, tuple)):
            return [self.value_to_dict(val) for val in value]
        return self.value_to_dict(value)

    def to_dict(self, search_fields=None):
        """Builds dict without None object fields"""
        fields = self._fields
        if search_fields == 'only':
            fields = self._search_fields
        elif search_fields == 'exclude':
            # exclude search fields for update actions
            fields = [field for field in self._fields
                      if field not in self._search_fields]

        return {field: self.field_to_dict(field) for field in fields
                if getattr(self, field, None) is not None}

    @classmethod
    def create(cls, connector, check_if_exists=True,
               update_if_exists=False, **kwargs):
        ib_obj = None
        if check_if_exists:
            ib_obj = cls.search(connector, **kwargs)
            if ib_obj:
                LOG.info(("Infoblox %(obj_type)s already exists: "
                          "%(ib_obj)s"),
                         {'obj_type': ib_obj.infoblox_type,
                          'ib_obj': ib_obj})
        local_obj = cls(connector, **kwargs)
        if not ib_obj:
            ib_obj = connector.create_object(local_obj.infoblox_type,
                                             local_obj.to_dict(),
                                             local_obj.return_fields)
            LOG.info("Infoblox %(obj_type)s was created: %(ib_obj)s",
                     {'obj_type': local_obj.infoblox_type, 'ib_obj': ib_obj})
        elif update_if_exists:
            update_fields = local_obj.to_dict(search_fields='exclude')
            ib_obj = connector.update_object(ib_obj['_ref'],
                                             update_fields,
                                             local_obj.return_fields)
            LOG.info('Infoblox object was updated: %s', ib_obj['_ref'])
        return local_obj.from_dict(connector, ib_obj)

    @classmethod
    def search(cls, connector, return_fields=None,
               extattrs=None,
               force_proxy=False, **kwargs):
        ib_obj_for_search = cls(connector, **kwargs)
        search_dict = ib_obj_for_search.to_dict(search_fields='only')
        if not return_fields and ib_obj_for_search.return_fields:
            return_fields = ib_obj_for_search.return_fields
        ib_obj = connector.get_object(ib_obj_for_search.infoblox_type,
                                      search_dict,
                                      return_fields=return_fields,
                                      extattrs=extattrs,
                                      force_proxy=force_proxy)
        if ib_obj:
            return ib_obj_for_search.from_dict(connector, ib_obj)
        return None

    def delete(self):
        try:
            self.connector.delete_object(self._ref)
        except ib_ex.InfobloxCannotDeleteObject as e:
            LOG.info(("Failed to delete an object: %s"), e)

    @property
    def infoblox_type(self):
        return self._infoblox_type

    @property
    def return_fields(self):
        return self._return_fields

    @classmethod
    def get_class_from_args(cls, kwargs):
        # skip processing if cls already versioned class
        if cls._ip_version:
            return cls

        for field in ['ip', 'cidr', 'start_ip']:
            if field in kwargs:
                if ib_utils.determine_ip_version(kwargs[field]) == 6:
                    return cls.get_v6_class()
                else:
                    return cls.get_v4_class()
        # fallback to IPv4 object if find nothing
        return cls.get_v4_class()

    @classmethod
    def _remap_fields(cls, kwargs):
        """Map fields from kwargs into dict acceptable by NIOS"""
        mapped = {}
        for key in kwargs:
            if key in cls._remap:
                mapped[cls._remap[key]] = kwargs[key]
            elif key in cls._fields or key in cls._shadow_fields:
                mapped[key] = kwargs[key]
            else:
                raise ValueError("Unknown parameter %s for class %s" %
                                 (key, cls))
        return mapped

    @classmethod
    def get_v4_class(cls):
        return cls

    @classmethod
    def get_v6_class(cls):
        return cls


class Network(InfobloxObject):
    _fields = ['_ref', 'network_view', 'network']
    _search_fields = ['network_view', 'network']
    _remap = {'cidr': 'network'}

    @classmethod
    def get_v4_class(cls):
        return NetworkV4

    @classmethod
    def get_v6_class(cls):
        return NetworkV6


class NetworkV4(Network):
    _infoblox_type = 'network'
    _ip_version = 4


class NetworkV6(Network):
    _infoblox_type = 'ipv6network'
    _ip_version = 6


class HostRecord(InfobloxObject):
    """Base class for HostRecords

    HostRecord uses ipvXaddr for search and ipvXaddrs for object creation.
    ipvXaddr and ipvXaddrs are quite different:
    ipvXaddr is single ip as a string
    ipvXaddrs is list of dicts with ipvXaddr, mac, configure_for_dhcp
    and host keys.
    In 'ipvXaddr' 'X' stands for 4 or 6 depending on ip version of the class.

    To find HostRecord use next syntax:
    hr = HostRecord.search(connector, ip='192.168.1.25', view='some-view')

    To create host record create IP object first:
    ip = IP(ip='192.168.1.25', mac='aa:ab;ce:12:23:34')
    hr = HostRecord.create(connector, ip=ip, view='some-view')

    """
    _infoblox_type = 'record:host'

    @classmethod
    def get_v4_class(cls):
        return HostRecordV4

    @classmethod
    def get_v6_class(cls):
        return HostRecordV6


class HostRecordV4(HostRecord):
    """HostRecord for IPv4"""
    _fields = ['_ref', 'ipv4addrs', 'view', 'extattrs', 'name']
    _search_fields = ['view', 'ipv4addr']
    _shadow_fields = ['ipv4addr']
    _remap = {'ip': 'ipv4addrs'}
    _ip_version = 4

    @property
    def ipv4addrs(self):
        return self._ipv4addrs

    @ipv4addrs.setter
    def ipv4addrs(self, ips):
        """Setter for ipv4addrs

        Accept as input string or list of IP instances.
        String case:
            only ipv4addr is going to be filled, that is enough to perform
            host record search using ip
        List of IP instances case:
            ipv4addrs is going to be filled with ips content,
            so create can be issues, since fully prepared IP objects in place.
            ip4addr is also filled to be able perform search on NIOS
            and verify that no such host record exists yet.
        """
        if isinstance(ips, six.string_types):
            self.ipv4addr = ips
        elif isinstance(ips, (list, tuple)) and isinstance(ips[0], IP):
            self._ipv4addrs = ips
            self.ipv4addr = ips[0].ip
        else:
            raise ValueError(
                "Invalid format of ip passed in: %s."
                "Should be string or list of NIOS IP objects." % ips)

    @staticmethod
    def _build_ipv4(ips_v4):
        if not ips_v4:
            raise ib_ex.HostRecordNotPresent()
        ip = ips_v4[0]['ipv4addr']
        if not ib_utils.is_valid_ip(ip):
            raise ib_ex.InfobloxInvalidIp(ip=ip)
        return [IPv4.from_dict(ip_addr) for ip_addr in ips_v4]

    _custom_field_processing = {'ipv4addrs': _build_ipv4.__func__}


class HostRecordV6(HostRecord):
    """HostRecord for IPv6"""
    _fields = ['_ref', 'ipv6addrs', 'view', 'extattrs',  'name']
    _search_fields = ['ipv6addr', 'view']
    _shadow_fields = ['ipv6addr']
    _remap = {'ip': 'ipv6addrs'}
    _ip_version = 6

    @property
    def ipv6addrs(self):
        return self._ipv6addrs

    @ipv6addrs.setter
    def ipv6addrs(self, ips):
        """Setter for ipv6addrs

        Refer to HostRecordV4.ipv6addrs setter for more details
        """
        if isinstance(ips, six.string_types):
            self.ipv6addr = ips
        elif isinstance(ips, (list, tuple)) and isinstance(ips[0], IP):
            self._ipv6addrs = ips
            self.ipv6addr = ips[0].ip
        else:
            raise ValueError

    @staticmethod
    def _build_ipv6(ips_v6):
        if not ips_v6:
            raise ib_ex.HostRecordNotPresent()
        ip = ips_v6[0]['ipv6addr']
        if not ib_utils.is_valid_ip(ip):
            raise ib_ex.InfobloxInvalidIp(ip=ip)
        return [IPv6.from_dict(ip_addr) for ip_addr in ips_v6]

    _custom_field_processing = {'ipv6addrs': _build_ipv6.__func__}


class IP(object):
    _fields = []
    _remap = {}

    @classmethod
    def create(cls, ip=None, mac=None, **kwargs):
        if ip is None:
            raise ValueError
        if ib_utils.determine_ip_version(ip) == 6:
            return IPv6(ipv6addr=ip, duid=ib_utils.generate_duid(mac),
                        **kwargs)
        else:
            return IPv4(ipv4addr=ip, mac=mac, **kwargs)

    def __init__(self, **kwargs):
        for field in self._fields:
            if field in kwargs:
                setattr(self, field, kwargs[field])

    def __getattr__(self, name):
        # Map aliases into real fields
        if name in self._remap:
            return getattr(self, self._remap[name])
        elif name in self._fields:
            return None
        else:
            # Default behaviour
            raise AttributeError

    @classmethod
    def from_dict(cls, ip_dict):
        return cls(**ip_dict)

    def to_dict(self):
        return {field: getattr(self, field) for field in self._fields
                if getattr(self, field, None) is not None}


class IPv4(IP):
    _fields = ['ipv4addr', 'configure_for_dhcp', 'host', 'mac']
    _remap = {'ip': 'ipv4addr'}
    ip_version = 4


class IPv6(IP):
    _fields = ['ipv6addr', 'configure_for_dhcp', 'host', 'duid']
    _remap = {'ip': 'ipv6addr'}
    ip_version = 6


class IPRange(InfobloxObject):
    _fields = ['_ref', 'start_addr', 'end_addr', 'network_view',
               'cidr', 'extattrs', 'disable']
    _remap = {'cidr': 'network'}
    _search_fields = ['network_view', 'start_addr']

    @classmethod
    def get_v4_class(cls):
        return IPRangeV4

    @classmethod
    def get_v6_class(cls):
        return IPRangeV6


class IPRangeV4(IPRange):
    _infoblox_type = 'range'
    _ip_version = 4


class IPRangeV6(IPRange):
    _infoblox_type = 'ipv6range'
    _ip_version = 6


class FixedAddress(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return FixedAddressV4

    @classmethod
    def get_v6_class(cls):
        return FixedAddressV6


class FixedAddressV4(FixedAddress):
    _infoblox_type = 'fixedaddress'
    _fields = ['_ref', 'ipv4addr', 'mac', 'network_view']
    _search_fields = ['ipv4addr', 'mac', 'network_view']
    _remap = {'ip': 'ipv4addr'}
    _ip_version = 4


class FixedAddressV6(FixedAddress):
    """FixedAddress for IPv6"""
    _infoblox_type = 'ipv6fixedaddress'
    _fields = ['_ref', 'ipv6addr', 'duid', 'network_view']
    _search_fields = ['ipv6addr', 'duid', 'network_view']
    _shadow_fields = ['mac']
    _remap = {'ip': 'ipv6addr'}
    _ip_version = 6

    @property
    def mac(self):
        return self._mac

    @mac.setter
    def mac(self, mac):
        """Set mac and duid fields

        To have common interface with FixedAddress accept mac address
        and set duid as a side effect.
        'mac' was added to _shadow_fields to prevent sending it out over wapi.
        """
        self._mac = mac
        if mac:
            self.duid = ib_utils.generate_duid(mac)
        elif hasattr(self, 'duid'):
            self.duid = None


class ARecordBase(InfobloxObject):

    @classmethod
    def get_v4_class(cls):
        return ARecord

    @classmethod
    def get_v6_class(cls):
        return AAAARecord


class ARecord(ARecordBase):
    _infoblox_type = 'record:a'
    _fields = ['_ref', 'ipv4addr', 'name', 'view', 'extattrs']
    _search_fields = ['ipv4addr', 'name', 'view']
    _remap = {'ip': 'ipv4addr'}
    _ip_version = 4


class AAAARecord(ARecordBase):
    _infoblox_type = 'record:aaaa'
    _fields = ['_ref', 'ipv6addr', 'name', 'view', 'extattrs']
    _search_fields = ['ipv6addr', 'name', 'view']
    _remap = {'ip': 'ipv6addr'}
    _ip_version = 6


class PtrRecord(InfobloxObject):
    _infoblox_type = 'record:ptr'

    @classmethod
    def get_v4_class(cls):
        return PtrRecordV4

    @classmethod
    def get_v6_class(cls):
        return PtrRecordV6


class PtrRecordV4(PtrRecord):
    _fields = ['_ref', 'view', 'ipv4addr', 'ptrdname', 'extattrs']
    _search_fields = ['view', 'ipv4addr', 'ptrdname']
    _remap = {'ip': 'ipv4addr'}
    _ip_version = 4


class PtrRecordV6(PtrRecord):
    _fields = ['_ref', 'view', 'ipv6addr', 'ptrdname', 'extattrs']
    _search_fields = ['view', 'ipv6addr', 'ptrdname']
    _remap = {'ip': 'ipv6addr'}
    _ip_version = 6


class NetworkView(InfobloxObject):
    _infoblox_type = 'networkview'
    _fields = ['_ref', 'name', 'extattrs']
    _search_fields = ['name']
    _ip_version = 'any'


class DNSView(InfobloxObject):
    _infoblox_type = 'view'
    _fields = ['_ref', 'name', 'network_view']
    _search_fields = ['name', 'network_view']
    _ip_version = 'any'


class DNSZone(InfobloxObject):
    # TODO(pbondar): Add special processing for dns_members
    _infoblox_type = 'zone_auth'
    _fields = ['_ref', 'fqdn', 'view', 'extattrs', 'zone_format', 'ns_group',
               'prefix', 'primary_dns_members', 'secondary_dns_members']
    _search_fields = ['fqdn', 'view']
    _ip_version = 'any'


class IPAllocation(object):

    def __init__(self, address, next_available_ip):
        self.ip_version = ib_utils.determine_ip_version(address)
        self.next_available_ip = next_available_ip

    @classmethod
    def next_available_ip_from_cidr(cls, net_view_name, cidr):
        return cls(cidr, 'func:nextavailableip:'
                         '{cidr:s},{net_view_name:s}'.format(**locals()))

    @classmethod
    def next_available_ip_from_range(cls, net_view_name, first_ip, last_ip):
        return cls(first_ip, 'func:nextavailableip:{first_ip}-{last_ip},'
                             '{net_view_name}'.format(**locals()))
