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


class BaseObject(object):
    """Base class that provides minimal new object model interface

    This class add next features to objects:
    - initialize public instance variables with None for fields
     defined in '_fields' and '_shadow_fields'
    - accept fields from '_fields' and '_shadow_fields' as a parameter on init
    - dynamically remap one fields into another using _remap dict,
     mapping is in effect on all stages (on init, getter and setter)
    - provides nice object representation that contains class
     and not None object fields (useful in python interpretter)
    """
    _fields = []
    _shadow_fields = []
    _remap = {}
    _infoblox_type = None

    def __init__(self, **kwargs):
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

    def __setattr__(self, name, value):
        if name in self._remap:
            return setattr(self, self._remap[name], value)
        else:
            super(BaseObject, self).__setattr__(name, value)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            for field in self._fields:
                if getattr(self, field) != getattr(other, field):
                    return False
            return True
        return False

    def __repr__(self):
        data = {field: getattr(self, field)
                for field in self._fields + self._shadow_fields
                if hasattr(self, field) and getattr(self, field) is not None}
        data_str = ', '.join(
            "{0}=\"{1}\"".format(key, data[key]) for key in data)
        return "{0}: {1}".format(self.__class__.__name__, data_str)

    @classmethod
    def _remap_fields(cls, kwargs):
        """Map fields from kwargs into dict acceptable by NIOS"""
        mapped = {}
        for key in kwargs:
            if key in cls._remap:
                mapped[cls._remap[key]] = kwargs[key]
            else:
                mapped[key] = kwargs[key]
        return mapped

    @classmethod
    def from_dict(cls, ip_dict):
        return cls(**ip_dict)

    def to_dict(self):
        return {field: getattr(self, field) for field in self._fields
                if getattr(self, field, None) is not None}

    @property
    def ref(self):
        if hasattr(self, '_ref'):
            return self._ref


class EA(object):
    """Extensible Attributes

    This class represents extensible attributes (EA).
    Converts EAs into format suitable for NIOS (to_dict)
    and builds EA class from NIOS reply (from_dict).
    """

    def __init__(self, ea_dict=None):
        """Optionally accept EAs as a dict on init.

        Expected EA format is {ea_name: ea_value}
        """
        if ea_dict is None:
            ea_dict = {}
        self._ea_dict = ea_dict

    def __repr__(self):
        eas = ()
        if self._ea_dict:
            eas = ("{0}={1}".format(name, self._ea_dict[name])
                   for name in self._ea_dict)
        return "EAs:{0}".format(','.join(eas))

    @property
    def ea_dict(self):
        """Returns dict with EAs in {ea_name: ea_value} format."""
        return self._ea_dict.copy()

    @classmethod
    def from_dict(cls, eas_from_nios):
        """Converts extensible attributes from the NIOS reply."""
        if not eas_from_nios:
            return
        return cls({name: cls._process_value(ib_utils.try_value_to_bool,
                                             eas_from_nios[name]['value'])
                    for name in eas_from_nios})

    def to_dict(self):
        """Converts extensible attributes into the format suitable for NIOS."""
        return {name: {'value': self._process_value(str, value)}
                for name, value in self._ea_dict.items()
                if not (value is None or value == "" or value == [])}

    @staticmethod
    def _process_value(func, value):
        """Applies processing method for value or each element in it.

        :param func: method to be called with value
        :param value: value to process
        :return: if 'value' is list/tupe, returns iterable with func results,
                 else func result is returned
        """
        if isinstance(value, (list, tuple)):
            return [func(item) for item in value]
        return func(value)

    def get(self, name, default=None):
        """Return value of requested EA."""
        return self._ea_dict.get(name, default)

    def set(self, name, value):
        """Set value of requested EA."""
        self._ea_dict[name] = value


class InfobloxObject(BaseObject):
    """Base class for all Infoblox related objects

    _fields - fields that represents NIOS object (WAPI fields) and
        are sent to NIOS on object creation
    _search_for_update_fields - field/fields used to find an object during an
        update operation. this should be the smallest number of fields that
        uniquely identify an object
    _all_searchable_fields - all fields that can be used to find object on NIOS
        side
    _updateable_search_fields - fields that can be used to find object on
        NIOS side, but also can be changed, so has to be sent on update.
    _shadow_fields - fields that object usually has but they should not
        be sent to NIOS. These fields can be received from NIOS. Examples:
        [_ref, is_default]
    _return_fields - fields requested to be returned from NIOS side
         if object is found/created
    _infoblox_type - string representing wapi type of described object
    _remap - dict that maps user faced names into internal
         representation (_fields)
    _custom_field_processing - dict that define rules (lambda) for building
         objects from data returned by NIOS side.
         Expected to be redefined in child class as needed,
         _custom_field_processing has priority over _global_field_processing,
         so can redefine for child class global rules
         defined in _global_field_processing.
    _global_field_processing - almost the same as _custom_field_processing,
         but defines rules for building field on global level.
         Fields defined in this dict will be processed in the same way in all
         child classes. Is not expected to be redefined in child classes.
    _ip_version - ip version of the object, used to mark version
        specific classes. Value other than None indicates that
        no versioned class lookup needed.
    """
    _fields = []
    _search_for_update_fields = []
    _all_searchable_fields = []
    _updateable_search_fields = []
    _shadow_fields = []
    _infoblox_type = None
    _remap = {}

    _return_fields = []
    _custom_field_processing = {}
    _global_field_processing = {'extattrs': EA.from_dict}
    _ip_version = None

    def __new__(cls, connector, **kwargs):
        return super(InfobloxObject,
                     cls).__new__(cls.get_class_from_args(kwargs))

    def __init__(self, connector, **kwargs):
        self.connector = connector
        super(InfobloxObject, self).__init__(**kwargs)

    def update_from_dict(self, ip_dict, only_ref=False):
        if only_ref:
            self._ref = ip_dict['_ref']
            return

        mapped_args = self._remap_fields(ip_dict)
        for field in self._fields + self._shadow_fields:
            if field in ip_dict:
                setattr(self, field, mapped_args[field])

    @classmethod
    def from_dict(cls, connector, ip_dict):
        """Build dict fields as SubObjects if needed.

        Checks if lambda for building object from dict exists.
        _global_field_processing and _custom_field_processing rules
        are checked.
        """
        mapping = cls._global_field_processing.copy()
        mapping.update(cls._custom_field_processing)
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
        if search_fields == 'update':
            fields = self._search_for_update_fields
        elif search_fields == 'all':
            fields = self._all_searchable_fields
        elif search_fields == 'exclude':
            # exclude search fields for update actions,
            # but include updateable_search_fields
            fields = [field for field in self._fields
                      if field in self._updateable_search_fields or
                      field not in self._search_for_update_fields]

        return {field: self.field_to_dict(field) for field in fields
                if getattr(self, field, None) is not None}

    @staticmethod
    def _object_from_reply(parse_class, connector, reply):
        if not reply:
            return None
        if isinstance(reply, dict):
            return parse_class.from_dict(connector, reply)

        # If no return fields were requested reply contains only string
        # with reference to object
        return_dict = {'_ref': reply}
        return parse_class.from_dict(connector, return_dict)

    @classmethod
    def create_check_exists(cls, connector, check_if_exists=True,
                            update_if_exists=False, **kwargs):
        # obj_created is used to check if object is being created or
        # pre-exists. obj_created is True if object is not pre-exists
        # and getting created with this function call
        obj_created = False
        local_obj = cls(connector, **kwargs)
        if check_if_exists:
            if local_obj.fetch(only_ref=True):
                LOG.info(("Infoblox %(obj_type)s already exists: "
                          "%(ib_obj)s"),
                         {'obj_type': local_obj.infoblox_type,
                          'ib_obj': local_obj})
                if not update_if_exists:
                    return local_obj, obj_created
        reply = None
        if not local_obj.ref:
            reply = connector.create_object(local_obj.infoblox_type,
                                            local_obj.to_dict(),
                                            local_obj.return_fields)
            obj_created = True
            LOG.info("Infoblox %(obj_type)s was created: %(ib_obj)s",
                     {'obj_type': local_obj.infoblox_type,
                      'ib_obj': local_obj})
        elif update_if_exists:
            update_fields = local_obj.to_dict(search_fields='exclude')
            reply = connector.update_object(local_obj.ref,
                                            update_fields,
                                            local_obj.return_fields)
            LOG.info('Infoblox object was updated: %s', local_obj.ref)
        return cls._object_from_reply(local_obj, connector, reply), obj_created

    @classmethod
    def create(cls, connector, check_if_exists=True,
               update_if_exists=False, **kwargs):
        ib_object, _ = (
            cls.create_check_exists(connector,
                                    check_if_exists=check_if_exists,
                                    update_if_exists=update_if_exists,
                                    **kwargs))
        return ib_object

    @classmethod
    def _search(cls, connector, return_fields=None,
                search_extattrs=None, force_proxy=False,
                max_results=None, **kwargs):
        ib_obj_for_search = cls(connector, **kwargs)
        search_dict = ib_obj_for_search.to_dict(search_fields='all')
        if return_fields is None and ib_obj_for_search.return_fields:
            return_fields = ib_obj_for_search.return_fields
        # allow search_extattrs to be instance of EA class
        # or dict in NIOS format
        extattrs = search_extattrs
        if hasattr(search_extattrs, 'to_dict'):
            extattrs = search_extattrs.to_dict()
        reply = connector.get_object(ib_obj_for_search.infoblox_type,
                                     search_dict,
                                     return_fields=return_fields,
                                     extattrs=extattrs,
                                     force_proxy=force_proxy,
                                     max_results=max_results)
        return reply, ib_obj_for_search

    @classmethod
    def search(cls, connector, **kwargs):
        ib_obj, parse_class = cls._search(
            connector, **kwargs)
        if ib_obj:
            return parse_class.from_dict(connector, ib_obj[0])

    @classmethod
    def search_all(cls, connector,  **kwargs):
        ib_objects, parsing_class = cls._search(
            connector, **kwargs)
        if ib_objects:
            return [parsing_class.from_dict(connector, obj)
                    for obj in ib_objects]
        return []

    def fetch(self, only_ref=False):
        """Fetch object from NIOS by _ref or searchfields

        Update existent object with fields returned from NIOS
        Return True on successful object fetch
        """
        if self.ref:
            reply = self.connector.get_object(
                self.ref, return_fields=self.return_fields)
            if reply:
                self.update_from_dict(reply)
                return True

        search_dict = self.to_dict(search_fields='update')
        return_fields = [] if only_ref else self.return_fields
        reply = self.connector.get_object(self.infoblox_type,
                                          search_dict,
                                          return_fields=return_fields)
        if reply:
            self.update_from_dict(reply[0], only_ref=only_ref)
            return True
        return False

    def update(self):
        update_fields = self.to_dict(search_fields='exclude')
        ib_obj = self.connector.update_object(self.ref,
                                              update_fields,
                                              self.return_fields)
        LOG.info('Infoblox object was updated: %s', self.ref)
        return self._object_from_reply(self, self.connector, ib_obj)

    def delete(self):
        try:
            self.connector.delete_object(self.ref)
        except ib_ex.InfobloxCannotDeleteObject as e:
            LOG.info("Failed to delete an object: %s", e)

    @property
    def infoblox_type(self):
        return self._infoblox_type

    @property
    def return_fields(self):
        return self._return_fields

    @property
    def ip_version(self):
        return self._ip_version

    @classmethod
    def get_class_from_args(cls, kwargs):
        # skip processing if cls already versioned class
        if cls._ip_version:
            return cls

        for field in ['ip', 'cidr', 'start_ip', 'ip_address', 'network',
                      'start_addr', 'end_addr']:
            if field in kwargs:
                if ib_utils.determine_ip_version(kwargs[field]) == 6:
                    return cls.get_v6_class()
                else:
                    return cls.get_v4_class()
        # fallback to IPv4 object if find nothing
        return cls.get_v4_class()

    @classmethod
    def get_v4_class(cls):
        return cls

    @classmethod
    def get_v6_class(cls):
        return cls


class Network(InfobloxObject):
    _fields = ['network_view', 'network', 'template',
               'options', 'members', 'extattrs', 'comment']
    _search_for_update_fields = ['network_view', 'network']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref']
    _return_fields = ['network_view', 'network', 'options', 'members',
                      'extattrs', 'comment']
    _remap = {'cidr': 'network'}

    @classmethod
    def get_v4_class(cls):
        return NetworkV4

    @classmethod
    def get_v6_class(cls):
        return NetworkV6

    @staticmethod
    def _build_member(members):
        if not members:
            return None
        return [AnyMember.from_dict(m) for m in members]

    # TODO(pbondar): Rework SubObject to correctly handle arrays
    # passed into from_dict, so all _build_options and _build_member
    # would be no longer needed
    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [DhcpOption.from_dict(m) for m in members]

    _custom_field_processing = {'members': _build_member.__func__,
                                'options': _build_options.__func__}


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

    def _ip_setter(self, ipaddr_name, ipaddrs_name, ips):
        """Setter for ip fields

        Accept as input string or list of IP instances.
        String case:
            only ipvXaddr is going to be filled, that is enough to perform
            host record search using ip
        List of IP instances case:
            ipvXaddrs is going to be filled with ips content,
            so create can be issues, since fully prepared IP objects in place.
            ipXaddr is also filled to be able perform search on NIOS
            and verify that no such host record exists yet.
        """
        if isinstance(ips, six.string_types):
            setattr(self, ipaddr_name, ips)
        elif isinstance(ips, (list, tuple)) and isinstance(ips[0], IP):
            setattr(self, ipaddr_name, ips[0].ip)
            setattr(self, ipaddrs_name, ips)
        elif isinstance(ips, IP):
            setattr(self, ipaddr_name, ips.ip)
            setattr(self, ipaddrs_name, [ips])
        elif ips is None:
            setattr(self, ipaddr_name, None)
            setattr(self, ipaddrs_name, None)
        else:
            raise ValueError(
                "Invalid format of ip passed in: %s."
                "Should be string or list of NIOS IP objects." % ips)


class HostRecordV4(HostRecord):
    """HostRecord for IPv4"""
    _fields = ['ipv4addrs', 'view', 'extattrs', 'name', 'zone',
               'configure_for_dns', 'network_view', 'mac', 'ttl',
               'comment', 'aliases']
    _search_for_update_fields = ['view', 'ipv4addr', 'name',
                                 'zone', 'network_view', 'mac']
    _all_searchable_fields = _search_for_update_fields
    _updateable_search_fields = ['name']
    _shadow_fields = ['_ref', 'ipv4addr']
    _return_fields = ['ipv4addrs', 'extattrs', 'aliases']
    _remap = {'ip': 'ipv4addrs',
              'ips': 'ipv4addrs'}
    _ip_version = 4

    @property
    def ipv4addrs(self):
        return self._ipv4addrs

    @ipv4addrs.setter
    def ipv4addrs(self, ips):
        """Setter for ipv4addrs/ipv4addr"""
        self._ip_setter('ipv4addr', '_ipv4addrs', ips)

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
    _fields = ['ipv6addrs', 'view', 'extattrs',  'name', 'zone',
               'configure_for_dns', 'network_view', 'ttl', 'comment',
               'aliases']
    _search_for_update_fields = ['ipv6addr', 'view', 'name',
                                 'zone', 'network_view']
    _all_searchable_fields = _search_for_update_fields
    _updateable_search_fields = ['name']
    _shadow_fields = ['_ref', 'ipv6addr']
    _return_fields = ['ipv6addrs', 'extattrs', 'aliases']
    _remap = {'ip': 'ipv6addrs',
              'ips': 'ipv6addrs'}

    _ip_version = 6

    @property
    def ipv6addrs(self):
        return self._ipv6addrs

    @ipv6addrs.setter
    def ipv6addrs(self, ips):
        """Setter for ipv6addrs/ipv6addr"""
        self._ip_setter('ipv6addr', '_ipv6addrs', ips)

    @staticmethod
    def _build_ipv6(ips_v6):
        if not ips_v6:
            raise ib_ex.HostRecordNotPresent()
        ip = ips_v6[0]['ipv6addr']
        if not ib_utils.is_valid_ip(ip):
            raise ib_ex.InfobloxInvalidIp(ip=ip)
        return [IPv6.from_dict(ip_addr) for ip_addr in ips_v6]

    _custom_field_processing = {'ipv6addrs': _build_ipv6.__func__}


class IPv6HostAddress(InfobloxObject):
    _infoblox_type = 'record:host_ipv6addr'
    _fields = ['duid', 'network_view', 'host']
    _search_for_update_fields = ['duid', 'network_view']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref']
    _return_fields = ['host']
    _ip_version = 6


class SubObjects(BaseObject):
    """Base class for objects that do not require all InfobloxObject power"""

    @classmethod
    def from_dict(cls, ip_dict):
        return cls(**ip_dict)

    def to_dict(self):
        return {field: getattr(self, field) for field in self._fields
                if getattr(self, field, None) is not None}


class IP(SubObjects):
    _fields = []
    _shadow_fields = ['_ref', 'ip', 'host']
    _remap = {}
    ip_version = None

    # better way for mac processing?
    @classmethod
    def create(cls, ip=None, mac=None, **kwargs):
        if ip is None:
            raise ValueError
        if ib_utils.determine_ip_version(ip) == 6:
            return IPv6(ip=ip, duid=ib_utils.generate_duid(mac),
                        **kwargs)
        else:
            return IPv4(ip=ip, mac=mac, **kwargs)

    def __eq__(self, other):
        if isinstance(other, six.string_types):
            return self.ip == other
        elif isinstance(other, self.__class__):
            return self.ip == other.ip
        return False

    @property
    def zone_auth(self):
        if self.host is not None:
            return self.host.partition('.')[2]

    @property
    def hostname(self):
        if self.host is not None:
            return self.host.partition('.')[0]

    @property
    def ip(self):
        # Convert IPAllocation objects to string
        if hasattr(self, '_ip'):
            return str(self._ip)

    @ip.setter
    def ip(self, ip):
        self._ip = ip


class IPv4(IP):
    _fields = ['ipv4addr', 'configure_for_dhcp',  'mac']
    _remap = {'ipv4addr': 'ip'}
    ip_version = 4


class IPv6(IP):
    _fields = ['ipv6addr', 'configure_for_dhcp', 'duid']
    _remap = {'ipv6addr': 'ip'}
    ip_version = 6


class AnyMember(SubObjects):
    _fields = ['_struct', 'name', 'ipv4addr', 'ipv6addr']
    _shadow_fields = ['ip']

    @property
    def ip(self):
        if hasattr(self, '_ip'):
            return str(self._ip)

    @ip.setter
    def ip(self, ip):
        # AnyMember represents both ipv4 and ipv6 objects, so don't need
        # versioned object for that. Just set v4 or v6 field additionally
        # to setting shadow 'ip' field itself.
        # So once dict is generated by to_dict only versioned ip field
        # to be shown.
        self._ip = ip
        if ib_utils.determine_ip_version(ip) == 6:
            self.ipv6addr = ip
        else:
            self.ipv4addr = ip


class DhcpOption(SubObjects):
    _fields = ['name', 'num', 'use_option', 'value', 'vendor_class']


class IPRange(InfobloxObject):
    _fields = ['start_addr', 'end_addr', 'network_view',
               'network', 'extattrs', 'disable']
    _remap = {'cidr': 'network'}
    _search_for_update_fields = ['network_view', 'start_addr',
                                 'end_addr', 'network']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref']
    _return_fields = ['start_addr', 'end_addr', 'network_view', 'extattrs']

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

    @property
    def ip(self):
        if hasattr(self, '_ip') and self._ip:
            return str(self._ip)

    @ip.setter
    def ip(self, ip):
        self._ip = ip


class FixedAddressV4(FixedAddress):
    _infoblox_type = 'fixedaddress'
    _fields = ['ipv4addr', 'mac', 'network_view', 'extattrs', 'network',
               'options', 'comment']
    _search_for_update_fields = ['ipv4addr', 'mac', 'network_view', 'network']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref', 'ip']
    _return_fields = ['ipv4addr', 'mac', 'network_view', 'extattrs']
    _remap = {'ipv4addr': 'ip'}
    _ip_version = 4

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [DhcpOption.from_dict(m) for m in members]

    _custom_field_processing = {'options': _build_options.__func__}


class FixedAddressV6(FixedAddress):
    """FixedAddress for IPv6"""
    _infoblox_type = 'ipv6fixedaddress'
    _fields = ['ipv6addr', 'duid', 'network_view', 'extattrs', 'network',
               'comment']
    _search_for_update_fields = ['ipv6addr', 'duid', 'network_view', 'network']
    _all_searchable_fields = _search_for_update_fields
    _return_fields = ['ipv6addr', 'duid', 'network_view', 'extattrs']
    _shadow_fields = ['_ref', 'mac', 'ip']
    _remap = {'ipv6addr': 'ip'}
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
        elif not hasattr(self, 'duid'):
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
    _fields = ['ipv4addr', 'name', 'view', 'comment', 'extattrs']
    _search_for_update_fields = ['ipv4addr', 'view']
    _all_searchable_fields = _search_for_update_fields + ['name']
    _return_fields = ['ipv4addr', 'name']
    _shadow_fields = ['_ref']
    _remap = {'ip': 'ipv4addr'}
    _ip_version = 4


class AAAARecord(ARecordBase):
    _infoblox_type = 'record:aaaa'
    _fields = ['ipv6addr', 'name', 'view', 'comment', 'extattrs']
    _search_for_update_fields = ['ipv6addr', 'view']
    _all_searchable_fields = _search_for_update_fields + ['name']
    _return_fields = ['ipv6addr', 'name']
    _shadow_fields = ['_ref']
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
    _fields = ['view', 'ipv4addr', 'ptrdname', 'extattrs']
    _search_for_update_fields = ['view', 'ipv4addr']
    _all_searchable_fields = _search_for_update_fields + ['ptrdname']
    _shadow_fields = ['_ref']
    _remap = {'ip': 'ipv4addr'}
    _ip_version = 4


class PtrRecordV6(PtrRecord):
    _fields = ['view', 'ipv6addr', 'ptrdname', 'extattrs']
    _search_for_update_fields = ['view', 'ipv6addr']
    _all_searchable_fields = _search_for_update_fields + ['ptrdname']
    _shadow_fields = ['_ref']
    _remap = {'ip': 'ipv6addr'}
    _ip_version = 6


class SRVRecord(InfobloxObject):
    _infoblox_type = 'record:srv'
    _fields = ['name', 'port', 'priority', 'target', 'weight',
               'aws_rte53_record_info', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal',
               'ddns_protected', 'disable', 'dns_name', 'dns_target',
               'extattrs', 'forbid_reclamation', 'reclaimable',
               'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['comment', 'creator', 'ddns_principal',
                                 'name', 'port', 'priority', 'reclaimable',
                                 'target', 'view', 'weight', 'zone']
    _all_searchable_fields = _search_for_update_fields
    _return_fields = ['name', 'port', 'priority', 'weight', 'target', 'view']
    _shadow_fields = ['_ref']


class NetworkView(InfobloxObject):
    _infoblox_type = 'networkview'
    _fields = ['name', 'extattrs']
    _return_fields = ['name', 'extattrs', 'is_default']
    _search_for_update_fields = ['name']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref', 'is_default']
    _ip_version = 'any'


class DNSView(InfobloxObject):
    _infoblox_type = 'view'
    _fields = ['name', 'network_view', 'extattrs']
    _return_fields = ['name', 'network_view', 'extattrs']
    _search_for_update_fields = ['name', 'network_view']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref', 'is_default']
    _ip_version = 'any'


class DNSZone(InfobloxObject):
    _infoblox_type = 'zone_auth'
    _fields = ['fqdn', 'view', 'extattrs', 'zone_format',
               'prefix', 'grid_primary', 'grid_secondaries']
    _return_fields = ['fqdn', 'view', 'extattrs', 'zone_format', 'ns_group',
                      'prefix', 'grid_primary', 'grid_secondaries']
    _search_for_update_fields = ['fqdn', 'view', 'zone_format']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref', 'ns_group']
    _ip_version = 'any'

    @staticmethod
    def _build_member(members):
        if not members:
            return None
        return [AnyMember.from_dict(m) for m in members]

    _custom_field_processing = {
        'primary_dns_members': _build_member.__func__,
        'secondary_dns_members': _build_member.__func__}


class Member(InfobloxObject):
    _infoblox_type = 'member'
    _fields = ['host_name', 'ipv6_setting', 'vip_setting',
               'extattrs', 'ipv4_address', 'ipv6_address', 'platform',
               'config_addr_type', 'service_type_configuration']
    _return_fields = ['host_name', 'ipv6_setting', 'node_info',
                      'vip_setting', 'extattrs']
    _search_for_update_fields = ['host_name', 'ipv4_address', 'ipv6_address']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref', 'ip', 'node_info']
    _ip_version = 'any'
    _remap = {'name': 'host_name'}


class EADefinition(InfobloxObject):
    """Extensible Attribute Definition"""
    _infoblox_type = 'extensibleattributedef'
    _fields = ['comment', 'default_value', 'flags', 'list_values',
               'max', 'min', 'name', 'namespace', 'type',
               'allowed_object_types']
    _search_for_update_fields = ['name']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref']
    _return_fields = ['comment', 'default_value', 'flags', 'list_values',
                      'max', 'min', 'name', 'namespace', 'type',
                      'allowed_object_types']


class IPAddress(InfobloxObject):
    _fields = ['network_view', 'ip_address', 'objects', 'network', 'status']
    _search_for_update_fields = ['network_view', 'ip_address',
                                 'network', 'status']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref']
    _return_fields = ['objects']

    @classmethod
    def get_v4_class(cls):
        return IPv4Address

    @classmethod
    def get_v6_class(cls):
        return IPv6Address


class IPv4Address(IPAddress):
    _infoblox_type = 'ipv4address'
    _ip_version = 4


class IPv6Address(IPAddress):
    _infoblox_type = 'ipv6address'
    _ip_version = 6


class IPAllocation(object):

    def __init__(self, address, next_available_ip):
        self.ip_version = ib_utils.determine_ip_version(address)
        self.next_available_ip = next_available_ip

    def __repr__(self):
        return "IPAllocation: {0}".format(self.next_available_ip)

    def __str__(self):
        return str(self.next_available_ip)

    @classmethod
    def next_available_ip_from_cidr(cls, net_view_name, cidr):
        return cls(cidr, 'func:nextavailableip:'
                         '{cidr:s},{net_view_name:s}'.format(**locals()))

    @classmethod
    def next_available_ip_from_range(cls, net_view_name, first_ip, last_ip):
        return cls(first_ip, 'func:nextavailableip:{first_ip}-{last_ip},'
                             '{net_view_name}'.format(**locals()))


class Tenant(InfobloxObject):
    _infoblox_type = 'grid:cloudapi:tenant'
    _fields = ['id', 'name', 'comment']
    _search_for_update_fields = ['id']
    _all_searchable_fields = _search_for_update_fields
    _shadow_fields = ['_ref']


class CNAMERecord(InfobloxObject):
    _infoblox_type = 'record:cname'
    _fields = ['name', 'canonical', 'view', 'extattrs', 'comment',
               'creator', 'ddns_principal', 'ddns_protected', 'disable',
               'forbid_reclamation', 'ttl', 'use_ttl']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = ['name']
    _all_searchable_fields = _search_for_update_fields + ['reclaimable',
                                                          'zone']
    _return_fields = ['canonical', 'name', 'view', 'extattrs']
    _shadow_fields = ['_ref']
