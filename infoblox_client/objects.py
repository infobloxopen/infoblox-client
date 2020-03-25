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
WAPI_VERSION = "2.11"

import six

try:
    from oslo_log import log as logging
except ImportError:  # pragma: no cover
    import logging

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
    def search_all(cls, connector, **kwargs):
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

    def _call_func(self, function, *args, **kwargs):
        ref = self._ref
        if ref is None:
            ref = self.infoblox_type

        return self.connector.call_func(function, ref, *args, **kwargs)

    @classmethod
    def get_v4_class(cls):
        return cls

    @classmethod
    def get_v6_class(cls):
        return cls


class SubObjects(BaseObject):
    """Base class for objects that do not require all InfobloxObject power"""

    @classmethod
    def from_dict(cls, ip_dict):
        if isinstance(ip_dict, list):
            return [cls(**item) for item in ip_dict]
        else:
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
    _fields = ['ipv4addr', 'configure_for_dhcp', 'mac']
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
### AUTOGENERATED CODE BELOW ###

class AdAuthServer(SubObjects):
    _fields = ['auth_port', 'comment', 'disabled', 'encryption', 'fqdn_or_ip', 'mgmt_port', 'use_mgmt_port']


class Addressac(SubObjects):
    _fields = ['address', 'permission', 'tsig_key', 'tsig_key_alg', 'tsig_key_name', 'use_tsig_key_name']


class Awsrte53Task(SubObjects):
    _fields = ['aws_user', 'credentials_type', 'disabled', 'filter', 'last_run', 'name', 'schedule_interval', 'schedule_units', 'state', 'state_msg', 'status_timestamp', 'sync_private_zones', 'sync_public_zones', 'zone_count']


class Bgpas(SubObjects):
    _fields = ['as', 'holddown', 'keepalive', 'link_detect', 'neighbors']


class CapacityreportObjectcount(SubObjects):
    _fields = ['count', 'type_name']


class CaptiveportalFile(SubObjects):
    _fields = ['name', 'type']


class Changedobject(SubObjects):
    _fields = ['action', 'name', 'object_type', 'properties', 'type']


class Clientsubnetdomain(SubObjects):
    _fields = ['domain', 'permission']


class Dhcpddns(SubObjects):
    _fields = ['dns_ext_primary', 'dns_ext_zone', 'dns_grid_primary', 'dns_grid_zone', 'zone_match']


class Dhcpmember(SubObjects):
    _fields = ['ipv4addr', 'ipv6addr', 'name']


class Dhcpoption(SubObjects):
    _fields = ['name', 'num', 'use_option', 'value', 'vendor_class']


class DiscoveryAutoconversionsetting(SubObjects):
    _fields = ['comment', 'condition', 'format', 'network_view', 'type']


class DiscoveryClicredential(SubObjects):
    _fields = ['comment', 'credential_type', 'id', 'password', 'user']


class DiscoveryIfaddrinfo(SubObjects):
    _fields = ['address', 'address_object', 'network']


class DiscoveryNetworkinfo(SubObjects):
    _fields = ['network', 'network_str']


class DiscoveryPort(SubObjects):
    _fields = ['comment', 'port', 'type']


class DiscoveryScaninterface(SubObjects):
    _fields = ['network_view', 'scan_virtual_ip', 'type']


class DiscoverySdnconfig(SubObjects):
    _fields = ['addresses', 'api_key', 'ca_certificate', 'comment', 'handle', 'network_interface_type', 'network_interface_virtual_ip', 'network_view', 'on_prem', 'password', 'protocol', 'sdn_type', 'use_global_proxy', 'username', 'uuid']


class DiscoverySeedrouter(SubObjects):
    _fields = ['address', 'comment', 'network_view']


class DiscoverySnmp3Credential(SubObjects):
    _fields = ['authentication_password', 'authentication_protocol', 'comment', 'privacy_password', 'privacy_protocol', 'user']


class DiscoverySnmpcredential(SubObjects):
    _fields = ['comment', 'community_string']


class DiscoveryVlaninfo(SubObjects):
    _fields = ['id', 'name']


class DiscoveryVrfmappingrule(SubObjects):
    _fields = ['comment', 'criteria', 'network_view']


class Discoverytaskport(SubObjects):
    _fields = ['comment', 'number']


class Discoverytaskvserver(SubObjects):
    _fields = ['connection_protocol', 'disable', 'fqdn_or_ip', 'password', 'port', 'username']


class Dnsseckey(SubObjects):
    _fields = ['algorithm', 'next_event_date', 'public_key', 'status', 'tag', 'type']


class Dnssectrustedkey(SubObjects):
    _fields = ['algorithm', 'dnssec_must_be_secure', 'fqdn', 'key', 'secure_entry_point']


class DtcMonitorSnmpOid(SubObjects):
    _fields = ['comment', 'condition', 'first', 'last', 'oid', 'type']


class DtcPoolConsolidatedMonitorHealth(SubObjects):
    _fields = ['availability', 'members', 'monitor']


class DtcPoolLink(SubObjects):
    _fields = ['pool', 'ratio']


class DtcServerLink(SubObjects):
    _fields = ['ratio', 'server']


class DtcServerMonitor(SubObjects):
    _fields = ['host', 'monitor']


class DtcTopologyRuleSource(SubObjects):
    _fields = ['source_op', 'source_type', 'source_value']


class DxlEndpointBroker(SubObjects):
    _fields = ['address', 'host_name', 'port', 'unique_id']


class Exclusionrange(SubObjects):
    _fields = ['comment', 'end_address', 'start_address']


class Exclusionrangetemplate(SubObjects):
    _fields = ['comment', 'number_of_addresses', 'offset']


class ExtensibleattributedefListvalues(SubObjects):
    _fields = ['value']


class Extserver(SubObjects):
    _fields = ['address', 'name', 'shared_with_ms_parent_delegation', 'stealth', 'tsig_key', 'tsig_key_alg', 'tsig_key_name', 'use_tsig_key_name']


class Extsyslogbackupserver(SubObjects):
    _fields = ['address', 'directory_path', 'enable', 'password', 'port', 'protocol', 'username']


class Filterrule(SubObjects):
    _fields = ['filter', 'permission']


class Forwardingmemberserver(SubObjects):
    _fields = ['forward_to', 'forwarders_only', 'name', 'use_override_forwarders']


class GridCloudapiUser(SubObjects):
    _fields = ['is_remote', 'local_admin', 'remote_admin']


class GridDnsFixedrrsetorderfqdn(SubObjects):
    _fields = ['fqdn', 'record_type']


class GridLicensesubpool(SubObjects):
    _fields = ['expiry_date', 'installed', 'key']


class GridmemberSoamname(SubObjects):
    _fields = ['dns_mname', 'grid_primary', 'mname', 'ms_server_primary']


class GridmemberSoaserial(SubObjects):
    _fields = ['grid_primary', 'ms_server_primary', 'serial']


class Hotfix(SubObjects):
    _fields = ['status_text', 'unique_id']


class HsmSafenet(SubObjects):
    _fields = ['disable', 'is_fips_compliant', 'name', 'partition_capacity', 'partition_id', 'partition_serial_number', 'server_cert', 'status']


class HsmThales(SubObjects):
    _fields = ['disable', 'keyhash', 'remote_esn', 'remote_ip', 'remote_port', 'status']


class Interface(SubObjects):
    _fields = ['anycast', 'comment', 'enable_bgp', 'enable_ospf', 'interface', 'ipv4_network_setting', 'ipv6_network_setting']


class Ipv6Networksetting(SubObjects):
    _fields = ['address', 'cidr', 'gateway']


class LdapEamapping(SubObjects):
    _fields = ['mapped_ea', 'name']


class LdapServer(SubObjects):
    _fields = ['address', 'authentication_type', 'base_dn', 'bind_password', 'bind_user_dn', 'comment', 'disable', 'encryption', 'port', 'use_mgmt_port', 'version']


class Logicfilterrule(SubObjects):
    _fields = ['filter', 'type']


class Lomnetworkconfig(SubObjects):
    _fields = ['address', 'gateway', 'is_lom_capable', 'subnet_mask']


class Lomuser(SubObjects):
    _fields = ['comment', 'disable', 'name', 'password', 'role']


class MemberDnsgluerecordaddr(SubObjects):
    _fields = ['attach_empty_recursive_view', 'glue_address_choice', 'glue_record_address', 'view']


class MemberDnsip(SubObjects):
    _fields = ['ip_address', 'ipsd']


class Memberserver(SubObjects):
    _fields = ['enable_preferred_primaries', 'grid_replicate', 'lead', 'name', 'preferred_primaries', 'stealth']


class Memberservicecommunication(SubObjects):
    _fields = ['option', 'service', 'type']


class Memberservicestatus(SubObjects):
    _fields = ['description', 'service', 'status']


class Msdhcpoption(SubObjects):
    _fields = ['name', 'num', 'type', 'user_class', 'value', 'vendor_class']


class Msdhcpserver(SubObjects):
    _fields = ['ipv4addr', 'ipv4addr', 'ipv6addr', 'name']


class Msdnsserver(SubObjects):
    _fields = ['address', 'is_master', 'ns_ip', 'ns_name', 'shared_with_ms_parent_delegation', 'stealth']


class MsserverDcnsrecordcreation(SubObjects):
    _fields = ['address', 'comment']


class NetworkviewAssocmember(SubObjects):
    _fields = ['failovers', 'member']


class Nodeinfo(SubObjects):
    _fields = ['ha_status', 'hwid', 'hwmodel', 'hwplatform', 'hwtype', 'lan2_physical_setting', 'lan_ha_port_setting', 'mgmt_network_setting', 'mgmt_physical_setting', 'nat_external_ip', 'paid_nios', 'physical_oid', 'service_status', 'v6_mgmt_network_setting']


class NotificationRestTemplateparameter(SubObjects):
    _fields = ['default_value', 'name', 'syntax', 'value']


class NotificationRuleexpressionop(SubObjects):
    _fields = ['op', 'op1', 'op1_type', 'op2', 'op2_type']


class Nxdomainrule(SubObjects):
    _fields = ['action', 'pattern']


class OcspResponder(SubObjects):
    _fields = ['certificate', 'certificate_token', 'comment', 'disabled', 'fqdn_or_ip', 'port']


class Option60Matchrule(SubObjects):
    _fields = ['is_substring', 'match_value', 'option_space', 'substring_length', 'substring_offset']


class Ospf(SubObjects):
    _fields = ['advertise_interface_vlan', 'area_id', 'area_type', 'authentication_key', 'authentication_type', 'auto_calc_cost_enabled', 'bfd_template', 'comment', 'cost', 'dead_interval', 'enable_bfd', 'hello_interval', 'interface', 'is_ipv4', 'key_id', 'retransmit_interval', 'transmit_delay']


class OutboundCloudclientEvent(SubObjects):
    _fields = ['enabled', 'event_type']


class ParentalcontrolAbs(SubObjects):
    _fields = ['blocking_policy', 'ip_address']


class ParentalcontrolMsp(SubObjects):
    _fields = ['ip_address']


class ParentalcontrolNasgateway(SubObjects):
    _fields = ['comment', 'ip_address', 'message_rate', 'name', 'send_ack', 'shared_secret']


class ParentalcontrolSitemember(SubObjects):
    _fields = ['name', 'type']


class ParentalcontrolSpm(SubObjects):
    _fields = ['ip_address']


class RadiusServer(SubObjects):
    _fields = ['acct_port', 'address', 'auth_port', 'auth_type', 'comment', 'disable', 'shared_secret', 'use_accounting', 'use_mgmt_port']


class Rdatasubfield(SubObjects):
    _fields = ['field_type', 'field_value', 'include_length']


class Remoteddnszone(SubObjects):
    _fields = ['fqdn', 'gss_tsig_dns_principal', 'gss_tsig_domain', 'key_type', 'server_address', 'tsig_key', 'tsig_key_alg', 'tsig_key_name']


class SettingNetwork(SubObjects):
    _fields = ['address', 'dscp', 'gateway', 'primary', 'subnet_mask', 'use_dscp', 'vlan_id']


class SettingViewaddress(SubObjects):
    _fields = ['dns_notify_transfer_source', 'dns_notify_transfer_source_address', 'dns_query_source_address', 'dns_query_source_interface', 'enable_notify_source_port', 'enable_query_source_port', 'notify_delay', 'notify_source_port', 'query_source_port', 'use_notify_delay', 'use_source_ports', 'view_name']


class SmartfolderGroupby(SubObjects):
    _fields = ['enable_grouping', 'value', 'value_type']


class SmartfolderQueryitem(SubObjects):
    _fields = ['field_type', 'name', 'op_match', 'operator', 'value', 'value_type']


class Sortlist(SubObjects):
    _fields = ['address', 'match_list']


class SyslogEndpointServers(SubObjects):
    _fields = ['address', 'certificate', 'certificate_token', 'connection_type', 'facility', 'format', 'hostname', 'port', 'severity']


class Syslogserver(SubObjects):
    _fields = ['address', 'category_list', 'certificate', 'certificate_token', 'connection_type', 'local_interface', 'message_node_id', 'message_source', 'only_category_list', 'port', 'severity']


class TacacsplusServer(SubObjects):
    _fields = ['address', 'auth_type', 'comment', 'disable', 'port', 'shared_secret', 'use_accounting', 'use_mgmt_port']


class TaxiiRpzconfig(SubObjects):
    _fields = ['collection_name', 'zone']


class ThreatprotectionNatrule(SubObjects):
    _fields = ['address', 'cidr', 'end_address', 'nat_ports', 'network', 'rule_type', 'start_address']


class ThreatprotectionStatinfo(SubObjects):
    _fields = ['critical', 'informational', 'major', 'timestamp', 'total', 'warning']


class Thresholdtrap(SubObjects):
    _fields = ['trap_reset', 'trap_trigger', 'trap_type']


class Trapnotification(SubObjects):
    _fields = ['enable_email', 'enable_trap', 'trap_type']


class Updatesdownloadmemberconfig(SubObjects):
    _fields = ['interface', 'is_online', 'member']


class UpgradegroupMember(SubObjects):
    _fields = ['member', 'time_zone']


class UpgradegroupSchedule(SubObjects):
    _fields = ['distribution_dependent_group', 'distribution_time', 'name', 'time_zone', 'upgrade_dependent_group', 'upgrade_time']


class Upgradestep(SubObjects):
    _fields = ['status_text', 'status_value']


class Vlanlink(SubObjects):
    _fields = ['id', 'name', 'vlan']


class Vtftpdirmember(SubObjects):
    _fields = ['address', 'cidr', 'end_address', 'ip_type', 'member', 'network', 'start_address']


class Zoneassociation(SubObjects):
    _fields = ['fqdn', 'is_default', 'view']


class Zonenameserver(SubObjects):
    _fields = ['address', 'auto_create_ptr']


class AdAuthService(InfobloxObject):
    _infoblox_type = 'ad_auth_service'
    _fields = ['ad_domain', 'additional_search_paths', 'comment', 'disable_default_search_path', 'disabled', 'domain_controllers', 'name', 'nested_group_querying', 'timeout']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['ad_domain', 'comment', 'name']
    _all_searchable_fields = ['ad_domain', 'comment', 'name']
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'domain_controllers': AdAuthServer.from_dict,
    }


class Admingroup(InfobloxObject):
    _infoblox_type = 'admingroup'
    _fields = ['access_method', 'admin_set_commands', 'admin_show_commands', 'admin_toplevel_commands', 'cloud_set_commands', 'comment', 'database_set_commands', 'database_show_commands', 'dhcp_set_commands', 'dhcp_show_commands', 'disable', 'disable_concurrent_login', 'dns_set_commands', 'dns_show_commands', 'dns_toplevel_commands', 'docker_set_commands', 'docker_show_commands', 'email_addresses', 'enable_restricted_user_access', 'extattrs', 'grid_set_commands', 'grid_show_commands', 'inactivity_lockout_setting', 'licensing_set_commands', 'licensing_show_commands', 'lockout_setting', 'machine_control_toplevel_commands', 'name', 'networking_set_commands', 'networking_show_commands', 'password_setting', 'roles', 'saml_setting', 'security_set_commands', 'security_show_commands', 'superuser', 'trouble_shooting_toplevel_commands', 'use_account_inactivity_lockout_enable', 'use_disable_concurrent_login', 'use_lockout_setting', 'use_password_setting', 'user_access']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name', 'roles', 'superuser']
    _all_searchable_fields = ['comment', 'name', 'roles', 'superuser']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'user_access': Addressac.from_dict,
    }


class Adminrole(InfobloxObject):
    _infoblox_type = 'adminrole'
    _fields = ['comment', 'disable', 'extattrs', 'name']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Adminuser(InfobloxObject):
    _infoblox_type = 'adminuser'
    _fields = ['admin_groups', 'auth_type', 'ca_certificate_issuer', 'client_certificate_serial_number', 'comment', 'disable', 'email', 'enable_certificate_authentication', 'extattrs', 'name', 'password', 'status', 'time_zone', 'use_time_zone']
    _search_for_update_fields = ['admin_groups', 'comment', 'name']
    _updateable_search_fields = ['admin_groups', 'ca_certificate_issuer', 'client_certificate_serial_number', 'comment', 'name']
    _all_searchable_fields = ['admin_groups', 'ca_certificate_issuer', 'client_certificate_serial_number', 'comment', 'name', 'status']
    _return_fields = ['admin_groups', 'comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Allendpoints(InfobloxObject):
    _infoblox_type = 'allendpoints'
    _fields = ['address', 'comment', 'disable', 'subscribing_member', 'type', 'version']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'comment', 'subscribing_member', 'type', 'version']
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']


class Allnsgroup(InfobloxObject):
    _infoblox_type = 'allnsgroup'
    _fields = ['comment', 'name', 'type']
    _search_for_update_fields = ['name', 'type']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'name', 'type']
    _return_fields = ['name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']


class Allrecords(InfobloxObject):
    _infoblox_type = 'allrecords'
    _fields = ['address', 'comment', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dtc_obscured', 'name', 'reclaimable', 'record', 'ttl', 'type', 'view', 'zone']
    _search_for_update_fields = ['comment', 'name', 'type', 'view', 'zone']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'name', 'reclaimable', 'type', 'view', 'zone']
    _return_fields = ['comment', 'name', 'type', 'view', 'zone']
    _remap = {}
    _shadow_fields = ['_ref']


class Allrpzrecords(InfobloxObject):
    _infoblox_type = 'allrpzrecords'
    _fields = ['alert_type', 'comment', 'disable', 'expiration_time', 'last_updated', 'name', 'record', 'rpz_rule', 'ttl', 'type', 'view', 'zone']
    _search_for_update_fields = ['name', 'type', 'view', 'zone']
    _updateable_search_fields = []
    _all_searchable_fields = ['name', 'rpz_rule', 'type', 'view', 'zone']
    _return_fields = ['comment', 'name', 'type', 'view', 'zone']
    _remap = {}
    _shadow_fields = ['_ref']


class Approvalworkflow(InfobloxObject):
    _infoblox_type = 'approvalworkflow'
    _fields = ['approval_group', 'approval_notify_to', 'approved_notify_to', 'approver_comment', 'enable_approval_notify', 'enable_approved_notify', 'enable_failed_notify', 'enable_notify_group', 'enable_notify_user', 'enable_rejected_notify', 'enable_rescheduled_notify', 'enable_succeeded_notify', 'extattrs', 'failed_notify_to', 'rejected_notify_to', 'rescheduled_notify_to', 'submitter_comment', 'submitter_group', 'succeeded_notify_to', 'ticket_number']
    _search_for_update_fields = ['approval_group', 'submitter_group']
    _updateable_search_fields = ['approval_group']
    _all_searchable_fields = ['approval_group', 'submitter_group']
    _return_fields = ['approval_group', 'extattrs', 'submitter_group']
    _remap = {}
    _shadow_fields = ['_ref']


class Authpolicy(InfobloxObject):
    _infoblox_type = 'authpolicy'
    _fields = ['admin_groups', 'auth_services', 'default_group', 'usage_type']
    _search_for_update_fields = ['default_group', 'usage_type']
    _updateable_search_fields = ['default_group', 'usage_type']
    _all_searchable_fields = ['default_group', 'usage_type']
    _return_fields = ['default_group', 'usage_type']
    _remap = {}
    _shadow_fields = ['_ref']


class Awsrte53Taskgroup(InfobloxObject):
    _infoblox_type = 'awsrte53taskgroup'
    _fields = ['account_id', 'comment', 'consolidate_zones', 'consolidated_view', 'disabled', 'grid_member', 'name', 'network_view', 'network_view_mapping_policy', 'sync_status', 'task_list']
    _search_for_update_fields = ['account_id', 'comment', 'disabled', 'name', 'sync_status']
    _updateable_search_fields = ['comment', 'disabled', 'grid_member', 'name']
    _all_searchable_fields = ['account_id', 'comment', 'consolidate_zones', 'consolidated_view', 'disabled', 'grid_member', 'name', 'network_view', 'network_view_mapping_policy', 'sync_status']
    _return_fields = ['account_id', 'comment', 'disabled', 'name', 'sync_status']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'task_list': Awsrte53Task.from_dict,
    }

    def task_control(self, *args, **kwargs):
        return self._call_func("task_control", *args, **kwargs)


class Awsuser(InfobloxObject):
    _infoblox_type = 'awsuser'
    _fields = ['access_key_id', 'account_id', 'last_used', 'name', 'nios_user_name', 'secret_access_key', 'status']
    _search_for_update_fields = ['access_key_id', 'account_id', 'name']
    _updateable_search_fields = ['access_key_id', 'account_id', 'name', 'nios_user_name']
    _all_searchable_fields = ['access_key_id', 'account_id', 'name', 'nios_user_name', 'status']
    _return_fields = ['access_key_id', 'account_id', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Bfdtemplate(InfobloxObject):
    _infoblox_type = 'bfdtemplate'
    _fields = ['authentication_key', 'authentication_key_id', 'authentication_type', 'detection_multiplier', 'min_rx_interval', 'min_tx_interval', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name']
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']


class Bulkhost(InfobloxObject):
    _infoblox_type = 'bulkhost'
    _fields = ['cloud_info', 'comment', 'disable', 'dns_prefix', 'end_addr', 'extattrs', 'last_queried', 'name_template', 'network_view', 'policy', 'prefix', 'reverse', 'start_addr', 'template_format', 'ttl', 'use_name_template', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['comment', 'prefix']
    _updateable_search_fields = ['comment', 'disable', 'end_addr', 'name_template', 'prefix', 'reverse', 'start_addr', 'ttl', 'use_name_template', 'view', 'zone']
    _all_searchable_fields = ['comment', 'disable', 'end_addr', 'name_template', 'prefix', 'reverse', 'start_addr', 'ttl', 'use_name_template', 'view', 'zone']
    _return_fields = ['comment', 'extattrs', 'prefix']
    _remap = {}
    _shadow_fields = ['_ref']


class Bulkhostnametemplate(InfobloxObject):
    _infoblox_type = 'bulkhostnametemplate'
    _fields = ['is_grid_default', 'pre_defined', 'template_format', 'template_name']
    _search_for_update_fields = ['template_format', 'template_name']
    _updateable_search_fields = ['template_format', 'template_name']
    _all_searchable_fields = ['template_format', 'template_name']
    _return_fields = ['is_grid_default', 'template_format', 'template_name']
    _remap = {}
    _shadow_fields = ['_ref']


class Cacertificate(InfobloxObject):
    _infoblox_type = 'cacertificate'
    _fields = ['distinguished_name', 'issuer', 'serial', 'used_by', 'valid_not_after', 'valid_not_before']
    _search_for_update_fields = ['distinguished_name', 'issuer', 'serial']
    _updateable_search_fields = []
    _all_searchable_fields = ['distinguished_name', 'issuer', 'serial']
    _return_fields = ['distinguished_name', 'issuer', 'serial', 'used_by', 'valid_not_after', 'valid_not_before']
    _remap = {}
    _shadow_fields = ['_ref']


class Capacityreport(InfobloxObject):
    _infoblox_type = 'capacityreport'
    _fields = ['hardware_type', 'max_capacity', 'name', 'object_counts', 'percent_used', 'role', 'total_objects']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['name', 'percent_used', 'role']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'object_counts': CapacityreportObjectcount.from_dict,
    }


class Captiveportal(InfobloxObject):
    _infoblox_type = 'captiveportal'
    _fields = ['authn_server_group', 'company_name', 'enable_syslog_auth_failure', 'enable_syslog_auth_success', 'enable_user_type', 'encryption', 'files', 'guest_custom_field1_name', 'guest_custom_field1_required', 'guest_custom_field2_name', 'guest_custom_field2_required', 'guest_custom_field3_name', 'guest_custom_field3_required', 'guest_custom_field4_name', 'guest_custom_field4_required', 'guest_email_required', 'guest_first_name_required', 'guest_last_name_required', 'guest_middle_name_required', 'guest_phone_required', 'helpdesk_message', 'listen_address_ip', 'listen_address_type', 'name', 'network_view', 'port', 'service_enabled', 'syslog_auth_failure_level', 'syslog_auth_success_level', 'welcome_message']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'files': CaptiveportalFile.from_dict,
    }


class CertificateAuthservice(InfobloxObject):
    _infoblox_type = 'certificate:authservice'
    _fields = ['auto_populate_login', 'ca_certificates', 'comment', 'disabled', 'enable_password_request', 'enable_remote_lookup', 'max_retries', 'name', 'ocsp_check', 'ocsp_responders', 'recovery_interval', 'remote_lookup_password', 'remote_lookup_service', 'remote_lookup_username', 'response_timeout', 'trust_model', 'user_match_type']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ocsp_responders': OcspResponder.from_dict,
    }

    def test_ocsp_responder_settings(self, *args, **kwargs):
        return self._call_func("test_ocsp_responder_settings", *args, **kwargs)


class CiscoiseEndpoint(InfobloxObject):
    _infoblox_type = 'ciscoise:endpoint'
    _fields = ['address', 'bulk_download_certificate_subject', 'bulk_download_certificate_token', 'bulk_download_certificate_valid_from', 'bulk_download_certificate_valid_to', 'client_certificate_subject', 'client_certificate_token', 'client_certificate_valid_from', 'client_certificate_valid_to', 'comment', 'connection_status', 'connection_timeout', 'disable', 'extattrs', 'network_view', 'publish_settings', 'resolved_address', 'resolved_secondary_address', 'secondary_address', 'subscribe_settings', 'subscribing_member', 'type', 'version']
    _search_for_update_fields = ['address', 'resolved_address', 'type', 'version']
    _updateable_search_fields = ['address', 'comment', 'network_view', 'secondary_address', 'subscribing_member', 'type', 'version']
    _all_searchable_fields = ['address', 'comment', 'network_view', 'resolved_address', 'resolved_secondary_address', 'secondary_address', 'subscribing_member', 'type', 'version']
    _return_fields = ['address', 'disable', 'extattrs', 'resolved_address', 'type', 'version']
    _remap = {}
    _shadow_fields = ['_ref']

    def test_connection(self, *args, **kwargs):
        return self._call_func("test_connection", *args, **kwargs)


class Csvimporttask(InfobloxObject):
    _infoblox_type = 'csvimporttask'
    _fields = ['action', 'admin_name', 'end_time', 'file_name', 'file_size', 'import_id', 'lines_failed', 'lines_processed', 'lines_warning', 'on_error', 'operation', 'separator', 'start_time', 'status', 'update_method']
    _search_for_update_fields = ['import_id']
    _updateable_search_fields = []
    _all_searchable_fields = ['import_id']
    _return_fields = ['action', 'admin_name', 'end_time', 'file_name', 'file_size', 'import_id', 'lines_failed', 'lines_processed', 'lines_warning', 'on_error', 'operation', 'separator', 'start_time', 'status', 'update_method']
    _remap = {}
    _shadow_fields = ['_ref']

    def stop(self, *args, **kwargs):
        return self._call_func("stop", *args, **kwargs)


class DbObjects(InfobloxObject):
    _infoblox_type = 'db_objects'
    _fields = ['last_sequence_id', 'object', 'object_type', 'unique_id']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['last_sequence_id', 'object', 'object_type', 'unique_id']
    _remap = {}
    _shadow_fields = ['_ref']


class Dbsnapshot(InfobloxObject):
    _infoblox_type = 'dbsnapshot'
    _fields = ['comment', 'timestamp']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['comment', 'timestamp']
    _remap = {}
    _shadow_fields = ['_ref']

    def rollback_db_snapshot(self, *args, **kwargs):
        return self._call_func("rollback_db_snapshot", *args, **kwargs)

    def save_db_snapshot(self, *args, **kwargs):
        return self._call_func("save_db_snapshot", *args, **kwargs)


class DdnsPrincipalcluster(InfobloxObject):
    _infoblox_type = 'ddns:principalcluster'
    _fields = ['comment', 'group', 'name', 'principals']
    _search_for_update_fields = ['comment', 'group', 'name']
    _updateable_search_fields = ['comment', 'group', 'name']
    _all_searchable_fields = ['comment', 'group', 'name']
    _return_fields = ['comment', 'group', 'name', 'principals']
    _remap = {}
    _shadow_fields = ['_ref']


class DdnsPrincipalclusterGroup(InfobloxObject):
    _infoblox_type = 'ddns:principalcluster:group'
    _fields = ['clusters', 'comment', 'name']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DeletedObjects(InfobloxObject):
    _infoblox_type = 'deleted_objects'
    _fields = ['object_type']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['object_type']
    _remap = {}
    _shadow_fields = ['_ref']


class DhcpStatistics(InfobloxObject):
    _infoblox_type = 'dhcp:statistics'
    _fields = ['dhcp_utilization', 'dhcp_utilization_status', 'dynamic_hosts', 'static_hosts', 'total_hosts']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['dhcp_utilization', 'dhcp_utilization_status', 'dynamic_hosts', 'static_hosts', 'total_hosts']
    _remap = {}
    _shadow_fields = ['_ref']


class Dhcpfailover(InfobloxObject):
    _infoblox_type = 'dhcpfailover'
    _fields = ['association_type', 'comment', 'extattrs', 'failover_port', 'load_balance_split', 'max_client_lead_time', 'max_load_balance_delay', 'max_response_delay', 'max_unacked_updates', 'ms_association_mode', 'ms_enable_authentication', 'ms_enable_switchover_interval', 'ms_failover_mode', 'ms_failover_partner', 'ms_hotstandby_partner_role', 'ms_is_conflict', 'ms_previous_state', 'ms_server', 'ms_shared_secret', 'ms_state', 'ms_switchover_interval', 'name', 'primary', 'primary_server_type', 'primary_state', 'recycle_leases', 'secondary', 'secondary_server_type', 'secondary_state', 'use_failover_port', 'use_ms_switchover_interval', 'use_recycle_leases']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    def set_dhcp_failover_partner_down(self, *args, **kwargs):
        return self._call_func("set_dhcp_failover_partner_down", *args, **kwargs)

    def set_dhcp_failover_secondary_recovery(self, *args, **kwargs):
        return self._call_func("set_dhcp_failover_secondary_recovery", *args, **kwargs)


class DhcpOptionDefinition(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return DhcpOptionDefinitionV4

    @classmethod
    def get_v6_class(cls):
        return DhcpOptionDefinitionV6


class DhcpOptionDefinitionV4(DhcpOptionDefinition):
    _infoblox_type = 'dhcpoptiondefinition'
    _fields = ['code', 'name', 'space', 'type']
    _search_for_update_fields = ['code', 'name', 'type']
    _updateable_search_fields = ['code', 'name', 'space', 'type']
    _all_searchable_fields = ['code', 'name', 'space', 'type']
    _return_fields = ['code', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4



class DhcpOptionDefinitionV6(DhcpOptionDefinition):
    _infoblox_type = 'ipv6dhcpoptiondefinition'
    _fields = ['code', 'name', 'space', 'type']
    _search_for_update_fields = ['code', 'name', 'type']
    _updateable_search_fields = ['code', 'name', 'space', 'type']
    _all_searchable_fields = ['code', 'name', 'space', 'type']
    _return_fields = ['code', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6


class DhcpOptionSpace(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return DhcpOptionSpaceV4

    @classmethod
    def get_v6_class(cls):
        return DhcpOptionSpaceV6


class DhcpOptionSpaceV4(DhcpOptionSpace):
    _infoblox_type = 'dhcpoptionspace'
    _fields = ['comment', 'name', 'option_definitions', 'space_type']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4



class DhcpOptionSpaceV6(DhcpOptionSpace):
    _infoblox_type = 'ipv6dhcpoptionspace'
    _fields = ['comment', 'enterprise_number', 'name', 'option_definitions']
    _search_for_update_fields = ['comment', 'enterprise_number', 'name']
    _updateable_search_fields = ['comment', 'enterprise_number', 'name']
    _all_searchable_fields = ['comment', 'enterprise_number', 'name']
    _return_fields = ['comment', 'enterprise_number', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6


class Discovery(InfobloxObject):
    _infoblox_type = 'discovery'
    _fields = []
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    def clear_network_port_assignment(self, *args, **kwargs):
        return self._call_func("clear_network_port_assignment", *args, **kwargs)

    def control_switch_port(self, *args, **kwargs):
        return self._call_func("control_switch_port", *args, **kwargs)

    def discovery_data_conversion(self, *args, **kwargs):
        return self._call_func("discovery_data_conversion", *args, **kwargs)

    def get_device_support_info(self, *args, **kwargs):
        return self._call_func("get_device_support_info", *args, **kwargs)

    def get_job_devices(self, *args, **kwargs):
        return self._call_func("get_job_devices", *args, **kwargs)

    def get_job_process_details(self, *args, **kwargs):
        return self._call_func("get_job_process_details", *args, **kwargs)

    def import_device_support_bundle(self, *args, **kwargs):
        return self._call_func("import_device_support_bundle", *args, **kwargs)

    def modify_sdn_assignment(self, *args, **kwargs):
        return self._call_func("modify_sdn_assignment", *args, **kwargs)

    def modify_vrf_assignment(self, *args, **kwargs):
        return self._call_func("modify_vrf_assignment", *args, **kwargs)

    def provision_network_dhcp_relay(self, *args, **kwargs):
        return self._call_func("provision_network_dhcp_relay", *args, **kwargs)

    def provision_network_port(self, *args, **kwargs):
        return self._call_func("provision_network_port", *args, **kwargs)


class DiscoveryDevice(InfobloxObject):
    _infoblox_type = 'discovery:device'
    _fields = ['address', 'address_ref', 'available_mgmt_ips', 'cap_admin_status_ind', 'cap_admin_status_na_reason', 'cap_description_ind', 'cap_description_na_reason', 'cap_net_deprovisioning_ind', 'cap_net_deprovisioning_na_reason', 'cap_net_provisioning_ind', 'cap_net_provisioning_na_reason', 'cap_net_vlan_provisioning_ind', 'cap_net_vlan_provisioning_na_reason', 'cap_vlan_assignment_ind', 'cap_vlan_assignment_na_reason', 'cap_voice_vlan_ind', 'cap_voice_vlan_na_reason', 'chassis_serial_number', 'description', 'extattrs', 'interfaces', 'location', 'model', 'ms_ad_user_data', 'name', 'neighbors', 'network', 'network_infos', 'network_view', 'networks', 'os_version', 'port_stats', 'type', 'user_defined_mgmt_ip', 'vendor', 'vlan_infos']
    _search_for_update_fields = ['address', 'name', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'chassis_serial_number', 'location', 'model', 'name', 'network_view', 'os_version', 'type', 'vendor']
    _return_fields = ['address', 'extattrs', 'name', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'network_infos': DiscoveryNetworkinfo.from_dict,
        'vlan_infos': DiscoveryVlaninfo.from_dict,
    }


class DiscoveryDevicecomponent(InfobloxObject):
    _infoblox_type = 'discovery:devicecomponent'
    _fields = ['component_name', 'description', 'device', 'model', 'serial', 'type']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = ['device']
    _return_fields = ['component_name', 'description', 'model', 'serial', 'type']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryDeviceinterface(InfobloxObject):
    _infoblox_type = 'discovery:deviceinterface'
    _fields = ['admin_status', 'admin_status_task_info', 'cap_if_admin_status_ind', 'cap_if_admin_status_na_reason', 'cap_if_description_ind', 'cap_if_description_na_reason', 'cap_if_net_deprovisioning_ipv4_ind', 'cap_if_net_deprovisioning_ipv4_na_reason', 'cap_if_net_deprovisioning_ipv6_ind', 'cap_if_net_deprovisioning_ipv6_na_reason', 'cap_if_net_provisioning_ipv4_ind', 'cap_if_net_provisioning_ipv4_na_reason', 'cap_if_net_provisioning_ipv6_ind', 'cap_if_net_provisioning_ipv6_na_reason', 'cap_if_vlan_assignment_ind', 'cap_if_vlan_assignment_na_reason', 'cap_if_voice_vlan_ind', 'cap_if_voice_vlan_na_reason', 'description', 'description_task_info', 'device', 'duplex', 'extattrs', 'ifaddr_infos', 'index', 'last_change', 'link_aggregation', 'mac', 'ms_ad_user_data', 'name', 'network_view', 'oper_status', 'port_fast', 'reserved_object', 'speed', 'trunk_status', 'type', 'vlan_info_task_info', 'vlan_infos', 'vrf_description', 'vrf_name', 'vrf_rd']
    _search_for_update_fields = ['name', 'type']
    _updateable_search_fields = []
    _all_searchable_fields = ['description', 'mac', 'name', 'network_view', 'oper_status', 'speed', 'type', 'vrf_description', 'vrf_name', 'vrf_rd']
    _return_fields = ['extattrs', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ifaddr_infos': DiscoveryIfaddrinfo.from_dict,
        'vlan_infos': DiscoveryVlaninfo.from_dict,
    }


class DiscoveryDeviceneighbor(InfobloxObject):
    _infoblox_type = 'discovery:deviceneighbor'
    _fields = ['address', 'address_ref', 'device', 'interface', 'mac', 'name', 'vlan_infos']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = ['device']
    _return_fields = ['address', 'address_ref', 'mac', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'vlan_infos': DiscoveryVlaninfo.from_dict,
    }


class DiscoveryDevicesupportbundle(InfobloxObject):
    _infoblox_type = 'discovery:devicesupportbundle'
    _fields = ['author', 'integrated_ind', 'name', 'version']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['author', 'integrated_ind', 'name', 'version']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryDiagnostictask(InfobloxObject):
    _infoblox_type = 'discovery:diagnostictask'
    _fields = ['community_string', 'debug_snmp', 'force_test', 'ip_address', 'network_view', 'start_time', 'task_id']
    _search_for_update_fields = ['ip_address', 'network_view', 'task_id']
    _updateable_search_fields = ['ip_address', 'network_view', 'task_id']
    _all_searchable_fields = ['ip_address', 'network_view', 'task_id']
    _return_fields = ['ip_address', 'network_view', 'task_id']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryGridproperties(InfobloxObject):
    _infoblox_type = 'discovery:gridproperties'
    _fields = ['advanced_polling_settings', 'advanced_sdn_polling_settings', 'advisor_settings', 'auto_conversion_settings', 'basic_polling_settings', 'basic_sdn_polling_settings', 'cli_credentials', 'discovery_blackout_setting', 'dns_lookup_option', 'dns_lookup_throttle', 'enable_advisor', 'enable_auto_conversion', 'enable_auto_updates', 'grid_name', 'ignore_conflict_duration', 'port_control_blackout_setting', 'ports', 'same_port_control_discovery_blackout', 'snmpv1v2_credentials', 'snmpv3_credentials', 'unmanaged_ips_limit', 'unmanaged_ips_timeout', 'vrf_mapping_policy', 'vrf_mapping_rules']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['grid_name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'auto_conversion_settings': DiscoveryAutoconversionsetting.from_dict,
        'cli_credentials': DiscoveryClicredential.from_dict,
        'ports': DiscoveryPort.from_dict,
        'snmpv1v2_credentials': DiscoverySnmpcredential.from_dict,
        'snmpv3_credentials': DiscoverySnmp3Credential.from_dict,
        'vrf_mapping_rules': DiscoveryVrfmappingrule.from_dict,
    }

    def advisor_run_now(self, *args, **kwargs):
        return self._call_func("advisor_run_now", *args, **kwargs)

    def advisor_test_connection(self, *args, **kwargs):
        return self._call_func("advisor_test_connection", *args, **kwargs)

    def diagnostic(self, *args, **kwargs):
        return self._call_func("diagnostic", *args, **kwargs)

    def diagnostic_status(self, *args, **kwargs):
        return self._call_func("diagnostic_status", *args, **kwargs)


class DiscoveryMemberproperties(InfobloxObject):
    _infoblox_type = 'discovery:memberproperties'
    _fields = ['address', 'cli_credentials', 'default_seed_routers', 'discovery_member', 'enable_service', 'gateway_seed_routers', 'is_sa', 'role', 'scan_interfaces', 'sdn_configs', 'seed_routers', 'snmpv1v2_credentials', 'snmpv3_credentials', 'use_cli_credentials', 'use_snmpv1v2_credentials', 'use_snmpv3_credentials']
    _search_for_update_fields = ['discovery_member']
    _updateable_search_fields = ['enable_service', 'is_sa', 'role']
    _all_searchable_fields = ['discovery_member', 'enable_service', 'is_sa', 'role']
    _return_fields = ['discovery_member']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'cli_credentials': DiscoveryClicredential.from_dict,
        'default_seed_routers': DiscoverySeedrouter.from_dict,
        'gateway_seed_routers': DiscoverySeedrouter.from_dict,
        'scan_interfaces': DiscoveryScaninterface.from_dict,
        'sdn_configs': DiscoverySdnconfig.from_dict,
        'seed_routers': DiscoverySeedrouter.from_dict,
        'snmpv1v2_credentials': DiscoverySnmpcredential.from_dict,
        'snmpv3_credentials': DiscoverySnmp3Credential.from_dict,
    }


class DiscoverySdnnetwork(InfobloxObject):
    _infoblox_type = 'discovery:sdnnetwork'
    _fields = ['first_seen', 'name', 'network_view', 'source_sdn_config']
    _search_for_update_fields = ['name', 'network_view', 'source_sdn_config']
    _updateable_search_fields = []
    _all_searchable_fields = ['name', 'network_view', 'source_sdn_config']
    _return_fields = ['name', 'network_view', 'source_sdn_config']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryStatus(InfobloxObject):
    _infoblox_type = 'discovery:status'
    _fields = ['address', 'cli_collection_enabled', 'cli_credential_info', 'existence_info', 'fingerprint_enabled', 'fingerprint_info', 'first_seen', 'last_action', 'last_seen', 'last_timestamp', 'name', 'network_view', 'reachable_info', 'sdn_collection_enabled', 'sdn_collection_info', 'snmp_collection_enabled', 'snmp_collection_info', 'snmp_credential_info', 'status', 'type']
    _search_for_update_fields = ['address', 'name', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'name', 'network_view']
    _return_fields = ['address', 'name', 'network_view', 'status']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryVrf(InfobloxObject):
    _infoblox_type = 'discovery:vrf'
    _fields = ['description', 'device', 'name', 'network_view', 'route_distinguisher']
    _search_for_update_fields = ['name', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['name', 'network_view']
    _return_fields = ['device', 'name', 'network_view', 'route_distinguisher']
    _remap = {}
    _shadow_fields = ['_ref']


class Discoverytask(InfobloxObject):
    _infoblox_type = 'discoverytask'
    _fields = ['csv_file_name', 'disable_ip_scanning', 'disable_vmware_scanning', 'discovery_task_oid', 'member_name', 'merge_data', 'mode', 'network_view', 'networks', 'ping_retries', 'ping_timeout', 'scheduled_run', 'state', 'state_time', 'status', 'status_time', 'tcp_ports', 'tcp_scan_technique', 'v_network_view', 'vservers', 'warning']
    _search_for_update_fields = ['discovery_task_oid']
    _updateable_search_fields = []
    _all_searchable_fields = ['discovery_task_oid']
    _return_fields = ['discovery_task_oid', 'member_name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'tcp_ports': Discoverytaskport.from_dict,
        'vservers': Discoverytaskvserver.from_dict,
    }

    def network_discovery_control(self, *args, **kwargs):
        return self._call_func("network_discovery_control", *args, **kwargs)


class Distributionschedule(InfobloxObject):
    _infoblox_type = 'distributionschedule'
    _fields = ['active', 'start_time', 'time_zone', 'upgrade_groups']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['active', 'start_time', 'time_zone']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'upgrade_groups': UpgradegroupSchedule.from_dict,
    }


class Dns64Group(InfobloxObject):
    _infoblox_type = 'dns64group'
    _fields = ['clients', 'comment', 'disable', 'enable_dnssec_dns64', 'exclude', 'extattrs', 'mapped', 'name', 'prefix']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name', 'prefix']
    _all_searchable_fields = ['comment', 'name', 'prefix']
    _return_fields = ['comment', 'disable', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'clients': Addressac.from_dict,
        'exclude': Addressac.from_dict,
        'mapped': Addressac.from_dict,
    }


class Dtc(InfobloxObject):
    _infoblox_type = 'dtc'
    _fields = []
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    def add_certificate(self, *args, **kwargs):
        return self._call_func("add_certificate", *args, **kwargs)

    def generate_ea_topology_db(self, *args, **kwargs):
        return self._call_func("generate_ea_topology_db", *args, **kwargs)

    def import_maxminddb(self, *args, **kwargs):
        return self._call_func("import_maxminddb", *args, **kwargs)

    def query(self, *args, **kwargs):
        return self._call_func("query", *args, **kwargs)


class DtcAllrecords(InfobloxObject):
    _infoblox_type = 'dtc:allrecords'
    _fields = ['comment', 'disable', 'dtc_server', 'record', 'ttl', 'type']
    _search_for_update_fields = ['comment', 'dtc_server', 'type']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'dtc_server', 'type']
    _return_fields = ['comment', 'dtc_server', 'type']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcCertificate(InfobloxObject):
    _infoblox_type = 'dtc:certificate'
    _fields = ['certificate', 'in_use']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']


class DtcLbdn(InfobloxObject):
    _infoblox_type = 'dtc:lbdn'
    _fields = ['auth_zones', 'comment', 'disable', 'extattrs', 'health', 'lb_method', 'name', 'patterns', 'persistence', 'pools', 'priority', 'topology', 'ttl', 'types', 'use_ttl']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'pools': DtcPoolLink.from_dict,
    }


class DtcMonitor(InfobloxObject):
    _infoblox_type = 'dtc:monitor'
    _fields = ['comment', 'extattrs', 'interval', 'monitor', 'name', 'port', 'retry_down', 'retry_up', 'timeout', 'type']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorHttp(InfobloxObject):
    _infoblox_type = 'dtc:monitor:http'
    _fields = ['ciphers', 'client_cert', 'comment', 'content_check', 'content_check_input', 'content_check_op', 'content_check_regex', 'content_extract_group', 'content_extract_type', 'content_extract_value', 'enable_sni', 'extattrs', 'interval', 'name', 'port', 'request', 'result', 'result_code', 'retry_down', 'retry_up', 'secure', 'timeout', 'validate_cert']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorIcmp(InfobloxObject):
    _infoblox_type = 'dtc:monitor:icmp'
    _fields = ['comment', 'extattrs', 'interval', 'name', 'retry_down', 'retry_up', 'timeout']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorPdp(InfobloxObject):
    _infoblox_type = 'dtc:monitor:pdp'
    _fields = ['comment', 'extattrs', 'interval', 'name', 'port', 'retry_down', 'retry_up', 'timeout']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorSip(InfobloxObject):
    _infoblox_type = 'dtc:monitor:sip'
    _fields = ['ciphers', 'client_cert', 'comment', 'extattrs', 'interval', 'name', 'port', 'request', 'result', 'result_code', 'retry_down', 'retry_up', 'timeout', 'transport', 'validate_cert']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorSnmp(InfobloxObject):
    _infoblox_type = 'dtc:monitor:snmp'
    _fields = ['comment', 'community', 'context', 'engine_id', 'extattrs', 'interval', 'name', 'oids', 'port', 'retry_down', 'retry_up', 'timeout', 'user', 'version']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'context', 'engine_id', 'name']
    _all_searchable_fields = ['comment', 'context', 'engine_id', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'oids': DtcMonitorSnmpOid.from_dict,
    }


class DtcMonitorTcp(InfobloxObject):
    _infoblox_type = 'dtc:monitor:tcp'
    _fields = ['comment', 'extattrs', 'interval', 'name', 'port', 'retry_down', 'retry_up', 'timeout']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcObject(InfobloxObject):
    _infoblox_type = 'dtc:object'
    _fields = ['abstract_type', 'comment', 'display_type', 'extattrs', 'ipv4_address_list', 'ipv6_address_list', 'name', 'object', 'status', 'status_time']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['abstract_type', 'comment', 'display_type', 'extattrs', 'name', 'status']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcPool(InfobloxObject):
    _infoblox_type = 'dtc:pool'
    _fields = ['availability', 'comment', 'consolidated_monitors', 'disable', 'extattrs', 'health', 'lb_alternate_method', 'lb_alternate_topology', 'lb_dynamic_ratio_alternate', 'lb_dynamic_ratio_preferred', 'lb_preferred_method', 'lb_preferred_topology', 'monitors', 'name', 'quorum', 'servers', 'ttl', 'use_ttl']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'consolidated_monitors': DtcPoolConsolidatedMonitorHealth.from_dict,
        'servers': DtcServerLink.from_dict,
    }


class ADtcRecordBase(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return ADtcRecord

    @classmethod
    def get_v6_class(cls):
        return AAAADtcRecord


class ADtcRecord(ADtcRecordBase):
    _infoblox_type = 'dtc:record:a'
    _fields = ['auto_created', 'comment', 'disable', 'dtc_server', 'ipv4addr', 'ttl', 'use_ttl']
    _search_for_update_fields = ['dtc_server', 'ipv4addr']
    _updateable_search_fields = ['comment', 'ipv4addr']
    _all_searchable_fields = ['comment', 'dtc_server', 'ipv4addr']
    _return_fields = ['dtc_server', 'ipv4addr']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 4



class AAAADtcRecord(ADtcRecordBase):
    _infoblox_type = 'dtc:record:aaaa'
    _fields = ['auto_created', 'comment', 'disable', 'dtc_server', 'ipv6addr', 'ttl', 'use_ttl']
    _search_for_update_fields = ['dtc_server', 'ipv6addr']
    _updateable_search_fields = ['comment', 'ipv6addr']
    _all_searchable_fields = ['comment', 'dtc_server', 'ipv6addr']
    _return_fields = ['dtc_server', 'ipv6addr']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 6


class CNAMEDtcRecord(InfobloxObject):
    _infoblox_type = 'dtc:record:cname'
    _fields = ['auto_created', 'canonical', 'comment', 'disable', 'dns_canonical', 'dtc_server', 'ttl', 'use_ttl']
    _search_for_update_fields = ['canonical', 'dtc_server']
    _updateable_search_fields = ['canonical', 'comment']
    _all_searchable_fields = ['canonical', 'comment', 'dtc_server']
    _return_fields = ['canonical', 'dtc_server']
    _remap = {}
    _shadow_fields = ['_ref']


class NaptrDtcRecord(InfobloxObject):
    _infoblox_type = 'dtc:record:naptr'
    _fields = ['comment', 'disable', 'dtc_server', 'flags', 'order', 'preference', 'regexp', 'replacement', 'services', 'ttl', 'use_ttl']
    _search_for_update_fields = ['dtc_server', 'order', 'preference', 'replacement', 'services']
    _updateable_search_fields = ['comment', 'flags', 'order', 'preference', 'replacement', 'services']
    _all_searchable_fields = ['comment', 'dtc_server', 'flags', 'order', 'preference', 'replacement', 'services']
    _return_fields = ['dtc_server', 'order', 'preference', 'regexp', 'replacement', 'services']
    _remap = {}
    _shadow_fields = ['_ref']


class SRVDtcRecord(InfobloxObject):
    _infoblox_type = 'dtc:record:srv'
    _fields = ['comment', 'disable', 'dtc_server', 'name', 'port', 'priority', 'target', 'ttl', 'use_ttl', 'weight']
    _search_for_update_fields = ['dtc_server', 'name', 'port', 'priority', 'target', 'weight']
    _updateable_search_fields = ['comment', 'name', 'port', 'priority', 'target', 'weight']
    _all_searchable_fields = ['comment', 'dtc_server', 'name', 'port', 'priority', 'target', 'weight']
    _return_fields = ['dtc_server', 'name', 'port', 'priority', 'target', 'weight']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcServer(InfobloxObject):
    _infoblox_type = 'dtc:server'
    _fields = ['auto_create_host_record', 'comment', 'disable', 'extattrs', 'health', 'host', 'monitors', 'name', 'sni_hostname', 'use_sni_hostname']
    _search_for_update_fields = ['comment', 'host', 'name']
    _updateable_search_fields = ['comment', 'host', 'name', 'sni_hostname']
    _all_searchable_fields = ['comment', 'host', 'name', 'sni_hostname']
    _return_fields = ['comment', 'extattrs', 'host', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'monitors': DtcServerMonitor.from_dict,
    }


class DtcTopology(InfobloxObject):
    _infoblox_type = 'dtc:topology'
    _fields = ['comment', 'extattrs', 'name', 'rules']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcTopologyLabel(InfobloxObject):
    _infoblox_type = 'dtc:topology:label'
    _fields = ['field', 'label']
    _search_for_update_fields = ['field', 'label']
    _updateable_search_fields = []
    _all_searchable_fields = ['field', 'label']
    _return_fields = ['field', 'label']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcTopologyRule(InfobloxObject):
    _infoblox_type = 'dtc:topology:rule'
    _fields = ['dest_type', 'destination_link', 'return_type', 'sources', 'topology', 'valid']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = ['topology']
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'sources': DtcTopologyRuleSource.from_dict,
    }


class DxlEndpoint(InfobloxObject):
    _infoblox_type = 'dxl:endpoint'
    _fields = ['brokers', 'brokers_import_token', 'client_certificate_subject', 'client_certificate_token', 'client_certificate_valid_from', 'client_certificate_valid_to', 'comment', 'disable', 'extattrs', 'log_level', 'name', 'outbound_member_type', 'outbound_members', 'template_instance', 'timeout', 'topics', 'vendor_identifier', 'wapi_user_name', 'wapi_user_password']
    _search_for_update_fields = ['name', 'outbound_member_type']
    _updateable_search_fields = ['log_level', 'name', 'outbound_member_type', 'vendor_identifier']
    _all_searchable_fields = ['log_level', 'name', 'outbound_member_type', 'vendor_identifier']
    _return_fields = ['disable', 'extattrs', 'name', 'outbound_member_type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'brokers': DxlEndpointBroker.from_dict,
    }

    def clear_outbound_worker_log(self, *args, **kwargs):
        return self._call_func("clear_outbound_worker_log", *args, **kwargs)

    def test_broker_connectivity(self, *args, **kwargs):
        return self._call_func("test_broker_connectivity", *args, **kwargs)


class EADefinition(InfobloxObject):
    _infoblox_type = 'extensibleattributedef'
    _fields = ['allowed_object_types', 'comment', 'default_value', 'descendants_action', 'flags', 'list_values', 'max', 'min', 'name', 'namespace', 'type']
    _search_for_update_fields = ['comment', 'name', 'type']
    _updateable_search_fields = ['comment', 'name', 'type']
    _all_searchable_fields = ['comment', 'name', 'namespace', 'type']
    _return_fields = ['comment', 'default_value', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'list_values': ExtensibleattributedefListvalues.from_dict,
    }


class Fileop(InfobloxObject):
    _infoblox_type = 'fileop'
    _fields = []
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    def csv_error_log(self, *args, **kwargs):
        return self._call_func("csv_error_log", *args, **kwargs)

    def csv_export(self, *args, **kwargs):
        return self._call_func("csv_export", *args, **kwargs)

    def csv_import(self, *args, **kwargs):
        return self._call_func("csv_import", *args, **kwargs)

    def csv_snapshot_file(self, *args, **kwargs):
        return self._call_func("csv_snapshot_file", *args, **kwargs)

    def csv_uploaded_file(self, *args, **kwargs):
        return self._call_func("csv_uploaded_file", *args, **kwargs)

    def download_atp_rule_update(self, *args, **kwargs):
        return self._call_func("download_atp_rule_update", *args, **kwargs)

    def download_pool_status(self, *args, **kwargs):
        return self._call_func("download_pool_status", *args, **kwargs)

    def downloadcertificate(self, *args, **kwargs):
        return self._call_func("downloadcertificate", *args, **kwargs)

    def downloadcomplete(self, *args, **kwargs):
        return self._call_func("downloadcomplete", *args, **kwargs)

    def generatecsr(self, *args, **kwargs):
        return self._call_func("generatecsr", *args, **kwargs)

    def generatedxlendpointcerts(self, *args, **kwargs):
        return self._call_func("generatedxlendpointcerts", *args, **kwargs)

    def generatesafenetclientcert(self, *args, **kwargs):
        return self._call_func("generatesafenetclientcert", *args, **kwargs)

    def generateselfsignedcert(self, *args, **kwargs):
        return self._call_func("generateselfsignedcert", *args, **kwargs)

    def get_file_url(self, *args, **kwargs):
        return self._call_func("get_file_url", *args, **kwargs)

    def get_last_uploaded_atp_ruleset(self, *args, **kwargs):
        return self._call_func("get_last_uploaded_atp_ruleset", *args, **kwargs)

    def get_log_files(self, *args, **kwargs):
        return self._call_func("get_log_files", *args, **kwargs)

    def get_support_bundle(self, *args, **kwargs):
        return self._call_func("get_support_bundle", *args, **kwargs)

    def getgriddata(self, *args, **kwargs):
        return self._call_func("getgriddata", *args, **kwargs)

    def getleasehistoryfiles(self, *args, **kwargs):
        return self._call_func("getleasehistoryfiles", *args, **kwargs)

    def getmemberdata(self, *args, **kwargs):
        return self._call_func("getmemberdata", *args, **kwargs)

    def getsafenetclientcert(self, *args, **kwargs):
        return self._call_func("getsafenetclientcert", *args, **kwargs)

    def read(self, *args, **kwargs):
        return self._call_func("read", *args, **kwargs)

    def restapi_template_export(self, *args, **kwargs):
        return self._call_func("restapi_template_export", *args, **kwargs)

    def restapi_template_export_schema(self, *args, **kwargs):
        return self._call_func("restapi_template_export_schema", *args, **kwargs)

    def restapi_template_import(self, *args, **kwargs):
        return self._call_func("restapi_template_import", *args, **kwargs)

    def restoredatabase(self, *args, **kwargs):
        return self._call_func("restoredatabase", *args, **kwargs)

    def restoredtcconfig(self, *args, **kwargs):
        return self._call_func("restoredtcconfig", *args, **kwargs)

    def set_captive_portal_file(self, *args, **kwargs):
        return self._call_func("set_captive_portal_file", *args, **kwargs)

    def set_dhcp_leases(self, *args, **kwargs):
        return self._call_func("set_dhcp_leases", *args, **kwargs)

    def set_downgrade_file(self, *args, **kwargs):
        return self._call_func("set_downgrade_file", *args, **kwargs)

    def set_last_uploaded_atp_ruleset(self, *args, **kwargs):
        return self._call_func("set_last_uploaded_atp_ruleset", *args, **kwargs)

    def set_upgrade_file(self, *args, **kwargs):
        return self._call_func("set_upgrade_file", *args, **kwargs)

    def setdiscoverycsv(self, *args, **kwargs):
        return self._call_func("setdiscoverycsv", *args, **kwargs)

    def setfiledest(self, *args, **kwargs):
        return self._call_func("setfiledest", *args, **kwargs)

    def setleasehistoryfiles(self, *args, **kwargs):
        return self._call_func("setleasehistoryfiles", *args, **kwargs)

    def setmemberdata(self, *args, **kwargs):
        return self._call_func("setmemberdata", *args, **kwargs)

    def update_atp_ruleset(self, *args, **kwargs):
        return self._call_func("update_atp_ruleset", *args, **kwargs)

    def update_licenses(self, *args, **kwargs):
        return self._call_func("update_licenses", *args, **kwargs)

    def uploadcertificate(self, *args, **kwargs):
        return self._call_func("uploadcertificate", *args, **kwargs)

    def uploadinit(self, *args, **kwargs):
        return self._call_func("uploadinit", *args, **kwargs)

    def uploadserviceaccount(self, *args, **kwargs):
        return self._call_func("uploadserviceaccount", *args, **kwargs)


class Filterfingerprint(InfobloxObject):
    _infoblox_type = 'filterfingerprint'
    _fields = ['comment', 'extattrs', 'fingerprint', 'name']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Filtermac(InfobloxObject):
    _infoblox_type = 'filtermac'
    _fields = ['comment', 'default_mac_address_expiration', 'disable', 'enforce_expiration_times', 'extattrs', 'lease_time', 'name', 'never_expires', 'options', 'reserved_for_infoblox']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'options': Dhcpoption.from_dict,
    }


class Filternac(InfobloxObject):
    _infoblox_type = 'filternac'
    _fields = ['comment', 'expression', 'extattrs', 'lease_time', 'name', 'options']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'options': Dhcpoption.from_dict,
    }


class Filteroption(InfobloxObject):
    _infoblox_type = 'filteroption'
    _fields = ['apply_as_class', 'bootfile', 'bootserver', 'comment', 'expression', 'extattrs', 'lease_time', 'name', 'next_server', 'option_list', 'option_space', 'pxe_lease_time']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'option_list': Dhcpoption.from_dict,
    }


class Filterrelayagent(InfobloxObject):
    _infoblox_type = 'filterrelayagent'
    _fields = ['circuit_id_name', 'circuit_id_substring_length', 'circuit_id_substring_offset', 'comment', 'extattrs', 'is_circuit_id', 'is_circuit_id_substring', 'is_remote_id', 'is_remote_id_substring', 'name', 'remote_id_name', 'remote_id_substring_length', 'remote_id_substring_offset']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Fingerprint(InfobloxObject):
    _infoblox_type = 'fingerprint'
    _fields = ['comment', 'device_class', 'disable', 'extattrs', 'ipv6_option_sequence', 'name', 'option_sequence', 'type', 'vendor_id']
    _search_for_update_fields = ['comment', 'device_class', 'name']
    _updateable_search_fields = ['comment', 'device_class', 'name', 'type']
    _all_searchable_fields = ['comment', 'device_class', 'name', 'type']
    _return_fields = ['comment', 'device_class', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class FixedAddress(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return FixedAddressV4

    @classmethod
    def get_v6_class(cls):
        return FixedAddressV6


class FixedAddressV4(FixedAddress):
    _infoblox_type = 'fixedaddress'
    _fields = ['agent_circuit_id', 'agent_remote_id', 'allow_telnet', 'always_update_dns', 'bootfile', 'bootserver', 'cli_credentials', 'client_identifier_prepend_zero', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_hostname', 'deny_bootp', 'device_description', 'device_location', 'device_type', 'device_vendor', 'dhcp_client_identifier', 'disable', 'disable_discovery', 'discover_now_status', 'discovered_data', 'enable_ddns', 'enable_immediate_discovery', 'enable_pxe_lease_time', 'extattrs', 'ignore_dhcp_option_list_request', 'ipv4addr', 'is_invalid_mac', 'logic_filter_rules', 'mac', 'match_client', 'ms_ad_user_data', 'ms_options', 'ms_server', 'name', 'network', 'network_view', 'nextserver', 'options', 'pxe_lease_time', 'reserved_interface', 'restart_if_needed', 'snmp3_credential', 'snmp_credential', 'template', 'use_bootfile', 'use_bootserver', 'use_cli_credentials', 'use_ddns_domainname', 'use_deny_bootp', 'use_enable_ddns', 'use_ignore_dhcp_option_list_request', 'use_logic_filter_rules', 'use_ms_options', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_snmp3_credential', 'use_snmp_credential']
    _search_for_update_fields = ['ipv4addr', 'network_view', 'mac']
    _updateable_search_fields = ['comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'ipv4addr', 'mac', 'match_client', 'ms_server', 'network', 'network_view']
    _all_searchable_fields = ['comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'ipv4addr', 'mac', 'match_client', 'ms_server', 'network', 'network_view']
    _return_fields = ['extattrs', 'ipv4addr', 'network_view', 'mac']
    _remap = {'ipv4addr': 'ip'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 4

    @property
    def ip(self):
        if hasattr(self, '_ip'):
            return str(self._ip)

    # This object represents both ipv4 and ipv6 objects, so it doesn't need
    # versioned object for that. Just set v4 or v6 field in addition
    # to setting shadow field 'ip' itself.
    @ip.setter
    def ip(self, ip):
        self._ip = ip
    

    _custom_field_processing = {
        'cli_credentials': DiscoveryClicredential.from_dict,
        'logic_filter_rules': Logicfilterrule.from_dict,
        'ms_options': Msdhcpoption.from_dict,
        'options': Dhcpoption.from_dict,
    }



class FixedAddressV6(FixedAddress):
    _infoblox_type = 'ipv6fixedaddress'
    _fields = ['address_type', 'allow_telnet', 'cli_credentials', 'cloud_info', 'comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'disable', 'disable_discovery', 'discover_now_status', 'discovered_data', 'domain_name', 'domain_name_servers', 'duid', 'enable_immediate_discovery', 'extattrs', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'ms_ad_user_data', 'name', 'network', 'network_view', 'options', 'preferred_lifetime', 'reserved_interface', 'restart_if_needed', 'snmp3_credential', 'snmp_credential', 'template', 'use_cli_credentials', 'use_domain_name', 'use_domain_name_servers', 'use_options', 'use_preferred_lifetime', 'use_snmp3_credential', 'use_snmp_credential', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['duid', 'ipv6addr', 'network_view']
    _updateable_search_fields = ['address_type', 'comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'duid', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'network', 'network_view']
    _all_searchable_fields = ['address_type', 'comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'duid', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'network', 'network_view']
    _return_fields = ['duid', 'extattrs', 'ipv6addr', 'network_view']
    _remap = {'ipv6addr': 'ip'}
    _shadow_fields = ['_ref', 'mac', 'ip']
    _ip_version = 6

    """Set mac and duid fields

    To have common interface with FixedAddress accept mac address
    and set duid as a side effect.
    'mac' was added to _shadow_fields to prevent sending it out over wapi.
    """
    @property
    def mac(self):
        return self._mac

    @mac.setter
    def mac(self, mac):
        self._mac = mac
        if mac:
            self.duid = ib_utils.generate_duid(mac)
        elif not hasattr(self, 'duid'):
            self.duid = None 
    

    @property
    def ip(self):
        if hasattr(self, '_ip'):
            return str(self._ip)

    # This object represents both ipv4 and ipv6 objects, so it doesn't need
    # versioned object for that. Just set v4 or v6 field in addition
    # to setting shadow field 'ip' itself.
    @ip.setter
    def ip(self, ip):
        self._ip = ip
    

    _custom_field_processing = {
        'cli_credentials': DiscoveryClicredential.from_dict,
        'options': Dhcpoption.from_dict,
    }


class FixedAddressTemplate(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return FixedAddressTemplateV4

    @classmethod
    def get_v6_class(cls):
        return FixedAddressTemplateV6


class FixedAddressTemplateV4(FixedAddressTemplate):
    _infoblox_type = 'fixedaddresstemplate'
    _fields = ['bootfile', 'bootserver', 'comment', 'ddns_domainname', 'ddns_hostname', 'deny_bootp', 'enable_ddns', 'enable_pxe_lease_time', 'extattrs', 'ignore_dhcp_option_list_request', 'logic_filter_rules', 'name', 'nextserver', 'number_of_addresses', 'offset', 'options', 'pxe_lease_time', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_deny_bootp', 'use_enable_ddns', 'use_ignore_dhcp_option_list_request', 'use_logic_filter_rules', 'use_nextserver', 'use_options', 'use_pxe_lease_time']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': Dhcpoption.from_dict,
    }



class FixedAddressTemplateV6(FixedAddressTemplate):
    _infoblox_type = 'ipv6fixedaddresstemplate'
    _fields = ['comment', 'domain_name', 'domain_name_servers', 'extattrs', 'name', 'number_of_addresses', 'offset', 'options', 'preferred_lifetime', 'use_domain_name', 'use_domain_name_servers', 'use_options', 'use_preferred_lifetime', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'options': Dhcpoption.from_dict,
    }


class Ftpuser(InfobloxObject):
    _infoblox_type = 'ftpuser'
    _fields = ['create_home_dir', 'extattrs', 'home_dir', 'password', 'permission', 'username']
    _search_for_update_fields = ['username']
    _updateable_search_fields = []
    _all_searchable_fields = ['username']
    _return_fields = ['extattrs', 'username']
    _remap = {}
    _shadow_fields = ['_ref']


class Grid(InfobloxObject):
    _infoblox_type = 'grid'
    _fields = ['allow_recursive_deletion', 'audit_log_format', 'audit_to_syslog_enable', 'automated_traffic_capture_setting', 'consent_banner_setting', 'csp_api_config', 'csp_grid_setting', 'deny_mgm_snapshots', 'descendants_action', 'dns_resolver_setting', 'dscp', 'email_setting', 'enable_gui_api_for_lan_vip', 'enable_lom', 'enable_member_redirect', 'enable_recycle_bin', 'enable_rir_swip', 'external_syslog_backup_servers', 'external_syslog_server_enable', 'http_proxy_server_setting', 'informational_banner_setting', 'is_grid_visualization_visible', 'lockout_setting', 'lom_users', 'mgm_strict_delegate_mode', 'ms_setting', 'name', 'nat_groups', 'ntp_setting', 'objects_changes_tracking_setting', 'password_setting', 'restart_banner_setting', 'restart_status', 'rpz_hit_rate_interval', 'rpz_hit_rate_max_query', 'rpz_hit_rate_min_query', 'scheduled_backup', 'secret', 'security_banner_setting', 'security_setting', 'service_status', 'snmp_setting', 'syslog_facility', 'syslog_servers', 'syslog_size', 'threshold_traps', 'time_zone', 'token_usage_delay', 'traffic_capture_auth_dns_setting', 'traffic_capture_chr_setting', 'traffic_capture_qps_setting', 'traffic_capture_rec_dns_setting', 'traffic_capture_rec_queries_setting', 'trap_notifications', 'updates_download_member_config', 'vpn_port']
    _search_for_update_fields = []
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name']
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'external_syslog_backup_servers': Extsyslogbackupserver.from_dict,
        'lom_users': Lomuser.from_dict,
        'syslog_servers': Syslogserver.from_dict,
        'threshold_traps': Thresholdtrap.from_dict,
        'trap_notifications': Trapnotification.from_dict,
        'updates_download_member_config': Updatesdownloadmemberconfig.from_dict,
    }

    def control_ip_address(self, *args, **kwargs):
        return self._call_func("control_ip_address", *args, **kwargs)

    def empty_recycle_bin(self, *args, **kwargs):
        return self._call_func("empty_recycle_bin", *args, **kwargs)

    def generate_tsig_key(self, *args, **kwargs):
        return self._call_func("generate_tsig_key", *args, **kwargs)

    def get_all_template_vendor_id(self, *args, **kwargs):
        return self._call_func("get_all_template_vendor_id", *args, **kwargs)

    def get_grid_revert_status(self, *args, **kwargs):
        return self._call_func("get_grid_revert_status", *args, **kwargs)

    def get_rpz_threat_details(self, *args, **kwargs):
        return self._call_func("get_rpz_threat_details", *args, **kwargs)

    def get_template_schema_versions(self, *args, **kwargs):
        return self._call_func("get_template_schema_versions", *args, **kwargs)

    def join(self, *args, **kwargs):
        return self._call_func("join", *args, **kwargs)

    def join_mgm(self, *args, **kwargs):
        return self._call_func("join_mgm", *args, **kwargs)

    def leave_mgm(self, *args, **kwargs):
        return self._call_func("leave_mgm", *args, **kwargs)

    def member_upgrade(self, *args, **kwargs):
        return self._call_func("member_upgrade", *args, **kwargs)

    def publish_changes(self, *args, **kwargs):
        return self._call_func("publish_changes", *args, **kwargs)

    def query_fqdn_on_member(self, *args, **kwargs):
        return self._call_func("query_fqdn_on_member", *args, **kwargs)

    def requestrestartservicestatus(self, *args, **kwargs):
        return self._call_func("requestrestartservicestatus", *args, **kwargs)

    def restartservices(self, *args, **kwargs):
        return self._call_func("restartservices", *args, **kwargs)

    def skip_member_upgrade(self, *args, **kwargs):
        return self._call_func("skip_member_upgrade", *args, **kwargs)

    def start_discovery(self, *args, **kwargs):
        return self._call_func("start_discovery", *args, **kwargs)

    def test_syslog_backup_server_connection(self, *args, **kwargs):
        return self._call_func("test_syslog_backup_server_connection", *args, **kwargs)

    def test_syslog_connection(self, *args, **kwargs):
        return self._call_func("test_syslog_connection", *args, **kwargs)

    def upgrade(self, *args, **kwargs):
        return self._call_func("upgrade", *args, **kwargs)

    def upgrade_group_now(self, *args, **kwargs):
        return self._call_func("upgrade_group_now", *args, **kwargs)

    def upload_keytab(self, *args, **kwargs):
        return self._call_func("upload_keytab", *args, **kwargs)


class GridCloudapi(InfobloxObject):
    _infoblox_type = 'grid:cloudapi'
    _fields = ['allow_api_admins', 'allowed_api_admins', 'enable_recycle_bin', 'gateway_config']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['allow_api_admins', 'allowed_api_admins', 'enable_recycle_bin']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'allowed_api_admins': GridCloudapiUser.from_dict,
    }


class GridCloudapiCloudstatistics(InfobloxObject):
    _infoblox_type = 'grid:cloudapi:cloudstatistics'
    _fields = ['allocated_available_ratio', 'allocated_ip_count', 'available_ip_count', 'fixed_ip_count', 'floating_ip_count', 'tenant_count', 'tenant_ip_count', 'tenant_vm_count']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['allocated_available_ratio', 'allocated_ip_count', 'available_ip_count', 'fixed_ip_count', 'floating_ip_count', 'tenant_count', 'tenant_ip_count', 'tenant_vm_count']
    _remap = {}
    _shadow_fields = ['_ref']


class Tenant(InfobloxObject):
    _infoblox_type = 'grid:cloudapi:tenant'
    _fields = ['cloud_info', 'comment', 'created_ts', 'id', 'last_event_ts', 'name', 'network_count', 'vm_count']
    _search_for_update_fields = ['comment', 'id', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'id', 'name']
    _return_fields = ['comment', 'id', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class GridCloudapiVm(InfobloxObject):
    _infoblox_type = 'grid:cloudapi:vm'
    _fields = ['availability_zone', 'cloud_info', 'comment', 'elastic_ip_address', 'extattrs', 'first_seen', 'hostname', 'id', 'kernel_id', 'last_seen', 'name', 'network_count', 'operating_system', 'primary_mac_address', 'subnet_address', 'subnet_cidr', 'subnet_id', 'tenant_name', 'vm_type', 'vpc_address', 'vpc_cidr', 'vpc_id', 'vpc_name']
    _search_for_update_fields = ['comment', 'id', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'elastic_ip_address', 'id', 'name', 'primary_mac_address']
    _return_fields = ['comment', 'extattrs', 'id', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class GridCloudapiVmaddress(InfobloxObject):
    _infoblox_type = 'grid:cloudapi:vmaddress'
    _fields = ['address', 'address_type', 'associated_ip', 'associated_object_types', 'associated_objects', 'cloud_info', 'dns_names', 'elastic_address', 'interface_name', 'is_ipv4', 'mac_address', 'ms_ad_user_data', 'network', 'network_view', 'port_id', 'private_address', 'private_hostname', 'public_address', 'public_hostname', 'subnet_address', 'subnet_cidr', 'subnet_id', 'tenant', 'vm_availability_zone', 'vm_comment', 'vm_creation_time', 'vm_hostname', 'vm_id', 'vm_kernel_id', 'vm_last_update_time', 'vm_name', 'vm_network_count', 'vm_operating_system', 'vm_type', 'vm_vpc_address', 'vm_vpc_cidr', 'vm_vpc_id', 'vm_vpc_name', 'vm_vpc_ref']
    _search_for_update_fields = ['address', 'vm_name']
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'mac_address', 'vm_id', 'vm_name']
    _return_fields = ['address', 'is_ipv4', 'network_view', 'port_id', 'vm_name']
    _remap = {}
    _shadow_fields = ['_ref']


class GridDashboard(InfobloxObject):
    _infoblox_type = 'grid:dashboard'
    _fields = ['analytics_tunneling_event_critical_threshold', 'analytics_tunneling_event_warning_threshold', 'atp_critical_event_critical_threshold', 'atp_critical_event_warning_threshold', 'atp_major_event_critical_threshold', 'atp_major_event_warning_threshold', 'atp_warning_event_critical_threshold', 'atp_warning_event_warning_threshold', 'rpz_blocked_hit_critical_threshold', 'rpz_blocked_hit_warning_threshold', 'rpz_passthru_event_critical_threshold', 'rpz_passthru_event_warning_threshold', 'rpz_substituted_hit_critical_threshold', 'rpz_substituted_hit_warning_threshold']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['analytics_tunneling_event_critical_threshold', 'analytics_tunneling_event_warning_threshold', 'atp_critical_event_critical_threshold', 'atp_critical_event_warning_threshold', 'atp_major_event_critical_threshold', 'atp_major_event_warning_threshold', 'atp_warning_event_critical_threshold', 'atp_warning_event_warning_threshold', 'rpz_blocked_hit_critical_threshold', 'rpz_blocked_hit_warning_threshold', 'rpz_passthru_event_critical_threshold', 'rpz_passthru_event_warning_threshold', 'rpz_substituted_hit_critical_threshold', 'rpz_substituted_hit_warning_threshold']
    _remap = {}
    _shadow_fields = ['_ref']


class GridDhcpproperties(InfobloxObject):
    _infoblox_type = 'grid:dhcpproperties'
    _fields = ['authority', 'bootfile', 'bootserver', 'capture_hostname', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_retry_interval', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'deny_bootp', 'disable_all_nac_filters', 'dns_update_style', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_email_warnings', 'enable_fingerprint', 'enable_gss_tsig', 'enable_hostname_rewrite', 'enable_leasequery', 'enable_roaming_hosts', 'enable_snmp_warnings', 'format_log_option_82', 'grid', 'gss_tsig_keys', 'high_water_mark', 'high_water_mark_reset', 'hostname_rewrite_policy', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'immediate_fa_configuration', 'ipv6_capture_hostname', 'ipv6_ddns_domainname', 'ipv6_ddns_enable_option_fqdn', 'ipv6_ddns_server_always_updates', 'ipv6_ddns_ttl', 'ipv6_default_prefix', 'ipv6_dns_update_style', 'ipv6_domain_name', 'ipv6_domain_name_servers', 'ipv6_enable_ddns', 'ipv6_enable_gss_tsig', 'ipv6_enable_lease_scavenging', 'ipv6_enable_retry_updates', 'ipv6_generate_hostname', 'ipv6_gss_tsig_keys', 'ipv6_kdc_server', 'ipv6_lease_scavenging_time', 'ipv6_microsoft_code_page', 'ipv6_options', 'ipv6_prefixes', 'ipv6_recycle_leases', 'ipv6_remember_expired_client_association', 'ipv6_retry_updates_interval', 'ipv6_txt_record_handling', 'ipv6_update_dns_on_lease_renewal', 'kdc_server', 'lease_logging_member', 'lease_per_client_settings', 'lease_scavenge_time', 'log_lease_events', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'microsoft_code_page', 'nextserver', 'option60_match_rules', 'options', 'ping_count', 'ping_timeout', 'preferred_lifetime', 'prefix_length_mode', 'protocol_hostname_rewrite_policies', 'pxe_lease_time', 'recycle_leases', 'restart_setting', 'retry_ddns_updates', 'syslog_facility', 'txt_record_handling', 'update_dns_on_lease_renewal', 'valid_lifetime']
    _search_for_update_fields = ['grid']
    _updateable_search_fields = []
    _all_searchable_fields = ['grid']
    _return_fields = ['disable_all_nac_filters', 'grid']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ipv6_options': Dhcpoption.from_dict,
        'logic_filter_rules': Logicfilterrule.from_dict,
        'option60_match_rules': Option60Matchrule.from_dict,
        'options': Dhcpoption.from_dict,
    }


class GridDns(InfobloxObject):
    _infoblox_type = 'grid:dns'
    _fields = ['add_client_ip_mac_options', 'allow_bulkhost_ddns', 'allow_gss_tsig_zone_updates', 'allow_query', 'allow_recursive_query', 'allow_transfer', 'allow_update', 'anonymize_response_logging', 'attack_mitigation', 'auto_blackhole', 'bind_check_names_policy', 'bind_hostname_directive', 'blackhole_list', 'blacklist_action', 'blacklist_log_query', 'blacklist_redirect_addresses', 'blacklist_redirect_ttl', 'blacklist_rulesets', 'bulk_host_name_templates', 'capture_dns_queries_on_all_domains', 'check_names_for_ddns_and_zone_transfer', 'client_subnet_domains', 'client_subnet_ipv4_prefix_length', 'client_subnet_ipv6_prefix_length', 'copy_client_ip_mac_options', 'copy_xfer_to_notify', 'custom_root_name_servers', 'ddns_force_creation_timestamp_update', 'ddns_principal_group', 'ddns_principal_tracking', 'ddns_restrict_patterns', 'ddns_restrict_patterns_list', 'ddns_restrict_protected', 'ddns_restrict_secure', 'ddns_restrict_static', 'default_bulk_host_name_template', 'default_ttl', 'disable_edns', 'dns64_groups', 'dns_cache_acceleration_ttl', 'dns_health_check_anycast_control', 'dns_health_check_domain_list', 'dns_health_check_interval', 'dns_health_check_recursion_flag', 'dns_health_check_retries', 'dns_health_check_timeout', 'dns_query_capture_file_time_limit', 'dnssec_blacklist_enabled', 'dnssec_dns64_enabled', 'dnssec_enabled', 'dnssec_expired_signatures_enabled', 'dnssec_key_params', 'dnssec_negative_trust_anchors', 'dnssec_nxdomain_enabled', 'dnssec_rpz_enabled', 'dnssec_trusted_keys', 'dnssec_validation_enabled', 'domains_to_capture_dns_queries', 'dtc_dnssec_mode', 'dtc_edns_prefer_client_subnet', 'dtc_scheduled_backup', 'dtc_topology_ea_list', 'email', 'enable_blackhole', 'enable_blacklist', 'enable_capture_dns_queries', 'enable_capture_dns_responses', 'enable_client_subnet_forwarding', 'enable_client_subnet_recursive', 'enable_delete_associated_ptr', 'enable_dns64', 'enable_dns_health_check', 'enable_dtc_dns_fall_through', 'enable_excluded_domain_names', 'enable_fixed_rrset_order_fqdns', 'enable_ftc', 'enable_gss_tsig', 'enable_host_rrset_order', 'enable_hsm_signing', 'enable_notify_source_port', 'enable_query_rewrite', 'enable_query_source_port', 'excluded_domain_names', 'expire_after', 'file_transfer_setting', 'filter_aaaa', 'filter_aaaa_list', 'fixed_rrset_order_fqdns', 'forward_only', 'forward_updates', 'forwarders', 'ftc_expired_record_timeout', 'ftc_expired_record_ttl', 'gss_tsig_keys', 'lame_ttl', 'logging_categories', 'max_cache_ttl', 'max_cached_lifetime', 'max_ncache_ttl', 'member_secondary_notify', 'negative_ttl', 'notify_delay', 'notify_source_port', 'nsgroup_default', 'nsgroups', 'nxdomain_log_query', 'nxdomain_redirect', 'nxdomain_redirect_addresses', 'nxdomain_redirect_addresses_v6', 'nxdomain_redirect_ttl', 'nxdomain_rulesets', 'preserve_host_rrset_order_on_secondaries', 'protocol_record_name_policies', 'query_rewrite_domain_names', 'query_rewrite_prefix', 'query_source_port', 'recursive_query_list', 'refresh_timer', 'resolver_query_timeout', 'response_rate_limiting', 'restart_setting', 'retry_timer', 'root_name_server_type', 'rpz_disable_nsdname_nsip', 'rpz_drop_ip_rule_enabled', 'rpz_drop_ip_rule_min_prefix_length_ipv4', 'rpz_drop_ip_rule_min_prefix_length_ipv6', 'rpz_qname_wait_recurse', 'scavenging_settings', 'serial_query_rate', 'server_id_directive', 'sortlist', 'store_locally', 'syslog_facility', 'transfer_excluded_servers', 'transfer_format', 'transfers_in', 'transfers_out', 'transfers_per_ns', 'zone_deletion_double_confirm']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'allow_query': Addressac.from_dict,
        'allow_transfer': Addressac.from_dict,
        'allow_update': Addressac.from_dict,
        'blackhole_list': Addressac.from_dict,
        'client_subnet_domains': Clientsubnetdomain.from_dict,
        'custom_root_name_servers': Extserver.from_dict,
        'dnssec_trusted_keys': Dnssectrustedkey.from_dict,
        'filter_aaaa_list': Addressac.from_dict,
        'fixed_rrset_order_fqdns': GridDnsFixedrrsetorderfqdn.from_dict,
        'recursive_query_list': Addressac.from_dict,
        'sortlist': Sortlist.from_dict,
    }

    def run_scavenging(self, *args, **kwargs):
        return self._call_func("run_scavenging", *args, **kwargs)


class GridFiledistribution(InfobloxObject):
    _infoblox_type = 'grid:filedistribution'
    _fields = ['allow_uploads', 'backup_storage', 'current_usage', 'enable_anonymous_ftp', 'global_status', 'name', 'storage_limit']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['allow_uploads', 'current_usage', 'global_status', 'name', 'storage_limit']
    _remap = {}
    _shadow_fields = ['_ref']


class GridLicensePool(InfobloxObject):
    _infoblox_type = 'grid:license_pool'
    _fields = ['assigned', 'expiration_status', 'expiry_date', 'installed', 'key', 'limit', 'limit_context', 'model', 'subpools', 'temp_assigned', 'type']
    _search_for_update_fields = ['type']
    _updateable_search_fields = []
    _all_searchable_fields = ['key', 'limit', 'model', 'type']
    _return_fields = ['type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'subpools': GridLicensesubpool.from_dict,
    }


class GridLicensePoolContainer(InfobloxObject):
    _infoblox_type = 'grid:license_pool_container'
    _fields = ['last_entitlement_update', 'lpc_uid']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    def allocate_licenses(self, *args, **kwargs):
        return self._call_func("allocate_licenses", *args, **kwargs)


class GridMaxminddbinfo(InfobloxObject):
    _infoblox_type = 'grid:maxminddbinfo'
    _fields = ['binary_major_version', 'binary_minor_version', 'build_time', 'database_type', 'deployment_time', 'member', 'topology_type']
    _search_for_update_fields = ['topology_type']
    _updateable_search_fields = []
    _all_searchable_fields = ['topology_type']
    _return_fields = ['binary_major_version', 'binary_minor_version', 'build_time', 'database_type', 'deployment_time', 'member', 'topology_type']
    _remap = {}
    _shadow_fields = ['_ref']


class GridMemberCloudapi(InfobloxObject):
    _infoblox_type = 'grid:member:cloudapi'
    _fields = ['allow_api_admins', 'allowed_api_admins', 'enable_service', 'extattrs', 'gateway_config', 'member', 'status']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['allow_api_admins', 'allowed_api_admins', 'enable_service', 'extattrs', 'member', 'status']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'allowed_api_admins': GridCloudapiUser.from_dict,
    }


class GridServicerestartGroup(InfobloxObject):
    _infoblox_type = 'grid:servicerestart:group'
    _fields = ['comment', 'extattrs', 'is_default', 'last_updated_time', 'members', 'mode', 'name', 'position', 'recurring_schedule', 'requests', 'service', 'status']
    _search_for_update_fields = ['comment', 'name', 'service']
    _updateable_search_fields = ['comment', 'name', 'service']
    _all_searchable_fields = ['comment', 'is_default', 'name', 'service']
    _return_fields = ['comment', 'extattrs', 'name', 'service']
    _remap = {}
    _shadow_fields = ['_ref']


class GridServicerestartGroupOrder(InfobloxObject):
    _infoblox_type = 'grid:servicerestart:group:order'
    _fields = ['groups']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']


class GridServicerestartRequest(InfobloxObject):
    _infoblox_type = 'grid:servicerestart:request'
    _fields = ['error', 'forced', 'group', 'last_updated_time', 'member', 'needed', 'order', 'result', 'service', 'state']
    _search_for_update_fields = ['group']
    _updateable_search_fields = []
    _all_searchable_fields = ['group', 'member']
    _return_fields = ['error', 'group', 'result', 'state']
    _remap = {}
    _shadow_fields = ['_ref']


class GridServicerestartRequestChangedobject(InfobloxObject):
    _infoblox_type = 'grid:servicerestart:request:changedobject'
    _fields = ['action', 'changed_properties', 'changed_time', 'object_name', 'object_type', 'user_name']
    _search_for_update_fields = ['user_name']
    _updateable_search_fields = []
    _all_searchable_fields = ['user_name']
    _return_fields = ['action', 'changed_properties', 'changed_time', 'object_name', 'object_type', 'user_name']
    _remap = {}
    _shadow_fields = ['_ref']


class GridServicerestartStatus(InfobloxObject):
    _infoblox_type = 'grid:servicerestart:status'
    _fields = ['failures', 'finished', 'grouped', 'needed_restart', 'no_restart', 'parent', 'pending', 'pending_restart', 'processing', 'restarting', 'success', 'timeouts']
    _search_for_update_fields = ['parent']
    _updateable_search_fields = []
    _all_searchable_fields = ['parent']
    _return_fields = ['failures', 'finished', 'grouped', 'needed_restart', 'no_restart', 'parent', 'pending', 'pending_restart', 'processing', 'restarting', 'success', 'timeouts']
    _remap = {}
    _shadow_fields = ['_ref']


class GridThreatanalytics(InfobloxObject):
    _infoblox_type = 'grid:threatanalytics'
    _fields = ['configure_domain_collapsing', 'current_moduleset', 'current_whitelist', 'dns_tunnel_black_list_rpz_zones', 'domain_collapsing_level', 'enable_auto_download', 'enable_scheduled_download', 'enable_whitelist_auto_download', 'enable_whitelist_scheduled_download', 'last_checked_for_update', 'last_checked_for_whitelist_update', 'last_module_update_time', 'last_module_update_version', 'last_whitelist_update_time', 'last_whitelist_update_version', 'module_update_policy', 'name', 'scheduled_download', 'scheduled_whitelist_download', 'whitelist_update_policy']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['enable_auto_download', 'enable_scheduled_download', 'module_update_policy', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    def download_threat_analytics_moduleset_update(self, *args, **kwargs):
        return self._call_func("download_threat_analytics_moduleset_update", *args, **kwargs)

    def download_threat_analytics_whitelist_update(self, *args, **kwargs):
        return self._call_func("download_threat_analytics_whitelist_update", *args, **kwargs)

    def move_blacklist_rpz_to_white_list(self, *args, **kwargs):
        return self._call_func("move_blacklist_rpz_to_white_list", *args, **kwargs)

    def set_last_uploaded_threat_analytics_moduleset(self, *args, **kwargs):
        return self._call_func("set_last_uploaded_threat_analytics_moduleset", *args, **kwargs)

    def test_threat_analytics_server_connectivity(self, *args, **kwargs):
        return self._call_func("test_threat_analytics_server_connectivity", *args, **kwargs)

    def update_threat_analytics_moduleset(self, *args, **kwargs):
        return self._call_func("update_threat_analytics_moduleset", *args, **kwargs)


class GridThreatprotection(InfobloxObject):
    _infoblox_type = 'grid:threatprotection'
    _fields = ['current_ruleset', 'disable_multiple_dns_tcp_request', 'enable_accel_resp_before_threat_protection', 'enable_auto_download', 'enable_nat_rules', 'enable_scheduled_download', 'events_per_second_per_rule', 'grid_name', 'last_checked_for_update', 'last_rule_update_timestamp', 'last_rule_update_version', 'nat_rules', 'outbound_settings', 'rule_update_policy', 'scheduled_download']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['grid_name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'nat_rules': ThreatprotectionNatrule.from_dict,
    }

    def atp_object_reset(self, *args, **kwargs):
        return self._call_func("atp_object_reset", *args, **kwargs)

    def test_atp_server_connectivity(self, *args, **kwargs):
        return self._call_func("test_atp_server_connectivity", *args, **kwargs)


class GridX509Certificate(InfobloxObject):
    _infoblox_type = 'grid:x509certificate'
    _fields = ['issuer', 'serial', 'subject', 'valid_not_after', 'valid_not_before']
    _search_for_update_fields = ['issuer', 'serial', 'subject']
    _updateable_search_fields = []
    _all_searchable_fields = ['issuer', 'serial', 'subject', 'valid_not_after', 'valid_not_before']
    _return_fields = ['issuer', 'serial', 'subject']
    _remap = {}
    _shadow_fields = ['_ref']


class Hostnamerewritepolicy(InfobloxObject):
    _infoblox_type = 'hostnamerewritepolicy'
    _fields = ['is_default', 'name', 'pre_defined', 'replacement_character', 'valid_characters']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name']
    _return_fields = ['name', 'replacement_character', 'valid_characters']
    _remap = {}
    _shadow_fields = ['_ref']


class HsmAllgroups(InfobloxObject):
    _infoblox_type = 'hsm:allgroups'
    _fields = ['groups']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['groups']
    _remap = {}
    _shadow_fields = ['_ref']


class HsmSafenetgroup(InfobloxObject):
    _infoblox_type = 'hsm:safenetgroup'
    _fields = ['comment', 'group_sn', 'hsm_safenet', 'hsm_version', 'name', 'pass_phrase', 'status']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'hsm_version', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'hsm_safenet': HsmSafenet.from_dict,
    }

    def refresh_hsm(self, *args, **kwargs):
        return self._call_func("refresh_hsm", *args, **kwargs)

    def test_hsm_status(self, *args, **kwargs):
        return self._call_func("test_hsm_status", *args, **kwargs)


class HsmThalesgroup(InfobloxObject):
    _infoblox_type = 'hsm:thalesgroup'
    _fields = ['card_name', 'comment', 'key_server_ip', 'key_server_port', 'name', 'pass_phrase', 'protection', 'status', 'thales_hsm']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'key_server_ip', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'thales_hsm': HsmThales.from_dict,
    }

    def refresh_hsm(self, *args, **kwargs):
        return self._call_func("refresh_hsm", *args, **kwargs)

    def test_hsm_status(self, *args, **kwargs):
        return self._call_func("test_hsm_status", *args, **kwargs)


class IpamStatistics(InfobloxObject):
    _infoblox_type = 'ipam:statistics'
    _fields = ['cidr', 'conflict_count', 'ms_ad_user_data', 'network', 'network_view', 'unmanaged_count', 'utilization', 'utilization_update']
    _search_for_update_fields = ['network', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['network', 'network_view']
    _return_fields = ['cidr', 'network', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']


class IPAddress(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return IPv4Address

    @classmethod
    def get_v6_class(cls):
        return IPv6Address


class IPv4Address(IPAddress):
    _infoblox_type = 'ipv4address'
    _fields = ['comment', 'conflict_types', 'dhcp_client_identifier', 'discover_now_status', 'discovered_data', 'extattrs', 'fingerprint', 'ip_address', 'is_conflict', 'is_invalid_mac', 'lease_state', 'mac_address', 'ms_ad_user_data', 'names', 'network', 'network_view', 'objects', 'reserved_port', 'status', 'types', 'usage', 'username']
    _search_for_update_fields = ['dhcp_client_identifier', 'ip_address', 'is_conflict', 'lease_state', 'mac_address', 'names', 'network', 'network_view', 'status', 'types', 'usage', 'username']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'dhcp_client_identifier', 'fingerprint', 'ip_address', 'is_conflict', 'lease_state', 'mac_address', 'names', 'network', 'network_view', 'status', 'types', 'usage', 'username']
    _return_fields = ['dhcp_client_identifier', 'extattrs', 'ip_address', 'is_conflict', 'lease_state', 'mac_address', 'names', 'network', 'network_view', 'objects', 'status', 'types', 'usage', 'username']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4



class IPv6Address(IPAddress):
    _infoblox_type = 'ipv6address'
    _fields = ['comment', 'conflict_types', 'discover_now_status', 'discovered_data', 'duid', 'extattrs', 'fingerprint', 'ip_address', 'is_conflict', 'lease_state', 'ms_ad_user_data', 'names', 'network', 'network_view', 'objects', 'reserved_port', 'status', 'types', 'usage']
    _search_for_update_fields = ['duid', 'ip_address', 'is_conflict', 'lease_state', 'names', 'network', 'network_view', 'status', 'types', 'usage']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'duid', 'fingerprint', 'ip_address', 'is_conflict', 'lease_state', 'names', 'network', 'network_view', 'status', 'types', 'usage']
    _return_fields = ['duid', 'extattrs', 'ip_address', 'is_conflict', 'lease_state', 'names', 'network', 'network_view', 'objects', 'status', 'types', 'usage']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6


class Network(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return NetworkV4

    @classmethod
    def get_v6_class(cls):
        return NetworkV6


class NetworkV4(Network):
    _infoblox_type = 'network'
    _fields = ['authority', 'auto_create_reversezone', 'bootfile', 'bootserver', 'cloud_info', 'comment', 'conflict_count', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'delete_reason', 'deny_bootp', 'dhcp_utilization', 'dhcp_utilization_status', 'disable', 'discover_now_status', 'discovered_bgp_as', 'discovered_bridge_domain', 'discovered_tenant', 'discovered_vlan_id', 'discovered_vlan_name', 'discovered_vrf_description', 'discovered_vrf_name', 'discovered_vrf_rd', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_engine_type', 'discovery_member', 'dynamic_hosts', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_discovery', 'enable_email_warnings', 'enable_ifmap_publishing', 'enable_immediate_discovery', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'endpoint_sources', 'extattrs', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'ipam_email_addresses', 'ipam_threshold_settings', 'ipam_trap_settings', 'ipv4addr', 'last_rir_registration_update_sent', 'last_rir_registration_update_status', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'members', 'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data', 'netmask', 'network', 'network_container', 'network_view', 'nextserver', 'options', 'port_control_blackout_setting', 'pxe_lease_time', 'recycle_leases', 'restart_if_needed', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'same_port_control_discovery_blackout', 'send_rir_request', 'static_hosts', 'subscribe_settings', 'template', 'total_hosts', 'unmanaged', 'unmanaged_count', 'update_dns_on_lease_renewal', 'use_authority', 'use_blackout_setting', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_update_fixed_addresses', 'use_ddns_use_option81', 'use_deny_bootp', 'use_discovery_basic_polling_settings', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_enable_discovery', 'use_enable_ifmap_publishing', 'use_ignore_dhcp_option_list_request', 'use_ignore_id', 'use_ipam_email_addresses', 'use_ipam_threshold_settings', 'use_ipam_trap_settings', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_mgm_private', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_subscribe_settings', 'use_update_dns_on_lease_renewal', 'use_zone_associations', 'utilization', 'utilization_update', 'vlans', 'zone_associations']
    _search_for_update_fields = ['comment', 'network', 'network_view']
    _updateable_search_fields = ['comment', 'discovered_bridge_domain', 'discovered_tenant', 'ipv4addr', 'network', 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovered_bgp_as', 'discovered_bridge_domain', 'discovered_tenant', 'discovered_vlan_id', 'discovered_vlan_name', 'discovered_vrf_description', 'discovered_vrf_name', 'discovered_vrf_rd', 'discovery_engine_type', 'ipv4addr', 'network', 'network_container', 'network_view', 'rir', 'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'extattrs', 'network', 'network_view']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'members': Msdhcpserver.from_dict,
        'options': Dhcpoption.from_dict,
        'vlans': Vlanlink.from_dict,
        'zone_associations': Zoneassociation.from_dict,
    }

    def expand_network(self, *args, **kwargs):
        return self._call_func("expand_network", *args, **kwargs)

    def next_available_ip(self, *args, **kwargs):
        return self._call_func("next_available_ip", *args, **kwargs)

    def next_available_network(self, *args, **kwargs):
        return self._call_func("next_available_network", *args, **kwargs)

    def next_available_vlan(self, *args, **kwargs):
        return self._call_func("next_available_vlan", *args, **kwargs)

    def resize(self, *args, **kwargs):
        return self._call_func("resize", *args, **kwargs)

    def split_network(self, *args, **kwargs):
        return self._call_func("split_network", *args, **kwargs)



class NetworkV6(Network):
    _infoblox_type = 'ipv6network'
    _fields = ['auto_create_reversezone', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_enable_option_fqdn', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'delete_reason', 'disable', 'discover_now_status', 'discovered_bgp_as', 'discovered_bridge_domain', 'discovered_tenant', 'discovered_vlan_id', 'discovered_vlan_name', 'discovered_vrf_description', 'discovered_vrf_name', 'discovered_vrf_rd', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_engine_type', 'discovery_member', 'domain_name', 'domain_name_servers', 'enable_ddns', 'enable_discovery', 'enable_ifmap_publishing', 'enable_immediate_discovery', 'endpoint_sources', 'extattrs', 'last_rir_registration_update_sent', 'last_rir_registration_update_status', 'members', 'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data', 'network', 'network_container', 'network_view', 'options', 'port_control_blackout_setting', 'preferred_lifetime', 'recycle_leases', 'restart_if_needed', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'same_port_control_discovery_blackout', 'send_rir_request', 'subscribe_settings', 'template', 'unmanaged', 'unmanaged_count', 'update_dns_on_lease_renewal', 'use_blackout_setting', 'use_ddns_domainname', 'use_ddns_enable_option_fqdn', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_discovery_basic_polling_settings', 'use_domain_name', 'use_domain_name_servers', 'use_enable_ddns', 'use_enable_discovery', 'use_enable_ifmap_publishing', 'use_mgm_private', 'use_options', 'use_preferred_lifetime', 'use_recycle_leases', 'use_subscribe_settings', 'use_update_dns_on_lease_renewal', 'use_valid_lifetime', 'use_zone_associations', 'valid_lifetime', 'vlans', 'zone_associations']
    _search_for_update_fields = ['comment', 'network', 'network_view']
    _updateable_search_fields = ['comment', 'discovered_bridge_domain', 'discovered_tenant', 'network', 'network_view', 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovered_bgp_as', 'discovered_bridge_domain', 'discovered_tenant', 'discovered_vlan_id', 'discovered_vlan_name', 'discovered_vrf_description', 'discovered_vrf_name', 'discovered_vrf_rd', 'discovery_engine_type', 'network', 'network_container', 'network_view', 'rir', 'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'extattrs', 'network', 'network_view']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 6

    _custom_field_processing = {
        'members': Dhcpmember.from_dict,
        'options': Dhcpoption.from_dict,
        'vlans': Vlanlink.from_dict,
        'zone_associations': Zoneassociation.from_dict,
    }

    def expand_network(self, *args, **kwargs):
        return self._call_func("expand_network", *args, **kwargs)

    def next_available_ip(self, *args, **kwargs):
        return self._call_func("next_available_ip", *args, **kwargs)

    def next_available_network(self, *args, **kwargs):
        return self._call_func("next_available_network", *args, **kwargs)

    def next_available_vlan(self, *args, **kwargs):
        return self._call_func("next_available_vlan", *args, **kwargs)

    def split_network(self, *args, **kwargs):
        return self._call_func("split_network", *args, **kwargs)


class NetworkContainer(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return NetworkContainerV4

    @classmethod
    def get_v6_class(cls):
        return NetworkContainerV6


class NetworkContainerV4(NetworkContainer):
    _infoblox_type = 'networkcontainer'
    _fields = ['authority', 'auto_create_reversezone', 'bootfile', 'bootserver', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'delete_reason', 'deny_bootp', 'discover_now_status', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_engine_type', 'discovery_member', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_discovery', 'enable_email_warnings', 'enable_immediate_discovery', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'endpoint_sources', 'extattrs', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'ipam_email_addresses', 'ipam_threshold_settings', 'ipam_trap_settings', 'last_rir_registration_update_sent', 'last_rir_registration_update_status', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data', 'network', 'network_container', 'network_view', 'nextserver', 'options', 'port_control_blackout_setting', 'pxe_lease_time', 'recycle_leases', 'remove_subnets', 'restart_if_needed', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'same_port_control_discovery_blackout', 'send_rir_request', 'subscribe_settings', 'unmanaged', 'update_dns_on_lease_renewal', 'use_authority', 'use_blackout_setting', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_update_fixed_addresses', 'use_ddns_use_option81', 'use_deny_bootp', 'use_discovery_basic_polling_settings', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_enable_discovery', 'use_ignore_dhcp_option_list_request', 'use_ignore_id', 'use_ipam_email_addresses', 'use_ipam_threshold_settings', 'use_ipam_trap_settings', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_mgm_private', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_subscribe_settings', 'use_update_dns_on_lease_renewal', 'use_zone_associations', 'utilization', 'zone_associations']
    _search_for_update_fields = ['comment', 'network', 'network_view']
    _updateable_search_fields = ['comment', 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovery_engine_type', 'network', 'network_container', 'network_view', 'rir', 'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'extattrs', 'network', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': Dhcpoption.from_dict,
        'zone_associations': Zoneassociation.from_dict,
    }

    def next_available_network(self, *args, **kwargs):
        return self._call_func("next_available_network", *args, **kwargs)

    def resize(self, *args, **kwargs):
        return self._call_func("resize", *args, **kwargs)



class NetworkContainerV6(NetworkContainer):
    _infoblox_type = 'ipv6networkcontainer'
    _fields = ['auto_create_reversezone', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_enable_option_fqdn', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'delete_reason', 'discover_now_status', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_engine_type', 'discovery_member', 'domain_name_servers', 'enable_ddns', 'enable_discovery', 'enable_immediate_discovery', 'endpoint_sources', 'extattrs', 'last_rir_registration_update_sent', 'last_rir_registration_update_status', 'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data', 'network', 'network_container', 'network_view', 'options', 'port_control_blackout_setting', 'preferred_lifetime', 'remove_subnets', 'restart_if_needed', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'same_port_control_discovery_blackout', 'send_rir_request', 'subscribe_settings', 'unmanaged', 'update_dns_on_lease_renewal', 'use_blackout_setting', 'use_ddns_domainname', 'use_ddns_enable_option_fqdn', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_discovery_basic_polling_settings', 'use_domain_name_servers', 'use_enable_ddns', 'use_enable_discovery', 'use_mgm_private', 'use_options', 'use_preferred_lifetime', 'use_subscribe_settings', 'use_update_dns_on_lease_renewal', 'use_valid_lifetime', 'use_zone_associations', 'utilization', 'valid_lifetime', 'zone_associations']
    _search_for_update_fields = ['comment', 'network', 'network_view']
    _updateable_search_fields = ['comment', 'network_view', 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovery_engine_type', 'network', 'network_container', 'network_view', 'rir', 'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'extattrs', 'network', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'options': Dhcpoption.from_dict,
        'zone_associations': Zoneassociation.from_dict,
    }

    def next_available_network(self, *args, **kwargs):
        return self._call_func("next_available_network", *args, **kwargs)


class NetworkTemplate(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return NetworkTemplateV4

    @classmethod
    def get_v6_class(cls):
        return NetworkTemplateV6


class NetworkTemplateV4(NetworkTemplate):
    _infoblox_type = 'networktemplate'
    _fields = ['allow_any_netmask', 'authority', 'auto_create_reversezone', 'bootfile', 'bootserver', 'cloud_api_compatible', 'comment', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'delegated_member', 'deny_bootp', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_email_warnings', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'extattrs', 'fixed_address_templates', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'ipam_email_addresses', 'ipam_threshold_settings', 'ipam_trap_settings', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'members', 'name', 'netmask', 'nextserver', 'options', 'pxe_lease_time', 'range_templates', 'recycle_leases', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'send_rir_request', 'update_dns_on_lease_renewal', 'use_authority', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_update_fixed_addresses', 'use_ddns_use_option81', 'use_deny_bootp', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_ignore_dhcp_option_list_request', 'use_ipam_email_addresses', 'use_ipam_threshold_settings', 'use_ipam_trap_settings', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name', 'rir_organization']
    _all_searchable_fields = ['comment', 'name', 'rir', 'rir_organization']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'members': Msdhcpserver.from_dict,
        'options': Dhcpoption.from_dict,
    }



class NetworkTemplateV6(NetworkTemplate):
    _infoblox_type = 'ipv6networktemplate'
    _fields = ['allow_any_netmask', 'auto_create_reversezone', 'cidr', 'cloud_api_compatible', 'comment', 'ddns_domainname', 'ddns_enable_option_fqdn', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'delegated_member', 'domain_name', 'domain_name_servers', 'enable_ddns', 'extattrs', 'fixed_address_templates', 'ipv6prefix', 'members', 'name', 'options', 'preferred_lifetime', 'range_templates', 'recycle_leases', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'send_rir_request', 'update_dns_on_lease_renewal', 'use_ddns_domainname', 'use_ddns_enable_option_fqdn', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_domain_name', 'use_domain_name_servers', 'use_enable_ddns', 'use_options', 'use_preferred_lifetime', 'use_recycle_leases', 'use_update_dns_on_lease_renewal', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'ipv6prefix', 'name', 'rir_organization']
    _all_searchable_fields = ['comment', 'ipv6prefix', 'name', 'rir', 'rir_organization']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'members': Dhcpmember.from_dict,
        'options': Dhcpoption.from_dict,
    }


class IPRange(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return IPRangeV4

    @classmethod
    def get_v6_class(cls):
        return IPRangeV6


class IPRangeV4(IPRange):
    _infoblox_type = 'range'
    _fields = ['always_update_dns', 'bootfile', 'bootserver', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_generate_hostname', 'deny_all_clients', 'deny_bootp', 'dhcp_utilization', 'dhcp_utilization_status', 'disable', 'discover_now_status', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_member', 'dynamic_hosts', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_discovery', 'enable_email_warnings', 'enable_ifmap_publishing', 'enable_immediate_discovery', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'end_addr', 'endpoint_sources', 'exclude', 'extattrs', 'failover_association', 'fingerprint_filter_rules', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'is_split_scope', 'known_clients', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'mac_filter_rules', 'member', 'ms_ad_user_data', 'ms_options', 'ms_server', 'nac_filter_rules', 'name', 'network', 'network_view', 'nextserver', 'option_filter_rules', 'options', 'port_control_blackout_setting', 'pxe_lease_time', 'recycle_leases', 'relay_agent_filter_rules', 'restart_if_needed', 'same_port_control_discovery_blackout', 'server_association_type', 'split_member', 'split_scope_exclusion_percent', 'start_addr', 'static_hosts', 'subscribe_settings', 'template', 'total_hosts', 'unknown_clients', 'update_dns_on_lease_renewal', 'use_blackout_setting', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_deny_bootp', 'use_discovery_basic_polling_settings', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_enable_discovery', 'use_enable_ifmap_publishing', 'use_ignore_dhcp_option_list_request', 'use_ignore_id', 'use_known_clients', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_ms_options', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_subscribe_settings', 'use_unknown_clients', 'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['comment', 'end_addr', 'network', 'network_view', 'start_addr']
    _updateable_search_fields = ['comment', 'end_addr', 'failover_association', 'member', 'ms_server', 'network', 'network_view', 'server_association_type', 'start_addr']
    _all_searchable_fields = ['comment', 'end_addr', 'failover_association', 'member', 'ms_server', 'network', 'network_view', 'server_association_type', 'start_addr']
    _return_fields = ['comment', 'end_addr', 'extattrs', 'network', 'network_view', 'start_addr']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 4

    _custom_field_processing = {
        'exclude': Exclusionrange.from_dict,
        'fingerprint_filter_rules': Filterrule.from_dict,
        'logic_filter_rules': Logicfilterrule.from_dict,
        'mac_filter_rules': Filterrule.from_dict,
        'ms_options': Msdhcpoption.from_dict,
        'nac_filter_rules': Filterrule.from_dict,
        'option_filter_rules': Filterrule.from_dict,
        'options': Dhcpoption.from_dict,
        'relay_agent_filter_rules': Filterrule.from_dict,
    }

    def next_available_ip(self, *args, **kwargs):
        return self._call_func("next_available_ip", *args, **kwargs)



class IPRangeV6(IPRange):
    _infoblox_type = 'ipv6range'
    _fields = ['address_type', 'cloud_info', 'comment', 'disable', 'discover_now_status', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_member', 'enable_discovery', 'enable_immediate_discovery', 'end_addr', 'endpoint_sources', 'exclude', 'extattrs', 'ipv6_end_prefix', 'ipv6_prefix_bits', 'ipv6_start_prefix', 'member', 'name', 'network', 'network_view', 'port_control_blackout_setting', 'recycle_leases', 'restart_if_needed', 'same_port_control_discovery_blackout', 'server_association_type', 'start_addr', 'subscribe_settings', 'template', 'use_blackout_setting', 'use_discovery_basic_polling_settings', 'use_enable_discovery', 'use_recycle_leases', 'use_subscribe_settings']
    _search_for_update_fields = ['comment', 'end_addr', 'network', 'network_view', 'start_addr']
    _updateable_search_fields = ['address_type', 'comment', 'end_addr', 'ipv6_end_prefix', 'ipv6_prefix_bits', 'ipv6_start_prefix', 'member', 'name', 'network', 'network_view', 'server_association_type', 'start_addr']
    _all_searchable_fields = ['address_type', 'comment', 'end_addr', 'ipv6_end_prefix', 'ipv6_prefix_bits', 'ipv6_start_prefix', 'member', 'name', 'network', 'network_view', 'server_association_type', 'start_addr']
    _return_fields = ['comment', 'end_addr', 'extattrs', 'network', 'network_view', 'start_addr']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 6

    _custom_field_processing = {
        'exclude': Exclusionrange.from_dict,
    }

    def next_available_ip(self, *args, **kwargs):
        return self._call_func("next_available_ip", *args, **kwargs)


class RangeTemplate(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return RangeTemplateV4

    @classmethod
    def get_v6_class(cls):
        return RangeTemplateV6


class RangeTemplateV4(RangeTemplate):
    _infoblox_type = 'rangetemplate'
    _fields = ['bootfile', 'bootserver', 'cloud_api_compatible', 'comment', 'ddns_domainname', 'ddns_generate_hostname', 'delegated_member', 'deny_all_clients', 'deny_bootp', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_email_warnings', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'exclude', 'extattrs', 'failover_association', 'fingerprint_filter_rules', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'known_clients', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'mac_filter_rules', 'member', 'ms_options', 'ms_server', 'nac_filter_rules', 'name', 'nextserver', 'number_of_addresses', 'offset', 'option_filter_rules', 'options', 'pxe_lease_time', 'recycle_leases', 'relay_agent_filter_rules', 'server_association_type', 'unknown_clients', 'update_dns_on_lease_renewal', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_deny_bootp', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_ignore_dhcp_option_list_request', 'use_known_clients', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_ms_options', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_unknown_clients', 'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'failover_association', 'member', 'ms_server', 'name', 'server_association_type']
    _all_searchable_fields = ['comment', 'failover_association', 'member', 'ms_server', 'name', 'server_association_type']
    _return_fields = ['comment', 'extattrs', 'name', 'number_of_addresses', 'offset']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    _custom_field_processing = {
        'exclude': Exclusionrangetemplate.from_dict,
        'fingerprint_filter_rules': Filterrule.from_dict,
        'logic_filter_rules': Logicfilterrule.from_dict,
        'mac_filter_rules': Filterrule.from_dict,
        'ms_options': Msdhcpoption.from_dict,
        'nac_filter_rules': Filterrule.from_dict,
        'option_filter_rules': Filterrule.from_dict,
        'options': Dhcpoption.from_dict,
        'relay_agent_filter_rules': Filterrule.from_dict,
    }



class RangeTemplateV6(RangeTemplate):
    _infoblox_type = 'ipv6rangetemplate'
    _fields = ['cloud_api_compatible', 'comment', 'delegated_member', 'exclude', 'member', 'name', 'number_of_addresses', 'offset', 'recycle_leases', 'server_association_type', 'use_recycle_leases']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'member', 'name', 'server_association_type']
    _all_searchable_fields = ['comment', 'member', 'name', 'server_association_type']
    _return_fields = ['comment', 'name', 'number_of_addresses', 'offset']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'exclude': Exclusionrangetemplate.from_dict,
    }


class SharedNetwork(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return SharedNetworkV4

    @classmethod
    def get_v6_class(cls):
        return SharedNetworkV6


class SharedNetworkV4(SharedNetwork):
    _infoblox_type = 'sharednetwork'
    _fields = ['authority', 'bootfile', 'bootserver', 'comment', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'deny_bootp', 'dhcp_utilization', 'dhcp_utilization_status', 'disable', 'dynamic_hosts', 'enable_ddns', 'enable_pxe_lease_time', 'extattrs', 'ignore_client_identifier', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'lease_scavenge_time', 'logic_filter_rules', 'ms_ad_user_data', 'name', 'network_view', 'networks', 'nextserver', 'options', 'pxe_lease_time', 'static_hosts', 'total_hosts', 'update_dns_on_lease_renewal', 'use_authority', 'use_bootfile', 'use_bootserver', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_update_fixed_addresses', 'use_ddns_use_option81', 'use_deny_bootp', 'use_enable_ddns', 'use_ignore_client_identifier', 'use_ignore_dhcp_option_list_request', 'use_ignore_id', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['comment', 'name', 'network_view']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name', 'network_view']
    _return_fields = ['comment', 'extattrs', 'name', 'network_view', 'networks']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': Dhcpoption.from_dict,
    }



class SharedNetworkV6(SharedNetwork):
    _infoblox_type = 'ipv6sharednetwork'
    _fields = ['comment', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_use_option81', 'disable', 'domain_name', 'domain_name_servers', 'enable_ddns', 'extattrs', 'name', 'network_view', 'networks', 'options', 'preferred_lifetime', 'update_dns_on_lease_renewal', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_use_option81', 'use_domain_name', 'use_domain_name_servers', 'use_enable_ddns', 'use_options', 'use_preferred_lifetime', 'use_update_dns_on_lease_renewal', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['comment', 'name', 'network_view']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name', 'network_view']
    _return_fields = ['comment', 'extattrs', 'name', 'network_view', 'networks']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'options': Dhcpoption.from_dict,
    }


class Kerberoskey(InfobloxObject):
    _infoblox_type = 'kerberoskey'
    _fields = ['domain', 'enctype', 'in_use', 'members', 'principal', 'upload_timestamp', 'version']
    _search_for_update_fields = ['domain', 'enctype', 'in_use', 'principal', 'version']
    _updateable_search_fields = []
    _all_searchable_fields = ['domain', 'enctype', 'in_use', 'principal', 'version']
    _return_fields = ['domain', 'enctype', 'in_use', 'principal', 'version']
    _remap = {}
    _shadow_fields = ['_ref']


class LdapAuthService(InfobloxObject):
    _infoblox_type = 'ldap_auth_service'
    _fields = ['comment', 'disable', 'ea_mapping', 'ldap_group_attribute', 'ldap_group_authentication_type', 'ldap_user_attribute', 'mode', 'name', 'recovery_interval', 'retries', 'search_scope', 'servers', 'timeout']
    _search_for_update_fields = ['comment', 'mode', 'name']
    _updateable_search_fields = ['comment', 'mode', 'name', 'search_scope']
    _all_searchable_fields = ['comment', 'mode', 'name', 'search_scope']
    _return_fields = ['comment', 'disable', 'ldap_user_attribute', 'mode', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ea_mapping': LdapEamapping.from_dict,
        'servers': LdapServer.from_dict,
    }

    def check_ldap_server_settings(self, *args, **kwargs):
        return self._call_func("check_ldap_server_settings", *args, **kwargs)


class DHCPLease(InfobloxObject):
    _infoblox_type = 'lease'
    _fields = ['address', 'billing_class', 'binding_state', 'client_hostname', 'cltt', 'discovered_data', 'ends', 'fingerprint', 'hardware', 'ipv6_duid', 'ipv6_iaid', 'ipv6_preferred_lifetime', 'ipv6_prefix_bits', 'is_invalid_mac', 'ms_ad_user_data', 'network', 'network_view', 'never_ends', 'never_starts', 'next_binding_state', 'on_commit', 'on_expiry', 'on_release', 'option', 'protocol', 'remote_id', 'served_by', 'server_host_name', 'starts', 'tsfp', 'tstp', 'uid', 'username', 'variable']
    _search_for_update_fields = ['address', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'client_hostname', 'fingerprint', 'hardware', 'ipv6_duid', 'ipv6_prefix_bits', 'network', 'network_view', 'protocol', 'remote_id', 'username']
    _return_fields = ['address', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']


class LicenseGridwide(InfobloxObject):
    _infoblox_type = 'license:gridwide'
    _fields = ['expiration_status', 'expiry_date', 'key', 'limit', 'limit_context', 'type']
    _search_for_update_fields = ['type']
    _updateable_search_fields = []
    _all_searchable_fields = ['key', 'limit', 'type']
    _return_fields = ['type']
    _remap = {}
    _shadow_fields = ['_ref']


class LocaluserAuthservice(InfobloxObject):
    _infoblox_type = 'localuser:authservice'
    _fields = ['comment', 'disabled', 'name']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['comment', 'disabled', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Macfilteraddress(InfobloxObject):
    _infoblox_type = 'macfilteraddress'
    _fields = ['authentication_time', 'comment', 'expiration_time', 'extattrs', 'filter', 'fingerprint', 'guest_custom_field1', 'guest_custom_field2', 'guest_custom_field3', 'guest_custom_field4', 'guest_email', 'guest_first_name', 'guest_last_name', 'guest_middle_name', 'guest_phone', 'is_registered_user', 'mac', 'never_expires', 'reserved_for_infoblox', 'username']
    _search_for_update_fields = ['authentication_time', 'comment', 'expiration_time', 'filter', 'guest_custom_field1', 'guest_custom_field2', 'guest_custom_field3', 'guest_custom_field4', 'guest_email', 'guest_first_name', 'guest_last_name', 'guest_middle_name', 'guest_phone', 'mac', 'never_expires', 'reserved_for_infoblox', 'username']
    _updateable_search_fields = ['authentication_time', 'comment', 'expiration_time', 'filter', 'guest_custom_field1', 'guest_custom_field2', 'guest_custom_field3', 'guest_custom_field4', 'guest_email', 'guest_first_name', 'guest_last_name', 'guest_middle_name', 'guest_phone', 'mac', 'never_expires', 'reserved_for_infoblox', 'username']
    _all_searchable_fields = ['authentication_time', 'comment', 'expiration_time', 'filter', 'fingerprint', 'guest_custom_field1', 'guest_custom_field2', 'guest_custom_field3', 'guest_custom_field4', 'guest_email', 'guest_first_name', 'guest_last_name', 'guest_middle_name', 'guest_phone', 'mac', 'never_expires', 'reserved_for_infoblox', 'username']
    _return_fields = ['authentication_time', 'comment', 'expiration_time', 'extattrs', 'filter', 'guest_custom_field1', 'guest_custom_field2', 'guest_custom_field3', 'guest_custom_field4', 'guest_email', 'guest_first_name', 'guest_last_name', 'guest_middle_name', 'guest_phone', 'is_registered_user', 'mac', 'never_expires', 'reserved_for_infoblox', 'username']
    _remap = {}
    _shadow_fields = ['_ref']


class Mastergrid(InfobloxObject):
    _infoblox_type = 'mastergrid'
    _fields = ['address', 'connection_disabled', 'connection_timestamp', 'detached', 'enable', 'joined', 'last_event', 'last_event_details', 'last_sync_timestamp', 'port', 'status', 'use_mgmt_port']
    _search_for_update_fields = ['address', 'port']
    _updateable_search_fields = ['address', 'port']
    _all_searchable_fields = ['address', 'port']
    _return_fields = ['address', 'enable', 'port']
    _remap = {}
    _shadow_fields = ['_ref']


class Member(InfobloxObject):
    _infoblox_type = 'member'
    _fields = ['active_position', 'additional_ip_list', 'automated_traffic_capture_setting', 'bgp_as', 'comment', 'config_addr_type', 'csp_member_setting', 'dns_resolver_setting', 'dscp', 'email_setting', 'enable_ha', 'enable_lom', 'enable_member_redirect', 'enable_ro_api_access', 'extattrs', 'external_syslog_backup_servers', 'external_syslog_server_enable', 'host_name', 'ipv6_setting', 'ipv6_static_routes', 'is_dscp_capable', 'lan2_enabled', 'lan2_port_setting', 'lcd_input', 'lom_network_config', 'lom_users', 'master_candidate', 'member_service_communication', 'mgmt_port_setting', 'mmdb_ea_build_time', 'mmdb_geoip_build_time', 'nat_setting', 'node_info', 'ntp_setting', 'ospf_list', 'passive_ha_arp_enabled', 'platform', 'pre_provisioning', 'preserve_if_owns_delegation', 'remote_console_access_enable', 'router_id', 'service_status', 'service_type_configuration', 'snmp_setting', 'static_routes', 'support_access_enable', 'support_access_info', 'syslog_proxy_setting', 'syslog_servers', 'syslog_size', 'threshold_traps', 'time_zone', 'traffic_capture_auth_dns_setting', 'traffic_capture_chr_setting', 'traffic_capture_qps_setting', 'traffic_capture_rec_dns_setting', 'traffic_capture_rec_queries_setting', 'trap_notifications', 'upgrade_group', 'use_automated_traffic_capture', 'use_dns_resolver_setting', 'use_dscp', 'use_email_setting', 'use_enable_lom', 'use_enable_member_redirect', 'use_external_syslog_backup_servers', 'use_lcd_input', 'use_remote_console_access_enable', 'use_snmp_setting', 'use_support_access_enable', 'use_syslog_proxy_setting', 'use_threshold_traps', 'use_time_zone', 'use_traffic_capture_auth_dns', 'use_traffic_capture_chr', 'use_traffic_capture_qps', 'use_traffic_capture_rec_dns', 'use_traffic_capture_rec_queries', 'use_trap_notifications', 'use_v4_vrrp', 'vip_setting', 'vpn_mtu']
    _search_for_update_fields = ['config_addr_type', 'host_name', 'platform', 'service_type_configuration']
    _updateable_search_fields = ['comment', 'config_addr_type', 'enable_ha', 'enable_ro_api_access', 'host_name', 'master_candidate', 'platform', 'preserve_if_owns_delegation', 'router_id', 'service_type_configuration']
    _all_searchable_fields = ['comment', 'config_addr_type', 'enable_ha', 'enable_ro_api_access', 'host_name', 'master_candidate', 'platform', 'preserve_if_owns_delegation', 'router_id', 'service_type_configuration']
    _return_fields = ['config_addr_type', 'extattrs', 'host_name', 'platform', 'service_type_configuration']
    _remap = {'name': 'host_name'}
    _shadow_fields = ['_ref', 'name']

    _custom_field_processing = {
        'additional_ip_list': Interface.from_dict,
        'bgp_as': Bgpas.from_dict,
        'external_syslog_backup_servers': Extsyslogbackupserver.from_dict,
        'ipv6_static_routes': Ipv6Networksetting.from_dict,
        'lom_network_config': Lomnetworkconfig.from_dict,
        'lom_users': Lomuser.from_dict,
        'member_service_communication': Memberservicecommunication.from_dict,
        'node_info': Nodeinfo.from_dict,
        'ospf_list': Ospf.from_dict,
        'service_status': Memberservicestatus.from_dict,
        'static_routes': SettingNetwork.from_dict,
        'syslog_servers': Syslogserver.from_dict,
        'threshold_traps': Thresholdtrap.from_dict,
        'trap_notifications': Trapnotification.from_dict,
    }

    def capture_traffic_control(self, *args, **kwargs):
        return self._call_func("capture_traffic_control", *args, **kwargs)

    def capture_traffic_status(self, *args, **kwargs):
        return self._call_func("capture_traffic_status", *args, **kwargs)

    def create_token(self, *args, **kwargs):
        return self._call_func("create_token", *args, **kwargs)

    def member_admin_operation(self, *args, **kwargs):
        return self._call_func("member_admin_operation", *args, **kwargs)

    def read_token(self, *args, **kwargs):
        return self._call_func("read_token", *args, **kwargs)

    def requestrestartservicestatus(self, *args, **kwargs):
        return self._call_func("requestrestartservicestatus", *args, **kwargs)

    def restartservices(self, *args, **kwargs):
        return self._call_func("restartservices", *args, **kwargs)


class MemberDhcpproperties(InfobloxObject):
    _infoblox_type = 'member:dhcpproperties'
    _fields = ['auth_server_group', 'authn_captive_portal', 'authn_captive_portal_authenticated_filter', 'authn_captive_portal_enabled', 'authn_captive_portal_guest_filter', 'authn_server_group_enabled', 'authority', 'bootfile', 'bootserver', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_retry_interval', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'ddns_zone_primaries', 'deny_bootp', 'dhcp_utilization', 'dhcp_utilization_status', 'dns_update_style', 'dynamic_hosts', 'email_list', 'enable_ddns', 'enable_dhcp', 'enable_dhcp_on_ipv6_lan2', 'enable_dhcp_on_lan2', 'enable_dhcp_thresholds', 'enable_dhcpv6_service', 'enable_email_warnings', 'enable_fingerprint', 'enable_gss_tsig', 'enable_hostname_rewrite', 'enable_leasequery', 'enable_snmp_warnings', 'extattrs', 'gss_tsig_keys', 'high_water_mark', 'high_water_mark_reset', 'host_name', 'hostname_rewrite_policy', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'immediate_fa_configuration', 'ipv4addr', 'ipv6_ddns_domainname', 'ipv6_ddns_enable_option_fqdn', 'ipv6_ddns_hostname', 'ipv6_ddns_server_always_updates', 'ipv6_ddns_ttl', 'ipv6_dns_update_style', 'ipv6_domain_name', 'ipv6_domain_name_servers', 'ipv6_enable_ddns', 'ipv6_enable_gss_tsig', 'ipv6_enable_lease_scavenging', 'ipv6_enable_retry_updates', 'ipv6_generate_hostname', 'ipv6_gss_tsig_keys', 'ipv6_kdc_server', 'ipv6_lease_scavenging_time', 'ipv6_microsoft_code_page', 'ipv6_options', 'ipv6_recycle_leases', 'ipv6_remember_expired_client_association', 'ipv6_retry_updates_interval', 'ipv6_server_duid', 'ipv6_update_dns_on_lease_renewal', 'ipv6addr', 'kdc_server', 'lease_per_client_settings', 'lease_scavenge_time', 'log_lease_events', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'microsoft_code_page', 'nextserver', 'option60_match_rules', 'options', 'ping_count', 'ping_timeout', 'preferred_lifetime', 'prefix_length_mode', 'pxe_lease_time', 'recycle_leases', 'retry_ddns_updates', 'static_hosts', 'syslog_facility', 'total_hosts', 'update_dns_on_lease_renewal', 'use_authority', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_update_fixed_addresses', 'use_ddns_use_option81', 'use_deny_bootp', 'use_dns_update_style', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_enable_fingerprint', 'use_enable_gss_tsig', 'use_enable_hostname_rewrite', 'use_enable_leasequery', 'use_enable_one_lease_per_client', 'use_gss_tsig_keys', 'use_ignore_dhcp_option_list_request', 'use_ignore_id', 'use_immediate_fa_configuration', 'use_ipv6_ddns_domainname', 'use_ipv6_ddns_enable_option_fqdn', 'use_ipv6_ddns_hostname', 'use_ipv6_ddns_ttl', 'use_ipv6_dns_update_style', 'use_ipv6_domain_name', 'use_ipv6_domain_name_servers', 'use_ipv6_enable_ddns', 'use_ipv6_enable_gss_tsig', 'use_ipv6_enable_retry_updates', 'use_ipv6_generate_hostname', 'use_ipv6_gss_tsig_keys', 'use_ipv6_lease_scavenging', 'use_ipv6_microsoft_code_page', 'use_ipv6_options', 'use_ipv6_recycle_leases', 'use_ipv6_update_dns_on_lease_renewal', 'use_lease_per_client_settings', 'use_lease_scavenge_time', 'use_log_lease_events', 'use_logic_filter_rules', 'use_microsoft_code_page', 'use_nextserver', 'use_options', 'use_ping_count', 'use_ping_timeout', 'use_preferred_lifetime', 'use_prefix_length_mode', 'use_pxe_lease_time', 'use_recycle_leases', 'use_retry_ddns_updates', 'use_syslog_facility', 'use_update_dns_on_lease_renewal', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['host_name', 'ipv4addr', 'ipv6addr']
    _updateable_search_fields = []
    _all_searchable_fields = ['host_name', 'ipv4addr', 'ipv6addr']
    _return_fields = ['extattrs', 'host_name', 'ipv4addr', 'ipv6addr']
    _remap = {}
    _shadow_fields = ['_ref', 'ip']

    @property
    def ip(self):
        if hasattr(self, '_ip'):
            return str(self._ip)

    # This object represents both ipv4 and ipv6 objects, so it doesn't need
    # versioned object for that. Just set v4 or v6 field in addition
    # to setting shadow field 'ip' itself.
    @ip.setter
    def ip(self, ip):
        self._ip = ip
    
        if ib_utils.determine_ip_version(ip) == 6:
            if 'ipv6addr' not in self._fields:
                raise ib_ex.InfobloxInvalidIp(ip=ip)
            self.ipv6addr = ip
        else:
            if 'ipv4addr' not in self._fields:
                raise ib_ex.InfobloxInvalidIp(ip=ip)
            self.ipv4addr = ip
    

    _custom_field_processing = {
        'ddns_zone_primaries': Dhcpddns.from_dict,
        'ipv6_options': Dhcpoption.from_dict,
        'logic_filter_rules': Logicfilterrule.from_dict,
        'option60_match_rules': Option60Matchrule.from_dict,
        'options': Dhcpoption.from_dict,
    }

    def clear_nac_auth_cache(self, *args, **kwargs):
        return self._call_func("clear_nac_auth_cache", *args, **kwargs)

    def purge_ifmap_data(self, *args, **kwargs):
        return self._call_func("purge_ifmap_data", *args, **kwargs)


class MemberDns(InfobloxObject):
    _infoblox_type = 'member:dns'
    _fields = ['add_client_ip_mac_options', 'additional_ip_list', 'additional_ip_list_struct', 'allow_gss_tsig_zone_updates', 'allow_query', 'allow_recursive_query', 'allow_transfer', 'allow_update', 'anonymize_response_logging', 'atc_fwd_enable', 'atc_fwd_forward_first', 'attack_mitigation', 'auto_blackhole', 'auto_create_a_and_ptr_for_lan2', 'auto_create_aaaa_and_ipv6ptr_for_lan2', 'auto_sort_views', 'bind_check_names_policy', 'bind_hostname_directive', 'bind_hostname_directive_fqdn', 'blackhole_list', 'blacklist_action', 'blacklist_log_query', 'blacklist_redirect_addresses', 'blacklist_redirect_ttl', 'blacklist_rulesets', 'capture_dns_queries_on_all_domains', 'check_names_for_ddns_and_zone_transfer', 'copy_client_ip_mac_options', 'copy_xfer_to_notify', 'custom_root_name_servers', 'disable_edns', 'dns64_groups', 'dns_cache_acceleration_status', 'dns_cache_acceleration_ttl', 'dns_health_check_anycast_control', 'dns_health_check_domain_list', 'dns_health_check_interval', 'dns_health_check_recursion_flag', 'dns_health_check_retries', 'dns_health_check_timeout', 'dns_notify_transfer_source', 'dns_notify_transfer_source_address', 'dns_query_capture_file_time_limit', 'dns_query_source_address', 'dns_query_source_interface', 'dns_view_address_settings', 'dnssec_blacklist_enabled', 'dnssec_dns64_enabled', 'dnssec_enabled', 'dnssec_expired_signatures_enabled', 'dnssec_negative_trust_anchors', 'dnssec_nxdomain_enabled', 'dnssec_rpz_enabled', 'dnssec_trusted_keys', 'dnssec_validation_enabled', 'domains_to_capture_dns_queries', 'dtc_edns_prefer_client_subnet', 'dtc_health_source', 'dtc_health_source_address', 'enable_blackhole', 'enable_blacklist', 'enable_capture_dns_queries', 'enable_capture_dns_responses', 'enable_dns', 'enable_dns64', 'enable_dns_cache_acceleration', 'enable_dns_health_check', 'enable_excluded_domain_names', 'enable_fixed_rrset_order_fqdns', 'enable_ftc', 'enable_gss_tsig', 'enable_notify_source_port', 'enable_query_rewrite', 'enable_query_source_port', 'excluded_domain_names', 'extattrs', 'file_transfer_setting', 'filter_aaaa', 'filter_aaaa_list', 'fixed_rrset_order_fqdns', 'forward_only', 'forward_updates', 'forwarders', 'ftc_expired_record_timeout', 'ftc_expired_record_ttl', 'glue_record_addresses', 'gss_tsig_keys', 'host_name', 'ipv4addr', 'ipv6_glue_record_addresses', 'ipv6addr', 'is_unbound_capable', 'lame_ttl', 'lan1_ipsd', 'lan1_ipv6_ipsd', 'lan2_ipsd', 'lan2_ipv6_ipsd', 'logging_categories', 'max_cache_ttl', 'max_cached_lifetime', 'max_ncache_ttl', 'mgmt_ipsd', 'mgmt_ipv6_ipsd', 'minimal_resp', 'notify_delay', 'notify_source_port', 'nxdomain_log_query', 'nxdomain_redirect', 'nxdomain_redirect_addresses', 'nxdomain_redirect_addresses_v6', 'nxdomain_redirect_ttl', 'nxdomain_rulesets', 'query_source_port', 'record_name_policy', 'recursive_client_limit', 'recursive_query_list', 'recursive_resolver', 'resolver_query_timeout', 'response_rate_limiting', 'root_name_server_type', 'rpz_disable_nsdname_nsip', 'rpz_drop_ip_rule_enabled', 'rpz_drop_ip_rule_min_prefix_length_ipv4', 'rpz_drop_ip_rule_min_prefix_length_ipv6', 'rpz_qname_wait_recurse', 'serial_query_rate', 'server_id_directive', 'server_id_directive_string', 'skip_in_grid_rpz_queries', 'sortlist', 'store_locally', 'syslog_facility', 'transfer_excluded_servers', 'transfer_format', 'transfers_in', 'transfers_out', 'transfers_per_ns', 'unbound_logging_level', 'use_add_client_ip_mac_options', 'use_allow_query', 'use_allow_transfer', 'use_attack_mitigation', 'use_auto_blackhole', 'use_bind_hostname_directive', 'use_blackhole', 'use_blacklist', 'use_capture_dns_queries_on_all_domains', 'use_copy_client_ip_mac_options', 'use_copy_xfer_to_notify', 'use_disable_edns', 'use_dns64', 'use_dns_cache_acceleration_ttl', 'use_dns_health_check', 'use_dnssec', 'use_dtc_edns_prefer_client_subnet', 'use_enable_capture_dns', 'use_enable_excluded_domain_names', 'use_enable_gss_tsig', 'use_enable_query_rewrite', 'use_filter_aaaa', 'use_fixed_rrset_order_fqdns', 'use_forward_updates', 'use_forwarders', 'use_ftc', 'use_gss_tsig_keys', 'use_lame_ttl', 'use_lan2_ipv6_port', 'use_lan2_port', 'use_lan_ipv6_port', 'use_lan_port', 'use_logging_categories', 'use_max_cache_ttl', 'use_max_cached_lifetime', 'use_max_ncache_ttl', 'use_mgmt_ipv6_port', 'use_mgmt_port', 'use_notify_delay', 'use_nxdomain_redirect', 'use_record_name_policy', 'use_recursive_client_limit', 'use_recursive_query_setting', 'use_resolver_query_timeout', 'use_response_rate_limiting', 'use_root_name_server', 'use_rpz_disable_nsdname_nsip', 'use_rpz_drop_ip_rule', 'use_rpz_qname_wait_recurse', 'use_serial_query_rate', 'use_server_id_directive', 'use_sortlist', 'use_source_ports', 'use_syslog_facility', 'use_transfers_in', 'use_transfers_out', 'use_transfers_per_ns', 'use_update_setting', 'use_zone_transfer_format', 'views']
    _search_for_update_fields = ['host_name', 'ipv4addr', 'ipv6addr']
    _updateable_search_fields = []
    _all_searchable_fields = ['host_name', 'ipv4addr', 'ipv6addr']
    _return_fields = ['extattrs', 'host_name', 'ipv4addr', 'ipv6addr']
    _remap = {}
    _shadow_fields = ['_ref', 'ip']

    @property
    def ip(self):
        if hasattr(self, '_ip'):
            return str(self._ip)

    # This object represents both ipv4 and ipv6 objects, so it doesn't need
    # versioned object for that. Just set v4 or v6 field in addition
    # to setting shadow field 'ip' itself.
    @ip.setter
    def ip(self, ip):
        self._ip = ip
    
        if ib_utils.determine_ip_version(ip) == 6:
            if 'ipv6addr' not in self._fields:
                raise ib_ex.InfobloxInvalidIp(ip=ip)
            self.ipv6addr = ip
        else:
            if 'ipv4addr' not in self._fields:
                raise ib_ex.InfobloxInvalidIp(ip=ip)
            self.ipv4addr = ip
    

    _custom_field_processing = {
        'additional_ip_list_struct': MemberDnsip.from_dict,
        'allow_query': Addressac.from_dict,
        'allow_transfer': Addressac.from_dict,
        'allow_update': Addressac.from_dict,
        'blackhole_list': Addressac.from_dict,
        'custom_root_name_servers': Extserver.from_dict,
        'dns_view_address_settings': SettingViewaddress.from_dict,
        'dnssec_trusted_keys': Dnssectrustedkey.from_dict,
        'filter_aaaa_list': Addressac.from_dict,
        'fixed_rrset_order_fqdns': GridDnsFixedrrsetorderfqdn.from_dict,
        'glue_record_addresses': MemberDnsgluerecordaddr.from_dict,
        'ipv6_glue_record_addresses': MemberDnsgluerecordaddr.from_dict,
        'recursive_query_list': Addressac.from_dict,
        'sortlist': Sortlist.from_dict,
    }

    def clear_dns_cache(self, *args, **kwargs):
        return self._call_func("clear_dns_cache", *args, **kwargs)


class MemberFiledistribution(InfobloxObject):
    _infoblox_type = 'member:filedistribution'
    _fields = ['allow_uploads', 'comment', 'enable_ftp', 'enable_ftp_filelist', 'enable_ftp_passive', 'enable_http', 'enable_http_acl', 'enable_tftp', 'ftp_acls', 'ftp_port', 'ftp_status', 'host_name', 'http_acls', 'http_status', 'ipv4_address', 'ipv6_address', 'status', 'tftp_acls', 'tftp_port', 'tftp_status', 'use_allow_uploads']
    _search_for_update_fields = ['host_name', 'ipv4_address', 'ipv6_address']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'host_name', 'ipv4_address', 'ipv6_address']
    _return_fields = ['host_name', 'ipv4_address', 'ipv6_address', 'status']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ftp_acls': Addressac.from_dict,
        'http_acls': Addressac.from_dict,
        'tftp_acls': Addressac.from_dict,
    }


class MemberLicense(InfobloxObject):
    _infoblox_type = 'member:license'
    _fields = ['expiration_status', 'expiry_date', 'hwid', 'key', 'kind', 'limit', 'limit_context', 'type']
    _search_for_update_fields = ['type']
    _updateable_search_fields = []
    _all_searchable_fields = ['hwid', 'key', 'kind', 'limit', 'type']
    _return_fields = ['type']
    _remap = {}
    _shadow_fields = ['_ref']


class MemberParentalcontrol(InfobloxObject):
    _infoblox_type = 'member:parentalcontrol'
    _fields = ['enable_service', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['enable_service', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class MemberThreatanalytics(InfobloxObject):
    _infoblox_type = 'member:threatanalytics'
    _fields = ['comment', 'enable_service', 'host_name', 'ipv4_address', 'ipv6_address', 'status']
    _search_for_update_fields = ['host_name', 'ipv4_address', 'ipv6_address']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'host_name', 'ipv4_address', 'ipv6_address']
    _return_fields = ['host_name', 'ipv4_address', 'ipv6_address', 'status']
    _remap = {}
    _shadow_fields = ['_ref']


class MemberThreatprotection(InfobloxObject):
    _infoblox_type = 'member:threatprotection'
    _fields = ['comment', 'current_ruleset', 'disable_multiple_dns_tcp_request', 'enable_accel_resp_before_threat_protection', 'enable_nat_rules', 'enable_service', 'events_per_second_per_rule', 'hardware_model', 'hardware_type', 'host_name', 'ipv4address', 'ipv6address', 'nat_rules', 'outbound_settings', 'profile', 'use_current_ruleset', 'use_disable_multiple_dns_tcp_request', 'use_enable_accel_resp_before_threat_protection', 'use_enable_nat_rules', 'use_events_per_second_per_rule', 'use_outbound_settings']
    _search_for_update_fields = []
    _updateable_search_fields = ['current_ruleset', 'profile']
    _all_searchable_fields = ['comment', 'current_ruleset', 'hardware_model', 'hardware_type', 'host_name', 'ipv4address', 'ipv6address', 'profile']
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'nat_rules': ThreatprotectionNatrule.from_dict,
    }


class Msserver(InfobloxObject):
    _infoblox_type = 'msserver'
    _fields = ['ad_domain', 'ad_sites', 'ad_user', 'address', 'comment', 'connection_status', 'connection_status_detail', 'dhcp_server', 'disabled', 'dns_server', 'dns_view', 'extattrs', 'grid_member', 'last_seen', 'log_destination', 'log_level', 'login_name', 'login_password', 'managing_member', 'ms_max_connection', 'ms_rpc_timeout_in_seconds', 'network_view', 'read_only', 'root_ad_domain', 'server_name', 'synchronization_min_delay', 'synchronization_status', 'synchronization_status_detail', 'use_log_destination', 'use_ms_max_connection', 'use_ms_rpc_timeout_in_seconds', 'version']
    _search_for_update_fields = ['address']
    _updateable_search_fields = ['address', 'grid_member']
    _all_searchable_fields = ['address', 'grid_member']
    _return_fields = ['address', 'extattrs']
    _remap = {}
    _shadow_fields = ['_ref']


class MsserverAdsitesDomain(InfobloxObject):
    _infoblox_type = 'msserver:adsites:domain'
    _fields = ['ea_definition', 'ms_sync_master_name', 'name', 'netbios', 'network_view', 'read_only']
    _search_for_update_fields = ['name', 'netbios', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['ea_definition', 'name', 'netbios', 'network_view']
    _return_fields = ['name', 'netbios', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']


class MsserverAdsitesSite(InfobloxObject):
    _infoblox_type = 'msserver:adsites:site'
    _fields = ['domain', 'name', 'networks']
    _search_for_update_fields = ['domain', 'name']
    _updateable_search_fields = ['domain', 'name']
    _all_searchable_fields = ['domain', 'name']
    _return_fields = ['domain', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    def move_subnets(self, *args, **kwargs):
        return self._call_func("move_subnets", *args, **kwargs)


class MsserverDhcp(InfobloxObject):
    _infoblox_type = 'msserver:dhcp'
    _fields = ['address', 'comment', 'dhcp_utilization', 'dhcp_utilization_status', 'dynamic_hosts', 'last_sync_ts', 'login_name', 'login_password', 'network_view', 'next_sync_control', 'read_only', 'server_name', 'static_hosts', 'status', 'status_detail', 'status_last_updated', 'supports_failover', 'synchronization_interval', 'total_hosts', 'use_login', 'use_synchronization_interval']
    _search_for_update_fields = ['address']
    _updateable_search_fields = []
    _all_searchable_fields = ['address']
    _return_fields = ['address']
    _remap = {}
    _shadow_fields = ['_ref']


class MsserverDns(InfobloxObject):
    _infoblox_type = 'msserver:dns'
    _fields = ['address', 'enable_dns_reports_sync', 'login_name', 'login_password', 'synchronization_interval', 'use_enable_dns_reports_sync', 'use_login', 'use_synchronization_interval']
    _search_for_update_fields = ['address']
    _updateable_search_fields = []
    _all_searchable_fields = ['address']
    _return_fields = ['address']
    _remap = {}
    _shadow_fields = ['_ref']


class Mssuperscope(InfobloxObject):
    _infoblox_type = 'mssuperscope'
    _fields = ['comment', 'dhcp_utilization', 'dhcp_utilization_status', 'disable', 'dynamic_hosts', 'extattrs', 'high_water_mark', 'high_water_mark_reset', 'low_water_mark', 'low_water_mark_reset', 'name', 'network_view', 'ranges', 'static_hosts', 'total_hosts']
    _search_for_update_fields = ['name', 'network_view']
    _updateable_search_fields = ['comment', 'name', 'network_view']
    _all_searchable_fields = ['comment', 'name', 'network_view']
    _return_fields = ['disable', 'extattrs', 'name', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']


class Namedacl(InfobloxObject):
    _infoblox_type = 'namedacl'
    _fields = ['access_list', 'comment', 'exploded_access_list', 'extattrs', 'name']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'access_list': Addressac.from_dict,
        'exploded_access_list': Addressac.from_dict,
    }

    def validate_acl_items(self, *args, **kwargs):
        return self._call_func("validate_acl_items", *args, **kwargs)


class Natgroup(InfobloxObject):
    _infoblox_type = 'natgroup'
    _fields = ['comment', 'name']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class NetworkDiscovery(InfobloxObject):
    _infoblox_type = 'network_discovery'
    _fields = []
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    def clear_discovery_data(self, *args, **kwargs):
        return self._call_func("clear_discovery_data", *args, **kwargs)


class Networkuser(InfobloxObject):
    _infoblox_type = 'networkuser'
    _fields = ['address', 'address_object', 'data_source', 'data_source_ip', 'domainname', 'first_seen_time', 'guid', 'last_seen_time', 'last_updated_time', 'logon_id', 'logout_time', 'name', 'network', 'network_view', 'user_status']
    _search_for_update_fields = ['address', 'domainname', 'name', 'network_view', 'user_status']
    _updateable_search_fields = ['address', 'domainname', 'guid', 'logon_id', 'name', 'network_view']
    _all_searchable_fields = ['address', 'domainname', 'guid', 'logon_id', 'name', 'network_view', 'user_status']
    _return_fields = ['address', 'domainname', 'name', 'network_view', 'user_status']
    _remap = {}
    _shadow_fields = ['_ref']


class NetworkView(InfobloxObject):
    _infoblox_type = 'networkview'
    _fields = ['associated_dns_views', 'associated_members', 'cloud_info', 'comment', 'ddns_dns_view', 'ddns_zone_primaries', 'extattrs', 'internal_forward_zones', 'is_default', 'mgm_private', 'ms_ad_user_data', 'name', 'remote_forward_zones', 'remote_reverse_zones']
    _search_for_update_fields = ['comment', 'is_default', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'is_default', 'name']
    _return_fields = ['comment', 'extattrs', 'is_default', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'associated_members': NetworkviewAssocmember.from_dict,
        'ddns_zone_primaries': Dhcpddns.from_dict,
        'remote_forward_zones': Remoteddnszone.from_dict,
        'remote_reverse_zones': Remoteddnszone.from_dict,
    }


class NotificationRestEndpoint(InfobloxObject):
    _infoblox_type = 'notification:rest:endpoint'
    _fields = ['client_certificate_subject', 'client_certificate_token', 'client_certificate_valid_from', 'client_certificate_valid_to', 'comment', 'extattrs', 'log_level', 'name', 'outbound_member_type', 'outbound_members', 'password', 'server_cert_validation', 'sync_disabled', 'template_instance', 'timeout', 'uri', 'username', 'vendor_identifier', 'wapi_user_name', 'wapi_user_password']
    _search_for_update_fields = ['name', 'outbound_member_type', 'uri']
    _updateable_search_fields = ['log_level', 'name', 'outbound_member_type', 'uri', 'vendor_identifier']
    _all_searchable_fields = ['log_level', 'name', 'outbound_member_type', 'uri', 'vendor_identifier']
    _return_fields = ['extattrs', 'name', 'outbound_member_type', 'uri']
    _remap = {}
    _shadow_fields = ['_ref']

    def clear_outbound_worker_log(self, *args, **kwargs):
        return self._call_func("clear_outbound_worker_log", *args, **kwargs)

    def test_connection(self, *args, **kwargs):
        return self._call_func("test_connection", *args, **kwargs)


class NotificationRestTemplate(InfobloxObject):
    _infoblox_type = 'notification:rest:template'
    _fields = ['action_name', 'added_on', 'comment', 'content', 'event_type', 'name', 'outbound_type', 'parameters', 'template_type', 'vendor_identifier']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name', 'outbound_type']
    _return_fields = ['content', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'parameters': NotificationRestTemplateparameter.from_dict,
    }


class NotificationRule(InfobloxObject):
    _infoblox_type = 'notification:rule'
    _fields = ['all_members', 'comment', 'disable', 'enable_event_deduplication', 'enable_event_deduplication_log', 'event_deduplication_fields', 'event_deduplication_lookback_period', 'event_priority', 'event_type', 'expression_list', 'name', 'notification_action', 'notification_target', 'publish_settings', 'scheduled_event', 'selected_members', 'template_instance', 'use_publish_settings']
    _search_for_update_fields = ['event_type', 'name', 'notification_action', 'notification_target']
    _updateable_search_fields = ['comment', 'event_priority', 'event_type', 'notification_action', 'notification_target']
    _all_searchable_fields = ['comment', 'event_priority', 'event_type', 'name', 'notification_action', 'notification_target']
    _return_fields = ['event_type', 'name', 'notification_action', 'notification_target']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'expression_list': NotificationRuleexpressionop.from_dict,
    }

    def trigger_outbound(self, *args, **kwargs):
        return self._call_func("trigger_outbound", *args, **kwargs)


class Nsgroup(InfobloxObject):
    _infoblox_type = 'nsgroup'
    _fields = ['comment', 'extattrs', 'external_primaries', 'external_secondaries', 'grid_primary', 'grid_secondaries', 'is_grid_default', 'is_multimaster', 'name', 'use_external_primary']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'external_primaries': Extserver.from_dict,
        'external_secondaries': Extserver.from_dict,
        'grid_primary': Memberserver.from_dict,
        'grid_secondaries': Memberserver.from_dict,
    }


class NsgroupDelegation(InfobloxObject):
    _infoblox_type = 'nsgroup:delegation'
    _fields = ['comment', 'delegate_to', 'extattrs', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['delegate_to', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'delegate_to': Extserver.from_dict,
    }


class NsgroupForwardingmember(InfobloxObject):
    _infoblox_type = 'nsgroup:forwardingmember'
    _fields = ['comment', 'extattrs', 'forwarding_servers', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['extattrs', 'forwarding_servers', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'forwarding_servers': Forwardingmemberserver.from_dict,
    }


class NsgroupForwardstubserver(InfobloxObject):
    _infoblox_type = 'nsgroup:forwardstubserver'
    _fields = ['comment', 'extattrs', 'external_servers', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['extattrs', 'external_servers', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'external_servers': Extserver.from_dict,
    }


class NsgroupStubmember(InfobloxObject):
    _infoblox_type = 'nsgroup:stubmember'
    _fields = ['comment', 'extattrs', 'name', 'stub_members']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'stub_members': Memberserver.from_dict,
    }


class Orderedranges(InfobloxObject):
    _infoblox_type = 'orderedranges'
    _fields = ['network', 'ranges']
    _search_for_update_fields = ['network']
    _updateable_search_fields = []
    _all_searchable_fields = ['network']
    _return_fields = ['network', 'ranges']
    _remap = {}
    _shadow_fields = ['_ref']


class Orderedresponsepolicyzones(InfobloxObject):
    _infoblox_type = 'orderedresponsepolicyzones'
    _fields = ['rp_zones', 'view']
    _search_for_update_fields = ['view']
    _updateable_search_fields = ['view']
    _all_searchable_fields = ['view']
    _return_fields = ['view']
    _remap = {}
    _shadow_fields = ['_ref']


class OutboundCloudclient(InfobloxObject):
    _infoblox_type = 'outbound:cloudclient'
    _fields = ['enable', 'grid_member', 'interval', 'outbound_cloud_client_events']
    _search_for_update_fields = []
    _updateable_search_fields = ['grid_member']
    _all_searchable_fields = ['grid_member']
    _return_fields = ['enable', 'interval']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'outbound_cloud_client_events': OutboundCloudclientEvent.from_dict,
    }


class ParentalcontrolAvp(InfobloxObject):
    _infoblox_type = 'parentalcontrol:avp'
    _fields = ['comment', 'domain_types', 'is_restricted', 'name', 'type', 'user_defined', 'value_type', 'vendor_id', 'vendor_type']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name', 'vendor_id', 'vendor_type']
    _all_searchable_fields = ['comment', 'name', 'vendor_id', 'vendor_type']
    _return_fields = ['name', 'type', 'value_type']
    _remap = {}
    _shadow_fields = ['_ref']


class ParentalcontrolBlockingpolicy(InfobloxObject):
    _infoblox_type = 'parentalcontrol:blockingpolicy'
    _fields = ['name', 'value']
    _search_for_update_fields = ['name', 'value']
    _updateable_search_fields = ['name', 'value']
    _all_searchable_fields = ['name', 'value']
    _return_fields = ['name', 'value']
    _remap = {}
    _shadow_fields = ['_ref']


class ParentalcontrolIpspacediscriminator(InfobloxObject):
    _infoblox_type = 'parentalcontrol:ipspacediscriminator'
    _fields = ['name', 'value']
    _search_for_update_fields = ['name', 'value']
    _updateable_search_fields = ['name', 'value']
    _all_searchable_fields = ['name', 'value']
    _return_fields = ['name', 'value']
    _remap = {}
    _shadow_fields = ['_ref']


class ParentalcontrolSubscriber(InfobloxObject):
    _infoblox_type = 'parentalcontrol:subscriber'
    _fields = ['alt_subscriber_id', 'alt_subscriber_id_regexp', 'alt_subscriber_id_subexpression', 'ancillaries', 'cat_acctname', 'cat_password', 'cat_update_frequency', 'category_url', 'enable_mgmt_only_nas', 'enable_parental_control', 'ident', 'interim_accounting_interval', 'ip_anchors', 'ip_space_disc_regexp', 'ip_space_disc_subexpression', 'ip_space_discriminator', 'local_id', 'local_id_regexp', 'local_id_subexpression', 'log_guest_lookups', 'nas_context_info', 'pc_zone_name', 'proxy_password', 'proxy_url', 'proxy_username', 'subscriber_id', 'subscriber_id_regexp', 'subscriber_id_subexpression']
    _search_for_update_fields = ['alt_subscriber_id', 'local_id', 'subscriber_id']
    _updateable_search_fields = ['alt_subscriber_id', 'local_id', 'subscriber_id']
    _all_searchable_fields = ['alt_subscriber_id', 'local_id', 'subscriber_id']
    _return_fields = ['alt_subscriber_id', 'local_id', 'subscriber_id']
    _remap = {}
    _shadow_fields = ['_ref']


class ParentalcontrolSubscriberrecord(InfobloxObject):
    _infoblox_type = 'parentalcontrol:subscriberrecord'
    _fields = ['accounting_session_id', 'alt_ip_addr', 'ans0', 'ans1', 'ans2', 'ans3', 'ans4', 'black_list', 'bwflag', 'dynamic_category_policy', 'flags', 'ip_addr', 'ipsd', 'localid', 'nas_contextual', 'parental_control_policy', 'prefix', 'proxy_all', 'site', 'subscriber_id', 'subscriber_secure_policy', 'unknown_category_policy', 'white_list', 'wpc_category_policy']
    _search_for_update_fields = ['ip_addr', 'ipsd', 'localid', 'prefix', 'site', 'subscriber_id']
    _updateable_search_fields = ['ip_addr', 'ipsd', 'localid', 'prefix', 'site', 'subscriber_id']
    _all_searchable_fields = ['ip_addr', 'ipsd', 'localid', 'prefix', 'site', 'subscriber_id']
    _return_fields = ['accounting_session_id', 'ip_addr', 'ipsd', 'localid', 'prefix', 'site', 'subscriber_id']
    _remap = {}
    _shadow_fields = ['_ref']


class ParentalcontrolSubscribersite(InfobloxObject):
    _infoblox_type = 'parentalcontrol:subscribersite'
    _fields = ['abss', 'block_size', 'blocking_ipv4_vip1', 'blocking_ipv4_vip2', 'blocking_ipv6_vip1', 'blocking_ipv6_vip2', 'comment', 'extattrs', 'first_port', 'maximum_subscribers', 'members', 'msps', 'name', 'nas_gateways', 'nas_port', 'spms', 'strict_nat']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['blocking_ipv4_vip1', 'blocking_ipv4_vip2', 'blocking_ipv6_vip1', 'blocking_ipv6_vip2', 'comment']
    _all_searchable_fields = ['blocking_ipv4_vip1', 'blocking_ipv4_vip2', 'blocking_ipv6_vip1', 'blocking_ipv6_vip2', 'comment', 'name']
    _return_fields = ['block_size', 'extattrs', 'first_port', 'name', 'strict_nat']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'abss': ParentalcontrolAbs.from_dict,
        'members': ParentalcontrolSitemember.from_dict,
        'msps': ParentalcontrolMsp.from_dict,
        'nas_gateways': ParentalcontrolNasgateway.from_dict,
        'spms': ParentalcontrolSpm.from_dict,
    }


class Permission(InfobloxObject):
    _infoblox_type = 'permission'
    _fields = ['group', 'object', 'permission', 'resource_type', 'role']
    _search_for_update_fields = ['group', 'permission', 'resource_type', 'role']
    _updateable_search_fields = ['group', 'object', 'permission', 'resource_type', 'role']
    _all_searchable_fields = ['group', 'object', 'permission', 'resource_type', 'role']
    _return_fields = ['group', 'permission', 'resource_type', 'role']
    _remap = {}
    _shadow_fields = ['_ref']


class PxgridEndpoint(InfobloxObject):
    _infoblox_type = 'pxgrid:endpoint'
    _fields = ['address', 'client_certificate_subject', 'client_certificate_token', 'client_certificate_valid_from', 'client_certificate_valid_to', 'comment', 'disable', 'extattrs', 'log_level', 'name', 'network_view', 'outbound_member_type', 'outbound_members', 'publish_settings', 'subscribe_settings', 'template_instance', 'timeout', 'vendor_identifier', 'wapi_user_name', 'wapi_user_password']
    _search_for_update_fields = ['address', 'name', 'outbound_member_type']
    _updateable_search_fields = ['address', 'comment', 'log_level', 'name', 'network_view', 'outbound_member_type', 'vendor_identifier']
    _all_searchable_fields = ['address', 'comment', 'log_level', 'name', 'network_view', 'outbound_member_type', 'vendor_identifier']
    _return_fields = ['address', 'disable', 'extattrs', 'name', 'outbound_member_type']
    _remap = {}
    _shadow_fields = ['_ref']

    def test_connection(self, *args, **kwargs):
        return self._call_func("test_connection", *args, **kwargs)


class RadiusAuthservice(InfobloxObject):
    _infoblox_type = 'radius:authservice'
    _fields = ['acct_retries', 'acct_timeout', 'auth_retries', 'auth_timeout', 'cache_ttl', 'comment', 'disable', 'enable_cache', 'mode', 'name', 'recovery_interval', 'servers']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'mode', 'name']
    _all_searchable_fields = ['comment', 'mode', 'name']
    _return_fields = ['comment', 'disable', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'servers': RadiusServer.from_dict,
    }

    def check_radius_server_settings(self, *args, **kwargs):
        return self._call_func("check_radius_server_settings", *args, **kwargs)


class ARecordBase(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return ARecord

    @classmethod
    def get_v6_class(cls):
        return AAAARecord


class ARecord(ARecordBase):
    _infoblox_type = 'record:a'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'discovered_data', 'dns_name', 'extattrs', 'forbid_reclamation', 'ipv4addr', 'last_queried', 'ms_ad_user_data', 'name', 'reclaimable', 'remove_associated_ptr', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv4addr', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'ipv4addr', 'name']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'ipv4addr', 'name', 'reclaimable', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv4addr', 'name', 'view']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 4



class AAAARecord(ARecordBase):
    _infoblox_type = 'record:aaaa'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'discovered_data', 'dns_name', 'extattrs', 'forbid_reclamation', 'ipv6addr', 'last_queried', 'ms_ad_user_data', 'name', 'reclaimable', 'remove_associated_ptr', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv6addr', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'ipv6addr', 'name', 'reclaimable', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv6addr', 'name', 'view']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 6


class AliasRecord(InfobloxObject):
    _infoblox_type = 'record:alias'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creator', 'disable', 'dns_name', 'dns_target_name', 'extattrs', 'last_queried', 'name', 'target_name', 'target_type', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'target_name', 'target_type', 'view']
    _updateable_search_fields = ['comment', 'name', 'target_name', 'target_type', 'view']
    _all_searchable_fields = ['comment', 'name', 'target_name', 'target_type', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'target_name', 'target_type', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class CaaRecord(InfobloxObject):
    _infoblox_type = 'record:caa'
    _fields = ['ca_flag', 'ca_tag', 'ca_value', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_name', 'extattrs', 'forbid_reclamation', 'last_queried', 'name', 'reclaimable', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = ['ca_flag', 'ca_tag', 'ca_value', 'comment', 'creator', 'ddns_principal', 'name', 'view']
    _all_searchable_fields = ['ca_flag', 'ca_tag', 'ca_value', 'comment', 'creator', 'ddns_principal', 'name', 'reclaimable', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class CNAMERecord(InfobloxObject):
    _infoblox_type = 'record:cname'
    _fields = ['aws_rte53_record_info', 'canonical', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_canonical', 'dns_name', 'extattrs', 'forbid_reclamation', 'last_queried', 'name', 'reclaimable', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'creator', 'ddns_principal', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'creator', 'ddns_principal', 'name', 'reclaimable', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DhcidRecord(InfobloxObject):
    _infoblox_type = 'record:dhcid'
    _fields = ['creation_time', 'creator', 'dhcid', 'dns_name', 'name', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['creator', 'dhcid', 'name', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DnameRecord(InfobloxObject):
    _infoblox_type = 'record:dname'
    _fields = ['cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_name', 'dns_target', 'extattrs', 'forbid_reclamation', 'last_queried', 'name', 'reclaimable', 'shared_record_group', 'target', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'target', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'name', 'target']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'name', 'reclaimable', 'target', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'target', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DnskeyRecord(InfobloxObject):
    _infoblox_type = 'record:dnskey'
    _fields = ['algorithm', 'comment', 'creation_time', 'creator', 'dns_name', 'flags', 'key_tag', 'last_queried', 'name', 'public_key', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'comment', 'creator', 'flags', 'key_tag', 'name', 'public_key', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DsRecord(InfobloxObject):
    _infoblox_type = 'record:ds'
    _fields = ['algorithm', 'cloud_info', 'comment', 'creation_time', 'creator', 'digest', 'digest_type', 'dns_name', 'key_tag', 'last_queried', 'name', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'comment', 'creator', 'digest_type', 'key_tag', 'name', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DtclbdnRecord(InfobloxObject):
    _infoblox_type = 'record:dtclbdn'
    _fields = ['comment', 'disable', 'extattrs', 'last_queried', 'lbdn', 'name', 'pattern', 'view', 'zone']
    _search_for_update_fields = ['comment', 'name', 'view', 'zone']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'disable', 'name', 'pattern', 'view', 'zone']
    _return_fields = ['comment', 'extattrs', 'name', 'view', 'zone']
    _remap = {}
    _shadow_fields = ['_ref']


class HostRecord(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return HostRecordV4

    @classmethod
    def get_v6_class(cls):
        return HostRecordV6


class HostRecordV4(HostRecord):
    _infoblox_type = 'record:host'
    _fields = ['aliases', 'allow_telnet', 'cli_credentials', 'cloud_info', 'comment', 'configure_for_dns', 'ddns_protected', 'device_description', 'device_location', 'device_type', 'device_vendor', 'disable', 'disable_discovery', 'dns_aliases', 'dns_name', 'enable_immediate_discovery', 'extattrs', 'ipv4addrs', 'last_queried', 'ms_ad_user_data', 'name', 'network_view', 'restart_if_needed', 'rrset_order', 'snmp3_credential', 'snmp_credential', 'ttl', 'use_cli_credentials', 'use_snmp3_credential', 'use_snmp_credential', 'use_ttl', 'view', 'zone', 'mac']
    _search_for_update_fields = ['name', 'view', 'mac', 'ipv4addr']
    _updateable_search_fields = ['comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'name', 'view']
    _all_searchable_fields = ['comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'name', 'network_view', 'view', 'zone', 'mac', 'ipv4addr']
    _return_fields = ['extattrs', 'ipv4addrs', 'name', 'view', 'aliases']
    _remap = {'ip': 'ipv4addrs', 'ips': 'ipv4addrs'}
    _shadow_fields = ['_ref', 'ipv4addr']
    _ip_version = 4

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

    @property
    def ipv4addrs(self):
        return self._ipv4addrs

    @ipv4addrs.setter
    def ipv4addrs(self, ips):
        """Setter for ipv4addrs/ipv4addr"""
        self._ip_setter('ipv4addr', '_ipv4addrs', ips)

    @staticmethod
    def _build_ip(ips):
        if not ips:
            raise ib_ex.HostRecordNotPresent()
        ip = ips[0]['ipv4addr']
        if not ib_utils.is_valid_ip(ip):
            raise ib_ex.InfobloxInvalidIp(ip=ip)
        return [IPv4.from_dict(ip_addr) for ip_addr in ips]

    

    _custom_field_processing = {
        'cli_credentials': DiscoveryClicredential.from_dict,
        'ipv4addrs': _build_ip.__func__,
    }



class HostRecordV6(HostRecord):
    _infoblox_type = 'record:host'
    _fields = ['aliases', 'allow_telnet', 'cli_credentials', 'cloud_info', 'comment', 'configure_for_dns', 'ddns_protected', 'device_description', 'device_location', 'device_type', 'device_vendor', 'disable', 'disable_discovery', 'dns_aliases', 'dns_name', 'enable_immediate_discovery', 'extattrs', 'ipv6addrs', 'last_queried', 'ms_ad_user_data', 'name', 'network_view', 'restart_if_needed', 'rrset_order', 'snmp3_credential', 'snmp_credential', 'ttl', 'use_cli_credentials', 'use_snmp3_credential', 'use_snmp_credential', 'use_ttl', 'view', 'zone', 'mac']
    _search_for_update_fields = ['name', 'view', 'mac', 'ipv6addr']
    _updateable_search_fields = ['comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'name', 'view']
    _all_searchable_fields = ['comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'name', 'network_view', 'view', 'zone', 'mac', 'ipv6addr']
    _return_fields = ['extattrs', 'ipv6addrs', 'name', 'view', 'aliases']
    _remap = {'ip': 'ipv6addrs', 'ips': 'ipv6addrs'}
    _shadow_fields = ['_ref', 'ipv6addr']
    _ip_version = 6

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

    @property
    def ipv6addrs(self):
        return self._ipv6addrs

    @ipv6addrs.setter
    def ipv6addrs(self, ips):
        """Setter for ipv6addrs/ipv6addr"""
        self._ip_setter('ipv6addr', '_ipv6addrs', ips)

    @staticmethod
    def _build_ip(ips):
        if not ips:
            raise ib_ex.HostRecordNotPresent()
        ip = ips[0]['ipv6addr']
        if not ib_utils.is_valid_ip(ip):
            raise ib_ex.InfobloxInvalidIp(ip=ip)
        return [IPv6.from_dict(ip_addr) for ip_addr in ips]

    

    _custom_field_processing = {
        'cli_credentials': DiscoveryClicredential.from_dict,
        'ipv6addrs': _build_ip.__func__,
    }


class IPv4HostAddress(InfobloxObject):
    _infoblox_type = 'record:host_ipv4addr'
    _fields = ['bootfile', 'bootserver', 'configure_for_dhcp', 'deny_bootp', 'discover_now_status', 'discovered_data', 'enable_pxe_lease_time', 'host', 'ignore_client_requested_options', 'ipv4addr', 'is_invalid_mac', 'last_queried', 'logic_filter_rules', 'mac', 'match_client', 'ms_ad_user_data', 'network', 'network_view', 'nextserver', 'options', 'pxe_lease_time', 'reserved_interface', 'use_bootfile', 'use_bootserver', 'use_deny_bootp', 'use_for_ea_inheritance', 'use_ignore_client_requested_options', 'use_logic_filter_rules', 'use_nextserver', 'use_options', 'use_pxe_lease_time']
    _search_for_update_fields = ['ipv4addr', 'mac']
    _updateable_search_fields = ['ipv4addr', 'mac']
    _all_searchable_fields = ['ipv4addr', 'mac', 'network_view']
    _return_fields = ['configure_for_dhcp', 'host', 'ipv4addr', 'mac']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ip']

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': Dhcpoption.from_dict,
    }


class IPv6HostAddress(InfobloxObject):
    _infoblox_type = 'record:host_ipv6addr'
    _fields = ['address_type', 'configure_for_dhcp', 'discover_now_status', 'discovered_data', 'domain_name', 'domain_name_servers', 'duid', 'host', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'last_queried', 'match_client', 'ms_ad_user_data', 'network', 'network_view', 'options', 'preferred_lifetime', 'reserved_interface', 'use_domain_name', 'use_domain_name_servers', 'use_for_ea_inheritance', 'use_options', 'use_preferred_lifetime', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['duid', 'ipv6addr']
    _updateable_search_fields = ['duid', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits']
    _all_searchable_fields = ['duid', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'network_view']
    _return_fields = ['configure_for_dhcp', 'duid', 'host', 'ipv6addr']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ip']

    _custom_field_processing = {
        'options': Dhcpoption.from_dict,
    }


class MXRecord(InfobloxObject):
    _infoblox_type = 'record:mx'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_mail_exchanger', 'dns_name', 'extattrs', 'forbid_reclamation', 'last_queried', 'mail_exchanger', 'name', 'preference', 'reclaimable', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['mail_exchanger', 'name', 'preference', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'mail_exchanger', 'name', 'preference', 'view']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'mail_exchanger', 'name', 'preference', 'reclaimable', 'view', 'zone']
    _return_fields = ['extattrs', 'mail_exchanger', 'name', 'preference', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class NaptrRecord(InfobloxObject):
    _infoblox_type = 'record:naptr'
    _fields = ['cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_name', 'dns_replacement', 'extattrs', 'flags', 'forbid_reclamation', 'last_queried', 'name', 'order', 'preference', 'reclaimable', 'regexp', 'replacement', 'services', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'order', 'preference', 'replacement', 'services', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'flags', 'name', 'order', 'preference', 'replacement', 'services']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'flags', 'name', 'order', 'preference', 'reclaimable', 'replacement', 'services', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'order', 'preference', 'regexp', 'replacement', 'services', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class NsRecord(InfobloxObject):
    _infoblox_type = 'record:ns'
    _fields = ['addresses', 'cloud_info', 'creator', 'dns_name', 'last_queried', 'ms_delegation_name', 'name', 'nameserver', 'policy', 'view', 'zone']
    _search_for_update_fields = ['name', 'nameserver', 'view']
    _updateable_search_fields = ['nameserver']
    _all_searchable_fields = ['creator', 'name', 'nameserver', 'view', 'zone']
    _return_fields = ['name', 'nameserver', 'view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'addresses': Zonenameserver.from_dict,
    }


class NsecRecord(InfobloxObject):
    _infoblox_type = 'record:nsec'
    _fields = ['cloud_info', 'creation_time', 'creator', 'dns_name', 'dns_next_owner_name', 'last_queried', 'name', 'next_owner_name', 'rrset_types', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['creator', 'name', 'next_owner_name', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class Nsec3Record(InfobloxObject):
    _infoblox_type = 'record:nsec3'
    _fields = ['algorithm', 'cloud_info', 'creation_time', 'creator', 'dns_name', 'flags', 'iterations', 'last_queried', 'name', 'next_owner_name', 'rrset_types', 'salt', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'creator', 'flags', 'iterations', 'name', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class Nsec3ParamRecord(InfobloxObject):
    _infoblox_type = 'record:nsec3param'
    _fields = ['algorithm', 'cloud_info', 'creation_time', 'creator', 'dns_name', 'flags', 'iterations', 'last_queried', 'name', 'salt', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'creator', 'flags', 'iterations', 'name', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class PtrRecord(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return PtrRecordV4

    @classmethod
    def get_v6_class(cls):
        return PtrRecordV6


class PtrRecordV4(PtrRecord):
    _infoblox_type = 'record:ptr'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'discovered_data', 'dns_name', 'dns_ptrdname', 'extattrs', 'forbid_reclamation', 'ipv4addr', 'last_queried', 'ms_ad_user_data', 'name', 'ptrdname', 'reclaimable', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ptrdname', 'view', 'ipv4addr']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'ipv4addr', 'name', 'ptrdname']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'ipv4addr', 'name', 'ptrdname', 'reclaimable', 'view', 'zone']
    _return_fields = ['extattrs', 'ptrdname', 'view', 'ipv4addr']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ipv4addr']
    _ip_version = 4



class PtrRecordV6(PtrRecord):
    _infoblox_type = 'record:ptr'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'discovered_data', 'dns_name', 'dns_ptrdname', 'extattrs', 'forbid_reclamation', 'ipv6addr', 'last_queried', 'ms_ad_user_data', 'name', 'ptrdname', 'reclaimable', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ptrdname', 'view', 'ipv6addr']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'ipv6addr', 'name', 'ptrdname']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'ipv6addr', 'name', 'ptrdname', 'reclaimable', 'view', 'zone']
    _return_fields = ['extattrs', 'ptrdname', 'view', 'ipv6addr']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ipv6addr']
    _ip_version = 6


class RpzARecord(InfobloxObject):
    _infoblox_type = 'record:rpz:a'
    _fields = ['comment', 'disable', 'extattrs', 'ipv4addr', 'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv4addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'ipv4addr', 'name', 'view']
    _all_searchable_fields = ['comment', 'ipv4addr', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv4addr', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzAIpaddressRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:a:ipaddress'
    _fields = ['comment', 'disable', 'extattrs', 'ipv4addr', 'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv4addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'ipv4addr', 'name', 'view']
    _all_searchable_fields = ['comment', 'ipv4addr', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv4addr', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzAaaaRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:aaaa'
    _fields = ['comment', 'disable', 'extattrs', 'ipv6addr', 'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv6addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'ipv6addr', 'name', 'view']
    _all_searchable_fields = ['comment', 'ipv6addr', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv6addr', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzAaaaIpaddressRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:aaaa:ipaddress'
    _fields = ['comment', 'disable', 'extattrs', 'ipv6addr', 'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv6addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'ipv6addr', 'name', 'view']
    _all_searchable_fields = ['comment', 'ipv6addr', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv6addr', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:cname'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameClientipaddressRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:cname:clientipaddress'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'is_ipv4', 'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameClientipaddressdnRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:cname:clientipaddressdn'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'is_ipv4', 'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameIpaddressRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:cname:ipaddress'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'is_ipv4', 'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameIpaddressdnRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:cname:ipaddressdn'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'is_ipv4', 'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzMxRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:mx'
    _fields = ['comment', 'disable', 'extattrs', 'mail_exchanger', 'name', 'preference', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['mail_exchanger', 'name', 'preference', 'view']
    _updateable_search_fields = ['comment', 'mail_exchanger', 'name', 'preference', 'view']
    _all_searchable_fields = ['comment', 'mail_exchanger', 'name', 'preference', 'view', 'zone']
    _return_fields = ['extattrs', 'mail_exchanger', 'name', 'preference', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzNaptrRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:naptr'
    _fields = ['comment', 'disable', 'extattrs', 'flags', 'last_queried', 'name', 'order', 'preference', 'regexp', 'replacement', 'rp_zone', 'services', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'order', 'preference', 'replacement', 'services', 'view']
    _updateable_search_fields = ['comment', 'flags', 'name', 'order', 'preference', 'replacement', 'services', 'view']
    _all_searchable_fields = ['comment', 'flags', 'name', 'order', 'preference', 'replacement', 'services', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'order', 'preference', 'regexp', 'replacement', 'services', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzPtrRecord(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return RpzPtrRecordV4

    @classmethod
    def get_v6_class(cls):
        return RpzPtrRecordV6


class RpzPtrRecordV4(RpzPtrRecord):
    _infoblox_type = 'record:rpz:ptr'
    _fields = ['comment', 'disable', 'extattrs', 'ipv4addr', 'name', 'ptrdname', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ptrdname', 'view', 'ipv4addr']
    _updateable_search_fields = ['comment', 'ipv4addr', 'name', 'ptrdname', 'view']
    _all_searchable_fields = ['comment', 'ipv4addr', 'name', 'ptrdname', 'view', 'zone']
    _return_fields = ['extattrs', 'ptrdname', 'view', 'ipv4addr']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ipv4addr']
    _ip_version = 4



class RpzPtrRecordV6(RpzPtrRecord):
    _infoblox_type = 'record:rpz:ptr'
    _fields = ['comment', 'disable', 'extattrs', 'ipv6addr', 'name', 'ptrdname', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ptrdname', 'view', 'ipv6addr']
    _updateable_search_fields = ['comment', 'ipv6addr', 'name', 'ptrdname', 'view']
    _all_searchable_fields = ['comment', 'ipv6addr', 'name', 'ptrdname', 'view', 'zone']
    _return_fields = ['extattrs', 'ptrdname', 'view', 'ipv6addr']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ipv6addr']
    _ip_version = 6


class RpzSrvRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:srv'
    _fields = ['comment', 'disable', 'extattrs', 'name', 'port', 'priority', 'rp_zone', 'target', 'ttl', 'use_ttl', 'view', 'weight', 'zone']
    _search_for_update_fields = ['name', 'port', 'priority', 'target', 'view', 'weight']
    _updateable_search_fields = ['comment', 'name', 'port', 'priority', 'target', 'view', 'weight']
    _all_searchable_fields = ['comment', 'name', 'port', 'priority', 'target', 'view', 'weight', 'zone']
    _return_fields = ['extattrs', 'name', 'port', 'priority', 'target', 'view', 'weight']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzTxtRecord(InfobloxObject):
    _infoblox_type = 'record:rpz:txt'
    _fields = ['comment', 'disable', 'extattrs', 'name', 'rp_zone', 'text', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'text', 'view']
    _updateable_search_fields = ['comment', 'name', 'text', 'view']
    _all_searchable_fields = ['comment', 'name', 'text', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'text', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RrsigRecord(InfobloxObject):
    _infoblox_type = 'record:rrsig'
    _fields = ['algorithm', 'cloud_info', 'creation_time', 'creator', 'dns_name', 'dns_signer_name', 'expiration_time', 'inception_time', 'key_tag', 'labels', 'last_queried', 'name', 'original_ttl', 'signature', 'signer_name', 'ttl', 'type_covered', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'creator', 'key_tag', 'labels', 'name', 'original_ttl', 'signer_name', 'type_covered', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class SRVRecord(InfobloxObject):
    _infoblox_type = 'record:srv'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_name', 'dns_target', 'extattrs', 'forbid_reclamation', 'last_queried', 'name', 'port', 'priority', 'reclaimable', 'shared_record_group', 'target', 'ttl', 'use_ttl', 'view', 'weight', 'zone']
    _search_for_update_fields = ['name', 'port', 'priority', 'target', 'view', 'weight']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'name', 'port', 'priority', 'target', 'weight']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'name', 'port', 'priority', 'reclaimable', 'target', 'view', 'weight', 'zone']
    _return_fields = ['extattrs', 'name', 'port', 'priority', 'target', 'view', 'weight']
    _remap = {}
    _shadow_fields = ['_ref']


class TlsaRecord(InfobloxObject):
    _infoblox_type = 'record:tlsa'
    _fields = ['certificate_data', 'certificate_usage', 'cloud_info', 'comment', 'creator', 'disable', 'dns_name', 'extattrs', 'last_queried', 'matched_type', 'name', 'selector', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'name', 'view']
    _all_searchable_fields = ['comment', 'creator', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class TXTRecord(InfobloxObject):
    _infoblox_type = 'record:txt'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_name', 'extattrs', 'forbid_reclamation', 'last_queried', 'name', 'reclaimable', 'shared_record_group', 'text', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'name', 'text', 'view']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'name', 'reclaimable', 'text', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'text', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class UnknownRecord(InfobloxObject):
    _infoblox_type = 'record:unknown'
    _fields = ['cloud_info', 'comment', 'creator', 'disable', 'display_rdata', 'dns_name', 'enable_host_name_policy', 'extattrs', 'last_queried', 'name', 'policy', 'record_type', 'subfield_values', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'name', 'record_type', 'subfield_values', 'view']
    _all_searchable_fields = ['comment', 'creator', 'display_rdata', 'name', 'record_type', 'subfield_values', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'subfield_values': Rdatasubfield.from_dict,
    }


class Recordnamepolicy(InfobloxObject):
    _infoblox_type = 'recordnamepolicy'
    _fields = ['is_default', 'name', 'pre_defined', 'regex']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name']
    _return_fields = ['is_default', 'name', 'regex']
    _remap = {}
    _shadow_fields = ['_ref']


class Restartservicestatus(InfobloxObject):
    _infoblox_type = 'restartservicestatus'
    _fields = ['dhcp_status', 'dns_status', 'member', 'reporting_status']
    _search_for_update_fields = ['member']
    _updateable_search_fields = []
    _all_searchable_fields = ['member']
    _return_fields = ['dhcp_status', 'dns_status', 'member', 'reporting_status']
    _remap = {}
    _shadow_fields = ['_ref']


class Rir(InfobloxObject):
    _infoblox_type = 'rir'
    _fields = ['communication_mode', 'email', 'name', 'url', 'use_email', 'use_url']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name']
    _return_fields = ['communication_mode', 'email', 'name', 'url']
    _remap = {}
    _shadow_fields = ['_ref']


class RirOrganization(InfobloxObject):
    _infoblox_type = 'rir:organization'
    _fields = ['extattrs', 'id', 'maintainer', 'name', 'password', 'rir', 'sender_email']
    _search_for_update_fields = ['id', 'maintainer', 'name', 'rir', 'sender_email']
    _updateable_search_fields = ['id', 'maintainer', 'name', 'rir', 'sender_email']
    _all_searchable_fields = ['id', 'maintainer', 'name', 'rir', 'sender_email']
    _return_fields = ['extattrs', 'id', 'maintainer', 'name', 'rir', 'sender_email']
    _remap = {}
    _shadow_fields = ['_ref']


class DHCPRoamingHost(InfobloxObject):
    _infoblox_type = 'roaminghost'
    _fields = ['address_type', 'bootfile', 'bootserver', 'client_identifier_prepend_zero', 'comment', 'ddns_domainname', 'ddns_hostname', 'deny_bootp', 'dhcp_client_identifier', 'disable', 'enable_ddns', 'enable_pxe_lease_time', 'extattrs', 'force_roaming_hostname', 'ignore_dhcp_option_list_request', 'ipv6_client_hostname', 'ipv6_ddns_domainname', 'ipv6_ddns_hostname', 'ipv6_domain_name', 'ipv6_domain_name_servers', 'ipv6_duid', 'ipv6_enable_ddns', 'ipv6_force_roaming_hostname', 'ipv6_match_option', 'ipv6_options', 'ipv6_template', 'mac', 'match_client', 'name', 'network_view', 'nextserver', 'options', 'preferred_lifetime', 'pxe_lease_time', 'template', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_deny_bootp', 'use_enable_ddns', 'use_ignore_dhcp_option_list_request', 'use_ipv6_ddns_domainname', 'use_ipv6_domain_name', 'use_ipv6_domain_name_servers', 'use_ipv6_enable_ddns', 'use_ipv6_options', 'use_nextserver', 'use_options', 'use_preferred_lifetime', 'use_pxe_lease_time', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['address_type', 'name', 'network_view']
    _updateable_search_fields = ['address_type', 'comment', 'dhcp_client_identifier', 'ipv6_duid', 'ipv6_match_option', 'mac', 'match_client', 'name', 'network_view']
    _all_searchable_fields = ['address_type', 'comment', 'dhcp_client_identifier', 'ipv6_duid', 'ipv6_match_option', 'mac', 'match_client', 'name', 'network_view']
    _return_fields = ['address_type', 'extattrs', 'name', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ipv6_options': Dhcpoption.from_dict,
        'options': Dhcpoption.from_dict,
    }


class Ruleset(InfobloxObject):
    _infoblox_type = 'ruleset'
    _fields = ['comment', 'disabled', 'name', 'nxdomain_rules', 'type']
    _search_for_update_fields = ['comment', 'disabled', 'name', 'type']
    _updateable_search_fields = ['comment', 'disabled', 'name', 'type']
    _all_searchable_fields = ['comment', 'disabled', 'name', 'type']
    _return_fields = ['comment', 'disabled', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'nxdomain_rules': Nxdomainrule.from_dict,
    }


class SamlAuthservice(InfobloxObject):
    _infoblox_type = 'saml:authservice'
    _fields = ['comment', 'idp', 'name', 'session_timeout']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']


class Scavengingtask(InfobloxObject):
    _infoblox_type = 'scavengingtask'
    _fields = ['action', 'associated_object', 'end_time', 'processed_records', 'reclaimable_records', 'reclaimed_records', 'start_time', 'status']
    _search_for_update_fields = ['action', 'associated_object', 'status']
    _updateable_search_fields = []
    _all_searchable_fields = ['action', 'associated_object', 'status']
    _return_fields = ['action', 'associated_object', 'status']
    _remap = {}
    _shadow_fields = ['_ref']


class Scheduledtask(InfobloxObject):
    _infoblox_type = 'scheduledtask'
    _fields = ['approval_status', 'approver', 'approver_comment', 'automatic_restart', 'changed_objects', 'dependent_tasks', 'execute_now', 'execution_details', 'execution_details_type', 'execution_status', 'execution_time', 'is_network_insight_task', 'member', 'predecessor_task', 're_execute_task', 'scheduled_time', 'submit_time', 'submitter', 'submitter_comment', 'task_id', 'task_type', 'ticket_number']
    _search_for_update_fields = ['approval_status', 'execution_status', 'task_id']
    _updateable_search_fields = ['approval_status', 'scheduled_time']
    _all_searchable_fields = ['approval_status', 'approver', 'execution_status', 'execution_time', 'member', 'scheduled_time', 'submit_time', 'submitter', 'task_id']
    _return_fields = ['approval_status', 'execution_status', 'task_id']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'changed_objects': Changedobject.from_dict,
    }


class Search(InfobloxObject):
    _infoblox_type = 'search'
    _fields = []
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']


class ASharedRecordBase(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return ASharedRecord

    @classmethod
    def get_v6_class(cls):
        return AAAASharedRecord


class ASharedRecord(ASharedRecordBase):
    _infoblox_type = 'sharedrecord:a'
    _fields = ['comment', 'disable', 'dns_name', 'extattrs', 'ipv4addr', 'name', 'shared_record_group', 'ttl', 'use_ttl']
    _search_for_update_fields = ['ipv4addr', 'name']
    _updateable_search_fields = ['comment', 'ipv4addr', 'name']
    _all_searchable_fields = ['comment', 'ipv4addr', 'name']
    _return_fields = ['extattrs', 'ipv4addr', 'name', 'shared_record_group']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4



class AAAASharedRecord(ASharedRecordBase):
    _infoblox_type = 'sharedrecord:aaaa'
    _fields = ['comment', 'disable', 'dns_name', 'extattrs', 'ipv6addr', 'name', 'shared_record_group', 'ttl', 'use_ttl']
    _search_for_update_fields = ['ipv6addr', 'name']
    _updateable_search_fields = ['comment', 'ipv6addr', 'name']
    _all_searchable_fields = ['comment', 'ipv6addr', 'name']
    _return_fields = ['extattrs', 'ipv6addr', 'name', 'shared_record_group']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6


class CNAMESharedRecord(InfobloxObject):
    _infoblox_type = 'sharedrecord:cname'
    _fields = ['canonical', 'comment', 'disable', 'dns_canonical', 'dns_name', 'extattrs', 'name', 'shared_record_group', 'ttl', 'use_ttl']
    _search_for_update_fields = ['canonical', 'name']
    _updateable_search_fields = ['canonical', 'comment', 'name']
    _all_searchable_fields = ['canonical', 'comment', 'name']
    _return_fields = ['canonical', 'extattrs', 'name', 'shared_record_group']
    _remap = {}
    _shadow_fields = ['_ref']


class MXSharedRecord(InfobloxObject):
    _infoblox_type = 'sharedrecord:mx'
    _fields = ['comment', 'disable', 'dns_mail_exchanger', 'dns_name', 'extattrs', 'mail_exchanger', 'name', 'preference', 'shared_record_group', 'ttl', 'use_ttl']
    _search_for_update_fields = ['mail_exchanger', 'name', 'preference']
    _updateable_search_fields = ['comment', 'mail_exchanger', 'name', 'preference']
    _all_searchable_fields = ['comment', 'mail_exchanger', 'name', 'preference']
    _return_fields = ['extattrs', 'mail_exchanger', 'name', 'preference', 'shared_record_group']
    _remap = {}
    _shadow_fields = ['_ref']


class SRVSharedRecord(InfobloxObject):
    _infoblox_type = 'sharedrecord:srv'
    _fields = ['comment', 'disable', 'dns_name', 'dns_target', 'extattrs', 'name', 'port', 'priority', 'shared_record_group', 'target', 'ttl', 'use_ttl', 'weight']
    _search_for_update_fields = ['name', 'port', 'priority', 'target', 'weight']
    _updateable_search_fields = ['comment', 'name', 'port', 'priority', 'target', 'weight']
    _all_searchable_fields = ['comment', 'name', 'port', 'priority', 'target', 'weight']
    _return_fields = ['extattrs', 'name', 'port', 'priority', 'shared_record_group', 'target', 'weight']
    _remap = {}
    _shadow_fields = ['_ref']


class TXTSharedRecord(InfobloxObject):
    _infoblox_type = 'sharedrecord:txt'
    _fields = ['comment', 'disable', 'dns_name', 'extattrs', 'name', 'shared_record_group', 'text', 'ttl', 'use_ttl']
    _search_for_update_fields = ['name', 'text']
    _updateable_search_fields = ['comment', 'name', 'text']
    _all_searchable_fields = ['comment', 'name', 'text']
    _return_fields = ['extattrs', 'name', 'shared_record_group', 'text']
    _remap = {}
    _shadow_fields = ['_ref']


class Sharedrecordgroup(InfobloxObject):
    _infoblox_type = 'sharedrecordgroup'
    _fields = ['comment', 'extattrs', 'name', 'record_name_policy', 'use_record_name_policy', 'zone_associations']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class SmartfolderChildren(InfobloxObject):
    _infoblox_type = 'smartfolder:children'
    _fields = ['resource', 'value', 'value_type']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['resource', 'value', 'value_type']
    _remap = {}
    _shadow_fields = ['_ref']


class SmartfolderGlobal(InfobloxObject):
    _infoblox_type = 'smartfolder:global'
    _fields = ['comment', 'group_bys', 'name', 'query_items']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'group_bys': SmartfolderGroupby.from_dict,
        'query_items': SmartfolderQueryitem.from_dict,
    }

    def save_as(self, *args, **kwargs):
        return self._call_func("save_as", *args, **kwargs)


class SmartfolderPersonal(InfobloxObject):
    _infoblox_type = 'smartfolder:personal'
    _fields = ['comment', 'group_bys', 'is_shortcut', 'name', 'query_items']
    _search_for_update_fields = ['comment', 'is_shortcut', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'is_shortcut', 'name']
    _return_fields = ['comment', 'is_shortcut', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'group_bys': SmartfolderGroupby.from_dict,
        'query_items': SmartfolderQueryitem.from_dict,
    }

    def save_as(self, *args, **kwargs):
        return self._call_func("save_as", *args, **kwargs)


class Snmpuser(InfobloxObject):
    _infoblox_type = 'snmpuser'
    _fields = ['authentication_password', 'authentication_protocol', 'comment', 'disable', 'extattrs', 'name', 'privacy_password', 'privacy_protocol']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Superhost(InfobloxObject):
    _infoblox_type = 'superhost'
    _fields = ['comment', 'delete_associated_objects', 'dhcp_associated_objects', 'disabled', 'dns_associated_objects', 'extattrs', 'name']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'disabled', 'name']
    _all_searchable_fields = ['comment', 'disabled', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Superhostchild(InfobloxObject):
    _infoblox_type = 'superhostchild'
    _fields = ['associated_object', 'comment', 'creation_timestamp', 'data', 'disabled', 'name', 'network_view', 'parent', 'record_parent', 'type', 'view']
    _search_for_update_fields = ['comment', 'data', 'name', 'network_view', 'parent', 'record_parent', 'type', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'creation_timestamp', 'data', 'name', 'network_view', 'parent', 'record_parent', 'type', 'view']
    _return_fields = ['comment', 'data', 'name', 'network_view', 'parent', 'record_parent', 'type', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class SyslogEndpoint(InfobloxObject):
    _infoblox_type = 'syslog:endpoint'
    _fields = ['extattrs', 'log_level', 'name', 'outbound_member_type', 'outbound_members', 'syslog_servers', 'template_instance', 'timeout', 'vendor_identifier', 'wapi_user_name', 'wapi_user_password']
    _search_for_update_fields = ['name', 'outbound_member_type']
    _updateable_search_fields = ['log_level', 'name', 'outbound_member_type', 'vendor_identifier']
    _all_searchable_fields = ['log_level', 'name', 'outbound_member_type', 'vendor_identifier']
    _return_fields = ['extattrs', 'name', 'outbound_member_type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'syslog_servers': SyslogEndpointServers.from_dict,
    }

    def test_syslog_connection(self, *args, **kwargs):
        return self._call_func("test_syslog_connection", *args, **kwargs)


class TacacsplusAuthservice(InfobloxObject):
    _infoblox_type = 'tacacsplus:authservice'
    _fields = ['acct_retries', 'acct_timeout', 'auth_retries', 'auth_timeout', 'comment', 'disable', 'name', 'servers']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'disable', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'servers': TacacsplusServer.from_dict,
    }

    def check_tacacsplus_server_settings(self, *args, **kwargs):
        return self._call_func("check_tacacsplus_server_settings", *args, **kwargs)


class Taxii(InfobloxObject):
    _infoblox_type = 'taxii'
    _fields = ['enable_service', 'ipv4addr', 'ipv6addr', 'name', 'taxii_rpz_config']
    _search_for_update_fields = ['ipv4addr', 'ipv6addr', 'name']
    _updateable_search_fields = []
    _all_searchable_fields = ['ipv4addr', 'ipv6addr', 'name']
    _return_fields = ['ipv4addr', 'ipv6addr', 'name']
    _remap = {}
    _shadow_fields = ['_ref', 'ip']

    @property
    def ip(self):
        if hasattr(self, '_ip'):
            return str(self._ip)

    # This object represents both ipv4 and ipv6 objects, so it doesn't need
    # versioned object for that. Just set v4 or v6 field in addition
    # to setting shadow field 'ip' itself.
    @ip.setter
    def ip(self, ip):
        self._ip = ip
    
        if ib_utils.determine_ip_version(ip) == 6:
            if 'ipv6addr' not in self._fields:
                raise ib_ex.InfobloxInvalidIp(ip=ip)
            self.ipv6addr = ip
        else:
            if 'ipv4addr' not in self._fields:
                raise ib_ex.InfobloxInvalidIp(ip=ip)
            self.ipv4addr = ip
    

    _custom_field_processing = {
        'taxii_rpz_config': TaxiiRpzconfig.from_dict,
    }


class Tftpfiledir(InfobloxObject):
    _infoblox_type = 'tftpfiledir'
    _fields = ['directory', 'is_synced_to_gm', 'last_modify', 'name', 'type', 'vtftp_dir_members']
    _search_for_update_fields = ['directory', 'name', 'type']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['directory', 'name', 'type']
    _return_fields = ['directory', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'vtftp_dir_members': Vtftpdirmember.from_dict,
    }


class ThreatanalyticsModuleset(InfobloxObject):
    _infoblox_type = 'threatanalytics:moduleset'
    _fields = ['version']
    _search_for_update_fields = ['version']
    _updateable_search_fields = []
    _all_searchable_fields = ['version']
    _return_fields = ['version']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatanalyticsWhitelist(InfobloxObject):
    _infoblox_type = 'threatanalytics:whitelist'
    _fields = ['version']
    _search_for_update_fields = ['version']
    _updateable_search_fields = []
    _all_searchable_fields = ['version']
    _return_fields = ['version']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatinsightCloudclient(InfobloxObject):
    _infoblox_type = 'threatinsight:cloudclient'
    _fields = ['blacklist_rpz_list', 'enable', 'force_refresh', 'interval']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['enable', 'interval']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionGridRule(InfobloxObject):
    _infoblox_type = 'threatprotection:grid:rule'
    _fields = ['allowed_actions', 'category', 'comment', 'config', 'description', 'disabled', 'is_factory_reset_enabled', 'name', 'ruleset', 'sid', 'template', 'type']
    _search_for_update_fields = ['name', 'ruleset', 'sid']
    _updateable_search_fields = ['comment', 'template']
    _all_searchable_fields = ['category', 'comment', 'description', 'name', 'ruleset', 'sid', 'template', 'type']
    _return_fields = ['name', 'ruleset', 'sid']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionProfile(InfobloxObject):
    _infoblox_type = 'threatprotection:profile'
    _fields = ['comment', 'current_ruleset', 'disable_multiple_dns_tcp_request', 'events_per_second_per_rule', 'extattrs', 'members', 'name', 'source_member', 'source_profile', 'use_current_ruleset', 'use_disable_multiple_dns_tcp_request', 'use_events_per_second_per_rule']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'current_ruleset', 'disable_multiple_dns_tcp_request', 'events_per_second_per_rule', 'name']
    _all_searchable_fields = ['comment', 'current_ruleset', 'disable_multiple_dns_tcp_request', 'events_per_second_per_rule', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionProfileRule(InfobloxObject):
    _infoblox_type = 'threatprotection:profile:rule'
    _fields = ['config', 'disable', 'profile', 'rule', 'sid', 'use_config', 'use_disable']
    _search_for_update_fields = ['profile', 'rule']
    _updateable_search_fields = []
    _all_searchable_fields = ['profile', 'rule', 'sid']
    _return_fields = ['profile', 'rule']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionRule(InfobloxObject):
    _infoblox_type = 'threatprotection:rule'
    _fields = ['config', 'disable', 'member', 'rule', 'sid', 'use_config', 'use_disable']
    _search_for_update_fields = ['member', 'rule']
    _updateable_search_fields = []
    _all_searchable_fields = ['member', 'rule', 'sid']
    _return_fields = ['member', 'rule']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionRulecategory(InfobloxObject):
    _infoblox_type = 'threatprotection:rulecategory'
    _fields = ['is_factory_reset_enabled', 'name', 'ruleset']
    _search_for_update_fields = ['name', 'ruleset']
    _updateable_search_fields = []
    _all_searchable_fields = ['name', 'ruleset']
    _return_fields = ['name', 'ruleset']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionRuleset(InfobloxObject):
    _infoblox_type = 'threatprotection:ruleset'
    _fields = ['add_type', 'added_time', 'comment', 'do_not_delete', 'is_factory_reset_enabled', 'used_by', 'version']
    _search_for_update_fields = ['add_type', 'version']
    _updateable_search_fields = ['comment']
    _all_searchable_fields = ['add_type', 'comment', 'version']
    _return_fields = ['add_type', 'version']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionRuletemplate(InfobloxObject):
    _infoblox_type = 'threatprotection:ruletemplate'
    _fields = ['allowed_actions', 'category', 'default_config', 'description', 'name', 'ruleset', 'sid']
    _search_for_update_fields = ['name', 'ruleset', 'sid']
    _updateable_search_fields = []
    _all_searchable_fields = ['category', 'description', 'name', 'ruleset', 'sid']
    _return_fields = ['name', 'ruleset', 'sid']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionStatistics(InfobloxObject):
    _infoblox_type = 'threatprotection:statistics'
    _fields = ['member', 'stat_infos']
    _search_for_update_fields = ['member']
    _updateable_search_fields = []
    _all_searchable_fields = ['member']
    _return_fields = ['member', 'stat_infos']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'stat_infos': ThreatprotectionStatinfo.from_dict,
    }


class Upgradegroup(InfobloxObject):
    _infoblox_type = 'upgradegroup'
    _fields = ['comment', 'distribution_dependent_group', 'distribution_policy', 'distribution_time', 'members', 'name', 'time_zone', 'upgrade_dependent_group', 'upgrade_policy', 'upgrade_time']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'members': UpgradegroupMember.from_dict,
    }


class Upgradeschedule(InfobloxObject):
    _infoblox_type = 'upgradeschedule'
    _fields = ['active', 'start_time', 'time_zone', 'upgrade_groups']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['active', 'start_time', 'time_zone']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'upgrade_groups': UpgradegroupSchedule.from_dict,
    }


class Upgradestatus(InfobloxObject):
    _infoblox_type = 'upgradestatus'
    _fields = ['allow_distribution', 'allow_distribution_scheduling', 'allow_upgrade', 'allow_upgrade_cancel', 'allow_upgrade_pause', 'allow_upgrade_resume', 'allow_upgrade_scheduling', 'allow_upgrade_test', 'allow_upload', 'alternate_version', 'comment', 'current_version', 'current_version_summary', 'distribution_schedule_active', 'distribution_schedule_time', 'distribution_state', 'distribution_version', 'distribution_version_summary', 'element_status', 'grid_state', 'group_state', 'ha_status', 'hotfixes', 'ipv4_address', 'ipv6_address', 'member', 'message', 'pnode_role', 'reverted', 'status_time', 'status_value', 'status_value_update_time', 'steps', 'steps_completed', 'steps_total', 'subelement_type', 'subelements_completed', 'subelements_status', 'subelements_total', 'type', 'upgrade_group', 'upgrade_schedule_active', 'upgrade_state', 'upgrade_test_status', 'upload_version', 'upload_version_summary']
    _search_for_update_fields = ['member', 'type', 'upgrade_group']
    _updateable_search_fields = []
    _all_searchable_fields = ['member', 'subelement_type', 'type', 'upgrade_group']
    _return_fields = ['alternate_version', 'comment', 'current_version', 'distribution_version', 'element_status', 'grid_state', 'group_state', 'ha_status', 'hotfixes', 'ipv4_address', 'ipv6_address', 'member', 'message', 'pnode_role', 'reverted', 'status_value', 'status_value_update_time', 'steps', 'steps_completed', 'steps_total', 'type', 'upgrade_group', 'upgrade_state', 'upgrade_test_status', 'upload_version']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'hotfixes': Hotfix.from_dict,
        'steps': Upgradestep.from_dict,
    }


class Userprofile(InfobloxObject):
    _infoblox_type = 'userprofile'
    _fields = ['active_dashboard_type', 'admin_group', 'days_to_expire', 'email', 'global_search_on_ea', 'global_search_on_ni_data', 'grid_admin_groups', 'last_login', 'lb_tree_nodes_at_gen_level', 'lb_tree_nodes_at_last_level', 'max_count_widgets', 'name', 'old_password', 'password', 'table_size', 'time_zone', 'use_time_zone', 'user_type']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']


class Vdiscoverytask(InfobloxObject):
    _infoblox_type = 'vdiscoverytask'
    _fields = ['allow_unsecured_connection', 'auto_consolidate_cloud_ea', 'auto_consolidate_managed_tenant', 'auto_consolidate_managed_vm', 'auto_create_dns_hostname_template', 'auto_create_dns_record', 'auto_create_dns_record_type', 'comment', 'credentials_type', 'dns_view_private_ip', 'dns_view_public_ip', 'domain_name', 'driver_type', 'enabled', 'fqdn_or_ip', 'identity_version', 'last_run', 'member', 'merge_data', 'name', 'password', 'port', 'private_network_view', 'private_network_view_mapping_policy', 'protocol', 'public_network_view', 'public_network_view_mapping_policy', 'scheduled_run', 'service_account_file', 'state', 'state_msg', 'update_dns_view_private_ip', 'update_dns_view_public_ip', 'update_metadata', 'use_identity', 'username']
    _search_for_update_fields = ['name', 'state']
    _updateable_search_fields = ['dns_view_private_ip', 'dns_view_public_ip', 'domain_name', 'driver_type', 'enabled', 'fqdn_or_ip', 'identity_version', 'member', 'name', 'port', 'private_network_view', 'private_network_view_mapping_policy', 'protocol', 'public_network_view', 'public_network_view_mapping_policy', 'service_account_file', 'update_dns_view_private_ip', 'update_dns_view_public_ip', 'use_identity', 'username']
    _all_searchable_fields = ['dns_view_private_ip', 'dns_view_public_ip', 'domain_name', 'driver_type', 'enabled', 'fqdn_or_ip', 'identity_version', 'member', 'name', 'port', 'private_network_view', 'private_network_view_mapping_policy', 'protocol', 'public_network_view', 'public_network_view_mapping_policy', 'service_account_file', 'state', 'update_dns_view_private_ip', 'update_dns_view_public_ip', 'use_identity', 'username']
    _return_fields = ['name', 'state']
    _remap = {}
    _shadow_fields = ['_ref']

    def vdiscovery_control(self, *args, **kwargs):
        return self._call_func("vdiscovery_control", *args, **kwargs)


class DNSView(InfobloxObject):
    _infoblox_type = 'view'
    _fields = ['blacklist_action', 'blacklist_log_query', 'blacklist_redirect_addresses', 'blacklist_redirect_ttl', 'blacklist_rulesets', 'cloud_info', 'comment', 'custom_root_name_servers', 'ddns_force_creation_timestamp_update', 'ddns_principal_group', 'ddns_principal_tracking', 'ddns_restrict_patterns', 'ddns_restrict_patterns_list', 'ddns_restrict_protected', 'ddns_restrict_secure', 'ddns_restrict_static', 'disable', 'dns64_enabled', 'dns64_groups', 'dnssec_enabled', 'dnssec_expired_signatures_enabled', 'dnssec_negative_trust_anchors', 'dnssec_trusted_keys', 'dnssec_validation_enabled', 'enable_blacklist', 'enable_fixed_rrset_order_fqdns', 'enable_match_recursive_only', 'extattrs', 'filter_aaaa', 'filter_aaaa_list', 'fixed_rrset_order_fqdns', 'forward_only', 'forwarders', 'is_default', 'lame_ttl', 'match_clients', 'match_destinations', 'max_cache_ttl', 'max_ncache_ttl', 'name', 'network_view', 'notify_delay', 'nxdomain_log_query', 'nxdomain_redirect', 'nxdomain_redirect_addresses', 'nxdomain_redirect_addresses_v6', 'nxdomain_redirect_ttl', 'nxdomain_rulesets', 'recursion', 'response_rate_limiting', 'root_name_server_type', 'rpz_drop_ip_rule_enabled', 'rpz_drop_ip_rule_min_prefix_length_ipv4', 'rpz_drop_ip_rule_min_prefix_length_ipv6', 'rpz_qname_wait_recurse', 'scavenging_settings', 'sortlist', 'use_blacklist', 'use_ddns_force_creation_timestamp_update', 'use_ddns_patterns_restriction', 'use_ddns_principal_security', 'use_ddns_restrict_protected', 'use_ddns_restrict_static', 'use_dns64', 'use_dnssec', 'use_filter_aaaa', 'use_fixed_rrset_order_fqdns', 'use_forwarders', 'use_lame_ttl', 'use_max_cache_ttl', 'use_max_ncache_ttl', 'use_nxdomain_redirect', 'use_recursion', 'use_response_rate_limiting', 'use_root_name_server', 'use_rpz_drop_ip_rule', 'use_rpz_qname_wait_recurse', 'use_scavenging_settings', 'use_sortlist']
    _search_for_update_fields = ['comment', 'is_default', 'name', 'network_view']
    _updateable_search_fields = ['blacklist_action', 'blacklist_log_query', 'comment', 'dns64_enabled', 'dnssec_enabled', 'dnssec_expired_signatures_enabled', 'dnssec_validation_enabled', 'enable_blacklist', 'filter_aaaa', 'forward_only', 'name', 'network_view', 'nxdomain_log_query', 'nxdomain_redirect', 'recursion', 'root_name_server_type']
    _all_searchable_fields = ['blacklist_action', 'blacklist_log_query', 'comment', 'dns64_enabled', 'dnssec_enabled', 'dnssec_expired_signatures_enabled', 'dnssec_validation_enabled', 'enable_blacklist', 'filter_aaaa', 'forward_only', 'is_default', 'name', 'network_view', 'nxdomain_log_query', 'nxdomain_redirect', 'recursion', 'root_name_server_type']
    _return_fields = ['comment', 'extattrs', 'is_default', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'custom_root_name_servers': Extserver.from_dict,
        'dnssec_trusted_keys': Dnssectrustedkey.from_dict,
        'filter_aaaa_list': Addressac.from_dict,
        'fixed_rrset_order_fqdns': GridDnsFixedrrsetorderfqdn.from_dict,
        'match_clients': Addressac.from_dict,
        'match_destinations': Addressac.from_dict,
        'sortlist': Sortlist.from_dict,
    }

    def run_scavenging(self, *args, **kwargs):
        return self._call_func("run_scavenging", *args, **kwargs)


class Vlan(InfobloxObject):
    _infoblox_type = 'vlan'
    _fields = ['assigned_to', 'comment', 'contact', 'department', 'description', 'extattrs', 'id', 'name', 'parent', 'reserved', 'status']
    _search_for_update_fields = ['id', 'name', 'parent']
    _updateable_search_fields = ['comment', 'contact', 'department', 'description', 'id', 'name', 'parent', 'reserved']
    _all_searchable_fields = ['assigned_to', 'comment', 'contact', 'department', 'description', 'id', 'name', 'parent', 'reserved', 'status']
    _return_fields = ['extattrs', 'id', 'name', 'parent']
    _remap = {}
    _shadow_fields = ['_ref']


class Vlanrange(InfobloxObject):
    _infoblox_type = 'vlanrange'
    _fields = ['comment', 'delete_vlans', 'end_vlan_id', 'extattrs', 'name', 'pre_create_vlan', 'start_vlan_id', 'vlan_name_prefix', 'vlan_view']
    _search_for_update_fields = ['end_vlan_id', 'name', 'start_vlan_id', 'vlan_view']
    _updateable_search_fields = ['comment', 'end_vlan_id', 'name', 'start_vlan_id', 'vlan_view']
    _all_searchable_fields = ['comment', 'end_vlan_id', 'name', 'start_vlan_id', 'vlan_view']
    _return_fields = ['end_vlan_id', 'extattrs', 'name', 'start_vlan_id', 'vlan_view']
    _remap = {}
    _shadow_fields = ['_ref']

    def next_available_vlan_id(self, *args, **kwargs):
        return self._call_func("next_available_vlan_id", *args, **kwargs)


class Vlanview(InfobloxObject):
    _infoblox_type = 'vlanview'
    _fields = ['allow_range_overlapping', 'comment', 'end_vlan_id', 'extattrs', 'name', 'pre_create_vlan', 'start_vlan_id', 'vlan_name_prefix']
    _search_for_update_fields = ['end_vlan_id', 'name', 'start_vlan_id']
    _updateable_search_fields = ['allow_range_overlapping', 'comment', 'end_vlan_id', 'name', 'start_vlan_id']
    _all_searchable_fields = ['allow_range_overlapping', 'comment', 'end_vlan_id', 'name', 'start_vlan_id']
    _return_fields = ['end_vlan_id', 'extattrs', 'name', 'start_vlan_id']
    _remap = {}
    _shadow_fields = ['_ref']

    def next_available_vlan_id(self, *args, **kwargs):
        return self._call_func("next_available_vlan_id", *args, **kwargs)


class DNSZone(InfobloxObject):
    _infoblox_type = 'zone_auth'
    _fields = ['address', 'allow_active_dir', 'allow_fixed_rrset_order', 'allow_gss_tsig_for_underscore_zone', 'allow_gss_tsig_zone_updates', 'allow_query', 'allow_transfer', 'allow_update', 'allow_update_forwarding', 'aws_rte53_zone_info', 'cloud_info', 'comment', 'copy_xfer_to_notify', 'create_ptr_for_bulk_hosts', 'create_ptr_for_hosts', 'create_underscore_zones', 'ddns_force_creation_timestamp_update', 'ddns_principal_group', 'ddns_principal_tracking', 'ddns_restrict_patterns', 'ddns_restrict_patterns_list', 'ddns_restrict_protected', 'ddns_restrict_secure', 'ddns_restrict_static', 'disable', 'disable_forwarding', 'display_domain', 'dns_fqdn', 'dns_integrity_enable', 'dns_integrity_frequency', 'dns_integrity_member', 'dns_integrity_verbose_logging', 'dns_soa_email', 'dnssec_key_params', 'dnssec_keys', 'dnssec_ksk_rollover_date', 'dnssec_zsk_rollover_date', 'do_host_abstraction', 'effective_check_names_policy', 'effective_record_name_policy', 'extattrs', 'external_primaries', 'external_secondaries', 'fqdn', 'grid_primary', 'grid_primary_shared_with_ms_parent_delegation', 'grid_secondaries', 'import_from', 'is_dnssec_enabled', 'is_dnssec_signed', 'is_multimaster', 'last_queried', 'locked', 'locked_by', 'mask_prefix', 'member_soa_mnames', 'member_soa_serials', 'ms_ad_integrated', 'ms_allow_transfer', 'ms_allow_transfer_mode', 'ms_dc_ns_record_creation', 'ms_ddns_mode', 'ms_managed', 'ms_primaries', 'ms_read_only', 'ms_secondaries', 'ms_sync_disabled', 'ms_sync_master_name', 'network_associations', 'network_view', 'notify_delay', 'ns_group', 'parent', 'prefix', 'primary_type', 'record_name_policy', 'records_monitored', 'restart_if_needed', 'rr_not_queried_enabled_time', 'scavenging_settings', 'set_soa_serial_number', 'soa_default_ttl', 'soa_email', 'soa_expire', 'soa_negative_ttl', 'soa_refresh', 'soa_retry', 'soa_serial_number', 'srgs', 'update_forwarding', 'use_allow_active_dir', 'use_allow_query', 'use_allow_transfer', 'use_allow_update', 'use_allow_update_forwarding', 'use_check_names_policy', 'use_copy_xfer_to_notify', 'use_ddns_force_creation_timestamp_update', 'use_ddns_patterns_restriction', 'use_ddns_principal_security', 'use_ddns_restrict_protected', 'use_ddns_restrict_static', 'use_dnssec_key_params', 'use_external_primary', 'use_grid_zone_timer', 'use_import_from', 'use_notify_delay', 'use_record_name_policy', 'use_scavenging_settings', 'use_soa_email', 'using_srg_associations', 'view', 'zone_format', 'zone_not_queried_enabled_time']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'dnssec_ksk_rollover_date', 'dnssec_zsk_rollover_date', 'fqdn', 'parent', 'view', 'zone_format']
    _return_fields = ['extattrs', 'fqdn', 'view', 'zone_format', 'ns_group', 'prefix', 'grid_primary', 'grid_secondaries']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'allow_active_dir': Addressac.from_dict,
        'allow_query': Addressac.from_dict,
        'allow_transfer': Addressac.from_dict,
        'allow_update': Addressac.from_dict,
        'dnssec_keys': Dnsseckey.from_dict,
        'external_primaries': Extserver.from_dict,
        'external_secondaries': Extserver.from_dict,
        'grid_primary': Memberserver.from_dict,
        'grid_secondaries': Memberserver.from_dict,
        'member_soa_mnames': GridmemberSoamname.from_dict,
        'member_soa_serials': GridmemberSoaserial.from_dict,
        'ms_allow_transfer': Addressac.from_dict,
        'ms_dc_ns_record_creation': MsserverDcnsrecordcreation.from_dict,
        'ms_primaries': Msdnsserver.from_dict,
        'ms_secondaries': Msdnsserver.from_dict,
        'update_forwarding': Addressac.from_dict,
    }

    def copyzonerecords(self, *args, **kwargs):
        return self._call_func("copyzonerecords", *args, **kwargs)

    def dnssec_export(self, *args, **kwargs):
        return self._call_func("dnssec_export", *args, **kwargs)

    def dnssec_get_zone_keys(self, *args, **kwargs):
        return self._call_func("dnssec_get_zone_keys", *args, **kwargs)

    def dnssec_operation(self, *args, **kwargs):
        return self._call_func("dnssec_operation", *args, **kwargs)

    def dnssec_set_zone_keys(self, *args, **kwargs):
        return self._call_func("dnssec_set_zone_keys", *args, **kwargs)

    def dnssecgetkskrollover(self, *args, **kwargs):
        return self._call_func("dnssecgetkskrollover", *args, **kwargs)

    def execute_dns_parent_check(self, *args, **kwargs):
        return self._call_func("execute_dns_parent_check", *args, **kwargs)

    def lock_unlock_zone(self, *args, **kwargs):
        return self._call_func("lock_unlock_zone", *args, **kwargs)

    def run_scavenging(self, *args, **kwargs):
        return self._call_func("run_scavenging", *args, **kwargs)


class ZoneAuthDiscrepancy(InfobloxObject):
    _infoblox_type = 'zone_auth_discrepancy'
    _fields = ['description', 'severity', 'timestamp', 'zone']
    _search_for_update_fields = ['severity', 'zone']
    _updateable_search_fields = []
    _all_searchable_fields = ['severity', 'zone']
    _return_fields = ['description', 'severity', 'timestamp', 'zone']
    _remap = {}
    _shadow_fields = ['_ref']


class DNSZoneDelegated(InfobloxObject):
    _infoblox_type = 'zone_delegated'
    _fields = ['address', 'comment', 'delegate_to', 'delegated_ttl', 'disable', 'display_domain', 'dns_fqdn', 'enable_rfc2317_exclusion', 'extattrs', 'fqdn', 'locked', 'locked_by', 'mask_prefix', 'ms_ad_integrated', 'ms_ddns_mode', 'ms_managed', 'ms_read_only', 'ms_sync_master_name', 'ns_group', 'parent', 'prefix', 'use_delegated_ttl', 'using_srg_associations', 'view', 'zone_format']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'fqdn', 'parent', 'view', 'zone_format']
    _return_fields = ['delegate_to', 'extattrs', 'fqdn', 'view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'delegate_to': Extserver.from_dict,
    }

    def lock_unlock_zone(self, *args, **kwargs):
        return self._call_func("lock_unlock_zone", *args, **kwargs)


class DNSZoneForward(InfobloxObject):
    _infoblox_type = 'zone_forward'
    _fields = ['address', 'comment', 'disable', 'disable_ns_generation', 'display_domain', 'dns_fqdn', 'extattrs', 'external_ns_group', 'forward_to', 'forwarders_only', 'forwarding_servers', 'fqdn', 'locked', 'locked_by', 'mask_prefix', 'ms_ad_integrated', 'ms_ddns_mode', 'ms_managed', 'ms_read_only', 'ms_sync_master_name', 'ns_group', 'parent', 'prefix', 'using_srg_associations', 'view', 'zone_format']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'fqdn', 'parent', 'view', 'zone_format']
    _return_fields = ['extattrs', 'forward_to', 'fqdn', 'view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'forward_to': Extserver.from_dict,
        'forwarding_servers': Forwardingmemberserver.from_dict,
    }

    def lock_unlock_zone(self, *args, **kwargs):
        return self._call_func("lock_unlock_zone", *args, **kwargs)


class ZoneRp(InfobloxObject):
    _infoblox_type = 'zone_rp'
    _fields = ['address', 'comment', 'disable', 'display_domain', 'dns_soa_email', 'extattrs', 'external_primaries', 'external_secondaries', 'fireeye_rule_mapping', 'fqdn', 'grid_primary', 'grid_secondaries', 'locked', 'locked_by', 'log_rpz', 'mask_prefix', 'member_soa_mnames', 'member_soa_serials', 'network_view', 'ns_group', 'parent', 'prefix', 'primary_type', 'record_name_policy', 'rpz_drop_ip_rule_enabled', 'rpz_drop_ip_rule_min_prefix_length_ipv4', 'rpz_drop_ip_rule_min_prefix_length_ipv6', 'rpz_last_updated_time', 'rpz_policy', 'rpz_priority', 'rpz_priority_end', 'rpz_severity', 'rpz_type', 'set_soa_serial_number', 'soa_default_ttl', 'soa_email', 'soa_expire', 'soa_negative_ttl', 'soa_refresh', 'soa_retry', 'soa_serial_number', 'substitute_name', 'use_external_primary', 'use_grid_zone_timer', 'use_log_rpz', 'use_record_name_policy', 'use_rpz_drop_ip_rule', 'use_soa_email', 'view']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'fqdn', 'parent', 'view']
    _return_fields = ['extattrs', 'fqdn', 'view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'external_primaries': Extserver.from_dict,
        'external_secondaries': Extserver.from_dict,
        'grid_primary': Memberserver.from_dict,
        'grid_secondaries': Memberserver.from_dict,
        'member_soa_mnames': GridmemberSoamname.from_dict,
        'member_soa_serials': GridmemberSoaserial.from_dict,
    }

    def copy_rpz_records(self, *args, **kwargs):
        return self._call_func("copy_rpz_records", *args, **kwargs)

    def lock_unlock_zone(self, *args, **kwargs):
        return self._call_func("lock_unlock_zone", *args, **kwargs)


class ZoneStub(InfobloxObject):
    _infoblox_type = 'zone_stub'
    _fields = ['address', 'comment', 'disable', 'disable_forwarding', 'display_domain', 'dns_fqdn', 'extattrs', 'external_ns_group', 'fqdn', 'locked', 'locked_by', 'mask_prefix', 'ms_ad_integrated', 'ms_ddns_mode', 'ms_managed', 'ms_read_only', 'ms_sync_master_name', 'ns_group', 'parent', 'prefix', 'soa_email', 'soa_expire', 'soa_mname', 'soa_negative_ttl', 'soa_refresh', 'soa_retry', 'soa_serial_number', 'stub_from', 'stub_members', 'stub_msservers', 'using_srg_associations', 'view', 'zone_format']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'fqdn', 'parent', 'view', 'zone_format']
    _return_fields = ['extattrs', 'fqdn', 'stub_from', 'view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'stub_from': Extserver.from_dict,
        'stub_members': Memberserver.from_dict,
        'stub_msservers': Msdnsserver.from_dict,
    }

    def lock_unlock_zone(self, *args, **kwargs):
        return self._call_func("lock_unlock_zone", *args, **kwargs)


