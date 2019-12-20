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
### AUTOGENERATED CODE BELOW ###


class IPv6HostAddress(InfobloxObject):
    _infoblox_type = 'record:host_ipv6addr'
    _fields = ['address_type', 'configure_for_dhcp', 'discover_now_status', 'discovered_data', 'domain_name', 'domain_name_servers', 'duid', 'host', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'last_queried', 'match_client', 'ms_ad_user_data', 'network', 'network_view', 'options', 'preferred_lifetime', 'reserved_interface', 'use_domain_name', 'use_domain_name_servers', 'use_for_ea_inheritance', 'use_options', 'use_preferred_lifetime', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['duid', 'ipv6addr']
    _updateable_search_fields = ['duid', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits']
    _all_searchable_fields = ['duid', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'network_view']
    _return_fields = ['configure_for_dhcp', 'duid', 'host', 'ipv6addr']
    _remap = {}
    _shadow_fields = ['_ref']

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    _custom_field_processing = {
        'options': _build_options.__func__,
    }


class IpamStatistics(InfobloxObject):
    _infoblox_type = 'ipam:statistics'
    _fields = ['cidr', 'conflict_count', 'ms_ad_user_data', 'network', 'network_view', 'unmanaged_count', 'utilization', 'utilization_update']
    _search_for_update_fields = ['network', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['network', 'network_view']
    _return_fields = ['cidr', 'network', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']


class Vlan(InfobloxObject):
    _infoblox_type = 'vlan'
    _fields = ['assigned_to', 'comment', 'contact', 'department', 'description', 'extattrs', 'id', 'name', 'parent', 'reserved', 'status']
    _search_for_update_fields = ['id', 'name', 'parent']
    _updateable_search_fields = ['comment', 'contact', 'department', 'description', 'id', 'name', 'parent', 'reserved']
    _all_searchable_fields = ['assigned_to', 'comment', 'contact', 'department', 'description', 'id', 'name', 'parent', 'reserved', 'status']
    _return_fields = ['id', 'name', 'parent']
    _remap = {}
    _shadow_fields = ['_ref']


class IPAddress(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return IPv4Address

    @classmethod
    def get_v6_class(cls):
        return IPv6Address


class IPv4Address(InfobloxObject):
    _infoblox_type = 'ipv4address'
    _fields = ['comment', 'conflict_types', 'dhcp_client_identifier', 'discover_now_status', 'discovered_data', 'extattrs', 'fingerprint', 'ip_address', 'is_conflict', 'is_invalid_mac', 'lease_state', 'mac_address', 'ms_ad_user_data', 'names', 'network', 'network_view', 'objects', 'reserved_port', 'status', 'types', 'usage', 'username']
    _search_for_update_fields = ['dhcp_client_identifier', 'ip_address', 'is_conflict', 'lease_state', 'mac_address', 'names', 'network', 'network_view', 'status', 'types', 'usage', 'username']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'dhcp_client_identifier', 'fingerprint', 'ip_address', 'is_conflict', 'lease_state', 'mac_address', 'names', 'network', 'network_view', 'status', 'types', 'usage', 'username']
    _return_fields = ['dhcp_client_identifier', 'ip_address', 'is_conflict', 'lease_state', 'mac_address', 'names', 'network', 'network_view', 'objects', 'status', 'types', 'usage', 'username']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4


class IPv6Address(InfobloxObject):
    _infoblox_type = 'ipv6address'
    _fields = ['comment', 'conflict_types', 'discover_now_status', 'discovered_data', 'duid', 'extattrs', 'fingerprint', 'ip_address', 'is_conflict', 'lease_state', 'ms_ad_user_data', 'names', 'network', 'network_view', 'objects', 'reserved_port', 'status', 'types', 'usage']
    _search_for_update_fields = ['duid', 'ip_address', 'is_conflict', 'lease_state', 'names', 'network', 'network_view', 'status', 'types', 'usage']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'duid', 'fingerprint', 'ip_address', 'is_conflict', 'lease_state', 'names', 'network', 'network_view', 'status', 'types', 'usage']
    _return_fields = ['duid', 'ip_address', 'is_conflict', 'lease_state', 'names', 'network', 'network_view', 'objects', 'status', 'types', 'usage']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6


class SRVRecord(InfobloxObject):
    _infoblox_type = 'record:srv'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_name', 'dns_target', 'extattrs', 'forbid_reclamation', 'last_queried', 'name', 'port', 'priority', 'reclaimable', 'shared_record_group', 'target', 'ttl', 'use_ttl', 'view', 'weight', 'zone']
    _search_for_update_fields = ['name', 'port', 'priority', 'target', 'view', 'weight']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'name', 'port', 'priority', 'target', 'weight']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'name', 'port', 'priority', 'reclaimable', 'target', 'view', 'weight', 'zone']
    _return_fields = ['name', 'port', 'priority', 'target', 'view', 'weight']
    _remap = {}
    _shadow_fields = ['_ref']


class DNSView(InfobloxObject):
    _infoblox_type = 'view'
    _fields = ['blacklist_action', 'blacklist_log_query', 'blacklist_redirect_addresses', 'blacklist_redirect_ttl', 'blacklist_rulesets', 'cloud_info', 'comment', 'custom_root_name_servers', 'ddns_force_creation_timestamp_update', 'ddns_principal_group', 'ddns_principal_tracking', 'ddns_restrict_patterns', 'ddns_restrict_patterns_list', 'ddns_restrict_protected', 'ddns_restrict_secure', 'ddns_restrict_static', 'disable', 'dns64_enabled', 'dns64_groups', 'dnssec_enabled', 'dnssec_expired_signatures_enabled', 'dnssec_negative_trust_anchors', 'dnssec_trusted_keys', 'dnssec_validation_enabled', 'enable_blacklist', 'enable_fixed_rrset_order_fqdns', 'enable_match_recursive_only', 'extattrs', 'filter_aaaa', 'filter_aaaa_list', 'fixed_rrset_order_fqdns', 'forward_only', 'forwarders', 'is_default', 'lame_ttl', 'match_clients', 'match_destinations', 'max_cache_ttl', 'max_ncache_ttl', 'name', 'network_view', 'notify_delay', 'nxdomain_log_query', 'nxdomain_redirect', 'nxdomain_redirect_addresses', 'nxdomain_redirect_addresses_v6', 'nxdomain_redirect_ttl', 'nxdomain_rulesets', 'recursion', 'response_rate_limiting', 'root_name_server_type', 'rpz_drop_ip_rule_enabled', 'rpz_drop_ip_rule_min_prefix_length_ipv4', 'rpz_drop_ip_rule_min_prefix_length_ipv6', 'rpz_qname_wait_recurse', 'run_scavenging', 'scavenging_settings', 'sortlist', 'use_blacklist', 'use_ddns_force_creation_timestamp_update', 'use_ddns_patterns_restriction', 'use_ddns_principal_security', 'use_ddns_restrict_protected', 'use_ddns_restrict_static', 'use_dns64', 'use_dnssec', 'use_filter_aaaa', 'use_fixed_rrset_order_fqdns', 'use_forwarders', 'use_lame_ttl', 'use_max_cache_ttl', 'use_max_ncache_ttl', 'use_nxdomain_redirect', 'use_recursion', 'use_response_rate_limiting', 'use_root_name_server', 'use_rpz_drop_ip_rule', 'use_rpz_qname_wait_recurse', 'use_scavenging_settings', 'use_sortlist']
    _search_for_update_fields = ['comment', 'is_default', 'name']
    _updateable_search_fields = ['blacklist_action', 'blacklist_log_query', 'comment', 'dns64_enabled', 'dnssec_enabled', 'dnssec_expired_signatures_enabled', 'dnssec_validation_enabled', 'enable_blacklist', 'filter_aaaa', 'forward_only', 'name', 'network_view', 'nxdomain_log_query', 'nxdomain_redirect', 'recursion', 'root_name_server_type']
    _all_searchable_fields = ['blacklist_action', 'blacklist_log_query', 'comment', 'dns64_enabled', 'dnssec_enabled', 'dnssec_expired_signatures_enabled', 'dnssec_validation_enabled', 'enable_blacklist', 'filter_aaaa', 'forward_only', 'is_default', 'name', 'network_view', 'nxdomain_log_query', 'nxdomain_redirect', 'recursion', 'root_name_server_type']
    _return_fields = ['comment', 'is_default', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    @staticmethod
    def _build_custom_root_name_servers(members):
        if not members:
            return None
        return [Extserver.from_dict(m) for m in members]

    @staticmethod
    def _build_dnssec_trusted_keys(members):
        if not members:
            return None
        return [Dnssectrustedkey.from_dict(m) for m in members]

    @staticmethod
    def _build_filter_aaaa_list(members):
        if not members:
            return None
        return [Addressac.from_dict(m) for m in members]

    @staticmethod
    def _build_fixed_rrset_order_fqdns(members):
        if not members:
            return None
        return [GridDnsFixedrrsetorderfqdn.from_dict(m) for m in members]

    @staticmethod
    def _build_match_clients(members):
        if not members:
            return None
        return [Addressac.from_dict(m) for m in members]

    @staticmethod
    def _build_match_destinations(members):
        if not members:
            return None
        return [Addressac.from_dict(m) for m in members]

    @staticmethod
    def _build_sortlist(members):
        if not members:
            return None
        return [Sortlist.from_dict(m) for m in members]

    _custom_field_processing = {
        'custom_root_name_servers': _build_custom_root_name_servers.__func__,
        'dnssec_trusted_keys': _build_dnssec_trusted_keys.__func__,
        'filter_aaaa_list': _build_filter_aaaa_list.__func__,
        'fixed_rrset_order_fqdns': _build_fixed_rrset_order_fqdns.__func__,
        'match_clients': _build_match_clients.__func__,
        'match_destinations': _build_match_destinations.__func__,
        'sortlist': _build_sortlist.__func__,
    }


class Vlanrange(InfobloxObject):
    _infoblox_type = 'vlanrange'
    _fields = ['comment', 'delete_vlans', 'end_vlan_id', 'extattrs', 'name', 'next_available_vlan_id', 'pre_create_vlan', 'start_vlan_id', 'vlan_name_prefix', 'vlan_view']
    _search_for_update_fields = ['end_vlan_id', 'name', 'start_vlan_id', 'vlan_view']
    _updateable_search_fields = ['comment', 'end_vlan_id', 'name', 'start_vlan_id', 'vlan_view']
    _all_searchable_fields = ['comment', 'end_vlan_id', 'name', 'start_vlan_id', 'vlan_view']
    _return_fields = ['end_vlan_id', 'name', 'start_vlan_id', 'vlan_view']
    _remap = {}
    _shadow_fields = ['_ref']


class Network(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return NetworkV4

    @classmethod
    def get_v6_class(cls):
        return NetworkV6


class NetworkV4(InfobloxObject):
    _infoblox_type = 'network'
    _fields = ['authority', 'auto_create_reversezone', 'bootfile', 'bootserver', 'cloud_info', 'comment', 'conflict_count', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'delete_reason', 'deny_bootp', 'dhcp_utilization', 'dhcp_utilization_status', 'disable', 'discover_now_status', 'discovered_bgp_as', 'discovered_bridge_domain', 'discovered_tenant', 'discovered_vlan_id', 'discovered_vlan_name', 'discovered_vrf_description', 'discovered_vrf_name', 'discovered_vrf_rd', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_engine_type', 'discovery_member', 'dynamic_hosts', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_discovery', 'enable_email_warnings', 'enable_ifmap_publishing', 'enable_immediate_discovery', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'endpoint_sources', 'expand_network', 'extattrs', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'ipam_email_addresses', 'ipam_threshold_settings', 'ipam_trap_settings', 'ipv4addr', 'last_rir_registration_update_sent', 'last_rir_registration_update_status', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'members', 'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data', 'netmask', 'network', 'network_container', 'network_view', 'next_available_ip', 'next_available_network', 'next_available_vlan', 'nextserver', 'options', 'port_control_blackout_setting', 'pxe_lease_time', 'recycle_leases', 'resize', 'restart_if_needed', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'same_port_control_discovery_blackout', 'send_rir_request', 'split_network', 'static_hosts', 'subscribe_settings', 'template', 'total_hosts', 'unmanaged', 'unmanaged_count', 'update_dns_on_lease_renewal', 'use_authority', 'use_blackout_setting', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_update_fixed_addresses', 'use_ddns_use_option81', 'use_deny_bootp', 'use_discovery_basic_polling_settings', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_enable_discovery', 'use_enable_ifmap_publishing', 'use_ignore_dhcp_option_list_request', 'use_ignore_id', 'use_ipam_email_addresses', 'use_ipam_threshold_settings', 'use_ipam_trap_settings', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_mgm_private', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_subscribe_settings', 'use_update_dns_on_lease_renewal', 'use_zone_associations', 'utilization', 'utilization_update', 'vlans', 'zone_associations']
    _search_for_update_fields = ['comment', 'network', 'network_view']
    _updateable_search_fields = ['comment', 'discovered_bridge_domain', 'discovered_tenant', 'ipv4addr', 'network', 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovered_bgp_as', 'discovered_bridge_domain', 'discovered_tenant', 'discovered_vlan_id', 'discovered_vlan_name', 'discovered_vrf_description', 'discovered_vrf_name', 'discovered_vrf_rd', 'discovery_engine_type', 'ipv4addr', 'network', 'network_container', 'network_view', 'rir', 'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'network', 'network_view']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 4

    @staticmethod
    def _build_logic_filter_rules(members):
        if not members:
            return None
        return [Logicfilterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_members(members):
        if not members:
            return None
        return [Msdhcpserver.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    @staticmethod
    def _build_vlans(members):
        if not members:
            return None
        return [Vlanlink.from_dict(m) for m in members]

    @staticmethod
    def _build_zone_associations(members):
        if not members:
            return None
        return [Zoneassociation.from_dict(m) for m in members]

    _custom_field_processing = {
        'logic_filter_rules': _build_logic_filter_rules.__func__,
        'members': _build_members.__func__,
        'options': _build_options.__func__,
        'vlans': _build_vlans.__func__,
        'zone_associations': _build_zone_associations.__func__,
    }


class NetworkV6(InfobloxObject):
    _infoblox_type = 'ipv6network'
    _fields = ['auto_create_reversezone', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_enable_option_fqdn', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'delete_reason', 'disable', 'discover_now_status', 'discovered_bgp_as', 'discovered_bridge_domain', 'discovered_tenant', 'discovered_vlan_id', 'discovered_vlan_name', 'discovered_vrf_description', 'discovered_vrf_name', 'discovered_vrf_rd', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_engine_type', 'discovery_member', 'domain_name', 'domain_name_servers', 'enable_ddns', 'enable_discovery', 'enable_ifmap_publishing', 'enable_immediate_discovery', 'endpoint_sources', 'expand_network', 'extattrs', 'last_rir_registration_update_sent', 'last_rir_registration_update_status', 'members', 'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data', 'network', 'network_container', 'network_view', 'next_available_ip', 'next_available_network', 'next_available_vlan', 'options', 'port_control_blackout_setting', 'preferred_lifetime', 'recycle_leases', 'restart_if_needed', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'same_port_control_discovery_blackout', 'send_rir_request', 'split_network', 'subscribe_settings', 'template', 'unmanaged', 'unmanaged_count', 'update_dns_on_lease_renewal', 'use_blackout_setting', 'use_ddns_domainname', 'use_ddns_enable_option_fqdn', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_discovery_basic_polling_settings', 'use_domain_name', 'use_domain_name_servers', 'use_enable_ddns', 'use_enable_discovery', 'use_enable_ifmap_publishing', 'use_mgm_private', 'use_options', 'use_preferred_lifetime', 'use_recycle_leases', 'use_subscribe_settings', 'use_update_dns_on_lease_renewal', 'use_valid_lifetime', 'use_zone_associations', 'valid_lifetime', 'vlans', 'zone_associations']
    _search_for_update_fields = ['comment', 'network', 'network_view']
    _updateable_search_fields = ['comment', 'discovered_bridge_domain', 'discovered_tenant', 'network', 'network_view', 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovered_bgp_as', 'discovered_bridge_domain', 'discovered_tenant', 'discovered_vlan_id', 'discovered_vlan_name', 'discovered_vrf_description', 'discovered_vrf_name', 'discovered_vrf_rd', 'discovery_engine_type', 'network', 'network_container', 'network_view', 'rir', 'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'network', 'network_view']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 6

    @staticmethod
    def _build_members(members):
        if not members:
            return None
        return [Dhcpmember.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    @staticmethod
    def _build_vlans(members):
        if not members:
            return None
        return [Vlanlink.from_dict(m) for m in members]

    @staticmethod
    def _build_zone_associations(members):
        if not members:
            return None
        return [Zoneassociation.from_dict(m) for m in members]

    _custom_field_processing = {
        'members': _build_members.__func__,
        'options': _build_options.__func__,
        'vlans': _build_vlans.__func__,
        'zone_associations': _build_zone_associations.__func__,
    }


class Vlanview(InfobloxObject):
    _infoblox_type = 'vlanview'
    _fields = ['allow_range_overlapping', 'comment', 'end_vlan_id', 'extattrs', 'name', 'next_available_vlan_id', 'pre_create_vlan', 'start_vlan_id', 'vlan_name_prefix']
    _search_for_update_fields = ['end_vlan_id', 'name', 'start_vlan_id']
    _updateable_search_fields = ['allow_range_overlapping', 'comment', 'end_vlan_id', 'name', 'start_vlan_id']
    _all_searchable_fields = ['allow_range_overlapping', 'comment', 'end_vlan_id', 'name', 'start_vlan_id']
    _return_fields = ['end_vlan_id', 'name', 'start_vlan_id']
    _remap = {}
    _shadow_fields = ['_ref']


class DNSZone(InfobloxObject):
    _infoblox_type = 'zone_auth'
    _fields = ['address', 'allow_active_dir', 'allow_fixed_rrset_order', 'allow_gss_tsig_for_underscore_zone', 'allow_gss_tsig_zone_updates', 'allow_query', 'allow_transfer', 'allow_update', 'allow_update_forwarding', 'aws_rte53_zone_info', 'cloud_info', 'comment', 'copy_xfer_to_notify', 'copyzonerecords', 'create_ptr_for_bulk_hosts', 'create_ptr_for_hosts', 'create_underscore_zones', 'ddns_force_creation_timestamp_update', 'ddns_principal_group', 'ddns_principal_tracking', 'ddns_restrict_patterns', 'ddns_restrict_patterns_list', 'ddns_restrict_protected', 'ddns_restrict_secure', 'ddns_restrict_static', 'disable', 'disable_forwarding', 'display_domain', 'dns_fqdn', 'dns_integrity_enable', 'dns_integrity_frequency', 'dns_integrity_member', 'dns_integrity_verbose_logging', 'dns_soa_email', 'dnssec_export', 'dnssec_get_zone_keys', 'dnssec_key_params', 'dnssec_keys', 'dnssec_ksk_rollover_date', 'dnssec_operation', 'dnssec_set_zone_keys', 'dnssec_zsk_rollover_date', 'dnssecgetkskrollover', 'do_host_abstraction', 'effective_check_names_policy', 'effective_record_name_policy', 'execute_dns_parent_check', 'extattrs', 'external_primaries', 'external_secondaries', 'fqdn', 'grid_primary', 'grid_primary_shared_with_ms_parent_delegation', 'grid_secondaries', 'import_from', 'is_dnssec_enabled', 'is_dnssec_signed', 'is_multimaster', 'last_queried', 'lock_unlock_zone', 'locked', 'locked_by', 'mask_prefix', 'member_soa_mnames', 'member_soa_serials', 'ms_ad_integrated', 'ms_allow_transfer', 'ms_allow_transfer_mode', 'ms_dc_ns_record_creation', 'ms_ddns_mode', 'ms_managed', 'ms_primaries', 'ms_read_only', 'ms_secondaries', 'ms_sync_disabled', 'ms_sync_master_name', 'network_associations', 'network_view', 'notify_delay', 'ns_group', 'parent', 'prefix', 'primary_type', 'record_name_policy', 'records_monitored', 'restart_if_needed', 'rr_not_queried_enabled_time', 'run_scavenging', 'scavenging_settings', 'set_soa_serial_number', 'soa_default_ttl', 'soa_email', 'soa_expire', 'soa_negative_ttl', 'soa_refresh', 'soa_retry', 'soa_serial_number', 'srgs', 'update_forwarding', 'use_allow_active_dir', 'use_allow_query', 'use_allow_transfer', 'use_allow_update', 'use_allow_update_forwarding', 'use_check_names_policy', 'use_copy_xfer_to_notify', 'use_ddns_force_creation_timestamp_update', 'use_ddns_patterns_restriction', 'use_ddns_principal_security', 'use_ddns_restrict_protected', 'use_ddns_restrict_static', 'use_dnssec_key_params', 'use_external_primary', 'use_grid_zone_timer', 'use_import_from', 'use_notify_delay', 'use_record_name_policy', 'use_scavenging_settings', 'use_soa_email', 'using_srg_associations', 'view', 'zone_format', 'zone_not_queried_enabled_time']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'dnssec_ksk_rollover_date', 'dnssec_zsk_rollover_date', 'fqdn', 'parent', 'view', 'zone_format']
    _return_fields = ['fqdn', 'view']
    _remap = {}
    _shadow_fields = ['_ref']

    @staticmethod
    def _build_allow_active_dir(members):
        if not members:
            return None
        return [Addressac.from_dict(m) for m in members]

    @staticmethod
    def _build_allow_query(members):
        if not members:
            return None
        return [Addressac.from_dict(m) for m in members]

    @staticmethod
    def _build_allow_transfer(members):
        if not members:
            return None
        return [Addressac.from_dict(m) for m in members]

    @staticmethod
    def _build_allow_update(members):
        if not members:
            return None
        return [Addressac.from_dict(m) for m in members]

    @staticmethod
    def _build_dnssec_keys(members):
        if not members:
            return None
        return [Dnsseckey.from_dict(m) for m in members]

    @staticmethod
    def _build_external_primaries(members):
        if not members:
            return None
        return [Extserver.from_dict(m) for m in members]

    @staticmethod
    def _build_external_secondaries(members):
        if not members:
            return None
        return [Extserver.from_dict(m) for m in members]

    @staticmethod
    def _build_grid_primary(members):
        if not members:
            return None
        return [Memberserver.from_dict(m) for m in members]

    @staticmethod
    def _build_grid_secondaries(members):
        if not members:
            return None
        return [Memberserver.from_dict(m) for m in members]

    @staticmethod
    def _build_member_soa_mnames(members):
        if not members:
            return None
        return [GridmemberSoamname.from_dict(m) for m in members]

    @staticmethod
    def _build_member_soa_serials(members):
        if not members:
            return None
        return [GridmemberSoaserial.from_dict(m) for m in members]

    @staticmethod
    def _build_ms_allow_transfer(members):
        if not members:
            return None
        return [Addressac.from_dict(m) for m in members]

    @staticmethod
    def _build_ms_dc_ns_record_creation(members):
        if not members:
            return None
        return [MsserverDcnsrecordcreation.from_dict(m) for m in members]

    @staticmethod
    def _build_ms_primaries(members):
        if not members:
            return None
        return [Msdnsserver.from_dict(m) for m in members]

    @staticmethod
    def _build_ms_secondaries(members):
        if not members:
            return None
        return [Msdnsserver.from_dict(m) for m in members]

    @staticmethod
    def _build_update_forwarding(members):
        if not members:
            return None
        return [Addressac.from_dict(m) for m in members]

    _custom_field_processing = {
        'allow_active_dir': _build_allow_active_dir.__func__,
        'allow_query': _build_allow_query.__func__,
        'allow_transfer': _build_allow_transfer.__func__,
        'allow_update': _build_allow_update.__func__,
        'dnssec_keys': _build_dnssec_keys.__func__,
        'external_primaries': _build_external_primaries.__func__,
        'external_secondaries': _build_external_secondaries.__func__,
        'grid_primary': _build_grid_primary.__func__,
        'grid_secondaries': _build_grid_secondaries.__func__,
        'member_soa_mnames': _build_member_soa_mnames.__func__,
        'member_soa_serials': _build_member_soa_serials.__func__,
        'ms_allow_transfer': _build_ms_allow_transfer.__func__,
        'ms_dc_ns_record_creation': _build_ms_dc_ns_record_creation.__func__,
        'ms_primaries': _build_ms_primaries.__func__,
        'ms_secondaries': _build_ms_secondaries.__func__,
        'update_forwarding': _build_update_forwarding.__func__,
    }


class NetworkContainer(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return NetworkContainerV4

    @classmethod
    def get_v6_class(cls):
        return NetworkContainerV6


class NetworkContainerV4(InfobloxObject):
    _infoblox_type = 'networkcontainer'
    _fields = ['authority', 'auto_create_reversezone', 'bootfile', 'bootserver', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'delete_reason', 'deny_bootp', 'discover_now_status', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_engine_type', 'discovery_member', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_discovery', 'enable_email_warnings', 'enable_immediate_discovery', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'endpoint_sources', 'extattrs', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'ipam_email_addresses', 'ipam_threshold_settings', 'ipam_trap_settings', 'last_rir_registration_update_sent', 'last_rir_registration_update_status', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data', 'network', 'network_container', 'network_view', 'next_available_network', 'nextserver', 'options', 'port_control_blackout_setting', 'pxe_lease_time', 'recycle_leases', 'remove_subnets', 'resize', 'restart_if_needed', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'same_port_control_discovery_blackout', 'send_rir_request', 'subscribe_settings', 'unmanaged', 'update_dns_on_lease_renewal', 'use_authority', 'use_blackout_setting', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_update_fixed_addresses', 'use_ddns_use_option81', 'use_deny_bootp', 'use_discovery_basic_polling_settings', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_enable_discovery', 'use_ignore_dhcp_option_list_request', 'use_ignore_id', 'use_ipam_email_addresses', 'use_ipam_threshold_settings', 'use_ipam_trap_settings', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_mgm_private', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_subscribe_settings', 'use_update_dns_on_lease_renewal', 'use_zone_associations', 'utilization', 'zone_associations']
    _search_for_update_fields = ['comment', 'network', 'network_view']
    _updateable_search_fields = ['comment', 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovery_engine_type', 'network', 'network_container', 'network_view', 'rir', 'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'network', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    @staticmethod
    def _build_logic_filter_rules(members):
        if not members:
            return None
        return [Logicfilterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    @staticmethod
    def _build_zone_associations(members):
        if not members:
            return None
        return [Zoneassociation.from_dict(m) for m in members]

    _custom_field_processing = {
        'logic_filter_rules': _build_logic_filter_rules.__func__,
        'options': _build_options.__func__,
        'zone_associations': _build_zone_associations.__func__,
    }


class NetworkContainerV6(InfobloxObject):
    _infoblox_type = 'ipv6networkcontainer'
    _fields = ['auto_create_reversezone', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_enable_option_fqdn', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'delete_reason', 'discover_now_status', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_engine_type', 'discovery_member', 'domain_name_servers', 'enable_ddns', 'enable_discovery', 'enable_immediate_discovery', 'endpoint_sources', 'extattrs', 'last_rir_registration_update_sent', 'last_rir_registration_update_status', 'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data', 'network', 'network_container', 'network_view', 'next_available_network', 'options', 'port_control_blackout_setting', 'preferred_lifetime', 'remove_subnets', 'restart_if_needed', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'same_port_control_discovery_blackout', 'send_rir_request', 'subscribe_settings', 'unmanaged', 'update_dns_on_lease_renewal', 'use_blackout_setting', 'use_ddns_domainname', 'use_ddns_enable_option_fqdn', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_discovery_basic_polling_settings', 'use_domain_name_servers', 'use_enable_ddns', 'use_enable_discovery', 'use_mgm_private', 'use_options', 'use_preferred_lifetime', 'use_subscribe_settings', 'use_update_dns_on_lease_renewal', 'use_valid_lifetime', 'use_zone_associations', 'utilization', 'valid_lifetime', 'zone_associations']
    _search_for_update_fields = ['comment', 'network', 'network_view']
    _updateable_search_fields = ['comment', 'network_view', 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovery_engine_type', 'network', 'network_container', 'network_view', 'rir', 'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'network', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    @staticmethod
    def _build_zone_associations(members):
        if not members:
            return None
        return [Zoneassociation.from_dict(m) for m in members]

    _custom_field_processing = {
        'options': _build_options.__func__,
        'zone_associations': _build_zone_associations.__func__,
    }


class NetworkTemplate(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return NetworkTemplateV4

    @classmethod
    def get_v6_class(cls):
        return NetworkTemplateV6


class NetworkTemplateV4(InfobloxObject):
    _infoblox_type = 'networktemplate'
    _fields = ['allow_any_netmask', 'authority', 'auto_create_reversezone', 'bootfile', 'bootserver', 'cloud_api_compatible', 'comment', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'delegated_member', 'deny_bootp', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_email_warnings', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'extattrs', 'fixed_address_templates', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'ipam_email_addresses', 'ipam_threshold_settings', 'ipam_trap_settings', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'members', 'name', 'netmask', 'nextserver', 'options', 'pxe_lease_time', 'range_templates', 'recycle_leases', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'send_rir_request', 'update_dns_on_lease_renewal', 'use_authority', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_update_fixed_addresses', 'use_ddns_use_option81', 'use_deny_bootp', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_ignore_dhcp_option_list_request', 'use_ipam_email_addresses', 'use_ipam_threshold_settings', 'use_ipam_trap_settings', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'name', 'rir_organization']
    _all_searchable_fields = ['comment', 'name', 'rir', 'rir_organization']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    @staticmethod
    def _build_logic_filter_rules(members):
        if not members:
            return None
        return [Logicfilterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_members(members):
        if not members:
            return None
        return [Msdhcpserver.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    _custom_field_processing = {
        'logic_filter_rules': _build_logic_filter_rules.__func__,
        'members': _build_members.__func__,
        'options': _build_options.__func__,
    }


class NetworkTemplateV6(InfobloxObject):
    _infoblox_type = 'ipv6networktemplate'
    _fields = ['allow_any_netmask', 'auto_create_reversezone', 'cidr', 'cloud_api_compatible', 'comment', 'ddns_domainname', 'ddns_enable_option_fqdn', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'delegated_member', 'domain_name', 'domain_name_servers', 'enable_ddns', 'extattrs', 'fixed_address_templates', 'ipv6prefix', 'members', 'name', 'options', 'preferred_lifetime', 'range_templates', 'recycle_leases', 'rir', 'rir_organization', 'rir_registration_action', 'rir_registration_status', 'send_rir_request', 'update_dns_on_lease_renewal', 'use_ddns_domainname', 'use_ddns_enable_option_fqdn', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_domain_name', 'use_domain_name_servers', 'use_enable_ddns', 'use_options', 'use_preferred_lifetime', 'use_recycle_leases', 'use_update_dns_on_lease_renewal', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'ipv6prefix', 'name', 'rir_organization']
    _all_searchable_fields = ['comment', 'ipv6prefix', 'name', 'rir', 'rir_organization']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    @staticmethod
    def _build_members(members):
        if not members:
            return None
        return [Dhcpmember.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    _custom_field_processing = {
        'members': _build_members.__func__,
        'options': _build_options.__func__,
    }


class IPRange(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return IPRangeV4

    @classmethod
    def get_v6_class(cls):
        return IPRangeV6


class IPRangeV4(InfobloxObject):
    _infoblox_type = 'range'
    _fields = ['always_update_dns', 'bootfile', 'bootserver', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_generate_hostname', 'deny_all_clients', 'deny_bootp', 'dhcp_utilization', 'dhcp_utilization_status', 'disable', 'discover_now_status', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_member', 'dynamic_hosts', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_discovery', 'enable_email_warnings', 'enable_ifmap_publishing', 'enable_immediate_discovery', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'end_addr', 'endpoint_sources', 'exclude', 'extattrs', 'failover_association', 'fingerprint_filter_rules', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'is_split_scope', 'known_clients', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'mac_filter_rules', 'member', 'ms_ad_user_data', 'ms_options', 'ms_server', 'nac_filter_rules', 'name', 'network', 'network_view', 'next_available_ip', 'nextserver', 'option_filter_rules', 'options', 'port_control_blackout_setting', 'pxe_lease_time', 'recycle_leases', 'relay_agent_filter_rules', 'restart_if_needed', 'same_port_control_discovery_blackout', 'server_association_type', 'split_member', 'split_scope_exclusion_percent', 'start_addr', 'static_hosts', 'subscribe_settings', 'template', 'total_hosts', 'unknown_clients', 'update_dns_on_lease_renewal', 'use_blackout_setting', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_deny_bootp', 'use_discovery_basic_polling_settings', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_enable_discovery', 'use_enable_ifmap_publishing', 'use_ignore_dhcp_option_list_request', 'use_ignore_id', 'use_known_clients', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_ms_options', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_subscribe_settings', 'use_unknown_clients', 'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['comment', 'end_addr', 'network', 'network_view', 'start_addr']
    _updateable_search_fields = ['comment', 'end_addr', 'failover_association', 'member', 'ms_server', 'network', 'network_view', 'server_association_type', 'start_addr']
    _all_searchable_fields = ['comment', 'end_addr', 'failover_association', 'member', 'ms_server', 'network', 'network_view', 'server_association_type', 'start_addr']
    _return_fields = ['comment', 'end_addr', 'network', 'network_view', 'start_addr']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 4

    @staticmethod
    def _build_exclude(members):
        if not members:
            return None
        return [Exclusionrange.from_dict(m) for m in members]

    @staticmethod
    def _build_fingerprint_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_logic_filter_rules(members):
        if not members:
            return None
        return [Logicfilterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_mac_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_ms_options(members):
        if not members:
            return None
        return [Msdhcpoption.from_dict(m) for m in members]

    @staticmethod
    def _build_nac_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_option_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    @staticmethod
    def _build_relay_agent_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    _custom_field_processing = {
        'exclude': _build_exclude.__func__,
        'fingerprint_filter_rules': _build_fingerprint_filter_rules.__func__,
        'logic_filter_rules': _build_logic_filter_rules.__func__,
        'mac_filter_rules': _build_mac_filter_rules.__func__,
        'ms_options': _build_ms_options.__func__,
        'nac_filter_rules': _build_nac_filter_rules.__func__,
        'option_filter_rules': _build_option_filter_rules.__func__,
        'options': _build_options.__func__,
        'relay_agent_filter_rules': _build_relay_agent_filter_rules.__func__,
    }


class IPRangeV6(InfobloxObject):
    _infoblox_type = 'ipv6range'
    _fields = ['address_type', 'cloud_info', 'comment', 'disable', 'discover_now_status', 'discovery_basic_poll_settings', 'discovery_blackout_setting', 'discovery_member', 'enable_discovery', 'enable_immediate_discovery', 'end_addr', 'endpoint_sources', 'exclude', 'extattrs', 'ipv6_end_prefix', 'ipv6_prefix_bits', 'ipv6_start_prefix', 'member', 'name', 'network', 'network_view', 'next_available_ip', 'port_control_blackout_setting', 'recycle_leases', 'restart_if_needed', 'same_port_control_discovery_blackout', 'server_association_type', 'start_addr', 'subscribe_settings', 'template', 'use_blackout_setting', 'use_discovery_basic_polling_settings', 'use_enable_discovery', 'use_recycle_leases', 'use_subscribe_settings']
    _search_for_update_fields = ['comment', 'end_addr', 'network', 'network_view', 'start_addr']
    _updateable_search_fields = ['address_type', 'comment', 'end_addr', 'ipv6_end_prefix', 'ipv6_prefix_bits', 'ipv6_start_prefix', 'member', 'name', 'network', 'network_view', 'server_association_type', 'start_addr']
    _all_searchable_fields = ['address_type', 'comment', 'end_addr', 'ipv6_end_prefix', 'ipv6_prefix_bits', 'ipv6_start_prefix', 'member', 'name', 'network', 'network_view', 'server_association_type', 'start_addr']
    _return_fields = ['comment', 'end_addr', 'network', 'network_view', 'start_addr']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 6

    @staticmethod
    def _build_exclude(members):
        if not members:
            return None
        return [Exclusionrange.from_dict(m) for m in members]

    _custom_field_processing = {
        'exclude': _build_exclude.__func__,
    }


class RangeTemplate(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return RangeTemplateV4

    @classmethod
    def get_v6_class(cls):
        return RangeTemplateV6


class RangeTemplateV4(InfobloxObject):
    _infoblox_type = 'rangetemplate'
    _fields = ['bootfile', 'bootserver', 'cloud_api_compatible', 'comment', 'ddns_domainname', 'ddns_generate_hostname', 'delegated_member', 'deny_all_clients', 'deny_bootp', 'email_list', 'enable_ddns', 'enable_dhcp_thresholds', 'enable_email_warnings', 'enable_pxe_lease_time', 'enable_snmp_warnings', 'exclude', 'extattrs', 'failover_association', 'fingerprint_filter_rules', 'high_water_mark', 'high_water_mark_reset', 'ignore_dhcp_option_list_request', 'known_clients', 'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset', 'mac_filter_rules', 'member', 'ms_options', 'ms_server', 'nac_filter_rules', 'name', 'nextserver', 'number_of_addresses', 'offset', 'option_filter_rules', 'options', 'pxe_lease_time', 'recycle_leases', 'relay_agent_filter_rules', 'server_association_type', 'unknown_clients', 'update_dns_on_lease_renewal', 'use_bootfile', 'use_bootserver', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_deny_bootp', 'use_email_list', 'use_enable_ddns', 'use_enable_dhcp_thresholds', 'use_ignore_dhcp_option_list_request', 'use_known_clients', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_ms_options', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_recycle_leases', 'use_unknown_clients', 'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'failover_association', 'member', 'ms_server', 'name', 'server_association_type']
    _all_searchable_fields = ['comment', 'failover_association', 'member', 'ms_server', 'name', 'server_association_type']
    _return_fields = ['comment', 'name', 'number_of_addresses', 'offset']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    @staticmethod
    def _build_exclude(members):
        if not members:
            return None
        return [Exclusionrangetemplate.from_dict(m) for m in members]

    @staticmethod
    def _build_fingerprint_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_logic_filter_rules(members):
        if not members:
            return None
        return [Logicfilterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_mac_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_ms_options(members):
        if not members:
            return None
        return [Msdhcpoption.from_dict(m) for m in members]

    @staticmethod
    def _build_nac_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_option_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    @staticmethod
    def _build_relay_agent_filter_rules(members):
        if not members:
            return None
        return [Filterrule.from_dict(m) for m in members]

    _custom_field_processing = {
        'exclude': _build_exclude.__func__,
        'fingerprint_filter_rules': _build_fingerprint_filter_rules.__func__,
        'logic_filter_rules': _build_logic_filter_rules.__func__,
        'mac_filter_rules': _build_mac_filter_rules.__func__,
        'ms_options': _build_ms_options.__func__,
        'nac_filter_rules': _build_nac_filter_rules.__func__,
        'option_filter_rules': _build_option_filter_rules.__func__,
        'options': _build_options.__func__,
        'relay_agent_filter_rules': _build_relay_agent_filter_rules.__func__,
    }


class RangeTemplateV6(InfobloxObject):
    _infoblox_type = 'ipv6rangetemplate'
    _fields = ['cloud_api_compatible', 'comment', 'delegated_member', 'exclude', 'member', 'name', 'number_of_addresses', 'offset', 'recycle_leases', 'server_association_type', 'use_recycle_leases']
    _search_for_update_fields = ['comment', 'name']
    _updateable_search_fields = ['comment', 'member', 'name', 'server_association_type']
    _all_searchable_fields = ['comment', 'member', 'name', 'server_association_type']
    _return_fields = ['comment', 'name', 'number_of_addresses', 'offset']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    @staticmethod
    def _build_exclude(members):
        if not members:
            return None
        return [Exclusionrangetemplate.from_dict(m) for m in members]

    _custom_field_processing = {
        'exclude': _build_exclude.__func__,
    }


class SharedNetwork(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return SharedNetworkV4

    @classmethod
    def get_v6_class(cls):
        return SharedNetworkV6


class SharedNetworkV4(InfobloxObject):
    _infoblox_type = 'sharednetwork'
    _fields = ['authority', 'bootfile', 'bootserver', 'comment', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81', 'deny_bootp', 'dhcp_utilization', 'dhcp_utilization_status', 'disable', 'dynamic_hosts', 'enable_ddns', 'enable_pxe_lease_time', 'extattrs', 'ignore_client_identifier', 'ignore_dhcp_option_list_request', 'ignore_id', 'ignore_mac_addresses', 'lease_scavenge_time', 'logic_filter_rules', 'ms_ad_user_data', 'name', 'network_view', 'networks', 'nextserver', 'options', 'pxe_lease_time', 'static_hosts', 'total_hosts', 'update_dns_on_lease_renewal', 'use_authority', 'use_bootfile', 'use_bootserver', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_update_fixed_addresses', 'use_ddns_use_option81', 'use_deny_bootp', 'use_enable_ddns', 'use_ignore_client_identifier', 'use_ignore_dhcp_option_list_request', 'use_ignore_id', 'use_lease_scavenge_time', 'use_logic_filter_rules', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['comment', 'name', 'network_view']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name', 'network_view']
    _return_fields = ['comment', 'name', 'network_view', 'networks']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    @staticmethod
    def _build_logic_filter_rules(members):
        if not members:
            return None
        return [Logicfilterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    _custom_field_processing = {
        'logic_filter_rules': _build_logic_filter_rules.__func__,
        'options': _build_options.__func__,
    }


class SharedNetworkV6(InfobloxObject):
    _infoblox_type = 'ipv6sharednetwork'
    _fields = ['comment', 'ddns_domainname', 'ddns_generate_hostname', 'ddns_server_always_updates', 'ddns_ttl', 'ddns_use_option81', 'disable', 'domain_name', 'domain_name_servers', 'enable_ddns', 'extattrs', 'name', 'network_view', 'networks', 'options', 'preferred_lifetime', 'update_dns_on_lease_renewal', 'use_ddns_domainname', 'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_ddns_use_option81', 'use_domain_name', 'use_domain_name_servers', 'use_enable_ddns', 'use_options', 'use_preferred_lifetime', 'use_update_dns_on_lease_renewal', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['comment', 'name', 'network_view']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name', 'network_view']
    _return_fields = ['comment', 'name', 'network_view', 'networks']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    _custom_field_processing = {
        'options': _build_options.__func__,
    }


class Member(InfobloxObject):
    _infoblox_type = 'member'
    _fields = ['active_position', 'additional_ip_list', 'automated_traffic_capture_setting', 'bgp_as', 'capture_traffic_control', 'capture_traffic_status', 'comment', 'config_addr_type', 'create_token', 'csp_member_setting', 'dns_resolver_setting', 'dscp', 'email_setting', 'enable_ha', 'enable_lom', 'enable_member_redirect', 'enable_ro_api_access', 'extattrs', 'external_syslog_backup_servers', 'external_syslog_server_enable', 'host_name', 'ipv6_setting', 'ipv6_static_routes', 'is_dscp_capable', 'lan2_enabled', 'lan2_port_setting', 'lcd_input', 'lom_network_config', 'lom_users', 'master_candidate', 'member_admin_operation', 'member_service_communication', 'mgmt_port_setting', 'mmdb_ea_build_time', 'mmdb_geoip_build_time', 'nat_setting', 'node_info', 'ntp_setting', 'ospf_list', 'passive_ha_arp_enabled', 'platform', 'pre_provisioning', 'preserve_if_owns_delegation', 'read_token', 'remote_console_access_enable', 'requestrestartservicestatus', 'restartservices', 'router_id', 'service_status', 'service_type_configuration', 'snmp_setting', 'static_routes', 'support_access_enable', 'support_access_info', 'syslog_proxy_setting', 'syslog_servers', 'syslog_size', 'threshold_traps', 'time_zone', 'traffic_capture_auth_dns_setting', 'traffic_capture_chr_setting', 'traffic_capture_qps_setting', 'traffic_capture_rec_dns_setting', 'traffic_capture_rec_queries_setting', 'trap_notifications', 'upgrade_group', 'use_automated_traffic_capture', 'use_dns_resolver_setting', 'use_dscp', 'use_email_setting', 'use_enable_lom', 'use_enable_member_redirect', 'use_external_syslog_backup_servers', 'use_lcd_input', 'use_remote_console_access_enable', 'use_snmp_setting', 'use_support_access_enable', 'use_syslog_proxy_setting', 'use_threshold_traps', 'use_time_zone', 'use_traffic_capture_auth_dns', 'use_traffic_capture_chr', 'use_traffic_capture_qps', 'use_traffic_capture_rec_dns', 'use_traffic_capture_rec_queries', 'use_trap_notifications', 'use_v4_vrrp', 'vip_setting', 'vpn_mtu']
    _search_for_update_fields = ['config_addr_type', 'host_name', 'platform', 'service_type_configuration']
    _updateable_search_fields = ['comment', 'config_addr_type', 'enable_ha', 'enable_ro_api_access', 'host_name', 'master_candidate', 'platform', 'preserve_if_owns_delegation', 'router_id', 'service_type_configuration']
    _all_searchable_fields = ['comment', 'config_addr_type', 'enable_ha', 'enable_ro_api_access', 'host_name', 'master_candidate', 'platform', 'preserve_if_owns_delegation', 'router_id', 'service_type_configuration']
    _return_fields = ['config_addr_type', 'host_name', 'platform', 'service_type_configuration']
    _remap = {'name': 'host_name'}
    _shadow_fields = ['_ref', 'name']

    @staticmethod
    def _build_additional_ip_list(members):
        if not members:
            return None
        return [Interface.from_dict(m) for m in members]

    @staticmethod
    def _build_bgp_as(members):
        if not members:
            return None
        return [Bgpas.from_dict(m) for m in members]

    @staticmethod
    def _build_external_syslog_backup_servers(members):
        if not members:
            return None
        return [Extsyslogbackupserver.from_dict(m) for m in members]

    @staticmethod
    def _build_ipv6_static_routes(members):
        if not members:
            return None
        return [Ipv6Networksetting.from_dict(m) for m in members]

    @staticmethod
    def _build_lom_network_config(members):
        if not members:
            return None
        return [Lomnetworkconfig.from_dict(m) for m in members]

    @staticmethod
    def _build_lom_users(members):
        if not members:
            return None
        return [Lomuser.from_dict(m) for m in members]

    @staticmethod
    def _build_member_service_communication(members):
        if not members:
            return None
        return [Memberservicecommunication.from_dict(m) for m in members]

    @staticmethod
    def _build_node_info(members):
        if not members:
            return None
        return [Nodeinfo.from_dict(m) for m in members]

    @staticmethod
    def _build_ospf_list(members):
        if not members:
            return None
        return [Ospf.from_dict(m) for m in members]

    @staticmethod
    def _build_service_status(members):
        if not members:
            return None
        return [Memberservicestatus.from_dict(m) for m in members]

    @staticmethod
    def _build_static_routes(members):
        if not members:
            return None
        return [SettingNetwork.from_dict(m) for m in members]

    @staticmethod
    def _build_syslog_servers(members):
        if not members:
            return None
        return [Syslogserver.from_dict(m) for m in members]

    @staticmethod
    def _build_threshold_traps(members):
        if not members:
            return None
        return [Thresholdtrap.from_dict(m) for m in members]

    @staticmethod
    def _build_trap_notifications(members):
        if not members:
            return None
        return [Trapnotification.from_dict(m) for m in members]

    _custom_field_processing = {
        'additional_ip_list': _build_additional_ip_list.__func__,
        'bgp_as': _build_bgp_as.__func__,
        'external_syslog_backup_servers': _build_external_syslog_backup_servers.__func__,
        'ipv6_static_routes': _build_ipv6_static_routes.__func__,
        'lom_network_config': _build_lom_network_config.__func__,
        'lom_users': _build_lom_users.__func__,
        'member_service_communication': _build_member_service_communication.__func__,
        'node_info': _build_node_info.__func__,
        'ospf_list': _build_ospf_list.__func__,
        'service_status': _build_service_status.__func__,
        'static_routes': _build_static_routes.__func__,
        'syslog_servers': _build_syslog_servers.__func__,
        'threshold_traps': _build_threshold_traps.__func__,
        'trap_notifications': _build_trap_notifications.__func__,
    }


class Csvimporttask(InfobloxObject):
    _infoblox_type = 'csvimporttask'
    _fields = ['action', 'admin_name', 'end_time', 'file_name', 'file_size', 'import_id', 'lines_failed', 'lines_processed', 'lines_warning', 'on_error', 'operation', 'separator', 'start_time', 'status', 'stop', 'update_method']
    _search_for_update_fields = ['import_id']
    _updateable_search_fields = []
    _all_searchable_fields = ['import_id']
    _return_fields = ['action', 'admin_name', 'end_time', 'file_name', 'file_size', 'import_id', 'lines_failed', 'lines_processed', 'lines_warning', 'on_error', 'operation', 'separator', 'start_time', 'status', 'update_method']
    _remap = {}
    _shadow_fields = ['_ref']


class NetworkView(InfobloxObject):
    _infoblox_type = 'networkview'
    _fields = ['associated_dns_views', 'associated_members', 'cloud_info', 'comment', 'ddns_dns_view', 'ddns_zone_primaries', 'extattrs', 'internal_forward_zones', 'is_default', 'mgm_private', 'ms_ad_user_data', 'name', 'remote_forward_zones', 'remote_reverse_zones']
    _search_for_update_fields = ['comment', 'is_default', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'is_default', 'name']
    _return_fields = ['comment', 'is_default', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    @staticmethod
    def _build_associated_members(members):
        if not members:
            return None
        return [NetworkviewAssocmember.from_dict(m) for m in members]

    @staticmethod
    def _build_ddns_zone_primaries(members):
        if not members:
            return None
        return [Dhcpddns.from_dict(m) for m in members]

    @staticmethod
    def _build_remote_forward_zones(members):
        if not members:
            return None
        return [Remoteddnszone.from_dict(m) for m in members]

    @staticmethod
    def _build_remote_reverse_zones(members):
        if not members:
            return None
        return [Remoteddnszone.from_dict(m) for m in members]

    _custom_field_processing = {
        'associated_members': _build_associated_members.__func__,
        'ddns_zone_primaries': _build_ddns_zone_primaries.__func__,
        'remote_forward_zones': _build_remote_forward_zones.__func__,
        'remote_reverse_zones': _build_remote_reverse_zones.__func__,
    }


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
    _fields = ['association_type', 'comment', 'extattrs', 'failover_port', 'load_balance_split', 'max_client_lead_time', 'max_load_balance_delay', 'max_response_delay', 'max_unacked_updates', 'ms_association_mode', 'ms_enable_authentication', 'ms_enable_switchover_interval', 'ms_failover_mode', 'ms_failover_partner', 'ms_hotstandby_partner_role', 'ms_is_conflict', 'ms_previous_state', 'ms_server', 'ms_shared_secret', 'ms_state', 'ms_switchover_interval', 'name', 'primary', 'primary_server_type', 'primary_state', 'recycle_leases', 'secondary', 'secondary_server_type', 'secondary_state', 'set_dhcp_failover_partner_down', 'set_dhcp_failover_secondary_recovery', 'use_failover_port', 'use_ms_switchover_interval', 'use_recycle_leases']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']


class Discovery(InfobloxObject):
    _infoblox_type = 'discovery'
    _fields = ['clear_network_port_assignment', 'control_switch_port', 'discovery_data_conversion', 'get_device_support_info', 'get_job_devices', 'get_job_process_details', 'import_device_support_bundle', 'modify_sdn_assignment', 'modify_vrf_assignment', 'provision_network_dhcp_relay', 'provision_network_port']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryDevice(InfobloxObject):
    _infoblox_type = 'discovery:device'
    _fields = ['address', 'address_ref', 'available_mgmt_ips', 'cap_admin_status_ind', 'cap_admin_status_na_reason', 'cap_description_ind', 'cap_description_na_reason', 'cap_net_deprovisioning_ind', 'cap_net_deprovisioning_na_reason', 'cap_net_provisioning_ind', 'cap_net_provisioning_na_reason', 'cap_net_vlan_provisioning_ind', 'cap_net_vlan_provisioning_na_reason', 'cap_vlan_assignment_ind', 'cap_vlan_assignment_na_reason', 'cap_voice_vlan_ind', 'cap_voice_vlan_na_reason', 'chassis_serial_number', 'description', 'extattrs', 'interfaces', 'location', 'model', 'ms_ad_user_data', 'name', 'neighbors', 'network', 'network_infos', 'network_view', 'networks', 'os_version', 'port_stats', 'type', 'user_defined_mgmt_ip', 'vendor', 'vlan_infos']
    _search_for_update_fields = ['address', 'name', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'chassis_serial_number', 'location', 'model', 'name', 'network_view', 'os_version', 'type', 'vendor']
    _return_fields = ['address', 'name', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']

    @staticmethod
    def _build_network_infos(members):
        if not members:
            return None
        return [DiscoveryNetworkinfo.from_dict(m) for m in members]

    @staticmethod
    def _build_vlan_infos(members):
        if not members:
            return None
        return [DiscoveryVlaninfo.from_dict(m) for m in members]

    _custom_field_processing = {
        'network_infos': _build_network_infos.__func__,
        'vlan_infos': _build_vlan_infos.__func__,
    }


class ARecordBase(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return ARecord

    @classmethod
    def get_v6_class(cls):
        return AAAARecord


class ARecord(InfobloxObject):
    _infoblox_type = 'record:a'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'discovered_data', 'dns_name', 'extattrs', 'forbid_reclamation', 'ipv4addr', 'last_queried', 'ms_ad_user_data', 'name', 'reclaimable', 'remove_associated_ptr', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv4addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'ipv4addr', 'name']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'ipv4addr', 'name', 'reclaimable', 'view', 'zone']
    _return_fields = ['ipv4addr', 'name', 'view']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 4


class AAAARecord(InfobloxObject):
    _infoblox_type = 'record:aaaa'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'discovered_data', 'dns_name', 'extattrs', 'forbid_reclamation', 'ipv6addr', 'last_queried', 'ms_ad_user_data', 'name', 'reclaimable', 'remove_associated_ptr', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv6addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'ipv6addr', 'name']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'ipv6addr', 'name', 'reclaimable', 'view', 'zone']
    _return_fields = ['ipv6addr', 'name', 'view']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 6


class EADefinition(InfobloxObject):
    _infoblox_type = 'extensibleattributedef'
    _fields = ['allowed_object_types', 'comment', 'default_value', 'descendants_action', 'flags', 'list_values', 'max', 'min', 'name', 'namespace', 'type']
    _search_for_update_fields = ['comment', 'name', 'type']
    _updateable_search_fields = ['comment', 'name', 'type']
    _all_searchable_fields = ['comment', 'name', 'namespace', 'type']
    _return_fields = ['comment', 'default_value', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']

    @staticmethod
    def _build_list_values(members):
        if not members:
            return None
        return [ExtensibleattributedefListvalues.from_dict(m) for m in members]

    _custom_field_processing = {
        'list_values': _build_list_values.__func__,
    }


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
    _fields = ['ipv6addrs', 'view', 'extattrs', 'name', 'zone',
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


class FixedAddress(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return FixedAddressV4

    @classmethod
    def get_v6_class(cls):
        return FixedAddressV6


class FixedAddressV4(InfobloxObject):
    _infoblox_type = 'fixedaddress'
    _fields = ['agent_circuit_id', 'agent_remote_id', 'allow_telnet', 'always_update_dns', 'bootfile', 'bootserver', 'cli_credentials', 'client_identifier_prepend_zero', 'cloud_info', 'comment', 'ddns_domainname', 'ddns_hostname', 'deny_bootp', 'device_description', 'device_location', 'device_type', 'device_vendor', 'dhcp_client_identifier', 'disable', 'disable_discovery', 'discover_now_status', 'discovered_data', 'enable_ddns', 'enable_immediate_discovery', 'enable_pxe_lease_time', 'extattrs', 'ignore_dhcp_option_list_request', 'ipv4addr', 'is_invalid_mac', 'logic_filter_rules', 'mac', 'match_client', 'ms_ad_user_data', 'ms_options', 'ms_server', 'name', 'network', 'network_view', 'nextserver', 'options', 'pxe_lease_time', 'reserved_interface', 'restart_if_needed', 'snmp3_credential', 'snmp_credential', 'template', 'use_bootfile', 'use_bootserver', 'use_cli_credentials', 'use_ddns_domainname', 'use_deny_bootp', 'use_enable_ddns', 'use_ignore_dhcp_option_list_request', 'use_logic_filter_rules', 'use_ms_options', 'use_nextserver', 'use_options', 'use_pxe_lease_time', 'use_snmp3_credential', 'use_snmp_credential']
    _search_for_update_fields = ['ipv4addr', 'network_view']
    _updateable_search_fields = ['comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'ipv4addr', 'mac', 'match_client', 'ms_server', 'network', 'network_view']
    _all_searchable_fields = ['comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'ipv4addr', 'mac', 'match_client', 'ms_server', 'network', 'network_view']
    _return_fields = ['ipv4addr', 'network_view']
    _remap = {'ipv4addr': 'ip'}
    _shadow_fields = ['_ref', 'ipv4addr']
    _ip_version = 4

    @staticmethod
    def _build_cli_credentials(members):
        if not members:
            return None
        return [DiscoveryClicredential.from_dict(m) for m in members]

    @staticmethod
    def _build_logic_filter_rules(members):
        if not members:
            return None
        return [Logicfilterrule.from_dict(m) for m in members]

    @staticmethod
    def _build_ms_options(members):
        if not members:
            return None
        return [Msdhcpoption.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    _custom_field_processing = {
        'cli_credentials': _build_cli_credentials.__func__,
        'logic_filter_rules': _build_logic_filter_rules.__func__,
        'ms_options': _build_ms_options.__func__,
        'options': _build_options.__func__,
    }


class FixedAddressV6(InfobloxObject):
    _infoblox_type = 'ipv6fixedaddress'
    _fields = ['address_type', 'allow_telnet', 'cli_credentials', 'cloud_info', 'comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'disable', 'disable_discovery', 'discover_now_status', 'discovered_data', 'domain_name', 'domain_name_servers', 'duid', 'enable_immediate_discovery', 'extattrs', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'ms_ad_user_data', 'name', 'network', 'network_view', 'options', 'preferred_lifetime', 'reserved_interface', 'restart_if_needed', 'snmp3_credential', 'snmp_credential', 'template', 'use_cli_credentials', 'use_domain_name', 'use_domain_name_servers', 'use_options', 'use_preferred_lifetime', 'use_snmp3_credential', 'use_snmp_credential', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['duid', 'ipv6addr', 'network_view']
    _updateable_search_fields = ['address_type', 'comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'duid', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'network', 'network_view']
    _all_searchable_fields = ['address_type', 'comment', 'device_description', 'device_location', 'device_type', 'device_vendor', 'duid', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits', 'network', 'network_view']
    _return_fields = ['duid', 'ipv6addr', 'network_view']
    _remap = {'ipv6addr': 'ip'}
    _shadow_fields = ['_ref', 'ipv6addr']
    _ip_version = 6

    @staticmethod
    def _build_cli_credentials(members):
        if not members:
            return None
        return [DiscoveryClicredential.from_dict(m) for m in members]

    @staticmethod
    def _build_options(members):
        if not members:
            return None
        return [Dhcpoption.from_dict(m) for m in members]

    _custom_field_processing = {
        'cli_credentials': _build_cli_credentials.__func__,
        'options': _build_options.__func__,
    }


class CNAMERecord(InfobloxObject):
    _infoblox_type = 'record:cname'
    _fields = ['aws_rte53_record_info', 'canonical', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_canonical', 'dns_name', 'extattrs', 'forbid_reclamation', 'last_queried', 'name', 'reclaimable', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'creator', 'ddns_principal', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'creator', 'ddns_principal', 'name', 'reclaimable', 'view', 'zone']
    _return_fields = ['canonical', 'name', 'view']
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


class MXRecord(InfobloxObject):
    _infoblox_type = 'record:mx'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creation_time', 'creator', 'ddns_principal', 'ddns_protected', 'disable', 'dns_mail_exchanger', 'dns_name', 'extattrs', 'forbid_reclamation', 'last_queried', 'mail_exchanger', 'name', 'preference', 'reclaimable', 'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['mail_exchanger', 'name', 'preference', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal', 'mail_exchanger', 'name', 'preference', 'view']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'mail_exchanger', 'name', 'preference', 'reclaimable', 'view', 'zone']
    _return_fields = ['mail_exchanger', 'name', 'preference', 'view']
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


class GridServicerestartStatus(InfobloxObject):
    _infoblox_type = 'grid:servicerestart:status'
    _fields = ['failures', 'finished', 'grouped', 'needed_restart', 'no_restart', 'parent', 'pending', 'pending_restart', 'processing', 'restarting', 'success', 'timeouts']
    _search_for_update_fields = ['parent']
    _updateable_search_fields = []
    _all_searchable_fields = ['parent']
    _return_fields = ['failures', 'finished', 'grouped', 'needed_restart', 'no_restart', 'parent', 'pending', 'pending_restart', 'processing', 'restarting', 'success', 'timeouts']
    _remap = {}
    _shadow_fields = ['_ref']


class PtrRecord(InfobloxObject):
    _infoblox_type = 'record:ptr'

    @classmethod
    def get_v4_class(cls):
        return PtrRecordV4

    @classmethod
    def get_v6_class(cls):
        return PtrRecordV6


class PtrRecordV4(PtrRecord):
    _fields = ['view', 'ipv4addr', 'ptrdname', 'extattrs', 'ttl']
    _search_for_update_fields = ['view', 'ipv4addr']
    _all_searchable_fields = _search_for_update_fields + ['ptrdname']
    _shadow_fields = ['_ref']
    _remap = {'ip': 'ipv4addr'}
    _ip_version = 4


class PtrRecordV6(PtrRecord):
    _fields = ['view', 'ipv6addr', 'ptrdname', 'extattrs', 'ttl']
    _search_for_update_fields = ['view', 'ipv6addr']
    _all_searchable_fields = _search_for_update_fields + ['ptrdname']
    _shadow_fields = ['_ref']
    _remap = {'ip': 'ipv6addr'}
    _ip_version = 6

