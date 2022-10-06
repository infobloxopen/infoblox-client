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
      - accept fields from '_fields' and '_shadow_fields' as a parameter on
        init
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
        """Returns dict with EAs in ``{ea_name: ea_value}`` format."""
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

    Attributes:
        _fields: fields that represents NIOS object (WAPI fields) and are sent
            to NIOS on object creation
        _search_for_update_fields: field/fields used to find an object during
            an update operation. this should be the smallest number of fields
            that uniquely identify an object
        _all_searchable_fields: all fields that can be used to find object on
            NIOS side
        _updateable_search_fields: fields that can be used to find object on
            NIOS side, but also can be changed, so has to be sent on update.
        _shadow_fields: fields that object usually has but they should not
            be sent to NIOS. These fields can be received from
            NIOS. Examples: [_ref, is_default]
        _return_fields: fields requested to be returned from NIOS side
            if object is found/created
        _infoblox_type: string representing wapi type of described object
        _remap: dict that maps user faced names into internal representation
            (_fields)
        _custom_field_processing: dict that define rules (lambda) for building
            objects from data returned by NIOS side. Expected to be redefined
            in child class as needed, _custom_field_processing has priority
            over _global_field_processing, so can redefine for child class
            global rules defined in _global_field_processing.
        _global_field_processing: almost the same as _custom_field_processing,
            but defines rules for building field on global level. Fields
            defined in this dict will be processed in the same way in all
            child classes. Is not expected to be redefined in child classes.
        _ip_version: ip version of the object, used to mark version specific
            classes. Value other than None indicates that no versioned class
            lookup needed.
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
        ipv_class = cls.get_class_from_args(ip_dict)
        mapping = ipv_class._global_field_processing.copy()
        mapping.update(ipv_class._custom_field_processing)
        # Process fields that require building themselves as objects
        for field in mapping:
            if field in ip_dict:
                ip_dict[field] = mapping[field](ip_dict[field])
        return ipv_class(connector, **ip_dict)

    @staticmethod
    def value_to_dict(value):
        return value.to_dict() if hasattr(value, 'to_dict') else value

    def field_to_dict(self, field):
        """Read field value and converts to dict if possible"""
        value = getattr(self, field)
        if isinstance(value, (list, tuple)):
            return [self.value_to_dict(val) for val in value]
        return self.value_to_dict(value)

    def to_dict(self, search_fields=None, update_fields=None):
        """Builds dict without None object fields"""
        fields = self._fields
        if search_fields == 'update':
            fields = self._search_for_update_fields
        elif search_fields == 'all':
            fields = self._all_searchable_fields
        elif search_fields == 'search':
            fields = self._fields
        elif search_fields == 'exclude':
            # exclude search fields for update actions,
            # but include updateable_search_fields
            fields = [field for field in self._fields
                      if field in self._updateable_search_fields or
                      field not in self._search_for_update_fields]

        elif search_fields == 'extra':
            fields = [field for field in self._fields
                      if field not in update_fields]

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
        response = None

        if check_if_exists:
            if local_obj.fetch(only_ref=True):
                LOG.info(("Infoblox %(obj_type)s already exists: "
                          "%(ib_obj)s"),
                         {'obj_type': local_obj.infoblox_type,
                          'ib_obj': local_obj})
                local_obj.response = "Infoblox Object already Exists"
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
            response = "Infoblox Object was Created"
        elif update_if_exists:
            update_fields = local_obj.to_dict(search_fields='exclude')
            reply = connector.update_object(local_obj.ref,
                                            update_fields,
                                            local_obj.return_fields)
            LOG.info('Infoblox object was updated: %s', local_obj.ref)
            response = "Infoblox Object was Updated"

        obj_result = cls._object_from_reply(local_obj, connector, reply)

        # Add response string if object is not None
        # and properly deserialized
        if issubclass(type(obj_result), BaseObject):
            obj_result.response = response

        return obj_result, obj_created

    @classmethod
    def create(cls, connector, check_if_exists=True,
               update_if_exists=False, **kwargs):
        """Create the object in NIOS.

        Args:
            check_if_exists: If True, create method will attempt
                to fetch the object to check if it exists.
            update_if_exists: If True, create method will attempt
                to update the object if one exists.

        Raises:
            InfobloxFetchGotMultipleObjects: Raised only when check_if_exists
                is True. The fetch method can raise this error when API return
                multiple objects.

        Returns: Created Infoblox object.
        """
        ib_object, _ = (
            cls.create_check_exists(connector,
                                    check_if_exists=check_if_exists,
                                    update_if_exists=update_if_exists,
                                    **kwargs))
        return ib_object

    @classmethod
    def _search(cls, connector, return_fields=None,
                search_extattrs=None, force_proxy=False,
                max_results=None, paging=False, **kwargs):
        ib_obj_for_search = cls(connector, **kwargs)
        search_dict = ib_obj_for_search.to_dict(search_fields='all')
        if return_fields is None and ib_obj_for_search.return_fields:
            return_fields = ib_obj_for_search.return_fields
        # allow search_extattrs to be instance of EA class
        # or dict in NIOS format
        extattrs = search_extattrs
        if hasattr(search_extattrs, 'to_dict'):
            extattrs = search_extattrs.to_dict()
        search_fields = ib_obj_for_search.to_dict(search_fields='search')
        for key in search_fields:
            if key not in search_dict:
                raise ib_ex.InfobloxFieldNotSearchable(
                    field=key)
        reply = connector.get_object(ib_obj_for_search.infoblox_type,
                                     search_dict,
                                     return_fields=return_fields,
                                     extattrs=extattrs,
                                     force_proxy=force_proxy,
                                     paging=paging, max_results=max_results)
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

        Returns:
            True if object successfully fetched. False otherwise.
        Raises:
            InfobloxFetchGotMultipleObjects:
                If fetch got multiple objects from the API and unable to
                deserialize API response to a single InfobloxObject.
        """
        if self.ref:
            reply = self.connector.get_object(
                self.ref, return_fields=self.return_fields, paging=False)
            if reply:
                self.update_from_dict(reply)
                return True

        search_dict = self.to_dict(search_fields='update')
        return_fields = [] if only_ref else self.return_fields
        reply = self.connector.get_object(self.infoblox_type,
                                          search_dict,
                                          return_fields=return_fields)
        if reply:
            if len(reply) > 1:
                LOG.debug("Fetch got multiple objects from the API. Reply: %s",
                          reply)
                raise ib_ex.InfobloxFetchGotMultipleObjects()
            self.update_from_dict(reply[0], only_ref=only_ref)
            return True
        return False

    def update(self):
        update_fields = self.to_dict(search_fields='exclude')
        fields = self.to_dict(search_fields='extra',
                              update_fields=update_fields)
        for key in fields:
            LOG.info(
                "Field is not allowed for update: %s - ignoring",
                key,
            )
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
    _fields = ['ipv4addr', 'configure_for_dhcp',
               'use_for_ea_inheritance', 'mac']
    _remap = {'ipv4addr': 'ip'}
    ip_version = 4


class IPv6(IP):
    _fields = ['ipv6addr', 'configure_for_dhcp',
               'use_for_ea_inheritance', 'duid']
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


WAPI_VERSION = "2.12.1"


#   AUTOGENERATED CODE BELOW   #


class AdAuthServer(SubObjects):
    _fields = ['auth_port', 'comment', 'disabled', 'encryption', 'fqdn_or_ip',
               'mgmt_port', 'use_mgmt_port']


class Addressac(SubObjects):
    _fields = ['address', 'permission', 'tsig_key', 'tsig_key_alg',
               'tsig_key_name', 'use_tsig_key_name']


class Awsrte53Task(SubObjects):
    _fields = ['aws_user', 'credentials_type', 'disabled', 'filter',
               'last_run', 'name', 'schedule_interval', 'schedule_units',
               'state', 'state_msg', 'status_timestamp', 'sync_private_zones',
               'sync_public_zones', 'zone_count']


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
    _fields = ['dns_ext_primary', 'dns_ext_zone', 'dns_grid_primary',
               'dns_grid_zone', 'zone_match']


class Dhcpmember(SubObjects):
    _fields = ['ipv4addr', 'ipv6addr', 'name', '_struct']


class DhcpOption(SubObjects):
    _fields = ['name', 'num', 'use_option', 'value', 'vendor_class']


class DiscoveryAutoconversionsetting(SubObjects):
    _fields = ['comment', 'condition', 'format', 'network_view', 'type']


class DiscoveryClicredential(SubObjects):
    _fields = ['comment', 'credential_group', 'credential_type', 'id',
               'password', 'user']


class DiscoveryIfaddrinfo(SubObjects):
    _fields = ['address', 'address_object', 'network']


class DiscoveryNetworkinfo(SubObjects):
    _fields = ['network', 'network_str']


class DiscoveryPort(SubObjects):
    _fields = ['comment', 'port', 'type']


class DiscoveryScaninterface(SubObjects):
    _fields = ['network_view', 'scan_virtual_ip', 'type']


class DiscoverySdnconfig(SubObjects):
    _fields = ['addresses', 'api_key', 'comment', 'handle',
               'network_interface_type', 'network_interface_virtual_ip',
               'network_view', 'on_prem', 'password', 'protocol', 'sdn_type',
               'use_global_proxy', 'username', 'uuid']


class DiscoverySeedrouter(SubObjects):
    _fields = ['address', 'comment', 'network_view']


class DiscoverySnmp3Credential(SubObjects):
    _fields = ['authentication_password', 'authentication_protocol', 'comment',
               'credential_group', 'privacy_password', 'privacy_protocol',
               'user']


class DiscoverySnmpcredential(SubObjects):
    _fields = ['comment', 'community_string', 'credential_group']


class DiscoveryVlaninfo(SubObjects):
    _fields = ['id', 'name']


class DiscoveryVrfmappingrule(SubObjects):
    _fields = ['comment', 'criteria', 'network_view']


class Discoverytaskport(SubObjects):
    _fields = ['comment', 'number']


class Discoverytaskvserver(SubObjects):
    _fields = ['connection_protocol', 'disable', 'fqdn_or_ip', 'password',
               'port', 'username']


class Dnsseckey(SubObjects):
    _fields = ['algorithm', 'next_event_date', 'public_key', 'status', 'tag',
               'type']


class Dnssectrustedkey(SubObjects):
    _fields = ['algorithm', 'dnssec_must_be_secure', 'fqdn', 'key',
               'secure_entry_point']


class DtcMonitorSnmpOid(SubObjects):
    _fields = ['comment', 'condition', 'first', 'last', 'oid', 'type']


class DtcPoolConsolidatedMonitorHealth(SubObjects):
    _fields = ['availability', 'full_health_communication', 'members',
               'monitor']


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
    _fields = ['address', 'name', 'shared_with_ms_parent_delegation',
               'stealth', 'tsig_key', 'tsig_key_alg', 'tsig_key_name',
               'use_tsig_key_name']


class Extsyslogbackupserver(SubObjects):
    _fields = ['address', 'directory_path', 'enable', 'password', 'port',
               'protocol', 'username']


class Filterrule(SubObjects):
    _fields = ['filter', 'permission']


class Forwardingmemberserver(SubObjects):
    _fields = ['forward_to', 'forwarders_only', 'name',
               'use_override_forwarders']


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
    _fields = ['disable', 'is_fips_compliant', 'name', 'partition_capacity',
               'partition_id', 'partition_serial_number', 'server_cert',
               'status']


class HsmThales(SubObjects):
    _fields = ['disable', 'keyhash', 'remote_esn', 'remote_ip', 'remote_port',
               'status']


class Interface(SubObjects):
    _fields = ['anycast', 'comment', 'enable_bgp', 'enable_ospf', 'interface',
               'ipv4_network_setting', 'ipv6_network_setting']


class Ipv6Networksetting(SubObjects):
    _fields = ['address', 'cidr', 'gateway']


class LdapEamapping(SubObjects):
    _fields = ['mapped_ea', 'name']


class LdapServer(SubObjects):
    _fields = ['address', 'authentication_type', 'base_dn', 'bind_password',
               'bind_user_dn', 'comment', 'disable', 'encryption', 'port',
               'use_mgmt_port', 'version']


class Logicfilterrule(SubObjects):
    _fields = ['filter', 'type']


class Lomnetworkconfig(SubObjects):
    _fields = ['address', 'gateway', 'is_lom_capable', 'subnet_mask']


class Lomuser(SubObjects):
    _fields = ['comment', 'disable', 'name', 'password', 'role']


class MemberDnsgluerecordaddr(SubObjects):
    _fields = ['attach_empty_recursive_view', 'glue_address_choice',
               'glue_record_address', 'view']


class MemberDnsip(SubObjects):
    _fields = ['ip_address']


class Memberserver(SubObjects):
    _fields = ['enable_preferred_primaries', 'grid_replicate', 'lead', 'name',
               'preferred_primaries', 'stealth']


class Memberservicecommunication(SubObjects):
    _fields = ['option', 'service', 'type']


class Memberservicestatus(SubObjects):
    _fields = ['description', 'service', 'status']


class Msdhcpoption(SubObjects):
    _fields = ['name', 'num', 'type', 'user_class', 'value', 'vendor_class']


class Msdhcpserver(SubObjects):
    _fields = ['ipv4addr', 'ipv4addr', 'ipv6addr', 'name']


class Msdnsserver(SubObjects):
    _fields = ['address', 'is_master', 'ns_ip', 'ns_name',
               'shared_with_ms_parent_delegation', 'stealth']


class MsserverDcnsrecordcreation(SubObjects):
    _fields = ['address', 'comment']


class NetworkviewAssocmember(SubObjects):
    _fields = ['failovers', 'member']


class Nodeinfo(SubObjects):
    _fields = ['ha_status', 'hwid', 'hwmodel', 'hwplatform', 'hwtype',
               'lan2_physical_setting', 'lan_ha_port_setting',
               'mgmt_network_setting', 'mgmt_physical_setting',
               'nat_external_ip', 'paid_nios', 'physical_oid',
               'service_status', 'v6_mgmt_network_setting']


class NotificationRestTemplateparameter(SubObjects):
    _fields = ['default_value', 'name', 'syntax', 'value']


class NotificationRuleexpressionop(SubObjects):
    _fields = ['op', 'op1', 'op1_type', 'op2', 'op2_type']


class Nxdomainrule(SubObjects):
    _fields = ['action', 'pattern']


class OcspResponder(SubObjects):
    _fields = ['certificate', 'certificate_token', 'comment', 'disabled',
               'fqdn_or_ip', 'port']


class Option60Matchrule(SubObjects):
    _fields = ['is_substring', 'match_value', 'option_space',
               'substring_length', 'substring_offset']


class Ospf(SubObjects):
    _fields = ['advertise_interface_vlan', 'area_id', 'area_type',
               'authentication_key', 'authentication_type',
               'auto_calc_cost_enabled', 'bfd_template', 'comment', 'cost',
               'dead_interval', 'enable_bfd', 'hello_interval', 'interface',
               'is_ipv4', 'key_id', 'retransmit_interval', 'transmit_delay']


class OutboundCloudclientEvent(SubObjects):
    _fields = ['enabled', 'event_type']


class ParentalcontrolAbs(SubObjects):
    _fields = ['blocking_policy', 'ip_address']


class ParentalcontrolMsp(SubObjects):
    _fields = ['ip_address']


class ParentalcontrolNasgateway(SubObjects):
    _fields = ['comment', 'ip_address', 'message_rate', 'name', 'send_ack',
               'shared_secret']


class ParentalcontrolSitemember(SubObjects):
    _fields = ['name', 'type']


class ParentalcontrolSpm(SubObjects):
    _fields = ['ip_address']


class RadiusServer(SubObjects):
    _fields = ['acct_port', 'address', 'auth_port', 'auth_type', 'comment',
               'disable', 'shared_secret', 'use_accounting', 'use_mgmt_port']


class Rdatasubfield(SubObjects):
    _fields = ['field_type', 'field_value', 'include_length']


class Remoteddnszone(SubObjects):
    _fields = ['fqdn', 'gss_tsig_dns_principal', 'gss_tsig_domain', 'key_type',
               'server_address', 'tsig_key', 'tsig_key_alg', 'tsig_key_name']


class SettingNetwork(SubObjects):
    _fields = ['address', 'dscp', 'gateway', 'primary', 'subnet_mask',
               'use_dscp', 'vlan_id']


class SettingViewaddress(SubObjects):
    _fields = ['dns_notify_transfer_source',
               'dns_notify_transfer_source_address',
               'dns_query_source_address', 'dns_query_source_interface',
               'enable_notify_source_port', 'enable_query_source_port',
               'notify_delay', 'notify_source_port', 'query_source_port',
               'use_notify_delay', 'use_source_ports', 'view_name']


class SmartfolderGroupby(SubObjects):
    _fields = ['enable_grouping', 'value', 'value_type']


class SmartfolderQueryitem(SubObjects):
    _fields = ['field_type', 'name', 'op_match', 'operator', 'value',
               'value_type']


class Sortlist(SubObjects):
    _fields = ['address', 'match_list']


class SshKey(SubObjects):
    _fields = ['key_name', 'key_type', 'key_value']


class SyslogEndpointServers(SubObjects):
    _fields = ['address', 'certificate', 'certificate_token',
               'connection_type', 'facility', 'format', 'hostname', 'port',
               'severity']


class Syslogserver(SubObjects):
    _fields = ['address', 'category_list', 'certificate', 'certificate_token',
               'connection_type', 'local_interface', 'message_node_id',
               'message_source', 'only_category_list', 'port', 'severity']


class TacacsplusServer(SubObjects):
    _fields = ['address', 'auth_type', 'comment', 'disable', 'port',
               'shared_secret', 'use_accounting', 'use_mgmt_port']


class TaxiiRpzconfig(SubObjects):
    _fields = ['collection_name', 'zone']


class ThreatprotectionNatrule(SubObjects):
    _fields = ['address', 'cidr', 'end_address', 'nat_ports', 'network',
               'rule_type', 'start_address']


class ThreatprotectionStatinfo(SubObjects):
    _fields = ['critical', 'informational', 'major', 'timestamp', 'total',
               'warning']


class Thresholdtrap(SubObjects):
    _fields = ['trap_reset', 'trap_trigger', 'trap_type']


class Trapnotification(SubObjects):
    _fields = ['enable_email', 'enable_trap', 'trap_type']


class Updatesdownloadmemberconfig(SubObjects):
    _fields = ['interface', 'is_online', 'member']


class UpgradegroupMember(SubObjects):
    _fields = ['member', 'time_zone']


class UpgradegroupSchedule(SubObjects):
    _fields = ['distribution_dependent_group', 'distribution_time', 'name',
               'time_zone', 'upgrade_dependent_group', 'upgrade_time']


class Upgradestep(SubObjects):
    _fields = ['status_text', 'status_value']


class Vlanlink(SubObjects):
    _fields = ['id', 'name', 'vlan']


class Vtftpdirmember(SubObjects):
    _fields = ['address', 'cidr', 'end_address', 'ip_type', 'member',
               'network', 'start_address']


class Zoneassociation(SubObjects):
    _fields = ['fqdn', 'is_default', 'view']


class Zonenameserver(SubObjects):
    _fields = ['address', 'auto_create_ptr']


class AdAuthService(InfobloxObject):
    """ AdAuthService: Active Directory Authentication Service object.
    Corresponds to WAPI object 'ad_auth_service'

    This object allows you to specify an Active Directory (AD)
    authentication method and the AD authentication servers that
    Infoblox uses to authenticate administrators.

    Attributes:
        ad_domain: The Active Directory domain to which this server
            belongs.
        additional_search_paths: The unordered list of additional search
            paths for nested group querying.
        comment: The descriptive comment for the AD authentication
            service.
        disable_default_search_path: Determines whether the default
            search path for nested group querying is used.
        disabled: Determines if Active Directory Authentication Service
            is disabled.
        domain_controllers: The AD authentication server list.
        name: The AD authentication service name.
        nested_group_querying: Determines whether the nested group
            querying is enabled.
        timeout: The number of seconds that the appliance waits for a
            response from the AD server.
    """
    _infoblox_type = 'ad_auth_service'
    _fields = ['ad_domain', 'additional_search_paths', 'comment',
               'disable_default_search_path', 'disabled', 'domain_controllers',
               'name', 'nested_group_querying', 'timeout']
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
    """ Admingroup: Admin Group object.
    Corresponds to WAPI object 'admingroup'

    An Admin Group object creates and manages a local admin group on the
    Infoblox appliance. The privileges and properties that are set for
    the group apply to all the admin accounts that are assigned to the
    group.

    Attributes:
        access_method: Access methods specify whether an admin group can
            use the GUI and the API to access the appliance or to send
            Taxii messages to the appliance. Note that API includes both
            the Perl API and RESTful API.
        admin_set_commands: Admin set commands for the admin command
            group.
        admin_show_commands: Admin show commands for the admin command
            group.
        admin_toplevel_commands: Admin_toplevel commands for the admin
            command group
        cloud_set_commands: Cloud set commands for the cloud command
            group.
        cloud_show_commands: Cloud show commands for admin group
        comment: Comment for the Admin Group; maximum 256 characters.
        database_set_commands: Database show commands for admin group.
        database_show_commands: Database show commands for the database
            command
        dhcp_set_commands: Dhcp set commands for the dhcp command group.
        dhcp_show_commands: Dhcp show commands for the dhcp command
            group.
        disable: Determines whether the Admin Group is disabled or not.
            When this is set to False, the Admin Group is enabled.
        disable_concurrent_login: Disable concurrent login feature
        dns_set_commands: Dns set commands for the dns command group.
        dns_show_commands: Dns show commands for the dns command group.
        dns_toplevel_commands: Dns toplevel commands for the dns command
            group.
        docker_set_commands: Docker set commands for the dcoker command
            group.
        docker_show_commands: Docker show commands for the dcoker
            command group.
        email_addresses: The e-mail addresses for the Admin Group.
        enable_restricted_user_access: Determines whether the
            restrictions will be applied to the admin connector level
            for users of this Admin Group.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        grid_set_commands: Grid set commands for the grid command group.
        grid_show_commands: Show commands for the grid command group.
        inactivity_lockout_setting: The Admin group inactivity lockout
            settings.
        licensing_set_commands: Set commands for the licensing command
            group.
        licensing_show_commands: Show commands for the licensing command
            group.
        lockout_setting: This struct specifies security policy settings
            in admin group.
        machine_control_toplevel_commands: Machine control toplevel
            commands for the machine control command group.
        name: The name of the Admin Group.
        networking_set_commands: Set commands for the networking command
            group.
        networking_show_commands: Show commands for the networking
            command group.
        password_setting: The Admin Group password settings.
        roles: The names of roles this Admin Group applies to.
        saml_setting: The Admin Group SAML settings.
        security_set_commands: Set commands for the security command
            group.
        security_show_commands: Show commands for the security command
            group.
        superuser: Determines whether this Admin Group is a superuser
            group. A superuser group can perform all operations on the
            appliance, and can view and configure all types of data.
        trouble_shooting_toplevel_commands: Toplevel commands for the
            troubleshooting command group.
        use_account_inactivity_lockout_enable: This is the use flag for
            account inactivity lockout settings.
        use_disable_concurrent_login: Whether to override grid
            concurrent login
        use_lockout_setting: Whether to override grid sequential lockout
            setting
        use_password_setting: Whether grid password expiry setting
            should be override.
        user_access: The access control items for this Admin Group.
    """
    _infoblox_type = 'admingroup'
    _fields = ['access_method', 'admin_set_commands', 'admin_show_commands',
               'admin_toplevel_commands', 'cloud_set_commands',
               'cloud_show_commands', 'comment', 'database_set_commands',
               'database_show_commands', 'dhcp_set_commands',
               'dhcp_show_commands', 'disable', 'disable_concurrent_login',
               'dns_set_commands', 'dns_show_commands',
               'dns_toplevel_commands', 'docker_set_commands',
               'docker_show_commands', 'email_addresses',
               'enable_restricted_user_access', 'extattrs',
               'grid_set_commands', 'grid_show_commands',
               'inactivity_lockout_setting', 'licensing_set_commands',
               'licensing_show_commands', 'lockout_setting',
               'machine_control_toplevel_commands', 'name',
               'networking_set_commands', 'networking_show_commands',
               'password_setting', 'roles', 'saml_setting',
               'security_set_commands', 'security_show_commands', 'superuser',
               'trouble_shooting_toplevel_commands',
               'use_account_inactivity_lockout_enable',
               'use_disable_concurrent_login', 'use_lockout_setting',
               'use_password_setting', 'user_access']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name', 'roles', 'superuser']
    _all_searchable_fields = ['comment', 'name', 'roles', 'superuser']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'user_access': Addressac.from_dict,
    }


class Adminrole(InfobloxObject):
    """ Adminrole: Admin Role object.
    Corresponds to WAPI object 'adminrole'

    An Admin Role object creates and manages a local admin role on the
    Infoblox appliance. A Role object is used to aggregate a set of
    permissions (represented by Permission objects).

    The name part of the admin role object reference has the following
    components:

    Name of the Admin Role object

    Example: adminrole/ZG5zLm5ldHdvcmtfdmlldyQxMTk:default

    Attributes:
        comment: The descriptive comment of the Admin Role object.
        disable: The disable flag.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name of an admin role.
    """
    _infoblox_type = 'adminrole'
    _fields = ['comment', 'disable', 'extattrs', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Adminuser(InfobloxObject):
    """ Adminuser: Admin User object.
    Corresponds to WAPI object 'adminuser'

    An admin account provides access to the Infoblox appliance. An admin
    account inherits the privileges and properties of the group to which
    it belongs.

    Attributes:
        admin_groups: The names of the Admin Groups to which this Admin
            User belongs. Currently, this is limited to only one Admin
            Group.
        auth_method: Determines the way of authentication
        auth_type: The authentication type for the admin user.
        ca_certificate_issuer: The CA certificate that is used for user
            lookup during authentication.
        client_certificate_serial_number: The serial number of the
            client certificate.
        comment: Comment for the admin user; maximum 256 characters.
        disable: Determines whether the admin user is disabled or not.
            When this is set to False, the admin user is enabled.
        email: The e-mail address for the admin user.
        enable_certificate_authentication: Determines whether the user
            is allowed to log in only with the certificate. Regular
            username/password authentication will be disabled for this
            user.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name of the admin user.
        password: The password for the administrator to use when logging
            in.
        ssh_keys: List of ssh keys for a particular user.
        status: Status of the user account.
        time_zone: The time zone for this admin user.
        use_ssh_keys:
        use_time_zone: Use flag for: time_zone
    """
    _infoblox_type = 'adminuser'
    _fields = ['admin_groups', 'auth_method', 'auth_type',
               'ca_certificate_issuer', 'client_certificate_serial_number',
               'comment', 'disable', 'email',
               'enable_certificate_authentication', 'extattrs', 'name',
               'password', 'ssh_keys', 'status', 'time_zone', 'use_ssh_keys',
               'use_time_zone']
    _search_for_update_fields = ['admin_groups', 'name']
    _updateable_search_fields = ['admin_groups', 'ca_certificate_issuer',
                                 'client_certificate_serial_number', 'comment',
                                 'name']
    _all_searchable_fields = ['admin_groups', 'ca_certificate_issuer',
                              'client_certificate_serial_number', 'comment',
                              'name', 'status']
    _return_fields = ['admin_groups', 'comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ssh_keys': SshKey.from_dict,
    }


class Allendpoints(InfobloxObject):
    """ Allendpoints: All Endpoints object.
    Corresponds to WAPI object 'allendpoints'

    The object provides information about all thrid-party servers
    configured on the Grid.

    Attributes:
        address: The Grid endpoint IPv4 Address or IPv6 Address or
            Fully-Qualified Domain Name (FQDN).
        comment: The Grid endpoint descriptive comment.
        disable: Determines whether a Grid endpoint is disabled or not.
            When this is set to False, the Grid endpoint is enabled.
        subscribing_member: The name of the Grid Member object that is
            serving Grid endpoint.
        type: The Grid endpoint type.
        version: The Grid endpoint version.
    """
    _infoblox_type = 'allendpoints'
    _fields = ['address', 'comment', 'disable', 'subscribing_member', 'type',
               'version']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'comment', 'subscribing_member',
                              'type', 'version']
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']


class Allnsgroup(InfobloxObject):
    """ Allnsgroup: All NS Group object.
    Corresponds to WAPI object 'allnsgroup'

    The All NS Groups object is a generic name server group object that
    provides information about all name server groups.

    Attributes:
        comment: The comment for the name server group.
        name: The name of the name server group.
        type: The type of the name server group.
    """
    _infoblox_type = 'allnsgroup'
    _fields = ['comment', 'name', 'type']
    _search_for_update_fields = ['name', 'type']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'name', 'type']
    _return_fields = ['name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']


class Allrecords(InfobloxObject):
    """ Allrecords: AllRecords object.
    Corresponds to WAPI object 'allrecords'

    The allrecords object is a read-only synthetic object used to
    retrieve records that belong to a particular zone.

    Since this is a synthetic object, it supports reading only by
    specifying search parameters, not by reference.

    Attributes:
        address: The record address.
        comment: The record comment.
        creator: The record creator.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: The disable value determines if the record is disabled
            or not. "False" means the record is enabled.
        dtc_obscured: The specific LBDN record.
        name: The name of the record.
        reclaimable: Determines if the record is reclaimable or not.
        record: The record object, if supported by the WAPI. Otherwise,
            the value is "None".
        ttl: The Time To Live (TTL) value for which the record is valid
            or being cached. The 32-bit unsigned integer represents the
            duration in seconds. Zero indicates that the record should
            not be cached.
        type: The record type. When searching for an unspecified record
            type, the search is performed for all records. On retrieval,
            the appliance returns "UNSUPPORTED" for unsupported records.
        view: Name of the DNS View in which the record resides.
        zone: Name of the zone in which the record resides.
    """
    _infoblox_type = 'allrecords'
    _fields = ['address', 'comment', 'creator', 'ddns_principal',
               'ddns_protected', 'disable', 'dtc_obscured', 'name',
               'reclaimable', 'record', 'ttl', 'type', 'view', 'zone']
    _search_for_update_fields = ['name', 'type', 'view', 'zone']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'name',
                              'reclaimable', 'type', 'view', 'zone']
    _return_fields = ['comment', 'name', 'type', 'view', 'zone']
    _remap = {}
    _shadow_fields = ['_ref']


class Allrpzrecords(InfobloxObject):
    """ Allrpzrecords: DNS All RPZ Records object.
    Corresponds to WAPI object 'allrpzrecords'

    A synthetic object used to return record object types that belong to
    a Response Policy Zone.

    Attributes:
        alert_type: The alert type of the record associated with the
            allrpzrecords object.
        comment: The descriptive comment of the record associated with
            the allrpzrecords object.
        disable: The disable flag of the record associated with the
            allrpzrecords object (if present).
        expiration_time: The expiration time of the record associated
            with the allrpzrecords object.
        last_updated: The time when the record associated with the
            allrpzrecords object was last updated.
        name: The name of the record associated with the allrpzrecords
            object. Note that this value might be different than the
            value of the name field for the associated record.
        record: The record object associated with the allrpzrecords
            object.
        rpz_rule: The RPZ rule type of the record associated with the
            allrpzrecrods object.
        ttl: The TTL value of the record associated with the
            allrpzrecords object (if present).
        type: The type of record associated with the allrpzrecords
            object. This is a descriptive string that identifies the
            record to which this allrpzrecords object refers. (Examples:
            'record:rpz:a', 'record:rpz:mx', etc.)
        view: The DNS view name of the record associated with the
            allrpzrecords object.
        zone: The Response Policy Zone name of the record associated
            with the allrpzrecords object.
    """
    _infoblox_type = 'allrpzrecords'
    _fields = ['alert_type', 'comment', 'disable', 'expiration_time',
               'last_updated', 'name', 'record', 'rpz_rule', 'ttl', 'type',
               'view', 'zone']
    _search_for_update_fields = ['name', 'type', 'view', 'zone']
    _updateable_search_fields = []
    _all_searchable_fields = ['name', 'rpz_rule', 'type', 'view', 'zone']
    _return_fields = ['comment', 'name', 'type', 'view', 'zone']
    _remap = {}
    _shadow_fields = ['_ref']


class Approvalworkflow(InfobloxObject):
    """ Approvalworkflow: The approval workflow object.
    Corresponds to WAPI object 'approvalworkflow'

    The approval workflow object supports routing certain core network
    service tasks submitted by an admin group to another approval. You
    can add an admin group to an approval workflow and define the group
    as a submitter or an approver group. You can also define when and to
    whom e-mail notifications must be sent, and configure options such
    as whether the submitters or approvers must enter a comment or a
    ticket number when they submit tasks for approval. Approval
    workflows are useful when you want to control tasks that require
    reviews.

    Attributes:
        approval_group: The approval administration group.
        approval_notify_to: The destination for approval task
            notifications.
        approved_notify_to: The destination for approved task
            notifications.
        approver_comment: The requirement for the comment when an
            approver approves a submitted task.
        enable_approval_notify: Determines whether approval task
            notifications are enabled.
        enable_approved_notify: Determines whether approved task
            notifications are enabled.
        enable_failed_notify: Determines whether failed task
            notifications are enabled.
        enable_notify_group: Determines whether e-mail notifications to
            admin group's e-mail address are enabled.
        enable_notify_user: Determines whether e-mail notifications to
            an admin member's e-mail address are enabled.
        enable_rejected_notify: Determines whether rejected task
            notifications are enabled.
        enable_rescheduled_notify: Determines whether rescheduled task
            notifications are enabled.
        enable_succeeded_notify: Determines whether succeeded task
            notifications are enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        failed_notify_to: The destination for failed task notifications.
        rejected_notify_to: The destination for rejected task
            notifications.
        rescheduled_notify_to: The destination for rescheduled task
            notifications.
        submitter_comment: The requirement for the comment when a
            submitter submits a task for approval.
        submitter_group: The submitter admininstration group.
        succeeded_notify_to: The destination for succeeded task
            notifications.
        ticket_number: The requirement for the ticket number when a
            submitter submits a task for approval.
    """
    _infoblox_type = 'approvalworkflow'
    _fields = ['approval_group', 'approval_notify_to', 'approved_notify_to',
               'approver_comment', 'enable_approval_notify',
               'enable_approved_notify', 'enable_failed_notify',
               'enable_notify_group', 'enable_notify_user',
               'enable_rejected_notify', 'enable_rescheduled_notify',
               'enable_succeeded_notify', 'extattrs', 'failed_notify_to',
               'rejected_notify_to', 'rescheduled_notify_to',
               'submitter_comment', 'submitter_group', 'succeeded_notify_to',
               'ticket_number']
    _search_for_update_fields = ['approval_group', 'submitter_group']
    _updateable_search_fields = ['approval_group']
    _all_searchable_fields = ['approval_group', 'submitter_group']
    _return_fields = ['approval_group', 'extattrs', 'submitter_group']
    _remap = {}
    _shadow_fields = ['_ref']


class Authpolicy(InfobloxObject):
    """ Authpolicy: The authentication policy object.
    Corresponds to WAPI object 'authpolicy'

    The authentication policy defines which authentication server groups
    the appliance uses to authenticate admins and lists the local admin
    groups that map to the remote admin groups.

    Attributes:
        admin_groups: List of names of local administration groups that
            are mapped to remote administration groups.
        auth_services: The array that contains an ordered list of refs
            to localuser:authservice object, ldap_auth_service object,
            radius:authservice object, tacacsplus:authservice object,
            ad_auth_service object, certificate:authservice object.
            saml:authservice object,
        default_group: The default admin group that provides
            authentication in case no valid group is found.
        usage_type: Remote policies usage.
    """
    _infoblox_type = 'authpolicy'
    _fields = ['admin_groups', 'auth_services', 'default_group', 'usage_type']
    _search_for_update_fields = ['default_group', 'usage_type']
    _updateable_search_fields = ['default_group', 'usage_type']
    _all_searchable_fields = ['default_group', 'usage_type']
    _return_fields = ['default_group', 'usage_type']
    _remap = {}
    _shadow_fields = ['_ref']


class Awsrte53Taskgroup(InfobloxObject):
    """ Awsrte53Taskgroup: AWS Route53 task group object.
    Corresponds to WAPI object 'awsrte53taskgroup'

    An AWS Route53 task group is a collection of one or more tasks
    allowing you to specify various zone filters to retrieve DNS zone
    data from AWS Route53 service using specified AWS user credentials.
    Grouping these tasks together helps organize related groups of sync
    data, enable/disable these and manage the grid member these run on.

    Attributes:
        account_id: The AWS Account ID associated with this task group.
        comment: Comment for the task group; maximum 256 characters.
        consolidate_zones: Indicates if all zones need to be saved into
            a single view.
        consolidated_view: The name of the DNS view for consolidating
            zones.
        disabled: Indicates if the task group is enabled or disabled.
        grid_member: Member on which the tasks in this task group will
            be run.
        name: The name of this AWS Route53 sync task group.
        network_view: The name of the tenant's network view.
        network_view_mapping_policy: The network view mapping policy.
        sync_status: Indicate the overall sync status of this task
            group.
        task_list: List of AWS Route53 tasks in this group.
    """
    _infoblox_type = 'awsrte53taskgroup'
    _fields = ['account_id', 'comment', 'consolidate_zones',
               'consolidated_view', 'disabled', 'grid_member', 'name',
               'network_view', 'network_view_mapping_policy', 'sync_status',
               'task_list']
    _search_for_update_fields = ['account_id', 'disabled', 'name',
                                 'sync_status']
    _updateable_search_fields = ['comment', 'disabled', 'grid_member', 'name']
    _all_searchable_fields = ['account_id', 'comment', 'consolidate_zones',
                              'consolidated_view', 'disabled', 'grid_member',
                              'name', 'network_view',
                              'network_view_mapping_policy', 'sync_status']
    _return_fields = ['account_id', 'comment', 'disabled', 'name',
                      'sync_status']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'task_list': Awsrte53Task.from_dict,
    }

    def task_control(self, *args, **kwargs):
        return self._call_func("task_control", *args, **kwargs)


class Awsuser(InfobloxObject):
    """ Awsuser: AWS User object.
    Corresponds to WAPI object 'awsuser'

    An AWS user object represents a specific access key and secret key
    pair credentials of an AWS user.

    Attributes:
        access_key_id: The unique Access Key ID of this AWS user.
            Maximum 255 characters.
        account_id: The AWS Account ID of this AWS user. Maximum 64
            characters.
        last_used: The timestamp when this AWS user credentials was last
            used.
        name: The AWS user name. Maximum 64 characters.
        nios_user_name: The NIOS user name mapped to this AWS user.
            Maximum 64 characters.
        secret_access_key: The Secret Access Key for the Access Key ID
            of this user. Maximum 255 characters.
        status: Indicate the validity status of this AWS user.
    """
    _infoblox_type = 'awsuser'
    _fields = ['access_key_id', 'account_id', 'last_used', 'name',
               'nios_user_name', 'secret_access_key', 'status']
    _search_for_update_fields = ['access_key_id', 'account_id', 'name']
    _updateable_search_fields = ['access_key_id', 'account_id', 'name',
                                 'nios_user_name']
    _all_searchable_fields = ['access_key_id', 'account_id', 'name',
                              'nios_user_name', 'status']
    _return_fields = ['access_key_id', 'account_id', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Bfdtemplate(InfobloxObject):
    """ Bfdtemplate: BFD template object.
    Corresponds to WAPI object 'bfdtemplate'

    The Bidirectional Forwarding Detection (BFD) template contains a
    configuration of advanced BFD settings such as authentication and
    timer intervals.

    Attributes:
        authentication_key: The authentication key for BFD protocol
            message-digest authentication.
        authentication_key_id: The authentication key identifier for BFD
            protocol authentication. Valid values are between 1 and 255.
        authentication_type: The authentication type for BFD protocol.
        detection_multiplier: The detection time multiplier value for
            BFD protocol. The negotiated transmit interval, multiplied
            by this value, provides the detection time for the receiving
            system in asynchronous BFD mode. Valid values are between 3
            and 50.
        min_rx_interval: The minimum receive time (in seconds) for BFD
            protocol. Valid values are between 50 and 9999.
        min_tx_interval: The minimum transmission time (in seconds) for
            BFD protocol. Valid values are between 50 and 9999.
        name: The name of the BFD template object.
    """
    _infoblox_type = 'bfdtemplate'
    _fields = ['authentication_key', 'authentication_key_id',
               'authentication_type', 'detection_multiplier',
               'min_rx_interval', 'min_tx_interval', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name']
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']


class Bulkhost(InfobloxObject):
    """ Bulkhost: Bulkhost object.
    Corresponds to WAPI object 'bulkhost'

    If you need to add a large number of hosts, you can have the
    Infoblox appliance add them as a group and automatically assign host
    names based on a range of IP addresses and name format applied to
    it. This group of hosts is referred to as a BulkHost. The Infoblox
    appliance uses the name space bulk-xx-xx-xx-xx for bulk host, so
    this name should not be used for CNAMEs and host aliases because
    doing so causes conflicts. Before adding a bulk host, make sure that
    no CNAMEs or host aliases uses this name.

    Attributes:
        cloud_info: The cloud API related information.
        comment: The descriptive comment.
        disable: The disable flag of a DNS BulkHost record.
        dns_prefix: The prefix, in punycode format, for the bulk host.
        end_addr: The last IP address in the address range for the bulk
            host.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name_template: The bulk host name template.
        network_view: The network view associated with the bulk host
            view.
        policy: The hostname policy for records under the bulk host
            parent zone.
        prefix: The prefix for the bulk host. The prefix is the name (or
            a series of characters) inserted at the beginning of each
            host name.
        reverse: The reverse flag of the BulkHost record.
        start_addr: The first IP address in the address range for the
            bulk host.
        template_format: The bulk host name template format.
        ttl: The Time to Live (TTL) value.
        use_name_template: Use flag for: name_template
        use_ttl: Use flag for: ttl
        view: The view for the bulk host.
        zone: The zone name.
    """
    _infoblox_type = 'bulkhost'
    _fields = ['cloud_info', 'comment', 'disable', 'dns_prefix', 'end_addr',
               'extattrs', 'last_queried', 'name_template', 'network_view',
               'policy', 'prefix', 'reverse', 'start_addr', 'template_format',
               'ttl', 'use_name_template', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['prefix']
    _updateable_search_fields = ['comment', 'disable', 'end_addr',
                                 'name_template', 'prefix', 'reverse',
                                 'start_addr', 'ttl', 'use_name_template',
                                 'view', 'zone']
    _all_searchable_fields = ['comment', 'disable', 'end_addr',
                              'name_template', 'prefix', 'reverse',
                              'start_addr', 'ttl', 'use_name_template', 'view',
                              'zone']
    _return_fields = ['comment', 'extattrs', 'prefix']
    _remap = {}
    _shadow_fields = ['_ref']


class Bulkhostnametemplate(InfobloxObject):
    """ Bulkhostnametemplate: The bulk host name template object.
    Corresponds to WAPI object 'bulkhostnametemplate'

    The object manages the DNS bulk host name formats defined at the
    Grid level.

    Attributes:
        is_grid_default: True if this template is Grid default.
        pre_defined: True if this is a pre-defined template, False
            otherwise.
        template_format: The format of bulk host name template. It
            should follow certain rules (please use Administration Guide
            as reference).
        template_name: The name of bulk host name template.
    """
    _infoblox_type = 'bulkhostnametemplate'
    _fields = ['is_grid_default', 'pre_defined', 'template_format',
               'template_name']
    _search_for_update_fields = ['template_format', 'template_name']
    _updateable_search_fields = ['template_format', 'template_name']
    _all_searchable_fields = ['template_format', 'template_name']
    _return_fields = ['is_grid_default', 'template_format', 'template_name']
    _remap = {}
    _shadow_fields = ['_ref']


class Cacertificate(InfobloxObject):
    """ Cacertificate: CA Certificate object.
    Corresponds to WAPI object 'cacertificate'

    An CA Certificate object represents a CA certificate description.

    Attributes:
        distinguished_name: The certificate subject name.
        issuer: The certificate issuer subject name.
        serial: The certificate serial number in hex format.
        used_by: Information about the CA certificate usage.
        valid_not_after: The date after which the certificate becomes
            invalid.
        valid_not_before: The date before which the certificate is not
            valid.
    """
    _infoblox_type = 'cacertificate'
    _fields = ['distinguished_name', 'issuer', 'serial', 'used_by',
               'valid_not_after', 'valid_not_before']
    _search_for_update_fields = ['distinguished_name', 'issuer', 'serial']
    _updateable_search_fields = []
    _all_searchable_fields = ['distinguished_name', 'issuer', 'serial']
    _return_fields = ['distinguished_name', 'issuer', 'serial', 'used_by',
                      'valid_not_after', 'valid_not_before']
    _remap = {}
    _shadow_fields = ['_ref']


class Capacityreport(InfobloxObject):
    """ Capacityreport: Grid member capacity report object.
    Corresponds to WAPI object 'capacityreport'

    The capacity report object provides information about the object
    count, interface count, and other memory usage statistics for a Grid
    member.

    Attributes:
        hardware_type: Hardware type of a Grid member.
        max_capacity: The maximum amount of capacity available for the
            Grid member.
        name: The Grid member name.
        object_counts: A list of instance counts for object types
            created on the Grid member.
        percent_used: The percentage of the capacity in use by the Grid
            member.
        role: The Grid member role.
        total_objects: The total number of objects created by the Grid
            member.
    """
    _infoblox_type = 'capacityreport'
    _fields = ['hardware_type', 'max_capacity', 'name', 'object_counts',
               'percent_used', 'role', 'total_objects']
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
    """ Captiveportal: Captive portal object.
    Corresponds to WAPI object 'captiveportal'

    This object represents the captive portal configuration.

    Attributes:
        authn_server_group: The authentication server group assigned to
            this captive portal.
        company_name: The company name that appears in the guest
            registration page.
        enable_syslog_auth_failure: Determines if authentication
            failures are logged to syslog or not.
        enable_syslog_auth_success: Determines if successful
            authentications are logged to syslog or not.
        enable_user_type: The type of user to be enabled for the captive
            portal.
        encryption: The encryption the captive portal uses.
        files: The list of files associated with the captive portal.
        guest_custom_field1_name: The name of the custom field that you
            are adding to the guest registration page.
        guest_custom_field1_required: Determines if the custom field is
            required or not.
        guest_custom_field2_name: The name of the custom field that you
            are adding to the guest registration page.
        guest_custom_field2_required: Determines if the custom field is
            required or not.
        guest_custom_field3_name: The name of the custom field that you
            are adding to the guest registration page.
        guest_custom_field3_required: Determines if the custom field is
            required or not.
        guest_custom_field4_name: The name of the custom field that you
            are adding to the guest registration page.
        guest_custom_field4_required: Determines if the custom field is
            required or not.
        guest_email_required: Determines if the email address of the
            guest is required or not.
        guest_first_name_required: Determines if the first name of the
            guest is required or not.
        guest_last_name_required: Determines if the last name of the
            guest is required or not.
        guest_middle_name_required: Determines if the middle name of the
            guest is required or not.
        guest_phone_required: Determines if the phone number of the
            guest is required or not.
        helpdesk_message: The helpdesk message that appears in the guest
            registration page.
        listen_address_ip: Determines the IP address on which the
            captive portal listens. Valid if listen address type is
            'IP'.
        listen_address_type: Determines the type of the IP address on
            which the captive portal listens.
        name: The hostname of the Grid member that hosts the captive
            portal.
        network_view: The network view of the captive portal.
        port: The TCP port used by the Captive Portal service. The port
            is required when the Captive Portal service is enabled.
            Valid values are between 1 and 63999. Please note that
            setting the port number to 80 or 443 might impact
            performance.
        service_enabled: Determines if the captive portal service is
            enabled or not.
        syslog_auth_failure_level: The syslog level at which
            authentication failures are logged.
        syslog_auth_success_level: The syslog level at which successful
            authentications are logged.
        welcome_message: The welcome message that appears in the guest
            registration page.
    """
    _infoblox_type = 'captiveportal'
    _fields = ['authn_server_group', 'company_name',
               'enable_syslog_auth_failure', 'enable_syslog_auth_success',
               'enable_user_type', 'encryption', 'files',
               'guest_custom_field1_name', 'guest_custom_field1_required',
               'guest_custom_field2_name', 'guest_custom_field2_required',
               'guest_custom_field3_name', 'guest_custom_field3_required',
               'guest_custom_field4_name', 'guest_custom_field4_required',
               'guest_email_required', 'guest_first_name_required',
               'guest_last_name_required', 'guest_middle_name_required',
               'guest_phone_required', 'helpdesk_message', 'listen_address_ip',
               'listen_address_type', 'name', 'network_view', 'port',
               'service_enabled', 'syslog_auth_failure_level',
               'syslog_auth_success_level', 'welcome_message']
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
    """ CertificateAuthservice: Certificate authentication service
    object.
    Corresponds to WAPI object 'certificate:authservice'

    This object represents an certificate authentication service.

    Attributes:
        auto_populate_login: Specifies the value of the client
            certificate for automatically populating the NIOS login
            name.
        ca_certificates: The list of CA certificates.
        comment: The descriptive comment for the certificate
            authentication service.
        disabled: Determines if this certificate authentication service
            is enabled or disabled.
        enable_password_request: Determines if username/password
            authentication together with client certificate
            authentication is enabled or disabled.
        enable_remote_lookup: Determines if the lookup for user group
            membership information on remote services is enabled or
            disabled.
        max_retries: The number of validation attempts before the
            appliance contacts the next responder.
        name: The name of the certificate authentication service.
        ocsp_check: Specifies the source of OCSP settings.
        ocsp_responders: An ordered list of OCSP responders that are
            part of the certificate authentication service.
        recovery_interval: The period of time the appliance waits before
            it attempts to contact a responder that is out of service
            again. The value must be between 1 and 600 seconds.
        remote_lookup_password: The password for the service account.
        remote_lookup_service: The service that will be used for remote
            lookup.
        remote_lookup_username: The username for the service account.
        response_timeout: The validation timeout period in milliseconds.
        trust_model: The OCSP trust model.
        user_match_type: Specifies how to search for a user.
    """
    _infoblox_type = 'certificate:authservice'
    _fields = ['auto_populate_login', 'ca_certificates', 'comment', 'disabled',
               'enable_password_request', 'enable_remote_lookup',
               'max_retries', 'name', 'ocsp_check', 'ocsp_responders',
               'recovery_interval', 'remote_lookup_password',
               'remote_lookup_service', 'remote_lookup_username',
               'response_timeout', 'trust_model', 'user_match_type']
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
    """ CiscoiseEndpoint: Cisco ISE Endpoint object.
    Corresponds to WAPI object 'ciscoise:endpoint'

    The object contains information and configuration for third-party
    Cisco ISE servers integration, configuration for Cisco ISE
    publishing and subscription.

    Attributes:
        address: The Cisco ISE endpoint IPv4 Address or IPv6 Address or
            Fully-Qualified Domain Name (FQDN)
        bulk_download_certificate_subject: The Cisco ISE bulk download
            certificate subject.
        bulk_download_certificate_token: The token returned by the
            uploadinit function call in object fileop for Cisco ISE bulk
            download certificate.
        bulk_download_certificate_valid_from: The Cisco ISE bulk
            download certificate valid from.
        bulk_download_certificate_valid_to: The Cisco ISE bulk download
            certificate valid to.
        client_certificate_subject: The Cisco ISE client certificate
            subject.
        client_certificate_token: The token returned by the uploadinit
            function call in object fileop for Cisco ISE client
            certificate.
        client_certificate_valid_from: The Cisco ISE client certificate
            valid from.
        client_certificate_valid_to: The Cisco ISE client certificate
            valid to.
        comment: The Cisco ISE endpoint descriptive comment.
        connection_status: The Cisco ISE connection status.
        connection_timeout: The Cisco ISE connection timeout.
        disable: Determines whether a Cisco ISE endpoint is disabled or
            not. When this is set to False, the Cisco ISE endpoint is
            enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        network_view: The Cisco ISE network view name.
        publish_settings: The Cisco ISE publish settings.
        resolved_address: The resolved IPv4 Address or IPv6 Address of
            the Cisco ISE endpoint.
        resolved_secondary_address: The resolved IPv4 Address or IPv6
            Address of the Cisco ISE endpoint.
        secondary_address: The Cisco ISE endpoint secondary IPv4 Address
            or IPv6 Address or Fully-Qualified Domain Name (FQDN)
        subscribe_settings: The Cisco ISE subscribe settings.
        subscribing_member: The name of the Grid Member object that is
            serving Cisco ISE endpoint.
        type: The Cisco ISE endpoint type.
        version: The Cisco ISE endpoint version.
    """
    _infoblox_type = 'ciscoise:endpoint'
    _fields = ['address', 'bulk_download_certificate_subject',
               'bulk_download_certificate_token',
               'bulk_download_certificate_valid_from',
               'bulk_download_certificate_valid_to',
               'client_certificate_subject', 'client_certificate_token',
               'client_certificate_valid_from', 'client_certificate_valid_to',
               'comment', 'connection_status', 'connection_timeout', 'disable',
               'extattrs', 'network_view', 'publish_settings',
               'resolved_address', 'resolved_secondary_address',
               'secondary_address', 'subscribe_settings', 'subscribing_member',
               'type', 'version']
    _search_for_update_fields = ['address', 'resolved_address', 'type',
                                 'version']
    _updateable_search_fields = ['address', 'comment', 'network_view',
                                 'secondary_address', 'subscribing_member',
                                 'type', 'version']
    _all_searchable_fields = ['address', 'comment', 'network_view',
                              'resolved_address', 'resolved_secondary_address',
                              'secondary_address', 'subscribing_member',
                              'type', 'version']
    _return_fields = ['address', 'disable', 'extattrs', 'resolved_address',
                      'type', 'version']
    _remap = {}
    _shadow_fields = ['_ref']

    def test_connection(self, *args, **kwargs):
        return self._call_func("test_connection", *args, **kwargs)


class Csvimporttask(InfobloxObject):
    """ Csvimporttask: CSV Import task object.
    Corresponds to WAPI object 'csvimporttask'

    This object represents a CSV import task, if the task was created
    but not started by an import operation, it can be started by
    modifying it and assigning the value 'START' to the 'action' field.

    Attributes:
        action: The action to execute.
        admin_name: The login name of the administrator.
        end_time: The end time of this import operation.
        file_name: The name of the file used for the import operation.
        file_size: The size of the file used for the import operation.
        import_id: The ID of the current import task.
        lines_failed: The number of lines that encountered an error.
        lines_processed: The number of lines that have been processed.
        lines_warning: The number of lines that encountered a warning.
        on_error: The action to take when an error is encountered.
        operation: The operation to execute.
        separator: The separator to be used for the data in the CSV
            file.
        start_time: The start time of the import operation.
        status: The status of the import operation
        update_method: The update method to be used for the operation.
    """
    _infoblox_type = 'csvimporttask'
    _fields = ['action', 'admin_name', 'end_time', 'file_name', 'file_size',
               'import_id', 'lines_failed', 'lines_processed', 'lines_warning',
               'on_error', 'operation', 'separator', 'start_time', 'status',
               'update_method']
    _search_for_update_fields = ['import_id']
    _updateable_search_fields = []
    _all_searchable_fields = ['import_id']
    _return_fields = ['action', 'admin_name', 'end_time', 'file_name',
                      'file_size', 'import_id', 'lines_failed',
                      'lines_processed', 'lines_warning', 'on_error',
                      'operation', 'separator', 'start_time', 'status',
                      'update_method']
    _remap = {}
    _shadow_fields = ['_ref']

    def stop(self, *args, **kwargs):
        return self._call_func("stop", *args, **kwargs)


class DbObjects(InfobloxObject):
    """ DbObjects: The DB Objects object.
    Corresponds to WAPI object 'db_objects'

    The DB Objects object is used to search for changes in objects of
    the Infoblox Grid.

    Attributes:
        last_sequence_id: The last returned sequence ID.
        object: The record object when supported by WAPI. Otherwise, the
            value is "None".
        object_type: The object type. This is undefined if the object is
            not supported.
        unique_id: The unique ID of the requested object.
    """
    _infoblox_type = 'db_objects'
    _fields = ['last_sequence_id', 'object', 'object_type', 'unique_id']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['last_sequence_id', 'object', 'object_type', 'unique_id']
    _remap = {}
    _shadow_fields = ['_ref']


class Dbsnapshot(InfobloxObject):
    """ Dbsnapshot: The DBSnapshot WAPI object.
    Corresponds to WAPI object 'dbsnapshot'

    The object provides information about the OneDB snapshot, the last
    time it was taken and the descriptive comment.

    Attributes:
        comment: The descriptive comment.
        timestamp: The time when the latest OneDB snapshot was taken in
            Epoch seconds format.
    """
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
    """ DdnsPrincipalcluster: DDNS Principal Cluster object.
    Corresponds to WAPI object 'ddns:principalcluster'

    The DDNS Principal Cluster object represents a set of principals
    such that any principal in a DDNS Principal Cluster can update
    records created by any other principal in the same cluster.

    Attributes:
        comment: Comment for the DDNS Principal Cluster.
        group: The DDNS Principal cluster group name.
        name: The name of this DDNS Principal Cluster.
        principals: The list of equivalent principals.
    """
    _infoblox_type = 'ddns:principalcluster'
    _fields = ['comment', 'group', 'name', 'principals']
    _search_for_update_fields = ['group', 'name']
    _updateable_search_fields = ['comment', 'group', 'name']
    _all_searchable_fields = ['comment', 'group', 'name']
    _return_fields = ['comment', 'group', 'name', 'principals']
    _remap = {}
    _shadow_fields = ['_ref']


class DdnsPrincipalclusterGroup(InfobloxObject):
    """ DdnsPrincipalclusterGroup: DDNS Principal Cluster Group object.
    Corresponds to WAPI object 'ddns:principalcluster:group'

    The DDNS Principal Cluster Group object represents a set of DDNS
    Principal Clusters. A single group can be active at any time.

    Attributes:
        clusters: The list of equivalent DDNS principal clusters.
        comment: Comment for the DDNS Principal Cluster Group.
        name: The name of this DDNS Principal Cluster Group.
    """
    _infoblox_type = 'ddns:principalcluster:group'
    _fields = ['clusters', 'comment', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DeletedObjects(InfobloxObject):
    """ DeletedObjects: The Deleted Objects object.
    Corresponds to WAPI object 'deleted_objects'

    The Deleted Objects object is used to display information about
    deleted objects. You can retrieve it from the appliance only as a
    part of DB Objects response.

    Attributes:
        object_type: The object type of the deleted object. This is
            undefined if the object is not supported.
    """
    _infoblox_type = 'deleted_objects'
    _fields = ['object_type']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['object_type']
    _remap = {}
    _shadow_fields = ['_ref']


class DhcpStatistics(InfobloxObject):
    """ DhcpStatistics: DHCP Statistics object.
    Corresponds to WAPI object 'dhcp:statistics'

    DHCP Statistics object is used to display information about DHCP
    utilization status, number of static and dynamic hosts, overall DHCP
    utilization in percentage. DHCP Statistics object supports
    references on following objects: network, range, sharednetwork,
    msserver:dhcp, member:dhcpproperties.

    Note that get by reference is not allowed for this object. Search
    result returns the dhcp:statistics object itself (not a list).

    Note that read by reference is not supported.

    Attributes:
        dhcp_utilization: The percentage of the total DHCP utilization
            of DHCP objects multiplied by 1000. This is the percentage
            of the total number of available IP addresses belonging to
            the object versus the total number of all IP addresses in
            object.
        dhcp_utilization_status: A string describing the utilization
            level of the DHCP object.
        dynamic_hosts: The total number of DHCP leases issued for the
            DHCP object.
        static_hosts: The number of static DHCP addresses configured in
            the DHCP object.
        total_hosts: The total number of DHCP addresses configured in
            the DHCP object.
    """
    _infoblox_type = 'dhcp:statistics'
    _fields = ['dhcp_utilization', 'dhcp_utilization_status', 'dynamic_hosts',
               'static_hosts', 'total_hosts']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['dhcp_utilization', 'dhcp_utilization_status',
                      'dynamic_hosts', 'static_hosts', 'total_hosts']
    _remap = {}
    _shadow_fields = ['_ref']


class Dhcpfailover(InfobloxObject):
    """ Dhcpfailover: DHCP Failover Association object.
    Corresponds to WAPI object 'dhcpfailover'

    DHCP failover is a protocol designed to allow a backup DHCP server
    to take over for a main server if the main server is taken off the
    network for any reason. DHCP failover can be used to configure two
    DHCP servers to operate as a redundant pair.

    Attributes:
        association_type: The value indicating whether the failover
            assoctaion is Microsoft or Grid based. This is a read-only
            attribute.
        comment: A descriptive comment about a DHCP failover object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        failover_port: Determines the TCP port on which the server
            should listen for connections from its failover peer. Valid
            values are between 1 and 63999.
        load_balance_split: A load balancing split value of a DHCP
            failover object. Specify the value of the maximum load
            balancing delay in a 8-bit integer format (range from 0 to
            256).
        max_client_lead_time: The maximum client lead time value of a
            DHCP failover object. Specify the value of the maximum
            client lead time in a 32-bit integer format (range from 0 to
            4294967295) that represents the duration in seconds. Valid
            values are between 1 and 4294967295.
        max_load_balance_delay: The maximum load balancing delay value
            of a DHCP failover object. Specify the value of the maximum
            load balancing delay in a 32-bit integer format (range from
            0 to 4294967295) that represents the duration in seconds.
            Valid values are between 1 and 4294967295.
        max_response_delay: The maximum response delay value of a DHCP
            failover object. Specify the value of the maximum response
            delay in a 32-bit integer format (range from 0 to
            4294967295) that represents the duration in seconds. Valid
            values are between 1 and 4294967295.
        max_unacked_updates: The maximum number of unacked updates value
            of a DHCP failover object. Specify the value of the maximum
            number of unacked updates in a 32-bit integer format (range
            from 0 to 4294967295) that represents the number of
            messages. Valid values are between 1 and 4294967295.
        ms_association_mode: The value that indicates whether the
            failover association is read-write or read-only. This is a
            read-only attribute.
        ms_enable_authentication: Determines if the authentication for
            the failover association is enabled or not.
        ms_enable_switchover_interval: Determines if the switchover
            interval is enabled or not.
        ms_failover_mode: The mode for the failover association.
        ms_failover_partner: Failover partner defined in the association
            with the Microsoft Server.
        ms_hotstandby_partner_role: The partner role in the case of
            HotStandby.
        ms_is_conflict: Determines if the matching Microsfot failover
            association (if any) is in synchronization (False) or not
            (True). If there is no matching failover association the
            returned values is False. This is a read-only attribute.
        ms_previous_state: The previous failover association state. This
            is a read-only attribute.
        ms_server: The primary Microsoft Server.
        ms_shared_secret: The failover association authentication. This
            is a write-only attribute.
        ms_state: The failover association state. This is a read-only
            attribute.
        ms_switchover_interval: The time (in seconds) that DHCPv4 server
            will wait before transitioning the server from the
            COMMUNICATION-INT state to PARTNER-DOWN state.
        name: The name of a DHCP failover object.
        primary: The primary server of a DHCP failover object.
        primary_server_type: The type of the primary server of DHCP
            Failover association object.
        primary_state: The primary server status of a DHCP failover
            object.
        recycle_leases: Determines if the leases are kept in recycle bin
            until one week after expiration or not.
        secondary: The secondary server of a DHCP failover object.
        secondary_server_type: The type of the secondary server of DHCP
            Failover association object.
        secondary_state: The secondary server status of a DHCP failover
            object.
        use_failover_port: Use flag for: failover_port
        use_ms_switchover_interval: Use flag for: ms_switchover_interval
        use_recycle_leases: Use flag for: recycle_leases
    """
    _infoblox_type = 'dhcpfailover'
    _fields = ['association_type', 'comment', 'extattrs', 'failover_port',
               'load_balance_split', 'max_client_lead_time',
               'max_load_balance_delay', 'max_response_delay',
               'max_unacked_updates', 'ms_association_mode',
               'ms_enable_authentication', 'ms_enable_switchover_interval',
               'ms_failover_mode', 'ms_failover_partner',
               'ms_hotstandby_partner_role', 'ms_is_conflict',
               'ms_previous_state', 'ms_server', 'ms_shared_secret',
               'ms_state', 'ms_switchover_interval', 'name', 'primary',
               'primary_server_type', 'primary_state', 'recycle_leases',
               'secondary', 'secondary_server_type', 'secondary_state',
               'use_failover_port', 'use_ms_switchover_interval',
               'use_recycle_leases']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    def set_dhcp_failover_partner_down(self, *args, **kwargs):
        return self._call_func("set_dhcp_failover_partner_down", *args,
                               **kwargs)

    def set_dhcp_failover_secondary_recovery(self, *args, **kwargs):
        return self._call_func("set_dhcp_failover_secondary_recovery", *args,
                               **kwargs)


class DhcpOptionDefinition(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return DhcpOptionDefinitionV4

    @classmethod
    def get_v6_class(cls):
        return DhcpOptionDefinitionV6


class DhcpOptionDefinitionV4(DhcpOptionDefinition):
    """ DhcpOptionDefinitionV4: DHCP option definition object.
    Corresponds to WAPI object 'dhcpoptiondefinition'

    An option definition defines a DHCP option within a specific option
    space. A custom option can be defined in the predefined DHCP option
    space or in the user-defined vendor option space. To define an
    option, add the option definition to the required option space.

    Attributes:
        code: The code of a DHCP option definition object. An option
            code number is used to identify the DHCP option.
        name: The name of a DHCP option definition object.
        space: The space of a DHCP option definition object.
        type: The data type of the Grid DHCP option.
    """
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
    """ DhcpOptionDefinitionV6: DHCP IPv6 option definition object.
    Corresponds to WAPI object 'ipv6dhcpoptiondefinition'

    An IPv6 option definition defines a DHCP IPv6 option within a
    specific IPv6 option space. A custom IPv6 option can be defined in
    the predefined DHCP IPv6 option space or in the user-defined vendor
    IPv6 option space. To define an IPv6 option, add the IPv6 option
    definition to the required IPv6 option space.

    Attributes:
        code: The code of a DHCP IPv6 option definition object. An
            option code number is used to identify the DHCP option.
        name: The name of a DHCP IPv6 option definition object.
        space: The space of a DHCP option definition object.
        type: The data type of the Grid DHCP IPv6 option.
    """
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
    """ DhcpOptionSpaceV4: DHCP option space object.
    Corresponds to WAPI object 'dhcpoptionspace'

    An Option Space defines a namespace in which vendor options can be
    defined. To define a specific vendor option space, add an option
    space to DHCP.

    Attributes:
        comment: A descriptive comment of a DHCP option space object.
        name: The name of a DHCP option space object.
        option_definitions: The list of DHCP option definition objects.
        space_type: The type of a DHCP option space object.
    """
    _infoblox_type = 'dhcpoptionspace'
    _fields = ['comment', 'name', 'option_definitions', 'space_type']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4


class DhcpOptionSpaceV6(DhcpOptionSpace):
    """ DhcpOptionSpaceV6: DHCP IPv6 option space object.
    Corresponds to WAPI object 'ipv6dhcpoptionspace'

    An IPv6 option space defines a namespace in which vendor IPv6
    options can be defined. To define a specific vendor IPv6 option
    space, add an IPv6 option space to DHCP.

    Attributes:
        comment: A descriptive comment of a DHCP IPv6 option space
            object.
        enterprise_number: The enterprise number of a DHCP IPv6 option
            space object.
        name: The name of a DHCP IPv6 option space object.
        option_definitions: The list of DHCP IPv6 option definition
            objects.
    """
    _infoblox_type = 'ipv6dhcpoptionspace'
    _fields = ['comment', 'enterprise_number', 'name', 'option_definitions']
    _search_for_update_fields = ['enterprise_number', 'name']
    _updateable_search_fields = ['comment', 'enterprise_number', 'name']
    _all_searchable_fields = ['comment', 'enterprise_number', 'name']
    _return_fields = ['comment', 'enterprise_number', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6


class Discovery(InfobloxObject):
    """ Discovery: Discovery object.
    Corresponds to WAPI object 'discovery'

    This object can be used to control the Network Insight functionality
    of the appliance.

    Attributes:
    """
    _infoblox_type = 'discovery'
    _fields = []
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    def clear_network_port_assignment(self, *args, **kwargs):
        return self._call_func("clear_network_port_assignment", *args,
                               **kwargs)

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


class DiscoveryCredentialgroup(InfobloxObject):
    """ DiscoveryCredentialgroup: The Credential group object.
    Corresponds to WAPI object 'discovery:credentialgroup'

    This object provides information about the Credential group.

    Attributes:
        name: The name of the Credential group.
    """
    _infoblox_type = 'discovery:credentialgroup'
    _fields = ['name']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryDevice(InfobloxObject):
    """ DiscoveryDevice: Discovery Device object.
    Corresponds to WAPI object 'discovery:device'

    The devices discovered by Network Automation

    Attributes:
        address: The IPv4 Address or IPv6 Address of the device.
        address_ref: The ref to management IP address of the device.
        available_mgmt_ips: The list of available management IPs for the
            device.
        cap_admin_status_ind: Determines whether to modify the admin
            status of an interface of the device.
        cap_admin_status_na_reason: The reason that the edit admin
            status action is not available.
        cap_description_ind: Determines whether to modify the
            description of an interface on the device.
        cap_description_na_reason: The reason that the edit description
            action is not available.
        cap_net_deprovisioning_ind: Determines whether to deprovision a
            network from interfaces of the device.
        cap_net_deprovisioning_na_reason: The reason that the
            deprovision a network from interfaces of this device is not
            available.
        cap_net_provisioning_ind: Determines whether to modify the
            network associated to an interface of the device.
        cap_net_provisioning_na_reason: The reason that network
            provisioning is not available.
        cap_net_vlan_provisioning_ind: Determines whether to create a
            VLAN and then provision a network to the interface of the
            device.
        cap_net_vlan_provisioning_na_reason: The reason that network
            provisioning on VLAN is not available.
        cap_vlan_assignment_ind: Determines whether to modify the VLAN
            assignement of an interface of the device.
        cap_vlan_assignment_na_reason: The reason that VLAN assignment
            action is not available.
        cap_voice_vlan_ind: Determines whether to modify the voice VLAN
            assignment of an interface of the device.
        cap_voice_vlan_na_reason: The reason that voice VLAN assignment
            action is not available.
        chassis_serial_number: The device chassis serial number.
        description: The description of the device.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        interfaces: List of the device interfaces.
        location: The location of the device.
        model: The model name of the device.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: The name of the device.
        neighbors: List of the device neighbors.
        network: The ref to the network to which belongs the management
            IP address belongs.
        network_infos: The list of networks to which the device
            interfaces belong.
        network_view: The name of the network view in which this device
            resides.
        networks: The list of networks to which the device interfaces
            belong.
        os_version: The Operating System version running on the device.
        port_stats: The port statistics of the device.
        privileged_polling: A flag indicated that NI should send enable
            command when interacting with device.
        type: The type of the device.
        user_defined_mgmt_ip: User-defined management IP address of the
            device.
        vendor: The vendor name of the device.
        vlan_infos: The list of VLAN information associated with the
            device.
    """
    _infoblox_type = 'discovery:device'
    _fields = ['address', 'address_ref', 'available_mgmt_ips',
               'cap_admin_status_ind', 'cap_admin_status_na_reason',
               'cap_description_ind', 'cap_description_na_reason',
               'cap_net_deprovisioning_ind',
               'cap_net_deprovisioning_na_reason', 'cap_net_provisioning_ind',
               'cap_net_provisioning_na_reason',
               'cap_net_vlan_provisioning_ind',
               'cap_net_vlan_provisioning_na_reason',
               'cap_vlan_assignment_ind', 'cap_vlan_assignment_na_reason',
               'cap_voice_vlan_ind', 'cap_voice_vlan_na_reason',
               'chassis_serial_number', 'description', 'extattrs',
               'interfaces', 'location', 'model', 'ms_ad_user_data', 'name',
               'neighbors', 'network', 'network_infos', 'network_view',
               'networks', 'os_version', 'port_stats', 'privileged_polling',
               'type', 'user_defined_mgmt_ip', 'vendor', 'vlan_infos']
    _search_for_update_fields = ['address', 'name', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'chassis_serial_number', 'location',
                              'model', 'name', 'network_view', 'os_version',
                              'type', 'vendor']
    _return_fields = ['address', 'extattrs', 'name', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'network_infos': DiscoveryNetworkinfo.from_dict,
        'vlan_infos': DiscoveryVlaninfo.from_dict,
    }


class DiscoveryDevicecomponent(InfobloxObject):
    """ DiscoveryDevicecomponent: Device Component object.
    Corresponds to WAPI object 'discovery:devicecomponent'

    The device components discovered by Network Automation.

    Attributes:
        component_name: The component name.
        description: The description of the device component.
        device: A reference to a device, to which this component belongs
            to.
        model: The model of the device component.
        serial: The serial number of the device component.
        type: The type of device component.
    """
    _infoblox_type = 'discovery:devicecomponent'
    _fields = ['component_name', 'description', 'device', 'model', 'serial',
               'type']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = ['device']
    _return_fields = ['component_name', 'description', 'model', 'serial',
                      'type']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryDeviceinterface(InfobloxObject):
    """ DiscoveryDeviceinterface: Device Interface object.
    Corresponds to WAPI object 'discovery:deviceinterface'

    Interfaces on devices discovered by Network Automation

    Attributes:
        admin_status: Administrative state of the interface.
        admin_status_task_info: The configured admin status task info of
            the interface.
        aggr_interface_name: Name of the port channel current interface
            belongs to.
        cap_if_admin_status_ind: Determines whether to modify the admin
            status of the interface.
        cap_if_admin_status_na_reason: The reason that the edit admin
            status action is not available.
        cap_if_description_ind: Determines whether to modify the
            description of the interface.
        cap_if_description_na_reason: The reason that the edit
            description action is not available.
        cap_if_net_deprovisioning_ipv4_ind: Determines whether to
            deprovision a IPv4 network from the interfaces.
        cap_if_net_deprovisioning_ipv4_na_reason: The reason that the
            deprovision a IPv4 network from the interface.
        cap_if_net_deprovisioning_ipv6_ind: Determines whether to
            deprovision a IPv6 network from the interfaces.
        cap_if_net_deprovisioning_ipv6_na_reason: The reason that the
            deprovision a IPv6 network from the interface.
        cap_if_net_provisioning_ipv4_ind: Determines whether to modify
            the IPv4 network associated to the interface.
        cap_if_net_provisioning_ipv4_na_reason: The reason that IPv4
            network provisioning is not available.
        cap_if_net_provisioning_ipv6_ind: Determines whether to modify
            the IPv6 network associated to the interface.
        cap_if_net_provisioning_ipv6_na_reason: The reason that IPv6
            network provisioning is not available.
        cap_if_vlan_assignment_ind: Determines whether to modify the
            VLAN assignement of the interface.
        cap_if_vlan_assignment_na_reason: The reason that VLAN
            assignment action is not available.
        cap_if_voice_vlan_ind: Determines whether to modify the voice
            VLAN assignement of the interface.
        cap_if_voice_vlan_na_reason: The reason that voice VLAN
            assignment action is not available.
        description: The description of the interface.
        description_task_info: The configured description task info of
            the interface.
        device: The ref to the device to which the interface belongs.
        duplex: The duplex state of the interface.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ifaddr_infos: List of IFaddr information associated with the
            interface.
        index: The interface index number, as reported by SNMP.
        last_change: Timestamp of the last interface property change
            detected.
        link_aggregation: This field indicates if this is a link
            aggregation interface.
        mac: The MAC address of the interface.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: The interface system name.
        network_view: Th name of the network view.
        oper_status: Operating state of the interface.
        port_fast: The Port Fast status of the interface.
        reserved_object: The reference to
            object(Host/FixedAddress/GridMember) to which this port is
            reserved.
        speed: The interface speed in bps.
        trunk_status: Indicates if the interface is tagged as a VLAN
            trunk or not.
        type: The type of interface.
        vlan_info_task_info: The configured VLAN status task info of the
            interface.
        vlan_infos: The list of VLAN information associated with the
            interface.
        vpc_peer: Aggregated interface name of vPC peer device current
            port is connected to.
        vpc_peer_device: The reference to vPC peer device.
        vrf_description: The description of the Virtual Routing and
            Forwarding (VRF) associated with the interface.
        vrf_name: The name of the Virtual Routing and Forwarding (VRF)
            associated with the interface.
        vrf_rd: The route distinguisher of the Virtual Routing and
            Forwarding (VRF) associated with the interface.
    """
    _infoblox_type = 'discovery:deviceinterface'
    _fields = ['admin_status', 'admin_status_task_info', 'aggr_interface_name',
               'cap_if_admin_status_ind', 'cap_if_admin_status_na_reason',
               'cap_if_description_ind', 'cap_if_description_na_reason',
               'cap_if_net_deprovisioning_ipv4_ind',
               'cap_if_net_deprovisioning_ipv4_na_reason',
               'cap_if_net_deprovisioning_ipv6_ind',
               'cap_if_net_deprovisioning_ipv6_na_reason',
               'cap_if_net_provisioning_ipv4_ind',
               'cap_if_net_provisioning_ipv4_na_reason',
               'cap_if_net_provisioning_ipv6_ind',
               'cap_if_net_provisioning_ipv6_na_reason',
               'cap_if_vlan_assignment_ind',
               'cap_if_vlan_assignment_na_reason', 'cap_if_voice_vlan_ind',
               'cap_if_voice_vlan_na_reason', 'description',
               'description_task_info', 'device', 'duplex', 'extattrs',
               'ifaddr_infos', 'index', 'last_change', 'link_aggregation',
               'mac', 'ms_ad_user_data', 'name', 'network_view', 'oper_status',
               'port_fast', 'reserved_object', 'speed', 'trunk_status', 'type',
               'vlan_info_task_info', 'vlan_infos', 'vpc_peer',
               'vpc_peer_device', 'vrf_description', 'vrf_name', 'vrf_rd']
    _search_for_update_fields = ['name', 'type']
    _updateable_search_fields = []
    _all_searchable_fields = ['aggr_interface_name', 'description', 'mac',
                              'name', 'network_view', 'oper_status', 'speed',
                              'type', 'vpc_peer', 'vrf_description',
                              'vrf_name', 'vrf_rd']
    _return_fields = ['extattrs', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ifaddr_infos': DiscoveryIfaddrinfo.from_dict,
        'vlan_infos': DiscoveryVlaninfo.from_dict,
    }


class DiscoveryDeviceneighbor(InfobloxObject):
    """ DiscoveryDeviceneighbor: Device Neighbor object.
    Corresponds to WAPI object 'discovery:deviceneighbor'

    The neighbor associated with the device discovered by Network
    Automation.

    Attributes:
        address: The IPv4 Address or IPv6 Address of the device
            neighbor.
        address_ref: The ref to the management IP address of the device
            neighbor.
        device: The ref to the device to which the device neighbor
            belongs.
        interface: The ref to the interface to which the device neighbor
            belongs.
        mac: The MAC address of the device neighbor.
        name: The name of the device neighbor.
        vlan_infos: The list of VLAN information associated with the
            device neighbor.
    """
    _infoblox_type = 'discovery:deviceneighbor'
    _fields = ['address', 'address_ref', 'device', 'interface', 'mac', 'name',
               'vlan_infos']
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
    """ DiscoveryDevicesupportbundle: Device support bundle object.
    Corresponds to WAPI object 'discovery:devicesupportbundle'

    Infoblox frequently provides support files for additional network
    devices that may not have previously been supported by discovery,
    and updates to support new operating system versions of existing
    devices.

    The device support bundle represents the entity for displaying and
    managing device support files.

    Attributes:
        author: The developer of the device support bundle.
        integrated_ind: Determines whether the device support bundle is
            integrated or imported. Note that integrated support bundles
            cannot be removed.
        name: The descriptive device name for the device support bundle.
        version: The version of the currently active device support
            bundle.
    """
    _infoblox_type = 'discovery:devicesupportbundle'
    _fields = ['author', 'integrated_ind', 'name', 'version']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['author', 'integrated_ind', 'name', 'version']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryDiagnostictask(InfobloxObject):
    """ DiscoveryDiagnostictask: The discovery diagnostic task object.
    Corresponds to WAPI object 'discovery:diagnostictask'

    The object provides information about the discovery diagnostic task.

    Attributes:
        community_string: The SNMP community string of the discovery
            diagnostic task.
        debug_snmp: The SNMP debug flag of the discovery diagnostic
            task.
        force_test: The force test flag of the discovery diagnostic
            task.
        ip_address: The IP address of the discovery diagnostic task.
        network_view: The network view name of the discovery diagnostic
            task.
        start_time: The time when the discovery diagnostic task was
            started.
        task_id: The ID of the discovery diagnostic task.
    """
    _infoblox_type = 'discovery:diagnostictask'
    _fields = ['community_string', 'debug_snmp', 'force_test', 'ip_address',
               'network_view', 'start_time', 'task_id']
    _search_for_update_fields = ['ip_address', 'network_view', 'task_id']
    _updateable_search_fields = ['ip_address', 'network_view', 'task_id']
    _all_searchable_fields = ['ip_address', 'network_view', 'task_id']
    _return_fields = ['ip_address', 'network_view', 'task_id']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryGridproperties(InfobloxObject):
    """ DiscoveryGridproperties: The Grid discovery properties object.
    Corresponds to WAPI object 'discovery:gridproperties'

    The object provides information about the Grid discovery properties.

    Attributes:
        advanced_polling_settings: Discovery advanced polling settings.
        advanced_sdn_polling_settings: Discovery advanced polling
            settings.
        advisor_settings: Advisor settings.
        auto_conversion_settings: Automatic conversion settings.
        basic_polling_settings: Discovery basic polling settings.
        basic_sdn_polling_settings: Discovery basic polling settings.
        cli_credentials: Discovery CLI credentials.
        discovery_blackout_setting: Discovery blackout setting.
        dns_lookup_option: The type of the devices the DNS processor
            operates on.
        dns_lookup_throttle: The percentage of available capacity the
            DNS processor operates at.Valid values are unsigned integer
            between 1 and 100, inclusive.
        enable_advisor: Advisor application enabled/disabled.
        enable_auto_conversion: The flag that enables automatic
            conversion of discovered data.
        enable_auto_updates: The flag that enables updating discovered
            data for managed objects.
        grid_name: The Grid name.
        ignore_conflict_duration: Determines the timeout to ignore the
            discovery conflict duration (in seconds).
        port_control_blackout_setting: Port control blackout setting.
        ports: Ports to scan.
        same_port_control_discovery_blackout: Determines if the same
            port control is used for discovery blackout.
        snmpv1v2_credentials: Discovery SNMP v1 and v2 credentials.
        snmpv3_credentials: Discovery SNMP v3 credentials.
        unmanaged_ips_limit: Limit of discovered unmanaged IP address
            which determines how frequently the user is notified about
            the new unmanaged IP address in a particular network.
        unmanaged_ips_timeout: Determines the timeout between two
            notifications (in seconds) about the new unmanaged IP
            address in a particular network. The value must be between
            60 seconds and the number of seconds remaining to Jan 2038.
        vrf_mapping_policy: The policy type used to define the behavior
            of the VRF mapping.
        vrf_mapping_rules: VRF mapping rules.
    """
    _infoblox_type = 'discovery:gridproperties'
    _fields = ['advanced_polling_settings', 'advanced_sdn_polling_settings',
               'advisor_settings', 'auto_conversion_settings',
               'basic_polling_settings', 'basic_sdn_polling_settings',
               'cli_credentials', 'discovery_blackout_setting',
               'dns_lookup_option', 'dns_lookup_throttle', 'enable_advisor',
               'enable_auto_conversion', 'enable_auto_updates', 'grid_name',
               'ignore_conflict_duration', 'port_control_blackout_setting',
               'ports', 'same_port_control_discovery_blackout',
               'snmpv1v2_credentials', 'snmpv3_credentials',
               'unmanaged_ips_limit', 'unmanaged_ips_timeout',
               'vrf_mapping_policy', 'vrf_mapping_rules']
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
    """ DiscoveryMemberproperties: The Grid discovery member properties
    object.
    Corresponds to WAPI object 'discovery:memberproperties'

    The object provides information about the Grid member discovery
    properties.

    Attributes:
        address: The Grid member address IP address.
        cli_credentials: Discovery CLI credentials.
        default_seed_routers: Default seed routers.
        discovery_member: The name of the network discovery Grid member.
        enable_service: Determines if the discovery service is enabled.
        gateway_seed_routers: Gateway seed routers.
        is_sa: Determines if the standalone mode for discovery network
            monitor is enabled or not.
        role: Discovery member role.
        scan_interfaces: Discovery networks to which the member is
            assigned.
        sdn_configs: List of SDN/SDWAN controller configurations.
        seed_routers: Seed routers.
        snmpv1v2_credentials: Discovery SNMP v1 and v2 credentials.
        snmpv3_credentials: Discovery SNMP v3 credentials.
        use_cli_credentials: Use flag for: cli_credentials
        use_snmpv1v2_credentials: Use flag for: snmpv1v2_credentials
        use_snmpv3_credentials: Use flag for: snmpv3_credentials
    """
    _infoblox_type = 'discovery:memberproperties'
    _fields = ['address', 'cli_credentials', 'default_seed_routers',
               'discovery_member', 'enable_service', 'gateway_seed_routers',
               'is_sa', 'role', 'scan_interfaces', 'sdn_configs',
               'seed_routers', 'snmpv1v2_credentials', 'snmpv3_credentials',
               'use_cli_credentials', 'use_snmpv1v2_credentials',
               'use_snmpv3_credentials']
    _search_for_update_fields = ['discovery_member']
    _updateable_search_fields = ['enable_service', 'is_sa', 'role']
    _all_searchable_fields = ['discovery_member', 'enable_service', 'is_sa',
                              'role']
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
    """ DiscoverySdnnetwork: The SDN network object.
    Corresponds to WAPI object 'discovery:sdnnetwork'

    This object provides information about the SDN networks. They are
    the elements of address space hierarchy discovered on SDN/SDWAN
    controllers

    Attributes:
        first_seen: Timestamp when this SDN network was first
            discovered.
        name: The name of the SDN network.
        network_view: The name of the network view assigned to this SDN
            network.
        source_sdn_config: Name of SDN configuration this network
            belongs to.
    """
    _infoblox_type = 'discovery:sdnnetwork'
    _fields = ['first_seen', 'name', 'network_view', 'source_sdn_config']
    _search_for_update_fields = ['name', 'network_view', 'source_sdn_config']
    _updateable_search_fields = []
    _all_searchable_fields = ['name', 'network_view', 'source_sdn_config']
    _return_fields = ['name', 'network_view', 'source_sdn_config']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryStatus(InfobloxObject):
    """ DiscoveryStatus: Discovery Status object.
    Corresponds to WAPI object 'discovery:status'

    The discovery status of discovered data

    Attributes:
        address: The IPv4 Address or IPv6 Address of the device.
        cli_collection_enabled: Indicates if CLI collection is enabled.
        cli_credential_info: The CLI credential status information of
            the device.
        existence_info: The existence status information of the device.
        fingerprint_enabled: Indicates if DHCP finterprinting is
            enabled.
        fingerprint_info: This DHCP finterprinting status information of
            the device.
        first_seen: The timestamp when the device was first discovered.
        last_action: The timestamp of the last detected interface
            property change.
        last_seen: The timestamp when the device was last discovered.
        last_timestamp: The timestamp of the last executed action for
            the device.
        name: The name of the device.
        network_view: The name of the network view in which this device
            resides.
        reachable_info: The reachable status information of the device.
        sdn_collection_enabled: Indicate whether SDN collection enabled
            for the device.
        sdn_collection_info: Device SDN collection status information.
        snmp_collection_enabled: Indicates if SNMP collection is
            enabled.
        snmp_collection_info: The SNMP collection status information of
            the device.
        snmp_credential_info: The SNMP credential status information of
            the device.
        status: The overall status of the device.
        type: The type of device.
    """
    _infoblox_type = 'discovery:status'
    _fields = ['address', 'cli_collection_enabled', 'cli_credential_info',
               'existence_info', 'fingerprint_enabled', 'fingerprint_info',
               'first_seen', 'last_action', 'last_seen', 'last_timestamp',
               'name', 'network_view', 'reachable_info',
               'sdn_collection_enabled', 'sdn_collection_info',
               'snmp_collection_enabled', 'snmp_collection_info',
               'snmp_credential_info', 'status', 'type']
    _search_for_update_fields = ['address', 'name', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'name', 'network_view']
    _return_fields = ['address', 'name', 'network_view', 'status']
    _remap = {}
    _shadow_fields = ['_ref']


class DiscoveryVrf(InfobloxObject):
    """ DiscoveryVrf: The VRF object.
    Corresponds to WAPI object 'discovery:vrf'

    This object provides information about the virtual network
    membership (VRF).

    Attributes:
        description: Additional information about the VRF.
        device: The device to which the VRF belongs.
        name: The name of the VRF.
        network_view: The name of the network view in which this VRF
            resides.
        route_distinguisher: The route distinguisher associated with the
            VRF.
    """
    _infoblox_type = 'discovery:vrf'
    _fields = ['description', 'device', 'name', 'network_view',
               'route_distinguisher']
    _search_for_update_fields = ['name', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['name', 'network_view']
    _return_fields = ['device', 'name', 'network_view', 'route_distinguisher']
    _remap = {}
    _shadow_fields = ['_ref']


class Discoverytask(InfobloxObject):
    """ Discoverytask: The discovery task object.
    Corresponds to WAPI object 'discoverytask'

    Represents the configuration of network discovery jobs.
    Configuration parameters have control over the behavior of network
    discovery jobs.

    Attributes:
        csv_file_name: The network discovery CSV file name.
        disable_ip_scanning: Determines whether IP scanning is disabled.
        disable_vmware_scanning: Determines whether VMWare scanning is
            disabled.
        discovery_task_oid: The discovery task identifier.
        member_name: The Grid member that runs the discovery.
        merge_data: Determines whether to replace or merge new data with
            existing data.
        mode: Network discovery scanning mode.
        network_view: Name of the network view in which target networks
            for network discovery reside.
        networks: The list of the networks on which the network
            discovery will be invoked.
        ping_retries: The number of times to perfrom ping for ICMP and
            FULL modes.
        ping_timeout: The ping timeout for ICMP and FULL modes.
        scheduled_run: The schedule setting for network discovery task.
        state: The network discovery process state.
        state_time: Time when the network discovery process state was
            last updated.
        status: The network discovery process descriptive status.
        status_time: The time when the network discovery process status
            was last updated.
        tcp_ports: The ports to scan for FULL and TCP modes.
        tcp_scan_technique: The TCP scan techinque for FULL and TCP
            modes.
        v_network_view: Name of the network view in which target
            networks for VMWare scanning reside.
        vservers: The list of VMware vSphere servers for VM discovery.
        warning: The network discovery process warning.
    """
    _infoblox_type = 'discoverytask'
    _fields = ['csv_file_name', 'disable_ip_scanning',
               'disable_vmware_scanning', 'discovery_task_oid', 'member_name',
               'merge_data', 'mode', 'network_view', 'networks',
               'ping_retries', 'ping_timeout', 'scheduled_run', 'state',
               'state_time', 'status', 'status_time', 'tcp_ports',
               'tcp_scan_technique', 'v_network_view', 'vservers', 'warning']
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
    """ Distributionschedule: Distribution schedule object.
    Corresponds to WAPI object 'distributionschedule'

    Distributing the software upgrade files involves unpacking the
    software files and loading the new software. When you distribute the
    files, the NIOS appliance loads the new software code into an
    alternative disk partition that overwrites any previously saved
    version of existing code. Therefore, starting the distribution
    disables the appliance from reverting to a release prior to the
    current version. The Grid Master distributes the software upgrade to
    each member in the Grid including itself.

    When you schedule a distribution, you schedule the distribution of
    the Grid Master as well as the upgrade groups, including the Default
    group. The Grid Master distribution must always occur before the
    distribution of the upgrade groups.

    The distribution schedule object provides configuration for
    scheduled distribution of the software, activation of the schedule,
    as well as date and time settings.

    Attributes:
        active: Determines whether the distribution schedule is active.
        start_time: The start time of the distribution.
        time_zone: Time zone of the distribution start time.
        upgrade_groups: The upgrade groups scheduling settings.
    """
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
    """ Dns64Group: DNS64 synthesis group object.
    Corresponds to WAPI object 'dns64group'

    To support the increasing number of IPv6 and dual-stack networks,
    Infoblox DNS servers now support DNS64, a mechanism that synthesizes
    AAAA records from A records when no AAAA records exist.

    The DNS64 synthesis group specifies the IPv6 prefix for the
    synthesized AAAA records. The Infoblox DNS server provides a default
    DNS64 synthesis group with the well-known prefix 64:ff9b::/96 which
    is reserved for representing IPv4 addresses in the IPv6 address
    space.

    Attributes:
        clients: Access Control settings that contain IPv4 and IPv6 DNS
            clients and networks to which the DNS server is allowed to
            send synthesized AAAA records with the specified IPv6
            prefix.
        comment: The descriptive comment for the DNS64 synthesis group
            object.
        disable: Determines whether the DNS64 synthesis group is
            disabled.
        enable_dnssec_dns64: Determines whether the DNS64 synthesis of
            AAAA records is enabled for DNS64 synthesis groups that
            request DNSSEC data.
        exclude: Access Control settings that contain IPv6 addresses or
            prefix ranges that cannot be used by IPv6-only hosts, such
            as IP addresses in the ::ffff:0:0/96 network. When DNS
            server retrieves an AAAA record that contains an IPv6
            address that matches an excluded address, it does not return
            the AAAA record. Instead it synthesizes an AAAA record from
            the A record.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        mapped: Access Control settings that contain IPv4 addresses and
            networks for which the DNS server can synthesize AAAA
            records with the specified prefix.
        name: The name of the DNS64 synthesis group object.
        prefix: The IPv6 prefix used for the synthesized AAAA records.
            The prefix length must be /32, /40, /48, /56, /64 or /96,
            and all bits beyond the specified length must be zero.
    """
    _infoblox_type = 'dns64group'
    _fields = ['clients', 'comment', 'disable', 'enable_dnssec_dns64',
               'exclude', 'extattrs', 'mapped', 'name', 'prefix']
    _search_for_update_fields = ['name']
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
    """ Dtc: DTC object.
    Corresponds to WAPI object 'dtc'

    This object can be used to control the DTC functionality of the
    appliance.

    Attributes:
    """
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
    """ DtcAllrecords: DTC AllRecords object.
    Corresponds to WAPI object 'dtc:allrecords'

    The DTC AllRecords object is a read-only synthetic object used to
    retrieve records that belong to a particular DTC server.

    Since this is a synthetic object, it is read-only by specifying
    search parameters, not by specifying a reference.

    Attributes:
        comment: The record comment.
        disable: The disable value determines if the record is disabled
            or not. "False" means the record is enabled.
        dtc_server: The name of the DTC Server object with which the
            record is associated.
        record: The record object, if supported by the WAPI. Otherwise,
            the value is "None".
        ttl: The TTL value of the record associated with the DTC
            AllRecords object.
        type: The record type. When searching for an unspecified record
            type, the search is performed for all records. On retrieval,
            the appliance returns "UNSUPPORTED" for unsupported records.
    """
    _infoblox_type = 'dtc:allrecords'
    _fields = ['comment', 'disable', 'dtc_server', 'record', 'ttl', 'type']
    _search_for_update_fields = ['dtc_server', 'type']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'dtc_server', 'type']
    _return_fields = ['comment', 'dtc_server', 'type']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcCertificate(InfobloxObject):
    """ DtcCertificate: DTC Certificate object.
    Corresponds to WAPI object 'dtc:certificate'

    These are DTC health monitor certificates.

    Attributes:
        certificate: Reference to underlying X509Certificate.
        in_use: Determines whether the certificate is in use or not.
    """
    _infoblox_type = 'dtc:certificate'
    _fields = ['certificate', 'in_use']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']


class DtcLbdn(InfobloxObject):
    """ DtcLbdn: DTC LBDN object.
    Corresponds to WAPI object 'dtc:lbdn'

    Load Balanced Domain Name (LBDN) is a Load balanced domain name
    record type, which is served by Infoblox Name Servers. LBDN is a
    qualified domain name associated with a specific service such as
    ftp.abc.com or www.abc.com.

    Attributes:
        auth_zones: List of linked auth zones.
        auto_consolidated_monitors: Flag for enabling auto managing DTC
            Consolidated Monitors on related DTC Pools.
        comment: Comment for the DTC LBDN; maximum 256 characters.
        disable: Determines whether the DTC LBDN is disabled or not.
            When this is set to False, the fixed address is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        health: The LBDN health information.
        lb_method: The load balancing method. Used to select pool.
        name: The display name of the DTC LBDN, not DNS related.
        patterns: LBDN wildcards for pattern match.
        persistence: Maximum time, in seconds, for which client specific
            LBDN responses will be cached. Zero specifies no caching.
        pools: The maximum time, in seconds, for which client specific
            LBDN responses will be cached. Zero specifies no caching.
        priority: The LBDN pattern match priority for "overlapping" DTC
            LBDN objects. LBDNs are "overlapping" if they are
            simultaneously assigned to a zone and have patterns that can
            match the same FQDN. The matching LBDN with highest priority
            (lowest ordinal) will be used.
        topology: The topology rules for TOPOLOGY method.
        ttl: The Time To Live (TTL) value for the DTC LBDN. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        types: The list of resource record types supported by LBDN.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'dtc:lbdn'
    _fields = ['auth_zones', 'auto_consolidated_monitors', 'comment',
               'disable', 'extattrs', 'health', 'lb_method', 'name',
               'patterns', 'persistence', 'pools', 'priority', 'topology',
               'ttl', 'types', 'use_ttl']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'pools': DtcPoolLink.from_dict,
    }


class DtcMonitor(InfobloxObject):
    """ DtcMonitor: DTC monitor object.
    Corresponds to WAPI object 'dtc:monitor'

    The DTC Monitor object is used to determine the health of a server
    by evaluating the response to a health request.

    Attributes:
        comment: Comment for this DTC monitor; maximum 256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        interval: The interval for a health check.
        monitor: The actual monitor object.
        name: The display name for this DTC monitor.
        port: The health monitor port value.
        retry_down: The number of how many times the server should
            appear as "DOWN" to be treated as dead after it was alive.
        retry_up: The number of many times the server should appear as
            "UP" to be treated as alive after it was dead.
        timeout: The timeout for a health check.
        type: The request transport type.
    """
    _infoblox_type = 'dtc:monitor'
    _fields = ['comment', 'extattrs', 'interval', 'monitor', 'name', 'port',
               'retry_down', 'retry_up', 'timeout', 'type']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorHttp(InfobloxObject):
    """ DtcMonitorHttp: DTC HTTP monitor object.
    Corresponds to WAPI object 'dtc:monitor:http'

    The DTC HTTP monitor object is used to determine the health of a
    HTTP service by first sending a specific http message to a server
    and then examining the response received from the server. The
    validation is successful if the received response matches the
    expected message.

    Attributes:
        ciphers: An optional cipher list for a secure HTTP/S connection.
        client_cert: An optional client certificate, supplied in a
            secure HTTP/S mode if present.
        comment: Comment for this DTC monitor; maximum 256 characters.
        content_check: The content check type.
        content_check_input: A portion of response to use as input for
            content check.
        content_check_op: A content check success criteria operator.
        content_check_regex: A content check regular expression.
        content_extract_group: A content extraction sub-expression to
            extract.
        content_extract_type: A content extraction expected type for the
            extracted data.
        content_extract_value: A content extraction value to compare
            with extracted result.
        enable_sni: Determines whether the Server Name Indication (SNI)
            for HTTPS monitor is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        interval: The interval for TCP health check.
        name: The display name for this DTC monitor.
        port: Port for TCP requests.
        request: An HTTP request to send.
        result: The type of an expected result.
        result_code: The expected return code.
        retry_down: The value of how many times the server should appear
            as down to be treated as dead after it was alive.
        retry_up: The value of how many times the server should appear
            as up to be treated as alive after it was dead.
        secure: The connection security status.
        timeout: The timeout for TCP health check in seconds.
        validate_cert: Determines whether the validation of the remote
            server's certificate is enabled.
    """
    _infoblox_type = 'dtc:monitor:http'
    _fields = ['ciphers', 'client_cert', 'comment', 'content_check',
               'content_check_input', 'content_check_op',
               'content_check_regex', 'content_extract_group',
               'content_extract_type', 'content_extract_value', 'enable_sni',
               'extattrs', 'interval', 'name', 'port', 'request', 'result',
               'result_code', 'retry_down', 'retry_up', 'secure', 'timeout',
               'validate_cert']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorIcmp(InfobloxObject):
    """ DtcMonitorIcmp: DTC ICMP monitor object.
    Corresponds to WAPI object 'dtc:monitor:icmp'

    The DTC ICMP monitor object is used to determine the health of a
    server by monitoring the response to an ICMP ping.

    Attributes:
        comment: Comment for this DTC monitor; maximum 256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        interval: The interval for TCP health check.
        name: The display name for this DTC monitor.
        retry_down: The value of how many times the server should appear
            as down to be treated as dead after it was alive.
        retry_up: The value of how many times the server should appear
            as up to be treated as alive after it was dead.
        timeout: The timeout for TCP health check in seconds.
    """
    _infoblox_type = 'dtc:monitor:icmp'
    _fields = ['comment', 'extattrs', 'interval', 'name', 'retry_down',
               'retry_up', 'timeout']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorPdp(InfobloxObject):
    """ DtcMonitorPdp: DTC PDP monitor object.
    Corresponds to WAPI object 'dtc:monitor:pdp'

    The DTC PDP monitor object is used to determine the health of a
    server by sending a PDP ECHO and considering a valid reply to mean
    that service is available.

    Attributes:
        comment: Comment for this DTC monitor; maximum 256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        interval: The interval for TCP health check.
        name: The display name for this DTC monitor.
        port: The port value for PDP requests.
        retry_down: The value of how many times the server should appear
            as down to be treated as dead after it was alive.
        retry_up: The value of how many times the server should appear
            as up to be treated as alive after it was dead.
        timeout: The timeout for TCP health check in seconds.
    """
    _infoblox_type = 'dtc:monitor:pdp'
    _fields = ['comment', 'extattrs', 'interval', 'name', 'port', 'retry_down',
               'retry_up', 'timeout']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorSip(InfobloxObject):
    """ DtcMonitorSip: DTC SIP monitor object.
    Corresponds to WAPI object 'dtc:monitor:sip'

    The DTC SIP monitor object is used to determine the health of a SIP
    server such as SIP Proxies and Session Border Controllers, and SIP
    gateways by issuing SIP options to a server and examining the
    response provided by the server. The service is considered available
    If the received response matches the expected response.

    Attributes:
        ciphers: An optional cipher list for secure TLS/SIPS connection.
        client_cert: An optional client certificate, supplied in TLS and
            SIPS mode if present.
        comment: Comment for this DTC monitor; maximum 256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        interval: The interval for TCP health check.
        name: The display name for this DTC monitor.
        port: The port value for SIP requests.
        request: A SIP request to send
        result: The type of an expected result.
        result_code: The expected return code value.
        retry_down: The value of how many times the server should appear
            as down to be treated as dead after it was alive.
        retry_up: The value of how many times the server should appear
            as up to be treated as alive after it was dead.
        timeout: The timeout for TCP health check in seconds.
        transport: The transport layer protocol to use for SIP check.
        validate_cert: Determines whether the validation of the remote
            server's certificate is enabled.
    """
    _infoblox_type = 'dtc:monitor:sip'
    _fields = ['ciphers', 'client_cert', 'comment', 'extattrs', 'interval',
               'name', 'port', 'request', 'result', 'result_code',
               'retry_down', 'retry_up', 'timeout', 'transport',
               'validate_cert']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcMonitorSnmp(InfobloxObject):
    """ DtcMonitorSnmp: DTC SNMP monitor object.
    Corresponds to WAPI object 'dtc:monitor:snmp'

    The DTC SNMP Health Monitor determines the health of SNMP servers,
    such as SNMP Proxies and Session Border Controllers, and SNMP
    gateways by issuing SNMP options to a server and examining the
    response sent by the server. The service is considered available if
    the returned response matches the expected response.

    Attributes:
        comment: Comment for this DTC monitor; maximum 256 characters.
        community: The SNMP community string for SNMP authentication.
        context: The SNMPv3 context.
        engine_id: The SNMPv3 engine identifier.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        interval: The interval for TCP health check.
        name: The display name for this DTC monitor.
        oids: A list of OIDs for SNMP monitoring.
        port: The port value for SNMP requests.
        retry_down: The value of how many times the server should appear
            as down to be treated as dead after it was alive.
        retry_up: The value of how many times the server should appear
            as up to be treated as alive after it was dead.
        timeout: The timeout for TCP health check in seconds.
        user: The SNMPv3 user setting.
        version: The SNMP protocol version for the SNMP health check.
    """
    _infoblox_type = 'dtc:monitor:snmp'
    _fields = ['comment', 'community', 'context', 'engine_id', 'extattrs',
               'interval', 'name', 'oids', 'port', 'retry_down', 'retry_up',
               'timeout', 'user', 'version']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'context', 'engine_id', 'name']
    _all_searchable_fields = ['comment', 'context', 'engine_id', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'oids': DtcMonitorSnmpOid.from_dict,
    }


class DtcMonitorTcp(InfobloxObject):
    """ DtcMonitorTcp: DTC TCP monitor object.
    Corresponds to WAPI object 'dtc:monitor:tcp'

    The DTC TCP monitor object is used to determine the health of a
    server by evaluating the response to a TCP request.

    Attributes:
        comment: Comment for this DTC monitor; maximum 256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        interval: The interval for TCP health check.
        name: The display name for this DTC monitor.
        port: The port value for TCP requests.
        retry_down: The value of how many times the server should appear
            as down to be treated as dead after it was alive.
        retry_up: The value of how many times the server should appear
            as up to be treated as alive after it was dead.
        timeout: The timeout for TCP health check in seconds.
    """
    _infoblox_type = 'dtc:monitor:tcp'
    _fields = ['comment', 'extattrs', 'interval', 'name', 'port', 'retry_down',
               'retry_up', 'timeout']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcObject(InfobloxObject):
    """ DtcObject: DTC object.
    Corresponds to WAPI object 'dtc:object'

    An object for all load balancer managed DTC objects.

    Attributes:
        abstract_type: The abstract object type.
        comment: The comment for the DTC object; maximum 256 characters.
        display_type: The display object type.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv4_address_list: The list of IPv4 addresses.
        ipv6_address_list: The list of IPv6 addresses.
        name: The display name of the DTC object.
        object: The specific DTC object.
        status: The availability color status.
        status_time: The timestamp when status or health was last
            determined.
    """
    _infoblox_type = 'dtc:object'
    _fields = ['abstract_type', 'comment', 'display_type', 'extattrs',
               'ipv4_address_list', 'ipv6_address_list', 'name', 'object',
               'status', 'status_time']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['abstract_type', 'comment', 'display_type', 'extattrs',
                      'name', 'status']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcPool(InfobloxObject):
    """ DtcPool: DTC Pool object.
    Corresponds to WAPI object 'dtc:pool'

    The collection of IDNS resources (virtual servers).

    Attributes:
        auto_consolidated_monitors: Flag for enabling auto managing DTC
            Consolidated Monitors in DTC Pool.
        availability: A resource in the pool is available if ANY, at
            least QUORUM, or ALL monitors for the pool say that it is
            up.
        comment: The comment for the DTC Pool; maximum 256 characters.
        consolidated_monitors: List of monitors and associated members
            statuses of which are shared across members and consolidated
            in server availability determination.
        disable: Determines whether the DTC Pool is disabled or not.
            When this is set to False, the fixed address is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        health: The health status.
        lb_alternate_method: The alternate load balancing method. Use
            this to select a method type from the pool if the preferred
            method does not return any results.
        lb_alternate_topology: The alternate topology for load
            balancing.
        lb_dynamic_ratio_alternate: The DTC Pool settings for dynamic
            ratio when it's selected as alternate method.
        lb_dynamic_ratio_preferred: The DTC Pool settings for dynamic
            ratio when it's selected as preferred method.
        lb_preferred_method: The preferred load balancing method. Use
            this to select a method type from the pool.
        lb_preferred_topology: The preferred topology for load
            balancing.
        monitors: The monitors related to pool.
        name: The DTC Pool display name.
        quorum: For availability mode QUORUM, at least this many
            monitors must report the resource as up for it to be
            available
        servers: The servers related to the pool.
        ttl: The Time To Live (TTL) value for the DTC Pool. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'dtc:pool'
    _fields = ['auto_consolidated_monitors', 'availability', 'comment',
               'consolidated_monitors', 'disable', 'extattrs', 'health',
               'lb_alternate_method', 'lb_alternate_topology',
               'lb_dynamic_ratio_alternate', 'lb_dynamic_ratio_preferred',
               'lb_preferred_method', 'lb_preferred_topology', 'monitors',
               'name', 'quorum', 'servers', 'ttl', 'use_ttl']
    _search_for_update_fields = ['name']
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
    """ ADtcRecord: DTC A Record object.
    Corresponds to WAPI object 'dtc:record:a'

    A DTC A object represents a DNS Traffic Control Address (DTC A)
    resource record. This resource record specifies mapping from domain
    name to IPv4 address.

    Attributes:
        auto_created: Flag that indicates whether this record was
            automatically created by NIOS.
        comment: Comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dtc_server: The name of the DTC Server object with which the DTC
            record is associated.
        ipv4addr: The IPv4 Address of the domain name.
        ttl: The Time to Live (TTL) value.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'dtc:record:a'
    _fields = ['auto_created', 'comment', 'disable', 'dtc_server', 'ipv4addr',
               'ttl', 'use_ttl']
    _search_for_update_fields = ['dtc_server', 'ipv4addr']
    _updateable_search_fields = ['comment', 'ipv4addr']
    _all_searchable_fields = ['comment', 'dtc_server', 'ipv4addr']
    _return_fields = ['dtc_server', 'ipv4addr']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 4


class AAAADtcRecord(ADtcRecordBase):
    """ AAAADtcRecord: DTC AAAA Record object.
    Corresponds to WAPI object 'dtc:record:aaaa'

    A DTC AAAA object represents a DNS Traffic Control IPv6 Address (DTC
    AAAA) resource record. This resource record specifies mapping from
    domain name to IPv6 address.

    Attributes:
        auto_created: Flag that indicates whether this record was
            automatically created by NIOS.
        comment: Comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dtc_server: The name of the DTC Server object with which the DTC
            record is associated.
        ipv6addr: The IPv6 Address of the domain name.
        ttl: The Time to Live (TTL) value.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'dtc:record:aaaa'
    _fields = ['auto_created', 'comment', 'disable', 'dtc_server', 'ipv6addr',
               'ttl', 'use_ttl']
    _search_for_update_fields = ['dtc_server', 'ipv6addr']
    _updateable_search_fields = ['comment', 'ipv6addr']
    _all_searchable_fields = ['comment', 'dtc_server', 'ipv6addr']
    _return_fields = ['dtc_server', 'ipv6addr']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 6


class CNAMEDtcRecord(InfobloxObject):
    """ CNAMEDtcRecord: DTC CNAME Record object.
    Corresponds to WAPI object 'dtc:record:cname'

    A DTC CNAME object represents a DNS Traffic Control Canonical name
    (DTC CNAME) resource record. DTC CNAME record maps domain name alias
    to its canonical domain name.

    Attributes:
        auto_created: Flag that indicates whether this record was
            automatically created by NIOS.
        canonical: The canonical name of the host.
        comment: Comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dns_canonical: The canonical name as server by DNS protocol.
        dtc_server: The name of the DTC Server object with which the DTC
            record is associated.
        ttl: The Time to Live (TTL) value.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'dtc:record:cname'
    _fields = ['auto_created', 'canonical', 'comment', 'disable',
               'dns_canonical', 'dtc_server', 'ttl', 'use_ttl']
    _search_for_update_fields = ['canonical', 'dtc_server']
    _updateable_search_fields = ['canonical', 'comment']
    _all_searchable_fields = ['canonical', 'comment', 'dtc_server']
    _return_fields = ['canonical', 'dtc_server']
    _remap = {}
    _shadow_fields = ['_ref']


class NaptrDtcRecord(InfobloxObject):
    """ NaptrDtcRecord: DTC NAPTR Record object.
    Corresponds to WAPI object 'dtc:record:naptr'

    A DTC NAPTR object represents a DNS Traffic Control Naming Authority
    Pointer (DTC NAPTR) resource record. This resource record specifies
    a regular expression-based rewrite rule that, when applied to an
    existing string, produces a new domain name or URI.

    Attributes:
        comment: Comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dtc_server: The name of the DTC Server object with which the DTC
            record is associated.
        flags: The flags used to control the interpretation of the
            fields for an NAPTR record object. Supported values for the
            flags field are "U", "S", "P" and "A".
        order: The order parameter of the NAPTR records. This parameter
            specifies the order in which the NAPTR rules are applied
            when multiple rules are present. Valid values are from 0 to
            65535 (inclusive), in 32-bit unsigned integer format.
        preference: The preference of the NAPTR record. The preference
            field determines the order the NAPTR records are processed
            when multiple records with the same order parameter are
            present. Valid values are from 0 to 65535 (inclusive), in
            32-bit unsigned integer format.
        regexp: The regular expression-based rewriting rule of the NAPTR
            record. This should be a POSIX compliant regular expression,
            including the substitution rule and flags. Refer to RFC 2915
            for the field syntax details.
        replacement: The replacement field of the NAPTR record object.
            For nonterminal NAPTR records, this field specifies the next
            domain name to look up. This value can be in unicode format.
        services: The services field of the NAPTR record object; maximum
            128 characters. The services field contains protocol and
            service identifiers, such as "http+E2U" or "SIPS+D2T".
        ttl: The Time to Live (TTL) value.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'dtc:record:naptr'
    _fields = ['comment', 'disable', 'dtc_server', 'flags', 'order',
               'preference', 'regexp', 'replacement', 'services', 'ttl',
               'use_ttl']
    _search_for_update_fields = ['dtc_server', 'order', 'preference',
                                 'replacement', 'services']
    _updateable_search_fields = ['comment', 'flags', 'order', 'preference',
                                 'replacement', 'services']
    _all_searchable_fields = ['comment', 'dtc_server', 'flags', 'order',
                              'preference', 'replacement', 'services']
    _return_fields = ['dtc_server', 'order', 'preference', 'regexp',
                      'replacement', 'services']
    _remap = {}
    _shadow_fields = ['_ref']


class SRVDtcRecord(InfobloxObject):
    """ SRVDtcRecord: DTC SRV Record object.
    Corresponds to WAPI object 'dtc:record:srv'

    A DTC SRV object represents a DNS Traffic Control (DTC SRV) resource
    record. This resource record provides information on available
    services.

    Attributes:
        comment: Comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dtc_server: The name of the DTC Server object with which the DTC
            record is associated.
        name: The name for an SRV record in unicode format.
        port: The port of the SRV record. Valid values are from 0 to
            65535 (inclusive), in 32-bit unsigned integer format.
        priority: The priority of the SRV record. Valid values are from
            0 to 65535 (inclusive), in 32-bit unsigned integer format.
        target: The target of the SRV record in FQDN format. This value
            can be in unicode format.
        ttl: The Time to Live (TTL) value.
        use_ttl: Use flag for: ttl
        weight: The weight of the SRV record. Valid values are from 0 to
            65535 (inclusive), in 32-bit unsigned integer format.
    """
    _infoblox_type = 'dtc:record:srv'
    _fields = ['comment', 'disable', 'dtc_server', 'name', 'port', 'priority',
               'target', 'ttl', 'use_ttl', 'weight']
    _search_for_update_fields = ['dtc_server', 'name', 'port', 'priority',
                                 'target', 'weight']
    _updateable_search_fields = ['comment', 'name', 'port', 'priority',
                                 'target', 'weight']
    _all_searchable_fields = ['comment', 'dtc_server', 'name', 'port',
                              'priority', 'target', 'weight']
    _return_fields = ['dtc_server', 'name', 'port', 'priority', 'target',
                      'weight']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcServer(InfobloxObject):
    """ DtcServer: DTC Server object.
    Corresponds to WAPI object 'dtc:server'

    This is a DTC Server. Aka resource, virtual server or pool member.

    Attributes:
        auto_create_host_record: Enabling this option will auto-create a
            single read-only A/AAAA/CNAME record corresponding to the
            configured hostname and update it if the hostname changes.
        comment: Comment for the DTC Server; maximum 256 characters.
        disable: Determines whether the DTC Server is disabled or not.
            When this is set to False, the fixed address is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        health: The health status.
        host: The address or FQDN of the server.
        monitors: List of IP/FQDN and monitor pairs to be used for
            additional monitoring.
        name: The DTC Server display name.
        sni_hostname: The hostname for Server Name Indication (SNI) in
            FQDN format.
        use_sni_hostname: Use flag for: sni_hostname
    """
    _infoblox_type = 'dtc:server'
    _fields = ['auto_create_host_record', 'comment', 'disable', 'extattrs',
               'health', 'host', 'monitors', 'name', 'sni_hostname',
               'use_sni_hostname']
    _search_for_update_fields = ['host', 'name']
    _updateable_search_fields = ['comment', 'host', 'name', 'sni_hostname']
    _all_searchable_fields = ['comment', 'host', 'name', 'sni_hostname']
    _return_fields = ['comment', 'extattrs', 'host', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'monitors': DtcServerMonitor.from_dict,
    }


class DtcTopology(InfobloxObject):
    """ DtcTopology: DTC Topology object.
    Corresponds to WAPI object 'dtc:topology'

    A topology is a named list of ordered topology rules. Topology rules
    map client IPs to pools or resources. They require the Topology DB
    and named labels refer to it.

    Attributes:
        comment: The comment for the DTC TOPOLOGY monitor object;
            maximum 256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: Display name of the DTC Topology.
        rules: Topology rules.
    """
    _infoblox_type = 'dtc:topology'
    _fields = ['comment', 'extattrs', 'name', 'rules']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcTopologyLabel(InfobloxObject):
    """ DtcTopologyLabel: DTC Topology Label object.
    Corresponds to WAPI object 'dtc:topology:label'

    This is the label of the field in the Topology database.

    Attributes:
        field: The name of the field in the Topology database the label
            was obtained from.
        label: The DTC Topology label name.
    """
    _infoblox_type = 'dtc:topology:label'
    _fields = ['field', 'label']
    _search_for_update_fields = ['field', 'label']
    _updateable_search_fields = []
    _all_searchable_fields = ['field', 'label']
    _return_fields = ['field', 'label']
    _remap = {}
    _shadow_fields = ['_ref']


class DtcTopologyRule(InfobloxObject):
    """ DtcTopologyRule: DTC Topology Rule object.
    Corresponds to WAPI object 'dtc:topology:rule'

    Topology rules map client IPs to pools or resources. They require
    the Topology DB and named labels refer to it. Can be created only as
    part of topology.

    Attributes:
        dest_type: The type of the destination for this DTC Topology
            rule.
        destination_link: The reference to the destination DTC pool or
            DTC server.
        return_type: Type of the DNS response for rule.
        sources: The conditions for matching sources. Should be empty to
            set rule as default destination.
        topology: The DTC Topology the rule belongs to.
        valid: True if the label in the rule exists in the current
            Topology DB. Always true for SUBNET rules. Rules with non-
            existent labels may be configured but will never match.
    """
    _infoblox_type = 'dtc:topology:rule'
    _fields = ['dest_type', 'destination_link', 'return_type', 'sources',
               'topology', 'valid']
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
    """ DxlEndpoint: The Data Exchange Layer endpoint object.
    Corresponds to WAPI object 'dxl:endpoint'

    The DXL endpoint object represents the settings of a particular DXL
    endpoint.

    Attributes:
        brokers: The list of DXL endpoint brokers. Note that you cannot
            specify brokers and brokers_import_token at the same time.
        brokers_import_token: The token returned by the uploadinit
            function call in object fileop for a DXL broker
            configuration file. Note that you cannot specify brokers and
            brokers_import_token at the same time.
        client_certificate_subject: The client certificate subject of a
            DXL endpoint.
        client_certificate_token: The token returned by the uploadinit
            function call in object fileop for a DXL endpoint client
            certificate.
        client_certificate_valid_from: The timestamp when client
            certificate for a DXL endpoint was created.
        client_certificate_valid_to: The timestamp when the client
            certificate for a DXL endpoint expires.
        comment: The comment of a DXL endpoint.
        disable: Determines whether a DXL endpoint is disabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        log_level: The log level for a DXL endpoint.
        name: The name of a DXL endpoint.
        outbound_member_type: The outbound member that will generate
            events.
        outbound_members: The list of members for outbound events.
        template_instance: The DXL template instance. You cannot change
            the parameters of the DXL endpoint template instance.
        timeout: The timeout of session management (in seconds).
        topics: DXL topics
        vendor_identifier: The vendor identifier.
        wapi_user_name: The user name for WAPI integration.
        wapi_user_password: The user password for WAPI integration.
    """
    _infoblox_type = 'dxl:endpoint'
    _fields = ['brokers', 'brokers_import_token', 'client_certificate_subject',
               'client_certificate_token', 'client_certificate_valid_from',
               'client_certificate_valid_to', 'comment', 'disable', 'extattrs',
               'log_level', 'name', 'outbound_member_type', 'outbound_members',
               'template_instance', 'timeout', 'topics', 'vendor_identifier',
               'wapi_user_name', 'wapi_user_password']
    _search_for_update_fields = ['name', 'outbound_member_type']
    _updateable_search_fields = ['log_level', 'name', 'outbound_member_type',
                                 'vendor_identifier']
    _all_searchable_fields = ['log_level', 'name', 'outbound_member_type',
                              'vendor_identifier']
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
    """ EADefinition: Extensible Attribute Definition object.
    Corresponds to WAPI object 'extensibleattributedef'

    The Extensible Attribute Definition object is used to retrieve the
    definition of an extensible attribute.

    Defined attributes can be associated with other Infoblox objects:
    DHCP Fixed Address, DHCP Fixed Address Template, DHCP Network, DHCP
    Network Template, DHCP Range, DHCP Range Template, DNS Host, DHCP
    Failover and DNS Zone objects that support extensible attributes

    Attributes:
        allowed_object_types: The object types this extensible attribute
            is allowed to associate with.
        comment: Comment for the Extensible Attribute Definition;
            maximum 256 characters.
        default_value: Default value used to pre-populate the attribute
            value in the GUI. For email, URL, and string types, the
            value is a string with a maximum of 256 characters. For an
            integer, the value is an integer from -2147483648 through
            2147483647. For a date, the value is the number of seconds
            that have elapsed since January 1st, 1970 UTC.
        descendants_action: This option describes the action that must
            be taken on the extensible attribute by its descendant in
            case the 'Inheritable' flag is set.
        flags: This field contains extensible attribute flags. Possible
            values: (A)udited, (C)loud API, Cloud (G)master,
            (I)nheritable, (L)isted, (M)andatory value, MGM (P)rivate,
            (R)ead Only, (S)ort enum values, Multiple (V)alues If there
            are two or more flags in the field, you must list them
            according to the order they are listed above.For example,
            'CR' is a valid value for the 'flags' field because C =
            Cloud API is listed before R = Read only. However, the value
            'RC' is invalid because the order for the 'flags' field is
            broken.
        list_values: List of Values. Applicable if the extensible
            attribute type is ENUM.
        max: Maximum allowed value of extensible attribute. Applicable
            if the extensible attribute type is INTEGER.
        min: Minimum allowed value of extensible attribute. Applicable
            if the extensible attribute type is INTEGER.
        name: The name of the Extensible Attribute Definition.
        namespace: Namespace for the Extensible Attribute Definition.
        type: Type for the Extensible Attribute Definition.
    """
    _infoblox_type = 'extensibleattributedef'
    _fields = ['allowed_object_types', 'comment', 'default_value',
               'descendants_action', 'flags', 'list_values', 'max', 'min',
               'name', 'namespace', 'type']
    _search_for_update_fields = ['name', 'type']
    _updateable_search_fields = ['comment', 'name', 'type']
    _all_searchable_fields = ['comment', 'name', 'namespace', 'type']
    _return_fields = ['comment', 'default_value', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'list_values': ExtensibleattributedefListvalues.from_dict,
    }


class Fileop(InfobloxObject):
    """ Fileop: File operations object.
    Corresponds to WAPI object 'fileop'

    This object controls uploading and downloading data from the
    appliance.

    Attributes:
    """
    _infoblox_type = 'fileop'
    _fields = []
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    def upload_file(self, *args, **kwargs):
        return self.connector.upload_file(*args, **kwargs)

    def download_file(self, *args, **kwargs):
        return self.connector.download_file(*args, **kwargs)

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
        return self._call_func("get_last_uploaded_atp_ruleset", *args,
                               **kwargs)

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
        return self._call_func("restapi_template_export_schema", *args,
                               **kwargs)

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
        return self._call_func("set_last_uploaded_atp_ruleset", *args,
                               **kwargs)

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
    """ Filterfingerprint: DHCP Fingerprint Filter object.
    Corresponds to WAPI object 'filterfingerprint'

    The appliance can filter an address request by the DHCP fingerprint
    of a requesting client. Depending on how you apply DHCP fingerprint
    filters, the appliance can grant or deny the address request if the
    requesting client matches the filter criteria.

    Only superuser can add/modify/delete fingerprint filters.

    Attributes:
        comment: The descriptive comment.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        fingerprint: The list of DHCP Fingerprint objects.
        name: The name of a DHCP Fingerprint Filter object.
    """
    _infoblox_type = 'filterfingerprint'
    _fields = ['comment', 'extattrs', 'fingerprint', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Filtermac(InfobloxObject):
    """ Filtermac: DHCP MAC Address Filter object.
    Corresponds to WAPI object 'filtermac'

    An Infoblox appliance can filter address requests by the MAC address
    and/or vendor prefix (i.e., the first 6 hexadecimal characters of
    the MAC address) of a requesting host. The filter instructs the
    appliance to either grant or deny an address request if the
    requesting host matches the filter.

    Attributes:
        comment: The descriptive comment of a DHCP MAC Filter object.
        default_mac_address_expiration: The default MAC expiration time
            of the DHCP MAC Address Filter object.By default, the MAC
            address filter never expires; otherwise, it is the absolute
            interval when the MAC address filter expires. The maximum
            value can extend up to 4294967295 secs. The minimum value is
            60 secs (1 min).
        disable: Determines if the DHCP Fingerprint object is disabled
            or not.
        enforce_expiration_times: The flag to enforce MAC address
            expiration of the DHCP MAC Address Filter object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        lease_time: The length of time the DHCP server leases an IP
            address to a client. The lease time applies to hosts that
            meet the filter criteria.
        name: The name of a DHCP MAC Filter object.
        never_expires: Determines if DHCP MAC Filter never expires or
            automatically expires.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        reserved_for_infoblox: This is reserved for writing comments
            related to the particular MAC address filter. The length of
            comment cannot exceed 1024 bytes.
    """
    _infoblox_type = 'filtermac'
    _fields = ['comment', 'default_mac_address_expiration', 'disable',
               'enforce_expiration_times', 'extattrs', 'lease_time', 'name',
               'never_expires', 'options', 'reserved_for_infoblox']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'options': DhcpOption.from_dict,
    }


class Filternac(InfobloxObject):
    """ Filternac: DHCP NAC Filter object.
    Corresponds to WAPI object 'filternac'

    If NAC authentication is configured, the appliance receives
    authentication responses from NAC authentication servers, and it
    grants or denies a lease request if the authentication response
    matches conditions defined by the NAC filters.

    Only superuser can add/modify/delete NAC filters.

    Attributes:
        comment: The descriptive comment of a DHCP NAC Filter object.
        expression: The conditional expression of a DHCP NAC Filter
            object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        lease_time: The length of time the DHCP server leases an IP
            address to a client. The lease time applies to hosts that
            meet the filter criteria.
        name: The name of a DHCP NAC Filter object.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
    """
    _infoblox_type = 'filternac'
    _fields = ['comment', 'expression', 'extattrs', 'lease_time', 'name',
               'options']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'options': DhcpOption.from_dict,
    }


class Filteroption(InfobloxObject):
    """ Filteroption: DHCP filter option object.
    Corresponds to WAPI object 'filteroption'

    In the ISC DHCP terms, it defines a class of clients that match a
    particular (option, value) pair. To define an option filter, add
    Option to the DHCP Filter object.

    Only superuser can add/modify/delete option filters.

    Attributes:
        apply_as_class: Determines if apply as class is enabled or not.
            If this flag is set to "true" the filter is treated as
            global DHCP class, e.g it is written to dhcpd config file
            even if it is not present in any DHCP range.
        bootfile: A name of boot file of a DHCP filter option object.
        bootserver: Determines the boot server of a DHCP filter option
            object. You can specify the name and/or IP address of the
            boot server that host needs to boot.
        comment: The descriptive comment of a DHCP filter option object.
        expression: The conditional expression of a DHCP filter option
            object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        lease_time: Determines the lease time of a DHCP filter option
            object.
        name: The name of a DHCP option filter object.
        next_server: Determines the next server of a DHCP filter option
            object. You can specify the name and/or IP address of the
            next server that the host needs to boot.
        option_list: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        option_space: The option space of a DHCP filter option object.
        pxe_lease_time: Determines the PXE (Preboot Execution
            Environment) lease time of a DHCP filter option object. To
            specify the duration of time it takes a host to connect to a
            boot server, such as a TFTP server, and download the file it
            needs to boot.
    """
    _infoblox_type = 'filteroption'
    _fields = ['apply_as_class', 'bootfile', 'bootserver', 'comment',
               'expression', 'extattrs', 'lease_time', 'name', 'next_server',
               'option_list', 'option_space', 'pxe_lease_time']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'option_list': DhcpOption.from_dict,
    }


class Filterrelayagent(InfobloxObject):
    """ Filterrelayagent: The filter relay agent object.
    Corresponds to WAPI object 'filterrelayagent'

    The Infoblox appliance can screen address requests through relay
    agent filters (DHCP option 82) that assist the agents in forwarding
    address assignments across the proper circuit. When a relay agent
    receives the DHCPDISCOVER message, it can add one or two agent IDs
    in the DHCP option 82 suboption fields to the message. If the agent
    ID strings match those defined in a relay agent filter applied to a
    DHCP address range, the Infoblox appliance either assigns addresses
    from that range or denies the request (based on previously
    configured parameters; that is, the Grant lease and Deny lease
    parameters).

    Attributes:
        circuit_id_name: The circuit_id_name of a DHCP relay agent
            filter object. This filter identifies the circuit between
            the remote host and the relay agent. For example, the
            identifier can be the ingress interface number of the
            circuit access unit, perhaps concatenated with the unit ID
            number and slot number. Also, the circuit ID can be an ATM
            virtual circuit ID or cable data virtual circuit ID.
        circuit_id_substring_length: The circuit ID substring length.
        circuit_id_substring_offset: The circuit ID substring offset.
        comment: A descriptive comment of a DHCP relay agent filter
            object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        is_circuit_id: The circuit ID matching rule of a DHCP relay
            agent filter object. The circuit_id value takes effect only
            if the value is "MATCHES_VALUE".
        is_circuit_id_substring: Determines if the substring of circuit
            ID, instead of the full circuit ID, is matched.
        is_remote_id: The remote ID matching rule of a DHCP relay agent
            filter object. The remote_id value takes effect only if the
            value is Matches_Value.
        is_remote_id_substring: Determines if the substring of remote
            ID, instead of the full remote ID, is matched.
        name: The name of a DHCP relay agent filter object.
        remote_id_name: The remote ID name attribute of a relay agent
            filter object. This filter identifies the remote host. The
            remote ID name can represent many different things such as
            the caller ID telephone number for a dial-up connection, a
            user name for logging in to the ISP, a modem ID, etc. When
            the remote ID name is defined on the relay agent, the DHCP
            server will have a trusted relationship to identify the
            remote host. The remote ID name is considered as a trusted
            identifier.
        remote_id_substring_length: The remote ID substring length.
        remote_id_substring_offset: The remote ID substring offset.
    """
    _infoblox_type = 'filterrelayagent'
    _fields = ['circuit_id_name', 'circuit_id_substring_length',
               'circuit_id_substring_offset', 'comment', 'extattrs',
               'is_circuit_id', 'is_circuit_id_substring', 'is_remote_id',
               'is_remote_id_substring', 'name', 'remote_id_name',
               'remote_id_substring_length', 'remote_id_substring_offset']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Fingerprint(InfobloxObject):
    """ Fingerprint: DHCP Fingerprint object.
    Corresponds to WAPI object 'fingerprint'

    The DHCP Fingerprint object is part of the Fingerprint filter.

    Only 'CUSTOM' fingerprint can be added or modified. The 'STANDARD'
    fingerprint can be disabled only.

    Attributes:
        comment: Comment for the Fingerprint; maximum 256 characters.
        device_class: A class of DHCP Fingerprint object; maximum 256
            characters.
        disable: Determines if the DHCP Fingerprint object is disabled
            or not.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv6_option_sequence: A list (comma separated list) of IPv6
            option number sequences of the device or operating system.
        name: Name of the DHCP Fingerprint object.
        option_sequence: A list (comma separated list) of IPv4 option
            number sequences of the device or operating system.
        type: The type of the DHCP Fingerprint object.
        vendor_id: A list of vendor IDs of the device or operating
            system.
    """
    _infoblox_type = 'fingerprint'
    _fields = ['comment', 'device_class', 'disable', 'extattrs',
               'ipv6_option_sequence', 'name', 'option_sequence', 'type',
               'vendor_id']
    _search_for_update_fields = ['device_class', 'name']
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
    """ FixedAddressV4: DHCP Fixed Address object.
    Corresponds to WAPI object 'fixedaddress'

    A fixed address is a specific IP address that a DHCP server always
    assigns when a lease request comes from a particular MAC address of
    the client.

    Attributes:
        agent_circuit_id: The agent circuit ID for the fixed address.
        agent_remote_id: The agent remote ID for the fixed address.
        allow_telnet: This field controls whether the credential is used
            for both the Telnet and SSH credentials. If set to False,
            the credential is used only for SSH.
        always_update_dns: This field controls whether only the DHCP
            server is allowed to update DNS, regardless of the DHCP
            client requests.
        bootfile: The bootfile name for the fixed address. You can
            configure the DHCP server to support clients that use the
            boot file name option in their DHCPREQUEST messages.
        bootserver: The bootserver address for the fixed address. You
            can specify the name and/or IP address of the boot server
            that the host needs to boot.The boot server IPv4 Address or
            name in FQDN format.
        cli_credentials: The CLI credentials for the fixed address.
        client_identifier_prepend_zero: This field controls whether
            there is a prepend for the dhcp-client-identifier of a fixed
            address.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the fixed address; maximum 256 characters.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this fixed address.
        ddns_hostname: The DDNS host name for this fixed address.
        deny_bootp: If set to true, BOOTP settings are disabled and
            BOOTP requests will be denied.
        device_description: The description of the device.
        device_location: The location of the device.
        device_type: The type of the device.
        device_vendor: The vendor of the device.
        dhcp_client_identifier: The DHCP client ID for the fixed
            address.
        disable: Determines whether a fixed address is disabled or not.
            When this is set to False, the fixed address is enabled.
        disable_discovery: Determines if the discovery for this fixed
            address is disabled or not. False means that the discovery
            is enabled.
        discover_now_status: The discovery status of this fixed address.
        discovered_data: The discovered data for this fixed address.
        enable_ddns: The dynamic DNS updates flag of a DHCP Fixed
            Address object. If set to True, the DHCP server sends DDNS
            updates to DNS servers in the same Grid, and to external DNS
            servers.
        enable_immediate_discovery: Determines if the discovery for the
            fixed address should be immediately enabled.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ignore_dhcp_option_list_request: If this field is set to False,
            the appliance returns all DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        ipv4addr: The IPv4 Address of the fixed address.
        is_invalid_mac: This flag reflects whether the MAC address for
            this fixed address is invalid.
        logic_filter_rules: This field contains the logic filters to be
            applied on the this fixed address.This list corresponds to
            the match rules that are written to the dhcpd configuration
            file.
        mac: The MAC address value for this fixed address.
        match_client: The match_client value for this fixed address.
            Valid values are:"MAC_ADDRESS": The fixed IP address is
            leased to the matching MAC address."CLIENT_ID": The fixed IP
            address is leased to the matching DHCP client
            identifier."RESERVED": The fixed IP address is reserved for
            later use with a MAC address that only has
            zeros."CIRCUIT_ID": The fixed IP address is leased to the
            DHCP client with a matching circuit ID. Note that the
            "agent_circuit_id" field must be set in this
            case."REMOTE_ID": The fixed IP address is leased to the DHCP
            client with a matching remote ID. Note that the
            "agent_remote_id" field must be set in this case.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        ms_options: This field contains the Microsoft DHCP options for
            this fixed address.
        ms_server: The Microsoft server associated with this fixed
            address.
        name: This field contains the name of this fixed address.
        network: The network to which this fixed address belongs, in
            IPv4 Address/CIDR format.
        network_view: The name of the network view in which this fixed
            address resides.
        nextserver: The name in FQDN and/or IPv4 Address format of the
            next server that the host needs to boot.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        pxe_lease_time: The PXE lease time value for a DHCP Fixed
            Address object. Some hosts use PXE (Preboot Execution
            Environment) to boot remotely from a server. To better
            manage your IP resources, set a different lease time for PXE
            boot requests. You can configure the DHCP server to allocate
            an IP address with a shorter lease time to hosts that send
            PXE boot requests, so IP addresses are not leased longer
            than necessary.A 32-bit unsigned integer that represents the
            duration, in seconds, for which the update is cached. Zero
            indicates that the update is not cached.
        reserved_interface: The ref to the reserved interface to which
            the device belongs.
        restart_if_needed: Restarts the member service. The
            restart_if_needed flag can trigger a restart on DHCP
            services only when it is enabled on CP member.
        snmp3_credential: The SNMPv3 credential for this fixed address.
        snmp_credential: The SNMPv1 or SNMPv2 credential for this fixed
            address.
        template: If set on creation, the fixed address will be created
            according to the values specified in the named template.
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_cli_credentials: If set to true, the CLI credential will
            override member-level settings.
        use_ddns_domainname: Use flag for: ddns_domainname
        use_deny_bootp: Use flag for: deny_bootp
        use_enable_ddns: Use flag for: enable_ddns
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_ms_options: Use flag for: ms_options
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_pxe_lease_time: Use flag for: pxe_lease_time
        use_snmp3_credential: Determines if the SNMPv3 credential should
            be used for the fixed address.
        use_snmp_credential: If set to true, the SNMP credential will
            override member-level settings.
    """
    _infoblox_type = 'fixedaddress'
    _fields = ['agent_circuit_id', 'agent_remote_id', 'allow_telnet',
               'always_update_dns', 'bootfile', 'bootserver',
               'cli_credentials', 'client_identifier_prepend_zero',
               'cloud_info', 'comment', 'ddns_domainname', 'ddns_hostname',
               'deny_bootp', 'device_description', 'device_location',
               'device_type', 'device_vendor', 'dhcp_client_identifier',
               'disable', 'disable_discovery', 'discover_now_status',
               'discovered_data', 'enable_ddns', 'enable_immediate_discovery',
               'enable_pxe_lease_time', 'extattrs',
               'ignore_dhcp_option_list_request', 'ipv4addr', 'is_invalid_mac',
               'logic_filter_rules', 'mac', 'match_client', 'ms_ad_user_data',
               'ms_options', 'ms_server', 'name', 'network', 'network_view',
               'nextserver', 'options', 'pxe_lease_time', 'reserved_interface',
               'restart_if_needed', 'snmp3_credential', 'snmp_credential',
               'template', 'use_bootfile', 'use_bootserver',
               'use_cli_credentials', 'use_ddns_domainname', 'use_deny_bootp',
               'use_enable_ddns', 'use_ignore_dhcp_option_list_request',
               'use_logic_filter_rules', 'use_ms_options', 'use_nextserver',
               'use_options', 'use_pxe_lease_time', 'use_snmp3_credential',
               'use_snmp_credential']
    _search_for_update_fields = ['ipv4addr', 'network_view', 'mac']
    _updateable_search_fields = ['comment', 'device_description',
                                 'device_location', 'device_type',
                                 'device_vendor', 'ipv4addr', 'mac',
                                 'match_client', 'ms_server', 'network',
                                 'network_view']
    _all_searchable_fields = ['comment', 'device_description',
                              'device_location', 'device_type',
                              'device_vendor', 'ipv4addr', 'mac',
                              'match_client', 'ms_server', 'network',
                              'network_view']
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
        'options': DhcpOption.from_dict,
    }


class FixedAddressV6(FixedAddress):
    """ FixedAddressV6: DHCP IPv6 Fixed Address object.
    Corresponds to WAPI object 'ipv6fixedaddress'

    A IPv6 fixed address is a specific IP address that a DHCP server
    always assigns when a lease request comes from a particular DUID of
    the client.

    Attributes:
        address_type: The address type value for this IPv6 fixed
            address.When the address type is "ADDRESS", a value for the
            'ipv6addr' member is required. When the address type is
            "PREFIX", values for 'ipv6prefix' and 'ipv6prefix_bits' are
            required. When the address type is "BOTH", values for
            'ipv6addr', 'ipv6prefix', and 'ipv6prefix_bits' are all
            required.
        allow_telnet: This field controls whether the credential is used
            for both the Telnet and SSH credentials. If set to False,
            the credential is used only for SSH.
        cli_credentials: The CLI credentials for the IPv6 fixed address.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the fixed address; maximum 256 characters.
        device_description: The description of the device.
        device_location: The location of the device.
        device_type: The type of the device.
        device_vendor: The vendor of the device.
        disable: Determines whether a fixed address is disabled or not.
            When this is set to False, the IPv6 fixed address is
            enabled.
        disable_discovery: Determines if the discovery for this IPv6
            fixed address is disabled or not. False means that the
            discovery is enabled.
        discover_now_status: The discovery status of this IPv6 fixed
            address.
        discovered_data: The discovered data for this IPv6 fixed
            address.
        domain_name: The domain name for this IPv6 fixed address.
        domain_name_servers: The IPv6 addresses of DNS recursive name
            servers to which the DHCP client can send name resolution
            requests. The DHCP server includes this information in the
            DNS Recursive Name Server option in Advertise, Rebind,
            Information-Request, and Reply messages.
        duid: The DUID value for this IPv6 fixed address.
        enable_immediate_discovery: Determines if the discovery for the
            IPv6 fixed address should be immediately enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv6addr: The IPv6 Address of the DHCP IPv6 fixed address.
        ipv6prefix: The IPv6 Address prefix of the DHCP IPv6 fixed
            address.
        ipv6prefix_bits: Prefix bits of the DHCP IPv6 fixed address.
        logic_filter_rules: This field contains the logic filters to be
            applied to this IPv6 fixed address.This list corresponds to
            the match rules that are written to the DHCPv6 configuration
            file.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: This field contains the name of this IPv6 fixed address.
        network: The network to which this IPv6 fixed address belongs,
            in IPv6 Address/CIDR format.
        network_view: The name of the network view in which this IPv6
            fixed address resides.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        preferred_lifetime: The preferred lifetime value for this DHCP
            IPv6 fixed address object.
        reserved_interface: The reference to the reserved interface to
            which the device belongs.
        restart_if_needed: Restarts the member service. The
            restart_if_needed flag can trigger a restart on DHCP
            services only when it is enabled on CP member.
        snmp3_credential: The SNMPv3 credential for this IPv6 fixed
            address.
        snmp_credential: The SNMPv1 or SNMPv2 credential for this IPv6
            fixed address.
        template: If set on creation, the IPv6 fixed address will be
            created according to the values specified in the named
            template.
        use_cli_credentials: If set to true, the CLI credential will
            override member-level settings.
        use_domain_name: Use flag for: domain_name
        use_domain_name_servers: Use flag for: domain_name_servers
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_options: Use flag for: options
        use_preferred_lifetime: Use flag for: preferred_lifetime
        use_snmp3_credential: Determines if the SNMPv3 credential should
            be used for the IPv6 fixed address.
        use_snmp_credential: If set to true, SNMP credential will
            override member level settings.
        use_valid_lifetime: Use flag for: valid_lifetime
        valid_lifetime: The valid lifetime value for this DHCP IPv6
            Fixed Address object.
    """
    _infoblox_type = 'ipv6fixedaddress'
    _fields = ['address_type', 'allow_telnet', 'cli_credentials', 'cloud_info',
               'comment', 'device_description', 'device_location',
               'device_type', 'device_vendor', 'disable', 'disable_discovery',
               'discover_now_status', 'discovered_data', 'domain_name',
               'domain_name_servers', 'duid', 'enable_immediate_discovery',
               'extattrs', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits',
               'logic_filter_rules', 'ms_ad_user_data', 'name', 'network',
               'network_view', 'options', 'preferred_lifetime',
               'reserved_interface', 'restart_if_needed', 'snmp3_credential',
               'snmp_credential', 'template', 'use_cli_credentials',
               'use_domain_name', 'use_domain_name_servers',
               'use_logic_filter_rules', 'use_options',
               'use_preferred_lifetime', 'use_snmp3_credential',
               'use_snmp_credential', 'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['duid', 'ipv6addr', 'network_view']
    _updateable_search_fields = ['address_type', 'comment',
                                 'device_description', 'device_location',
                                 'device_type', 'device_vendor', 'duid',
                                 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits',
                                 'network', 'network_view']
    _all_searchable_fields = ['address_type', 'comment', 'device_description',
                              'device_location', 'device_type',
                              'device_vendor', 'duid', 'ipv6addr',
                              'ipv6prefix', 'ipv6prefix_bits', 'network',
                              'network_view']
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
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': DhcpOption.from_dict,
    }


class FixedAddressTemplate(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return FixedAddressTemplateV4

    @classmethod
    def get_v6_class(cls):
        return FixedAddressTemplateV6


class FixedAddressTemplateV4(FixedAddressTemplate):
    """ FixedAddressTemplateV4: The fixed address template object.
    Corresponds to WAPI object 'fixedaddresstemplate'

    The fixed address template used to create a fixed address objects in
    a quick and consistent way. Fixed address object created from a
    fixed address template will inherit most properties defined in fixed
    address template object so most of the fixed address template
    properties are the same as the fixed address object properties.

    Attributes:
        bootfile: The boot file name for the fixed address. You can
            configure the DHCP server to support clients that use the
            boot file name option in their DHCPREQUEST messages.
        bootserver: The boot server address for the fixed address. You
            can specify the name and/or IP address of the boot server
            that the host needs to boot.The boot server IPv4 Address or
            name in FQDN format.
        comment: A descriptive comment of a fixed address template
            object.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this fixed address.
        ddns_hostname: The DDNS host name for this fixed address.
        deny_bootp: Determines if BOOTP settings are disabled and BOOTP
            requests will be denied.
        enable_ddns: Determines if the DHCP server sends DDNS updates to
            DNS servers in the same Grid, and to external DNS servers.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ignore_dhcp_option_list_request: If this field is set to False,
            the appliance returns all DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        logic_filter_rules: This field contains the logic filters to be
            applied on this fixed address.This list corresponds to the
            match rules that are written to the dhcpd configuration
            file.
        name: The name of a fixed address template object.
        nextserver: The name in FQDN and/or IPv4 Address format of the
            next server that the host needs to boot.
        number_of_addresses: The number of addresses for this fixed
            address.
        offset: The start address offset for this fixed address.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        pxe_lease_time: The PXE lease time value for a DHCP Fixed
            Address object. Some hosts use PXE (Preboot Execution
            Environment) to boot remotely from a server. To better
            manage your IP resources, set a different lease time for PXE
            boot requests. You can configure the DHCP server to allocate
            an IP address with a shorter lease time to hosts that send
            PXE boot requests, so IP addresses are not leased longer
            than necessary.A 32-bit unsigned integer that represents the
            duration, in seconds, for which the update is cached. Zero
            indicates that the update is not cached.
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_ddns_domainname: Use flag for: ddns_domainname
        use_deny_bootp: Use flag for: deny_bootp
        use_enable_ddns: Use flag for: enable_ddns
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_pxe_lease_time: Use flag for: pxe_lease_time
    """
    _infoblox_type = 'fixedaddresstemplate'
    _fields = ['bootfile', 'bootserver', 'comment', 'ddns_domainname',
               'ddns_hostname', 'deny_bootp', 'enable_ddns',
               'enable_pxe_lease_time', 'extattrs',
               'ignore_dhcp_option_list_request', 'logic_filter_rules', 'name',
               'nextserver', 'number_of_addresses', 'offset', 'options',
               'pxe_lease_time', 'use_bootfile', 'use_bootserver',
               'use_ddns_domainname', 'use_deny_bootp', 'use_enable_ddns',
               'use_ignore_dhcp_option_list_request', 'use_logic_filter_rules',
               'use_nextserver', 'use_options', 'use_pxe_lease_time']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': DhcpOption.from_dict,
    }


class FixedAddressTemplateV6(FixedAddressTemplate):
    """ FixedAddressTemplateV6: The IPv6 fixed address template object.
    Corresponds to WAPI object 'ipv6fixedaddresstemplate'

    The IPv6 fixed address template used to create IPv6 fixed address
    objects in a quick and consistent way. An IPv6 fixed address object
    created from an IPv6 fixed address template will inherit most
    properties defined in the IPv6 fixed address template object;
    therefor, most of the IPv6 fixed address template properties are the
    same as the fixed address object properties.

    Attributes:
        comment: A descriptive comment of an IPv6 fixed address template
            object.
        domain_name: Domain name of the IPv6 fixed address template
            object.
        domain_name_servers: The IPv6 addresses of DNS recursive name
            servers to which the DHCP client can send name resolution
            requests. The DHCP server includes this information in the
            DNS Recursive Name Server option in Advertise, Rebind,
            Information-Request, and Reply messages.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        logic_filter_rules: This field contains the logic filters to be
            applied to this IPv6 fixed address.This list corresponds to
            the match rules that are written to the DHCPv6 configuration
            file.
        name: Name of an IPv6 fixed address template object.
        number_of_addresses: The number of IPv6 addresses for this fixed
            address.
        offset: The start address offset for this IPv6 fixed address.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        preferred_lifetime: The preferred lifetime value for this DHCP
            IPv6 fixed address template object.
        use_domain_name: Use flag for: domain_name
        use_domain_name_servers: Use flag for: domain_name_servers
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_options: Use flag for: options
        use_preferred_lifetime: Use flag for: preferred_lifetime
        use_valid_lifetime: Use flag for: valid_lifetime
        valid_lifetime: The valid lifetime value for this DHCP IPv6
            fixed address template object.
    """
    _infoblox_type = 'ipv6fixedaddresstemplate'
    _fields = ['comment', 'domain_name', 'domain_name_servers', 'extattrs',
               'logic_filter_rules', 'name', 'number_of_addresses', 'offset',
               'options', 'preferred_lifetime', 'use_domain_name',
               'use_domain_name_servers', 'use_logic_filter_rules',
               'use_options', 'use_preferred_lifetime', 'use_valid_lifetime',
               'valid_lifetime']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': DhcpOption.from_dict,
    }


class Ftpuser(InfobloxObject):
    """ Ftpuser: FTP user object.
    Corresponds to WAPI object 'ftpuser'

    The FTP user represents the user accounts to be used with the FTP
    client.

    Attributes:
        create_home_dir: Determines whether to create the home directory
            with the user name or to use the existing directory as the
            home directory.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        home_dir: The absolute path of the FTP user's home directory.
        password: The FTP user password.
        permission: The FTP user permission.
        username: The FTP user name.
    """
    _infoblox_type = 'ftpuser'
    _fields = ['create_home_dir', 'extattrs', 'home_dir', 'password',
               'permission', 'username']
    _search_for_update_fields = ['username']
    _updateable_search_fields = []
    _all_searchable_fields = ['username']
    _return_fields = ['extattrs', 'username']
    _remap = {}
    _shadow_fields = ['_ref']


class Grid(InfobloxObject):
    """ Grid: Grid object.
    Corresponds to WAPI object 'grid'

    This object represents the Infoblox Grid.

    Attributes:
        allow_recursive_deletion: The property to allow recursive
            deletion. Determines the users who can choose to perform
            recursive deletion on networks or zones from the GUI only.
        audit_log_format: Determines the audit log format.
        audit_to_syslog_enable: If set to True, audit log messages are
            also copied to the syslog.
        automated_traffic_capture_setting: The grid level settings for
            automated traffic capture.
        consent_banner_setting: The Grid consent banner settings.
        csp_api_config: The Grid csp api config settings.
        csp_grid_setting: CSP settings at grid level
        deny_mgm_snapshots: If set to True, the managed Grid will not
            send snapshots to the Multi-Grid Master.
        descendants_action: The default actions for extensbile
            attributes that exist on descendants.
        dns_resolver_setting: The DNS resolver setting.
        dscp: The DSCP value.Valid values are integers between 0 and 63
            inclusive.
        email_setting: The e-mail settings for the Grid.
        enable_gui_api_for_lan_vip: If set to True, GUI and API access
            are enabled on the LAN/VIP port and MGMT port (if
            configured).
        enable_lom: Determines if the LOM functionality is enabled or
            not.
        enable_member_redirect: Determines redirections is enabled or
            not for members.
        enable_recycle_bin: Determines if the Recycle Bin is enabled or
            not.
        enable_rir_swip: Determines if the RIR/SWIP support is enabled
            or not.
        external_syslog_backup_servers: The list of external backup
            syslog servers.
        external_syslog_server_enable: If set to True, external syslog
            servers are enabled.
        http_proxy_server_setting: The Grid HTTP proxy server settings.
        informational_banner_setting: The Grid informational level
            banner settings.
        is_grid_visualization_visible: If set to True, graphical
            visualization of the Grid is enabled.
        lockout_setting: Security Setting for Account lockout.
        lom_users: The list of LOM users.
        mgm_strict_delegate_mode: Determines if strict delegate mode for
            the Grid managed by the Master Grid is enabled or not.
        ms_setting: The settings for all Microsoft servers in the Grid.
        name: The grid name.
        nat_groups: The list of all Network Address Translation (NAT)
            groups configured on the Grid.
        ntp_setting: The Grid Network Time Protocol (NTP) settings.
        objects_changes_tracking_setting: Determines the object changes
            tracking settings.
        password_setting: The Grid password settings.
        restart_banner_setting: The setting for the Restart Banner.
        restart_status: The restart status for the Grid.
        rpz_hit_rate_interval: The time interval (in seconds) that
            determines how often the appliance calculates the RPZ hit
            rate.
        rpz_hit_rate_max_query: The maximum number of incoming queries
            between the RPZ hit rate checks.
        rpz_hit_rate_min_query: The minimum number of incoming queries
            between the RPZ hit rate checks.
        scheduled_backup: The scheduled backup configuration.
        secret: The shared secret of the Grid. This is a write-only
            attribute.
        security_banner_setting: The Grid security banner settings.
        security_setting: The Grid security settings.
        service_status: Determines overall service status of the Grid.
        snmp_setting: The Grid SNMP settings.
        support_bundle_download_timeout: Support bundle download timeout
            in seconds.
        syslog_facility: If 'audit_to_syslog_enable' is set to True, the
            facility that determines the processes and daemons from
            which the log messages are generated.
        syslog_servers: The list of external syslog servers.
        syslog_size: The maximum size for the syslog file expressed in
            megabytes.
        threshold_traps: Determines the list of threshold traps. The
            user can only change the values for each trap or remove
            traps.
        time_zone: The time zone of the Grid. The UTC string that
            represents the time zone, such as "(UTC - 5:00) Eastern Time
            (US and Canada)".
        token_usage_delay: The delayed usage (in minutes) of a
            permission token.
        traffic_capture_auth_dns_setting: Grid level settings for
            enabling authoritative DNS latency thresholds for automated
            traffic capture.
        traffic_capture_chr_setting: Grid level settings for enabling
            DNS cache hit ratio threshold for automated traffic capture.
        traffic_capture_qps_setting: Grid level settings for enabling
            DNS query per second threshold for automated traffic
            capture.
        traffic_capture_rec_dns_setting: Grid level settings for
            enabling recursive DNS latency thresholds for automated
            traffic capture.
        traffic_capture_rec_queries_setting: Grid level settings for
            enabling count for concurrent outgoing recursive queries for
            automated traffic capture.
        trap_notifications: Determines configuration of the trap
            notifications.
        updates_download_member_config: The list of member configuration
            structures, which provides information and settings for
            configuring the member that is responsible for downloading
            updates.
        vpn_port: The VPN port.
    """
    _infoblox_type = 'grid'
    _fields = ['allow_recursive_deletion', 'audit_log_format',
               'audit_to_syslog_enable', 'automated_traffic_capture_setting',
               'consent_banner_setting', 'csp_api_config', 'csp_grid_setting',
               'deny_mgm_snapshots', 'descendants_action',
               'dns_resolver_setting', 'dscp', 'email_setting',
               'enable_gui_api_for_lan_vip', 'enable_lom',
               'enable_member_redirect', 'enable_recycle_bin',
               'enable_rir_swip', 'external_syslog_backup_servers',
               'external_syslog_server_enable', 'http_proxy_server_setting',
               'informational_banner_setting', 'is_grid_visualization_visible',
               'lockout_setting', 'lom_users', 'mgm_strict_delegate_mode',
               'ms_setting', 'name', 'nat_groups', 'ntp_setting',
               'objects_changes_tracking_setting', 'password_setting',
               'restart_banner_setting', 'restart_status',
               'rpz_hit_rate_interval', 'rpz_hit_rate_max_query',
               'rpz_hit_rate_min_query', 'scheduled_backup', 'secret',
               'security_banner_setting', 'security_setting', 'service_status',
               'snmp_setting', 'support_bundle_download_timeout',
               'syslog_facility', 'syslog_servers', 'syslog_size',
               'threshold_traps', 'time_zone', 'token_usage_delay',
               'traffic_capture_auth_dns_setting',
               'traffic_capture_chr_setting', 'traffic_capture_qps_setting',
               'traffic_capture_rec_dns_setting',
               'traffic_capture_rec_queries_setting', 'trap_notifications',
               'updates_download_member_config', 'vpn_port']
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
        'updates_download_member_config':
            Updatesdownloadmemberconfig.from_dict,
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

    def join_mgm_mod2(self, *args, **kwargs):
        return self._call_func("join_mgm_mod2", *args, **kwargs)

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
        return self._call_func("test_syslog_backup_server_connection", *args,
                               **kwargs)

    def test_syslog_connection(self, *args, **kwargs):
        return self._call_func("test_syslog_connection", *args, **kwargs)

    def upgrade(self, *args, **kwargs):
        return self._call_func("upgrade", *args, **kwargs)

    def upgrade_group_now(self, *args, **kwargs):
        return self._call_func("upgrade_group_now", *args, **kwargs)

    def upload_keytab(self, *args, **kwargs):
        return self._call_func("upload_keytab", *args, **kwargs)


class GridCloudapi(InfobloxObject):
    """ GridCloudapi: Grid Cloud API object.
    Corresponds to WAPI object 'grid:cloudapi'

    This object represents the Cloud Grid.

    Attributes:
        allow_api_admins: Defines administrators who can perform cloud
            API requests on the Grid Master. The valid value is NONE (no
            administrator), ALL (all administrators), or LIST
            (administrators on the ACL).
        allowed_api_admins: The list of administrators who can perform
            cloud API requests on the Cloud Platform Appliance.
        enable_recycle_bin: Determines whether the recycle bin for
            deleted cloud objects is enabled or not on the Grid Master.
        gateway_config: Structure containing all the information related
            to Gateway configuration for the Grid Master
    """
    _infoblox_type = 'grid:cloudapi'
    _fields = ['allow_api_admins', 'allowed_api_admins', 'enable_recycle_bin',
               'gateway_config']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['allow_api_admins', 'allowed_api_admins',
                      'enable_recycle_bin']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'allowed_api_admins': GridCloudapiUser.from_dict,
    }


class GridCloudapiCloudstatistics(InfobloxObject):
    """ GridCloudapiCloudstatistics: Grid Cloud Statistics object.
    Corresponds to WAPI object 'grid:cloudapi:cloudstatistics'

    Represents the cloud statistics data.

    Attributes:
        allocated_available_ratio: Ratio of allocated vs. available IPs
        allocated_ip_count: Total number of IPs allocated by tenants.
        available_ip_count: The total number of IP addresses available
            to tenants. Only IP addresses in networks that are within a
            delegation scope are counted.
        fixed_ip_count: The total number of fixed IP addresses currently
            in use by all tenants in the system.
        floating_ip_count: The total number of floating IP addresses
            currently in use by all tenants in the system.
        tenant_count: Total number of tenant currently in the system.
        tenant_ip_count: The total number of IP addresses currently in
            use by all tenants in the system.
        tenant_vm_count: The total number of VMs currently in use by all
            tenants in the system.
    """
    _infoblox_type = 'grid:cloudapi:cloudstatistics'
    _fields = ['allocated_available_ratio', 'allocated_ip_count',
               'available_ip_count', 'fixed_ip_count', 'floating_ip_count',
               'tenant_count', 'tenant_ip_count', 'tenant_vm_count']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['allocated_available_ratio', 'allocated_ip_count',
                      'available_ip_count', 'fixed_ip_count',
                      'floating_ip_count', 'tenant_count', 'tenant_ip_count',
                      'tenant_vm_count']
    _remap = {}
    _shadow_fields = ['_ref']


class Tenant(InfobloxObject):
    """ Tenant: Grid Cloud API Tenant object.
    Corresponds to WAPI object 'grid:cloudapi:tenant'

    A Tenant object represents an abstract administrative concept in
    Cloud Management Platforms, which encompasses all network elements
    such as networks, zones, VMs, IP addresses (fixed and floating),
    network views, default DNS view, and all related extensive
    attributes.

    Attributes:
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the Grid Cloud API Tenant object; maximum
            256 characters.
        created_ts: The timestamp when the tenant was first created in
            the system.
        id: Unique ID associated with the tenant. This is set only when
            the tenant is first created.
        last_event_ts: The timestamp when the last event associated with
            the tenant happened.
        name: Name of the tenant.
        network_count: Number of Networks associated with the tenant.
        vm_count: Number of VMs associated with the tenant.
    """
    _infoblox_type = 'grid:cloudapi:tenant'
    _fields = ['cloud_info', 'comment', 'created_ts', 'id', 'last_event_ts',
               'name', 'network_count', 'vm_count']
    _search_for_update_fields = ['id', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'id', 'name']
    _return_fields = ['comment', 'id', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class GridCloudapiVm(InfobloxObject):
    """ GridCloudapiVm: Grid Cloud API vm object.
    Corresponds to WAPI object 'grid:cloudapi:vm'

    A vm object represents a virtual machine which encompasses network
    elements such as IP addresses (fixed and floating, private and
    public), DNS names and all related extensive attributes.

    Attributes:
        availability_zone: Availability zone of the VM.
        cloud_info: Structure containing all the cloud API related
            information for this object.
        comment: Comment for the vm object; maximum 1024 characters.
        elastic_ip_address: Elastic IP address associated with the VM's
            primary interface.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        first_seen: The timestamp when the VM was first seen in the
            system.
        hostname: Hostname part of the FQDN for the address associated
            with the VM's primary interface.
        id: Unique ID associated with the VM. This is set only when the
            VM is first created.
        kernel_id: Identifier of the kernel that this VM is running;
            maximum 128 characters.
        last_seen: The timestamp when the last event associated with the
            VM happened.
        name: Name of the VM.
        network_count: Number of Networks containing any address
            associated with this VM.
        operating_system: Guest Operating system that this VM is
            running; maximum 128 characters.
        primary_mac_address: MAC address associated with the VM's
            primary interface.
        subnet_address: Address of the network that is the container of
            the address associated with the VM's primary interface.
        subnet_cidr: CIDR of the network that is the container of the
            address associated with the VM's primary interface.
        subnet_id: Subnet ID of the network that is the container of the
            address associated with the VM's primary interface.
        tenant_name: Name of the tenant associated with the VM.
        vm_type: VM type; maximum 64 characters.
        vpc_address: Network address of the parent VPC.
        vpc_cidr: Network CIDR of the parent VPC.
        vpc_id: Identifier of the parent VPC.
        vpc_name: Name of the parent VPC.
    """
    _infoblox_type = 'grid:cloudapi:vm'
    _fields = ['availability_zone', 'cloud_info', 'comment',
               'elastic_ip_address', 'extattrs', 'first_seen', 'hostname',
               'id', 'kernel_id', 'last_seen', 'name', 'network_count',
               'operating_system', 'primary_mac_address', 'subnet_address',
               'subnet_cidr', 'subnet_id', 'tenant_name', 'vm_type',
               'vpc_address', 'vpc_cidr', 'vpc_id', 'vpc_name']
    _search_for_update_fields = ['id', 'name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'elastic_ip_address', 'id', 'name',
                              'primary_mac_address']
    _return_fields = ['comment', 'extattrs', 'id', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class GridCloudapiVmaddress(InfobloxObject):
    """ GridCloudapiVmaddress: Grid Cloud API VM address object.
    Corresponds to WAPI object 'grid:cloudapi:vmaddress'

    VM address is an abstract object that represents a virtual machine
    running on the Cloud Management Platform.

    Attributes:
        address: The IP address of the interface.
        address_type: IP address type (Public, Private, Elastic,
            Floating, ...).
        associated_ip: Reference to associated IPv4 or IPv6 address.
        associated_object_types: Array of string denoting the types of
            underlying objects IPv4/IPv6 - "A", "AAAA", "PTR", "HOST",
            "FA", "RESERVATION", "UNMANAGED" + ("BULKHOST",
            "DHCP_RANGE", "RESERVED_RANGE", "LEASE", "NETWORK",
            "BROADCAST", "PENDING"),
        associated_objects: The list of references to the object (Host,
            Fixed Address, RR, ...) that defines this IP.
        cloud_info: Structure containing all the cloud API related
            information. Only management platform "mgmt_platform" is
            updated for this object.
        dns_names: The list of all FQDNs associated with the IP address.
        elastic_address: Elastic IP address associated with this private
            address, if this address is a private address; otherwise
            empty.
        interface_name: Name of the interface associated with this IP
            address.
        is_ipv4: Indicates whether the address is IPv4 or IPv6.
        mac_address: The MAC address of the interface.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        network: The network to which this address belongs, in IPv4
            Address/CIDR format.
        network_view: Network view name of the delegated object.
        port_id: Port identifier of the interface.
        private_address: Private IP address associated with this public
            (or elastic or floating) address, if this address is a
            public address; otherwise empty.
        private_hostname: Host part of the FQDN of this address if this
            address is a private address; otherwise empty
        public_address: Public IP address associated with this private
            address, if this address is a private address; otherwise
            empty.
        public_hostname: Host part of the FQDN of this address if this
            address is a public (or elastic or floating) address;
            otherwise empty
        subnet_address: Network address of the subnet that is the
            container of this address.
        subnet_cidr: CIDR of the subnet that is the container of this
            address.
        subnet_id: Subnet ID that is the container of this address.
        tenant: The Cloud API Tenant object.
        vm_availability_zone: Availability zone of the VM.
        vm_comment: VM comment.
        vm_creation_time: Date/time the VM was first created as NIOS
            object.
        vm_hostname: Host part of the FQDN of the address attached to
            the primary interface.
        vm_id: The UUID of the Virtual Machine.
        vm_kernel_id: Kernel ID of the VM that this address is
            associated with.
        vm_last_update_time: Last time the VM was updated.
        vm_name: The name of the Virtual Machine.
        vm_network_count: Count of networks containing all the addresses
            of the VM.
        vm_operating_system: Operating system that the VM is running.
        vm_type: Type of the VM this address is associated with.
        vm_vpc_address: Network address of the VPC of the VM that this
            address is associated with.
        vm_vpc_cidr: CIDR of the VPC of the VM that this address is
            associated with.
        vm_vpc_id: Identifier of the VPC where the VM is defined.
        vm_vpc_name: Name of the VPC where the VM is defined.
        vm_vpc_ref: Reference to the VPC where the VM is defined.
    """
    _infoblox_type = 'grid:cloudapi:vmaddress'
    _fields = ['address', 'address_type', 'associated_ip',
               'associated_object_types', 'associated_objects', 'cloud_info',
               'dns_names', 'elastic_address', 'interface_name', 'is_ipv4',
               'mac_address', 'ms_ad_user_data', 'network', 'network_view',
               'port_id', 'private_address', 'private_hostname',
               'public_address', 'public_hostname', 'subnet_address',
               'subnet_cidr', 'subnet_id', 'tenant', 'vm_availability_zone',
               'vm_comment', 'vm_creation_time', 'vm_hostname', 'vm_id',
               'vm_kernel_id', 'vm_last_update_time', 'vm_name',
               'vm_network_count', 'vm_operating_system', 'vm_type',
               'vm_vpc_address', 'vm_vpc_cidr', 'vm_vpc_id', 'vm_vpc_name',
               'vm_vpc_ref']
    _search_for_update_fields = ['address', 'vm_name']
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'mac_address', 'vm_id', 'vm_name']
    _return_fields = ['address', 'is_ipv4', 'network_view', 'port_id',
                      'vm_name']
    _remap = {}
    _shadow_fields = ['_ref']


class GridDashboard(InfobloxObject):
    """ GridDashboard: Grid Dashboard object.
    Corresponds to WAPI object 'grid:dashboard'

    The Grid Dashboard object provides a configuration interface for
    threshold values that are used to warn about critical ATP, RPZ and
    Analytics events. These threshold values are used to calculate the
    security status for ATP, RPZ, and Analytics.

    Attributes:
        analytics_tunneling_event_critical_threshold: The Grid Dashboard
            critical threshold for Analytics tunneling events.
        analytics_tunneling_event_warning_threshold: The Grid Dashboard
            warning threshold for Analytics tunneling events.
        atp_critical_event_critical_threshold: The Grid Dashboard
            critical threshold for ATP critical events.
        atp_critical_event_warning_threshold: The Grid Dashboard warning
            threshold for ATP critical events.
        atp_major_event_critical_threshold: The Grid Dashboard critical
            threshold for ATP major events.
        atp_major_event_warning_threshold: The Grid Dashboard warning
            threshold for ATP major events.
        atp_warning_event_critical_threshold: The Grid Dashboard
            critical threshold for ATP warning events.
        atp_warning_event_warning_threshold: The Grid Dashboard warning
            threshold for ATP warning events.
        rpz_blocked_hit_critical_threshold: The critical threshold value
            for blocked RPZ hits in the Grid dashboard.
        rpz_blocked_hit_warning_threshold: The warning threshold value
            for blocked RPZ hits in the Grid dashboard.
        rpz_passthru_event_critical_threshold: The Grid Dashboard
            critical threshold for RPZ passthru events.
        rpz_passthru_event_warning_threshold: The Grid Dashboard warning
            threshold for RPZ passthru events.
        rpz_substituted_hit_critical_threshold: The critical threshold
            value for substituted RPZ hits in the Grid dashboard.
        rpz_substituted_hit_warning_threshold: The warning threshold
            value for substituted RPZ hits in the Grid dashboard.
    """
    _infoblox_type = 'grid:dashboard'
    _fields = ['analytics_tunneling_event_critical_threshold',
               'analytics_tunneling_event_warning_threshold',
               'atp_critical_event_critical_threshold',
               'atp_critical_event_warning_threshold',
               'atp_major_event_critical_threshold',
               'atp_major_event_warning_threshold',
               'atp_warning_event_critical_threshold',
               'atp_warning_event_warning_threshold',
               'rpz_blocked_hit_critical_threshold',
               'rpz_blocked_hit_warning_threshold',
               'rpz_passthru_event_critical_threshold',
               'rpz_passthru_event_warning_threshold',
               'rpz_substituted_hit_critical_threshold',
               'rpz_substituted_hit_warning_threshold']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['analytics_tunneling_event_critical_threshold',
                      'analytics_tunneling_event_warning_threshold',
                      'atp_critical_event_critical_threshold',
                      'atp_critical_event_warning_threshold',
                      'atp_major_event_critical_threshold',
                      'atp_major_event_warning_threshold',
                      'atp_warning_event_critical_threshold',
                      'atp_warning_event_warning_threshold',
                      'rpz_blocked_hit_critical_threshold',
                      'rpz_blocked_hit_warning_threshold',
                      'rpz_passthru_event_critical_threshold',
                      'rpz_passthru_event_warning_threshold',
                      'rpz_substituted_hit_critical_threshold',
                      'rpz_substituted_hit_warning_threshold']
    _remap = {}
    _shadow_fields = ['_ref']


class GridDhcpproperties(InfobloxObject):
    """ GridDhcpproperties: Grid DHCP properties object.
    Corresponds to WAPI object 'grid:dhcpproperties'

    This object represents a subset of the Infoblox Grid DHCP
    properties.

    Attributes:
        authority: The Grid-level authority flag. This flag specifies
            whether a DHCP server is authoritative for a domain.
        bootfile: The name of a file that DHCP clients need to boot.
            Some DHCP clients use BOOTP (bootstrap protocol) or include
            the boot file name option in their DHCPREQUEST messages.
        bootserver: The name of the server on which a boot file is
            stored.
        capture_hostname: The Grid-level capture hostname flag. Set this
            flag to capture the hostname and lease time when assigning a
            fixed address.
        ddns_domainname: The member DDNS domain name value.
        ddns_generate_hostname: Determines if the ability of a DHCP
            server to generate a host name and update DNS with this host
            name when it receives a DHCP REQUEST message that does not
            include a host name is enabled or not.
        ddns_retry_interval: Determines the retry interval when the DHCP
            server makes repeated attempts to send DDNS updates to a DNS
            server.
        ddns_server_always_updates: Determines that only the DHCP server
            is allowed to update DNS, regardless of the requests from
            the DHCP clients.
        ddns_ttl: The DDNS TTL (Dynamic DNS Time To Live) value
            specifies the number of seconds an IP address for the name
            is cached.
        ddns_update_fixed_addresses: Determines if the Grid DHCP
            server's ability to update the A and PTR records with a
            fixed address is enabled or not.
        ddns_use_option81: Determines if support for option 81 is
            enabled or not.
        deny_bootp: Determines if deny BOOTP is enabled or not.
        disable_all_nac_filters: If set to True, NAC filters will be
            disabled on the Infoblox Grid.
        dns_update_style: The update style for dynamic DNS updates.
        email_list: The Grid-level email_list value. Specify an e-mail
            address to which you want the Infoblox appliance to send
            e-mail notifications when the DHCP address usage for the
            grid crosses a threshold. You can create a list of several
            e-mail addresses.
        enable_ddns: Determines if the member DHCP server's ability to
            send DDNS updates is enabled or not.
        enable_dhcp_thresholds: Represents the watermarks above or below
            which address usage in a network is unexpected and might
            warrant your attention.
        enable_email_warnings: Determines if e-mail warnings are enabled
            or disabled. When DHCP threshold is enabled and DHCP address
            usage crosses a watermark threshold, the appliance sends an
            e-mail notification to an administrator.
        enable_fingerprint: Determines if the fingerprint feature is
            enabled or not. If you enable this feature, the server will
            match a fingerprint for incoming lease requests.
        enable_gss_tsig: Determines whether all appliances are enabled
            to receive GSS-TSIG authenticated updates from DHCP clients.
        enable_hostname_rewrite: Determines if the Grid-level host name
            rewrite feature is enabled or not.
        enable_leasequery: Determines if lease query is allowed or not.
        enable_roaming_hosts: Determines if DHCP servers in a Grid
            support roaming hosts or not.
        enable_snmp_warnings: Determined if the SNMP warnings on Grid-
            level are enabled or not. When DHCP threshold is enabled and
            DHCP address usage crosses a watermark threshold, the
            appliance sends an SNMP trap to the trap receiver that you
            defined you defined at the Grid member level.
        format_log_option_82: The format option for Option 82 logging.
        grid: Determines the Grid that serves DHCP. This specifies a
            group of Infoblox appliances that are connected together to
            provide a single point of device administration and service
            configuration in a secure, highly available environment.
        gss_tsig_keys: The list of GSS-TSIG keys for a Grid DHCP object.
        high_water_mark: Determines the high watermark value of a Grid
            DHCP server. If the percentage of allocated addresses
            exceeds this watermark, the appliance makes a syslog entry
            and sends an e-mail notification (if enabled). Specifies the
            percentage of allocated addresses. The range is from 1 to
            100.
        high_water_mark_reset: Determines the high watermark reset value
            of a member DHCP server. If the percentage of allocated
            addresses drops below this value, a corresponding SNMP trap
            is reset. Specifies the percentage of allocated addresses.
            The range is from 1 to 100. The high watermark reset value
            must be lower than the high watermark value.
        hostname_rewrite_policy: The name of the default hostname
            rewrite policy, which is also in the
            protocol_hostname_rewrite_policies array.
        ignore_dhcp_option_list_request: Determines if the ignore DHCP
            option list request flag of a Grid DHCP is enabled or not.
            If this flag is set to true all available DHCP options will
            be returned to the client.
        ignore_id: Indicates whether the appliance will ignore DHCP
            client IDs or MAC addresses. Valid values are "NONE",
            "CLIENT", or "MACADDR". The default is "NONE".
        ignore_mac_addresses: A list of MAC addresses the appliance will
            ignore.
        immediate_fa_configuration: Determines if the fixed address
            configuration takes effect immediately without DHCP service
            restart or not.
        ipv6_capture_hostname: Determines if the IPv6 host name and
            lease time is captured or not while assigning a fixed
            address.
        ipv6_ddns_domainname: The Grid-level DDNS domain name value.
        ipv6_ddns_enable_option_fqdn: Controls whether the FQDN option
            sent by the client is to be used, or if the server can
            automatically generate the FQDN.
        ipv6_ddns_server_always_updates: Determines if the server always
            updates DNS or updates only if requested by the client.
        ipv6_ddns_ttl: The Grid-level IPv6 DDNS TTL value.
        ipv6_default_prefix: The Grid-level IPv6 default prefix.
        ipv6_dns_update_style: The update style for dynamic DHCPv6 DNS
            updates.
        ipv6_domain_name: The IPv6 domain name.
        ipv6_domain_name_servers: The comma separated list of domain
            name server addresses in IPv6 address format.
        ipv6_enable_ddns: Determines if sending DDNS updates by the
            DHCPv6 server is enabled or not.
        ipv6_enable_gss_tsig: Determines whether the all appliances are
            enabled to receive GSS-TSIG authenticated updates from
            DHCPv6 clients.
        ipv6_enable_lease_scavenging: Indicates whether DHCPv6 lease
            scavenging is enabled or disabled.
        ipv6_enable_retry_updates: Determines if the DHCPv6 server
            retries failed dynamic DNS updates or not.
        ipv6_generate_hostname: Determines if the server generates the
            hostname if it is not sent by the client.
        ipv6_gss_tsig_keys: The list of GSS-TSIG keys for a Grid DHCPv6
            object.
        ipv6_kdc_server: The IPv6 address or FQDN of the Kerberos server
            for DHCPv6 GSS-TSIG authentication.
        ipv6_lease_scavenging_time: The Grid-level grace period (in
            seconds) to keep an expired lease before it is deleted by
            the scavenging process.
        ipv6_microsoft_code_page: The Grid-level Microsoft client DHCP
            IPv6 code page value. This value is the hostname translation
            code page for Microsoft DHCP IPv6 clients.
        ipv6_options: An array of DHCP option structs that lists the
            DHCPv6 options associated with the object.
        ipv6_prefixes: The Grid-level list of IPv6 prefixes.
        ipv6_recycle_leases: Determines if the IPv6 recycle leases
            feature is enabled or not. If the feature is enabled, leases
            are kept in the Recycle Bin until one week after expiration.
            When the feature is disabled, the leases are irrecoverably
            deleted.
        ipv6_remember_expired_client_association: Enable binding for
            expired DHCPv6 leases.
        ipv6_retry_updates_interval: Determines the retry interval when
            the member DHCPv6 server makes repeated attempts to send
            DDNS updates to a DNS server.
        ipv6_txt_record_handling: The Grid-level TXT record handling
            value. This value specifies how DHCPv6 should treat the TXT
            records when performing DNS updates.
        ipv6_update_dns_on_lease_renewal: Controls whether the DHCPv6
            server updates DNS when an IPv6 DHCP lease is renewed.
        kdc_server: The IPv4 address or FQDN of the Kerberos server for
            DHCPv4 GSS-TSIG authentication.
        lease_logging_member: The Grid member on which you want to store
            the DHCP lease history log. Infoblox recommends that you
            dedicate a member other than the master as a logging member.
            If possible, use this member solely for storing the DHCP
            lease history log. If you do not select a member, no logging
            can occur.
        lease_per_client_settings: Defines how the appliance releases
            DHCP leases. Valid values are "RELEASE_MACHING_ID",
            "NEVER_RELEASE", or "ONE_LEASE_PER_CLIENT". The default is
            "RELEASE_MATCHING_ID".
        lease_scavenge_time: Determines the lease scavenging time value.
            When this field is set, the appliance permanently deletes
            the free and backup leases, that remain in the database
            beyond a specified period of time.To disable lease
            scavenging, set the parameter to -1. The minimum positive
            value must be greater than 86400 seconds (1 day).
        log_lease_events: This value specifies whether the Grid DHCP
            members log lease events is enabled or not.
        logic_filter_rules: This field contains the logic filters to be
            applied on the Infoblox Grid.This list corresponds to the
            match rules that are written to the dhcpd configuration
            file.
        low_water_mark: Determines the low watermark value. If the
            percent of allocated addresses drops below this watermark,
            the appliance makes a syslog entry and if enabled, sends an
            e-mail notification.
        low_water_mark_reset: Determines the low watermark reset
            value.If the percentage of allocated addresses exceeds this
            value, a corresponding SNMP trap is reset.A number that
            specifies the percentage of allocated addresses. The range
            is from 1 to 100. The low watermark reset value must be
            higher than the low watermark value.
        microsoft_code_page: The Microsoft client DHCP IPv4 code page
            value of a Grid. This value is the hostname translation code
            page for Microsoft DHCP IPv4 clients.
        nextserver: The next server value of a DHCP server. This value
            is the IP address or name of the boot file server on which
            the boot file is stored.
        option60_match_rules: The list of option 60 match rules.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object. Note that WAPI does not
            return special options 'routers', 'domain-name-servers',
            'domain-name' and 'broadcast-address' with empty values for
            this object.
        ping_count: Specifies the number of pings that the Infoblox
            appliance sends to an IP address to verify that it is not in
            use. Values are range is from 0 to 10, where 0 disables
            pings.
        ping_timeout: Indicates the number of milliseconds the appliance
            waits for a response to its ping.Valid values are 100, 500,
            1000, 2000, 3000, 4000 and 5000 milliseconds.
        preferred_lifetime: The preferred lifetime value.
        prefix_length_mode: The Prefix length mode for DHCPv6.
        protocol_hostname_rewrite_policies: The list of hostname rewrite
            policies.
        pxe_lease_time: Specifies the duration of time it takes a host
            to connect to a boot server, such as a TFTP server, and
            download the file it needs to boot.A 32-bit unsigned integer
            that represents the duration, in seconds, for which the
            update is cached. Zero indicates that the update is not
            cached.
        recycle_leases: Determines if the recycle leases feature is
            enabled or not. If you enabled this feature, and then delete
            a DHCP range, the appliance stores active leases from this
            range up to one week after the leases expires.
        restart_setting: The restart setting.
        retry_ddns_updates: Indicates whether the DHCP server makes
            repeated attempts to send DDNS updates to a DNS server.
        syslog_facility: The syslog facility is the location on the
            syslog server to which you want to sort the syslog messages.
        txt_record_handling: The Grid-level TXT record handling value.
            This value specifies how DHCP should treat the TXT records
            when performing DNS updates.
        update_dns_on_lease_renewal: Controls whether the DHCP server
            updates DNS when a DHCP lease is renewed.
        valid_lifetime: The valid lifetime for the Grid members.
    """
    _infoblox_type = 'grid:dhcpproperties'
    _fields = ['authority', 'bootfile', 'bootserver', 'capture_hostname',
               'ddns_domainname', 'ddns_generate_hostname',
               'ddns_retry_interval', 'ddns_server_always_updates', 'ddns_ttl',
               'ddns_update_fixed_addresses', 'ddns_use_option81',
               'deny_bootp', 'disable_all_nac_filters', 'dns_update_style',
               'email_list', 'enable_ddns', 'enable_dhcp_thresholds',
               'enable_email_warnings', 'enable_fingerprint',
               'enable_gss_tsig', 'enable_hostname_rewrite',
               'enable_leasequery', 'enable_roaming_hosts',
               'enable_snmp_warnings', 'format_log_option_82', 'grid',
               'gss_tsig_keys', 'high_water_mark', 'high_water_mark_reset',
               'hostname_rewrite_policy', 'ignore_dhcp_option_list_request',
               'ignore_id', 'ignore_mac_addresses',
               'immediate_fa_configuration', 'ipv6_capture_hostname',
               'ipv6_ddns_domainname', 'ipv6_ddns_enable_option_fqdn',
               'ipv6_ddns_server_always_updates', 'ipv6_ddns_ttl',
               'ipv6_default_prefix', 'ipv6_dns_update_style',
               'ipv6_domain_name', 'ipv6_domain_name_servers',
               'ipv6_enable_ddns', 'ipv6_enable_gss_tsig',
               'ipv6_enable_lease_scavenging', 'ipv6_enable_retry_updates',
               'ipv6_generate_hostname', 'ipv6_gss_tsig_keys',
               'ipv6_kdc_server', 'ipv6_lease_scavenging_time',
               'ipv6_microsoft_code_page', 'ipv6_options', 'ipv6_prefixes',
               'ipv6_recycle_leases',
               'ipv6_remember_expired_client_association',
               'ipv6_retry_updates_interval', 'ipv6_txt_record_handling',
               'ipv6_update_dns_on_lease_renewal', 'kdc_server',
               'lease_logging_member', 'lease_per_client_settings',
               'lease_scavenge_time', 'log_lease_events', 'logic_filter_rules',
               'low_water_mark', 'low_water_mark_reset', 'microsoft_code_page',
               'nextserver', 'option60_match_rules', 'options', 'ping_count',
               'ping_timeout', 'preferred_lifetime', 'prefix_length_mode',
               'protocol_hostname_rewrite_policies', 'pxe_lease_time',
               'recycle_leases', 'restart_setting', 'retry_ddns_updates',
               'syslog_facility', 'txt_record_handling',
               'update_dns_on_lease_renewal', 'valid_lifetime']
    _search_for_update_fields = ['grid']
    _updateable_search_fields = []
    _all_searchable_fields = ['grid']
    _return_fields = ['disable_all_nac_filters', 'grid']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ipv6_options': DhcpOption.from_dict,
        'logic_filter_rules': Logicfilterrule.from_dict,
        'option60_match_rules': Option60Matchrule.from_dict,
        'options': DhcpOption.from_dict,
    }


class GridDns(InfobloxObject):
    """ GridDns: Grid DNS properties object.
    Corresponds to WAPI object 'grid:dns'

    This object supports DNS service management and configuration such
    as time-to-live (TTL) settings, zone transfers, queries, root name
    servers, dynamic updates, sort lists, Transaction Signatures (TSIG)
    for DNS and others, all at the grid level. The service
    configurations of a grid are inherited by all members, zones, and
    networks unless you specifically override them for selected members,
    zones, and networks. For this reason, it is recommended that you
    configure services at the grid level before configuring member, zone
    and network services.

    Attributes:
        add_client_ip_mac_options: Add custom IP, MAC and DNS View name
            ENDS0 options to outgoing recursive queries.
        allow_bulkhost_ddns: Determines if DDNS bulk host is allowed or
            not.
        allow_gss_tsig_zone_updates: Determines whether GSS-TSIG zone
            update is enabled for all Grid members.
        allow_query: Determines if queries from the specified IPv4 or
            IPv6 addresses and networks are allowed or not. The
            appliance can also use Transaction Signature (TSIG) keys to
            authenticate the queries.
        allow_recursive_query: Determines if the responses to recursive
            queries are enabled or not.
        allow_transfer: Determines if zone transfers from specified IPv4
            or IPv6 addresses and networks or transfers from hosts
            authenticated by Transaction signature (TSIG) key are
            allowed or not.
        allow_update: Determines if dynamic updates from specified IPv4
            or IPv6 addresses, networks or from host authenticated by
            TSIG key are allowed or not.
        anonymize_response_logging: Determines if the anonymization of
            captured DNS responses is enabled or disabled.
        attack_mitigation: Mitigation settings for DNS attacks.
        auto_blackhole: The auto blackhole settings.
        bind_check_names_policy: The BIND check names policy, which
            indicates the action the appliance takes when it encounters
            host names that do not comply with the Strict Hostname
            Checking policy. This method applies only if the host name
            restriction policy is set to "Strict Hostname Checking".
        bind_hostname_directive: The value of the hostname directive for
            BIND.
        blackhole_list: The list of IPv4 or IPv6 addresses and networks
            from which DNS queries are blocked.
        blacklist_action: The action to perform when a domain name
            matches the pattern defined in a rule that is specified by
            the blacklist ruleset.
        blacklist_log_query: Determines if blacklist redirection queries
            are logged or not.
        blacklist_redirect_addresses: The IP addresses the appliance
            includes in the response it sends in place of a blacklisted
            IP address.
        blacklist_redirect_ttl: The TTL value (in seconds) of the
            synthetic DNS responses that result from blacklist
            redirection.
        blacklist_rulesets: The DNS Ruleset object names assigned at the
            Grid level for blacklist redirection.
        bulk_host_name_templates: The list of bulk host name templates.
            There are four Infoblox predefined bulk host name templates.
            Template Name Template Format "Four Octets" -$1-$2-$3-$4
            "Three Octets" -$2-$3-$4 "Two Octets" -$3-$4 "One Octet" -$4
        capture_dns_queries_on_all_domains: Determines if the capture of
            DNS queries for all domains is enabled or disabled.
        check_names_for_ddns_and_zone_transfer: Determines whether the
            application of BIND check-names for zone transfers and DDNS
            updates are enabled.
        client_subnet_domains: The list of zone domain names that are
            allowed or forbidden for EDNS client subnet (ECS) recursion.
        client_subnet_ipv4_prefix_length: Default IPv4 Source Prefix-
            Length used when sending queries with EDNS client subnet
            option.
        client_subnet_ipv6_prefix_length: Default IPv6 Source Prefix-
            Length used when sending queries with EDNS client subnet
            option.
        copy_client_ip_mac_options: Copy custom IP, MAC and DNS View
            name ENDS0 options from incoming to outgoing recursive
            queries.
        copy_xfer_to_notify: The allowed IPs, from the zone transfer
            list, added to the also-notify statement in the named.conf
            file.
        custom_root_name_servers: The list of customized root
            nameserver(s). You can use Internet root name servers or
            specify host names and IP addresses of custom root name
            servers.
        ddns_force_creation_timestamp_update: Defines whether creation
            timestamp of RR should be updated ' when DDNS update happens
            even if there is no change to ' the RR.
        ddns_principal_group: The DDNS Principal cluster group name.
        ddns_principal_tracking: Determines if the DDNS principal track
            is enabled or disabled.
        ddns_restrict_patterns: Determines if an option to restrict DDNS
            update request based on FQDN patterns is enabled or
            disabled.
        ddns_restrict_patterns_list: The unordered list of restriction
            patterns for an option of to restrict DDNS updates based on
            FQDN patterns.
        ddns_restrict_protected: Determines if an option to restrict
            DDNS update request to protected resource records is enabled
            or disabled.
        ddns_restrict_secure: Determines if DDNS update request for
            principal other than target resource record's principal is
            restricted.
        ddns_restrict_static: Determines if an option to restrict DDNS
            update request to resource records which are marked as
            'STATIC' is enabled or disabled.
        default_bulk_host_name_template: Default bulk host name of a
            Grid DNS.
        default_ttl: The default TTL value of a Grid DNS object. This
            interval tells the secondary how long the data can be
            cached.
        disable_edns: Determines if the EDNS0 support for queries that
            require recursive resolution on Grid members is enabled or
            not.
        dns64_groups: The list of DNS64 synthesis groups associated with
            this Grid DNS object.
        dns_cache_acceleration_ttl: The minimum TTL value, in seconds,
            that a DNS record must have in order for it to be cached by
            the DNS Cache Acceleration service.An integer from 1 to
            65000 that represents the TTL in seconds.
        dns_health_check_anycast_control: Determines if the anycast
            failure (BFD session down) is enabled on member failure or
            not.
        dns_health_check_domain_list: The list of domain names for the
            DNS health check.
        dns_health_check_interval: The time interval (in seconds) for
            DNS health check.
        dns_health_check_recursion_flag: Determines if the recursive DNS
            health check is enabled or not.
        dns_health_check_retries: The number of DNS health check
            retries.
        dns_health_check_timeout: The DNS health check timeout interval
            (in seconds).
        dns_query_capture_file_time_limit: The time limit (in minutes)
            for the DNS query capture file.
        dnssec_blacklist_enabled: Determines if the blacklist rules for
            DNSSEC-enabled clients are enabled or not.
        dnssec_dns64_enabled: Determines if the DNS64 groups for DNSSEC-
            enabled clients are enabled or not.
        dnssec_enabled: Determines if the DNS security extension is
            enabled or not.
        dnssec_expired_signatures_enabled: Determines when the DNS
            member accepts expired signatures.
        dnssec_key_params: This structure contains the DNSSEC key
            parameters for this zone.
        dnssec_negative_trust_anchors: A list of zones for which the
            server does not perform DNSSEC validation.
        dnssec_nxdomain_enabled: Determines if the NXDOMAIN rules for
            DNSSEC-enabled clients are enabled or not.
        dnssec_rpz_enabled: Determines if the RPZ policies for DNSSEC-
            enabled clients are enabled or not.
        dnssec_trusted_keys: The list of trusted keys for the DNSSEC
            feature.
        dnssec_validation_enabled: Determines if the DNS security
            validation is enabled or not.
        dnstap_setting: The DNSTAP settings.
        domains_to_capture_dns_queries: The list of domains for DNS
            query capture.
        dtc_dns_queries_specific_behavior: Setting to control specific
            behavior for DTC DNS responses for incoming lbdn matched
            queries.
        dtc_dnssec_mode: DTC DNSSEC operation mode.
        dtc_edns_prefer_client_subnet: Determines whether to prefer the
            client address from the edns-client-subnet option for DTC or
            not.
        dtc_scheduled_backup: The scheduled backup configuration.
        dtc_topology_ea_list: The DTC topology extensible attribute
            definition list. When configuring a DTC topology, users may
            configure classification as either "Geographic" or
            "Extensible Attributes". Selecting extensible attributes
            will replace supported Topology database labels (Continent,
            Country, Subdivision, City) with the names of the selection
            EA types and provide values extracted from DHCP Network
            Container, Network and Range objects with those extensible
            attributes.
        edns_udp_size: Advertises the EDNS0 buffer size to the upstream
            server. The value should be between 512 and 4096 bytes. The
            recommended value is between 512 and 1220 bytes.
        email: The email address of a Grid DNS object.
        enable_blackhole: Determines if the blocking of DNS queries is
            enabled or not.
        enable_blacklist: Determines if a blacklist is enabled or not.
        enable_capture_dns_queries: Determines if the capture of DNS
            queries is enabled or disabled.
        enable_capture_dns_responses: Determines if the capture of DNS
            responses is enabled or disabled.
        enable_client_subnet_forwarding: Determines whether to enable
            forwarding EDNS client subnet options to upstream servers.
        enable_client_subnet_recursive: Determines whether to enable
            adding EDNS client subnet options in recursive resolution.
        enable_delete_associated_ptr: Determines if the ability to
            automatically remove associated PTR records while deleting A
            or AAAA records is enabled or not.
        enable_dns64: Determines if the DNS64 support is enabled or not.
        enable_dns_health_check: Determines if the DNS health check is
            enabled or not.
        enable_dnstap_queries: Determines whether the query messages
            need to be forwarded to DNSTAP or not.
        enable_dnstap_responses: Determines whether the response
            messages need to be forwarded to DNSTAP or not.
        enable_excluded_domain_names: Determines if excluding domain
            names from captured DNS queries and responses is enabled or
            disabled.
        enable_fixed_rrset_order_fqdns: Determines if the fixed RRset
            order FQDN is enabled or not.
        enable_ftc: Determines whether Fault Tolerant Caching (FTC) is
            enabled.
        enable_gss_tsig: Determines whether all appliances in the Grid
            are enabled to receive GSS-TSIG authenticated updates from
            DNS clients.
        enable_host_rrset_order: Determines if the host RRset order is
            enabled or not.
        enable_hsm_signing: Determines whether Hardware Security Modules
            (HSMs) are enabled for key generation and signing. Note,
            that you must configure the HSM group with at least one
            enabled HSM.
        enable_notify_source_port: Determines if the notify source port
            at the Grid Level is enabled or not.
        enable_query_rewrite: Determines if the DNS query rewrite is
            enabled or not.
        enable_query_source_port: Determines if the query source port at
            the Grid Level is enabled or not.
        excluded_domain_names: The list of domains that are excluded
            from DNS query and response capture.
        expire_after: The expiration time of a Grid DNS object. If the
            secondary DNS server fails to contact the primary server for
            the specified interval, the secondary server stops giving
            out answers about the zone because the zone data is too old
            to be useful.
        file_transfer_setting: The DNS capture file transfer
            settings.Include the specified parameter to set the
            attribute value. Omit the parameter to retrieve the
            attribute value.
        filter_aaaa: The type of AAAA filtering for this member DNS
            object.
        filter_aaaa_list: The list of IPv4 addresses and networks from
            which queries are received. AAAA filtering is applied to
            these addresses.
        fixed_rrset_order_fqdns: The fixed RRset order FQDN. If this
            field does not contain an empty value, the appliance will
            automatically set the enable_fixed_rrset_order_fqdns field
            to 'true', unless the same request sets the enable field to
            'false'.
        forward_only: Determines if member sends queries to forwarders
            only. When the value is "true", the member sends queries to
            forwarders only, and not to other internal or Internet root
            servers.
        forward_updates: Determines if secondary servers is allowed to
            forward updates to the DNS server or not.
        forwarders: The forwarders for the member. A forwarder is
            essentially a name server to which other name servers first
            send all of their off-site queries. The forwarder builds up
            a cache of information, avoiding the need for the other name
            servers to send queries off-site.
        ftc_expired_record_timeout: The timeout interval (in seconds)
            after which the expired Fault Tolerant Caching (FTC)record
            is stale and no longer valid.
        ftc_expired_record_ttl: The TTL value (in seconds) of the
            expired Fault Tolerant Caching (FTC) record in DNS
            responses.
        gen_eadb_from_hosts: Flag for taking EA values from IPAM Hosts
            into consideration for the DTC topology EA database.
        gen_eadb_from_network_containers: Flag for taking EA values from
            IPAM Network Containers into consideration for the DTC
            topology EA database.
        gen_eadb_from_networks: Flag for taking EA values from IPAM
            Network into consideration for the DTC topology EA database.
        gen_eadb_from_ranges: Flag for taking EA values from IPAM Ranges
            into consideration for the DTC topology EA database.
        gss_tsig_keys: The list of GSS-TSIG keys for a Grid DNS object.
        lame_ttl: The number of seconds to cache lame delegations or
            lame servers.
        last_queried_acl: Determines last queried ACL for the specified
            IPv4 or IPv6 addresses and networks in scavenging settings.
        logging_categories: The logging categories.
        max_cache_ttl: The maximum time (in seconds) for which the
            server will cache positive answers.
        max_cached_lifetime: The maximum time (in seconds) a DNS
            response can be stored in the hardware acceleration
            cache.Valid values are unsigned integer between 60 and
            86400, inclusive.
        max_ncache_ttl: The maximum time (in seconds) for which the
            server will cache negative (NXDOMAIN) responses.The maximum
            allowed value is 604800.
        max_udp_size: The value is used by authoritative DNS servers to
            never send DNS responses larger than the configured value.
            The value should be between 512 and 4096 bytes. The
            recommended value is between 512 and 1220 bytes.
        member_secondary_notify: Determines if Grid members that are
            authoritative secondary servers are allowed to send
            notification messages to external name servers, if the Grid
            member that is primary for a zone fails or loses
            connectivity.
        negative_ttl: The negative TTL value of a Grid DNS object. This
            interval tells the secondary how long data can be cached for
            "Does Not Respond" responses.
        notify_delay: Specifies with how many seconds of delay the
            notify messages are sent to secondaries.
        notify_source_port: The source port for notify messages. When
            requesting zone transfers from the primary server, some
            secondary DNS servers use the source port number (the
            primary server used to send the notify message) as the
            destination port number in the zone transfer request.Valid
            values are between 1 and 63999. The default is picked by
            BIND.
        nsgroup_default: The default nameserver group.
        nsgroups: A name server group is a collection of one primary DNS
            server and one or more secondary DNS servers.
        nxdomain_log_query: Determines if NXDOMAIN redirection queries
            are logged or not.
        nxdomain_redirect: Determines if NXDOMAIN redirection is enabled
            or not.
        nxdomain_redirect_addresses: The list of IPv4 NXDOMAIN
            redirection addresses.
        nxdomain_redirect_addresses_v6: The list of IPv6 NXDOMAIN
            redirection addresses.
        nxdomain_redirect_ttl: The TTL value (in seconds) of synthetic
            DNS responses that result from NXDOMAIN redirection.
        nxdomain_rulesets: The Ruleset object names assigned at the Grid
            level for NXDOMAIN redirection.
        preserve_host_rrset_order_on_secondaries: Determines if the host
            RRset order on secondaries is preserved or not.
        protocol_record_name_policies: The list of record name policies.
        query_rewrite_domain_names: The list of domain names that
            trigger DNS query rewrite.
        query_rewrite_prefix: The domain name prefix for DNS query
            rewrite.
        query_source_port: The source port for queries. Specifying a
            source port number for recursive queries ensures that a
            firewall will allow the response.Valid values are between 1
            and 63999. The default is picked by BIND.
        recursive_query_list: The list of IPv4 or IPv6 addresses,
            networks or hosts authenticated by Transaction signature
            (TSIG) key from which recursive queries are allowed or
            denied.
        refresh_timer: The refresh time. This interval tells the
            secondary how often to send a message to the primary for a
            zone to check that its data is current, and retrieve fresh
            data if it is not.
        resolver_query_timeout: The recursive query timeout for the
            member.
        response_rate_limiting: The response rate limiting settings for
            the member.
        restart_setting: The restart setting.
        retry_timer: The retry time. This interval tells the secondary
            how long to wait before attempting to recontact the primary
            after a connection failure occurs between the two servers.
        root_name_server_type: Determines the type of root name servers.
        rpz_disable_nsdname_nsip: Determines if NSDNAME and NSIP
            resource records from RPZ feeds are enabled or not.
        rpz_drop_ip_rule_enabled: Enables the appliance to ignore RPZ-IP
            triggers with prefix lengths less than the specified minimum
            prefix length.
        rpz_drop_ip_rule_min_prefix_length_ipv4: The minimum prefix
            length for IPv4 RPZ-IP triggers. The appliance ignores RPZ-
            IP triggers with prefix lengths less than the specified
            minimum IPv4 prefix length.
        rpz_drop_ip_rule_min_prefix_length_ipv6: The minimum prefix
            length for IPv6 RPZ-IP triggers. The appliance ignores RPZ-
            IP triggers with prefix lengths less than the specified
            minimum IPv6 prefix length.
        rpz_qname_wait_recurse: Determines if recursive RPZ lookups are
            enabled.
        scavenging_settings: The Grid level scavenging settings.
        serial_query_rate: The number of maximum concurrent SOA queries
            per second.Valid values are unsigned integer between 20 and
            1000, inclusive.
        server_id_directive: The value of the server-id directive for
            BIND and Unbound DNS.
        sortlist: A sort list determines the order of addresses in
            responses made to DNS queries.
        store_locally: Determines if the storage of query capture
            reports on the appliance is enabled or disabled.
        syslog_facility: The syslog facility. This is the location on
            the syslog server to which you want to sort the DNS logging
            messages.
        transfer_excluded_servers: The list of excluded DNS servers
            during zone transfers.
        transfer_format: The BIND format for a zone transfer. This
            provides tracking capabilities for single or multiple
            transfers and their associated servers.
        transfers_in: The number of maximum concurrent transfers for the
            Grid.Valid values are unsigned integer between 10 and 10000,
            inclusive.
        transfers_out: The number of maximum outbound concurrent zone
            transfers.Valid values are unsigned integer between 10 and
            10000, inclusive.
        transfers_per_ns: The number of maximum concurrent transfers per
            member.Valid values are unsigned integer between 2 and
            10000, inclusive.
        zone_deletion_double_confirm: Determines if the double
            confirmation during zone deletion is enabled or not.
    """
    _infoblox_type = 'grid:dns'
    _fields = ['add_client_ip_mac_options', 'allow_bulkhost_ddns',
               'allow_gss_tsig_zone_updates', 'allow_query',
               'allow_recursive_query', 'allow_transfer', 'allow_update',
               'anonymize_response_logging', 'attack_mitigation',
               'auto_blackhole', 'bind_check_names_policy',
               'bind_hostname_directive', 'blackhole_list', 'blacklist_action',
               'blacklist_log_query', 'blacklist_redirect_addresses',
               'blacklist_redirect_ttl', 'blacklist_rulesets',
               'bulk_host_name_templates',
               'capture_dns_queries_on_all_domains',
               'check_names_for_ddns_and_zone_transfer',
               'client_subnet_domains', 'client_subnet_ipv4_prefix_length',
               'client_subnet_ipv6_prefix_length',
               'copy_client_ip_mac_options', 'copy_xfer_to_notify',
               'custom_root_name_servers',
               'ddns_force_creation_timestamp_update', 'ddns_principal_group',
               'ddns_principal_tracking', 'ddns_restrict_patterns',
               'ddns_restrict_patterns_list', 'ddns_restrict_protected',
               'ddns_restrict_secure', 'ddns_restrict_static',
               'default_bulk_host_name_template', 'default_ttl',
               'disable_edns', 'dns64_groups', 'dns_cache_acceleration_ttl',
               'dns_health_check_anycast_control',
               'dns_health_check_domain_list', 'dns_health_check_interval',
               'dns_health_check_recursion_flag', 'dns_health_check_retries',
               'dns_health_check_timeout', 'dns_query_capture_file_time_limit',
               'dnssec_blacklist_enabled', 'dnssec_dns64_enabled',
               'dnssec_enabled', 'dnssec_expired_signatures_enabled',
               'dnssec_key_params', 'dnssec_negative_trust_anchors',
               'dnssec_nxdomain_enabled', 'dnssec_rpz_enabled',
               'dnssec_trusted_keys', 'dnssec_validation_enabled',
               'dnstap_setting', 'domains_to_capture_dns_queries',
               'dtc_dns_queries_specific_behavior', 'dtc_dnssec_mode',
               'dtc_edns_prefer_client_subnet', 'dtc_scheduled_backup',
               'dtc_topology_ea_list', 'edns_udp_size', 'email',
               'enable_blackhole', 'enable_blacklist',
               'enable_capture_dns_queries', 'enable_capture_dns_responses',
               'enable_client_subnet_forwarding',
               'enable_client_subnet_recursive',
               'enable_delete_associated_ptr', 'enable_dns64',
               'enable_dns_health_check', 'enable_dnstap_queries',
               'enable_dnstap_responses', 'enable_excluded_domain_names',
               'enable_fixed_rrset_order_fqdns', 'enable_ftc',
               'enable_gss_tsig', 'enable_host_rrset_order',
               'enable_hsm_signing', 'enable_notify_source_port',
               'enable_query_rewrite', 'enable_query_source_port',
               'excluded_domain_names', 'expire_after',
               'file_transfer_setting', 'filter_aaaa', 'filter_aaaa_list',
               'fixed_rrset_order_fqdns', 'forward_only', 'forward_updates',
               'forwarders', 'ftc_expired_record_timeout',
               'ftc_expired_record_ttl', 'gen_eadb_from_hosts',
               'gen_eadb_from_network_containers', 'gen_eadb_from_networks',
               'gen_eadb_from_ranges', 'gss_tsig_keys', 'lame_ttl',
               'last_queried_acl', 'logging_categories', 'max_cache_ttl',
               'max_cached_lifetime', 'max_ncache_ttl', 'max_udp_size',
               'member_secondary_notify', 'negative_ttl', 'notify_delay',
               'notify_source_port', 'nsgroup_default', 'nsgroups',
               'nxdomain_log_query', 'nxdomain_redirect',
               'nxdomain_redirect_addresses', 'nxdomain_redirect_addresses_v6',
               'nxdomain_redirect_ttl', 'nxdomain_rulesets',
               'preserve_host_rrset_order_on_secondaries',
               'protocol_record_name_policies', 'query_rewrite_domain_names',
               'query_rewrite_prefix', 'query_source_port',
               'recursive_query_list', 'refresh_timer',
               'resolver_query_timeout', 'response_rate_limiting',
               'restart_setting', 'retry_timer', 'root_name_server_type',
               'rpz_disable_nsdname_nsip', 'rpz_drop_ip_rule_enabled',
               'rpz_drop_ip_rule_min_prefix_length_ipv4',
               'rpz_drop_ip_rule_min_prefix_length_ipv6',
               'rpz_qname_wait_recurse', 'scavenging_settings',
               'serial_query_rate', 'server_id_directive', 'sortlist',
               'store_locally', 'syslog_facility', 'transfer_excluded_servers',
               'transfer_format', 'transfers_in', 'transfers_out',
               'transfers_per_ns', 'zone_deletion_double_confirm']
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
        'last_queried_acl': Addressac.from_dict,
        'recursive_query_list': Addressac.from_dict,
        'sortlist': Sortlist.from_dict,
    }

    def run_scavenging(self, *args, **kwargs):
        return self._call_func("run_scavenging", *args, **kwargs)


class GridFiledistribution(InfobloxObject):
    """ GridFiledistribution: Grid file distribution object.
    Corresponds to WAPI object 'grid:filedistribution'

    The Grid file distribution object represents the file distribution
    storage limit configuration and global file distribution statistics.

    Attributes:
        allow_uploads: Determines whether the uploads to Grid members
            are allowed.
        backup_storage: Determines whether to include distributed files
            in the backup.
        current_usage: The value is the percentage of the allocated TFTP
            storage space that is used, expressed in tenth of a percent.
            Valid values are from 0 to 1000.
        enable_anonymous_ftp: Determines whether the FTP anonymous login
            is enabled.
        global_status: The Grid file distribution global status.
        name: The Grid name.
        storage_limit: Maximum storage in megabytes allowed on the Grid.
            The maximum storage space allowed for all file distribution
            services on a Grid is equal to the storage space allowed to
            the Grid member with the smallest amount of space allowed.
    """
    _infoblox_type = 'grid:filedistribution'
    _fields = ['allow_uploads', 'backup_storage', 'current_usage',
               'enable_anonymous_ftp', 'global_status', 'name',
               'storage_limit']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['allow_uploads', 'current_usage', 'global_status',
                      'name', 'storage_limit']
    _remap = {}
    _shadow_fields = ['_ref']


class GridLicensePool(InfobloxObject):
    """ GridLicensePool: Grid License Pool object.
    Corresponds to WAPI object 'grid:license_pool'

    This object represents the Grid license pool.

    Attributes:
        assigned: The number of dynamic licenses allocated to vNIOS
            appliances.
        expiration_status: The license expiration status.
        expiry_date: The expiration timestamp of the license.
        installed: The total number of dynamic licenses allowed for this
            license pool.
        key: The license string for the license pool.
        limit: The limitation of dynamic license that can be allocated
            from the license pool.
        limit_context: The license limit context.
        model: The supported vNIOS virtual appliance model.
        subpools: The license pool subpools.
        temp_assigned: The total number of temporary dynamic licenses
            allocated to vNIOS appliances.
        type: The license type.
    """
    _infoblox_type = 'grid:license_pool'
    _fields = ['assigned', 'expiration_status', 'expiry_date', 'installed',
               'key', 'limit', 'limit_context', 'model', 'subpools',
               'temp_assigned', 'type']
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
    """ GridLicensePoolContainer: Grid License Pool Container object.
    Corresponds to WAPI object 'grid:license_pool_container'

    This object represents the Grid license pool container.

    Attributes:
        last_entitlement_update: The timestamp when the last pool
            licenses were updated.
        lpc_uid: The world-wide unique ID for the license pool
            container.
    """
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
    """ GridMaxminddbinfo:  Topology DB Info object.
    Corresponds to WAPI object 'grid:maxminddbinfo'

    The information about Topology DB.

    Attributes:
        binary_major_version: The major version of DB binary format.
        binary_minor_version: The minor version of DB binary format.
        build_time: The time at which the DB was built.
        database_type: The structure of data records
            ("GeoLite2-Country", GeoLite2-City", etc.).
        deployment_time: The time at which the current Topology DB was
            deployed.
        member: The member for testing the connection.
        topology_type: The topology type.
    """
    _infoblox_type = 'grid:maxminddbinfo'
    _fields = ['binary_major_version', 'binary_minor_version', 'build_time',
               'database_type', 'deployment_time', 'member', 'topology_type']
    _search_for_update_fields = ['topology_type']
    _updateable_search_fields = []
    _all_searchable_fields = ['topology_type']
    _return_fields = ['binary_major_version', 'binary_minor_version',
                      'build_time', 'database_type', 'deployment_time',
                      'member', 'topology_type']
    _remap = {}
    _shadow_fields = ['_ref']


class GridMemberCloudapi(InfobloxObject):
    """ GridMemberCloudapi: Member Cloud API object.
    Corresponds to WAPI object 'grid:member:cloudapi'

    Class that represents member Cloud configuration settings.

    Attributes:
        allow_api_admins: Defines which administrators are allowed to
            perform Cloud API request on the Grid Member: no
            administrators (NONE), any administrators (ALL) or
            administrators in the ACL list (LIST). Default is ALL.
        allowed_api_admins: List of administrators allowed to perform
            Cloud Platform API requests on that member.
        enable_service: Controls whether the Cloud API service runs on
            the member or not.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        gateway_config: Structure containing all the information related
            to Gateway configuration for the member
        member: The related Grid Member.
        status: Status of Cloud API service on the member.
    """
    _infoblox_type = 'grid:member:cloudapi'
    _fields = ['allow_api_admins', 'allowed_api_admins', 'enable_service',
               'extattrs', 'gateway_config', 'member', 'status']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['allow_api_admins', 'allowed_api_admins',
                      'enable_service', 'extattrs', 'member', 'status']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'allowed_api_admins': GridCloudapiUser.from_dict,
    }


class GridServicerestartGroup(InfobloxObject):
    """ GridServicerestartGroup: Service Restart Group object.
    Corresponds to WAPI object 'grid:servicerestart:group'

    The Grid Service Restart Group object provides the following
    information about the restart: applicable services, members, restart
    order, and periodicity.

    Attributes:
        comment: Comment for the Restart Group; maximum 256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        is_default: Determines if this Restart Group is the default
            group.
        last_updated_time: The timestamp when the status of the latest
            request has changed.
        members: The list of members belonging to the group.
        mode: The default restart method for this Restart Group.
        name: The name of this Restart Group.
        position: The order to restart.
        recurring_schedule: The recurring schedule for restart of a
            group.
        requests: The list of requests associated with a restart group.
        service: The applicable service for this Restart Group.
        status: The restart status for a restart group.
    """
    _infoblox_type = 'grid:servicerestart:group'
    _fields = ['comment', 'extattrs', 'is_default', 'last_updated_time',
               'members', 'mode', 'name', 'position', 'recurring_schedule',
               'requests', 'service', 'status']
    _search_for_update_fields = ['name', 'service']
    _updateable_search_fields = ['comment', 'name', 'service']
    _all_searchable_fields = ['comment', 'is_default', 'name', 'service']
    _return_fields = ['comment', 'extattrs', 'name', 'service']
    _remap = {}
    _shadow_fields = ['_ref']


class GridServicerestartGroupOrder(InfobloxObject):
    """ GridServicerestartGroupOrder: Restart Group Order object.
    Corresponds to WAPI object 'grid:servicerestart:group:order'

    The Grid Service Restart Group Order Setting is used to set the
    restart order for particular services and members.

    Attributes:
        groups: The ordered list of the Service Restart Group.
    """
    _infoblox_type = 'grid:servicerestart:group:order'
    _fields = ['groups']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']


class GridServicerestartRequest(InfobloxObject):
    """ GridServicerestartRequest: Restart Request object.
    Corresponds to WAPI object 'grid:servicerestart:request'

    The Restart Request object provides information and statistics about
    the service restart routine for the Service Restart Group.

    Attributes:
        error: The error message if restart has failed.
        forced: Indicates if this is a force restart.
        group: The name of the Restart Group associated with the
            request.
        last_updated_time: The timestamp when the status of the request
            has changed.
        member: The member to restart.
        needed: Indicates if restart is needed.
        order: The order to restart.
        result: The result of the restart operation.
        service: The service to restart.
        state: The state of the request.
    """
    _infoblox_type = 'grid:servicerestart:request'
    _fields = ['error', 'forced', 'group', 'last_updated_time', 'member',
               'needed', 'order', 'result', 'service', 'state']
    _search_for_update_fields = ['group']
    _updateable_search_fields = []
    _all_searchable_fields = ['group', 'member']
    _return_fields = ['error', 'group', 'result', 'state']
    _remap = {}
    _shadow_fields = ['_ref']


class GridServicerestartRequestChangedobject(InfobloxObject):
    """ GridServicerestartRequestChangedobject: Grid service restart
    request changed object.
    Corresponds to WAPI object
    'grid:servicerestart:request:changedobject'

    The Grid service restart request changed object provides information
    about changes that are waiting for the restart.

    Attributes:
        action: The operation on the changed object.
        changed_properties: The list of changed properties in the
            object.
        changed_time: The time when the object was changed.
        object_name: The name of the changed object.
        object_type: The type of the changed object. This is undefined
            if the object is not supported.
        user_name: The name of the user who changed the object
            properties.
    """
    _infoblox_type = 'grid:servicerestart:request:changedobject'
    _fields = ['action', 'changed_properties', 'changed_time', 'object_name',
               'object_type', 'user_name']
    _search_for_update_fields = ['user_name']
    _updateable_search_fields = []
    _all_searchable_fields = ['user_name']
    _return_fields = ['action', 'changed_properties', 'changed_time',
                      'object_name', 'object_type', 'user_name']
    _remap = {}
    _shadow_fields = ['_ref']


class GridServicerestartStatus(InfobloxObject):
    """ GridServicerestartStatus: Restart Status object.
    Corresponds to WAPI object 'grid:servicerestart:status'

    The Restart Status object provides information and statistics about
    service restart routine for the Grid or Service Restart Group.

    Attributes:
        failures: The number of failed requests.
        finished: The number of finished requests.
        grouped: The type of grouping.
        needed_restart: The number of created yet unprocessed requests
            for restart.
        no_restart: The number of requests that did not require a
            restart.
        parent: A reference to the grid or grid:servicerestart:group
            object associated with the request.
        pending: The number of requests that are pending a restart.
        pending_restart: The number of forced or needed requests pending
            for restart.
        processing: The number of not forced and not needed requests
            pending for restart.
        restarting: The number of service restarts for corresponding
            members.
        success: The number of requests associated with successful
            restarts.
        timeouts: The number of timeout requests.
    """
    _infoblox_type = 'grid:servicerestart:status'
    _fields = ['failures', 'finished', 'grouped', 'needed_restart',
               'no_restart', 'parent', 'pending', 'pending_restart',
               'processing', 'restarting', 'success', 'timeouts']
    _search_for_update_fields = ['parent']
    _updateable_search_fields = []
    _all_searchable_fields = ['parent']
    _return_fields = ['failures', 'finished', 'grouped', 'needed_restart',
                      'no_restart', 'parent', 'pending', 'pending_restart',
                      'processing', 'restarting', 'success', 'timeouts']
    _remap = {}
    _shadow_fields = ['_ref']


class GridThreatanalytics(InfobloxObject):
    """ GridThreatanalytics: Grid threat analytics object.
    Corresponds to WAPI object 'grid:threatanalytics'

    To mitigate DNS data exfiltration, Infoblox DNS threat analytics
    employs analytics algorithms that analyze incoming DNS queries and
    responses to detect DNS tunneling traffic.

    The Grid threat analytics object contains settings and information
    about updates download, and mitigation response policy zone to which
    queries on blacklisted domains are transfered.

    Attributes:
        configure_domain_collapsing: Disable domain collapsing at grid
            level
        current_moduleset: The current threat analytics module set.
        current_whitelist: The Grid whitelist.
        dns_tunnel_black_list_rpz_zones: The list of response policy
            zones for DNS tunnelling requests.
        domain_collapsing_level: Level of domain collapsing
        enable_auto_download: Determines whether the automatic threat
            analytics module set download is enabled.
        enable_scheduled_download: Determines whether the scheduled
            download of the threat analytics module set is enabled.
        enable_whitelist_auto_download: Indicates whether auto download
            service is enabled
        enable_whitelist_scheduled_download: Indicates whether the
            custom scheduled settings for auto download is enabled. If
            false then default frequency is once per 24 hours
        last_checked_for_update: The last time when the threat analytics
            module set was checked for the update.
        last_checked_for_whitelist_update: Timestamp of last checked
            whitelist
        last_module_update_time: The last update time for the threat
            analytics module set.
        last_module_update_version: The version number of the last
            updated threat analytics module set.
        last_whitelist_update_time: The last update time for the threat
            analytics whitelist.
        last_whitelist_update_version: The version number of the last
            updated threat analytics whitelist.
        module_update_policy: The update policy for the threat analytics
            module set.
        name: The Grid name.
        scheduled_download: The schedule settings for the threat
            analytics module set download.
        scheduled_whitelist_download: Schedule setting for automatic
            whitelist update run
        whitelist_update_policy: whitelist update policy (manual or
            automatic)
    """
    _infoblox_type = 'grid:threatanalytics'
    _fields = ['configure_domain_collapsing', 'current_moduleset',
               'current_whitelist', 'dns_tunnel_black_list_rpz_zones',
               'domain_collapsing_level', 'enable_auto_download',
               'enable_scheduled_download', 'enable_whitelist_auto_download',
               'enable_whitelist_scheduled_download',
               'last_checked_for_update', 'last_checked_for_whitelist_update',
               'last_module_update_time', 'last_module_update_version',
               'last_whitelist_update_time', 'last_whitelist_update_version',
               'module_update_policy', 'name', 'scheduled_download',
               'scheduled_whitelist_download', 'whitelist_update_policy']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['enable_auto_download', 'enable_scheduled_download',
                      'module_update_policy', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    def download_threat_analytics_moduleset_update(self, *args, **kwargs):
        return self._call_func("download_threat_analytics_moduleset_update",
                               *args, **kwargs)

    def download_threat_analytics_whitelist_update(self, *args, **kwargs):
        return self._call_func("download_threat_analytics_whitelist_update",
                               *args, **kwargs)

    def move_blacklist_rpz_to_white_list(self, *args, **kwargs):
        return self._call_func("move_blacklist_rpz_to_white_list", *args,
                               **kwargs)

    def set_last_uploaded_threat_analytics_moduleset(self, *args, **kwargs):
        return self._call_func("set_last_uploaded_threat_analytics_moduleset",
                               *args, **kwargs)

    def test_threat_analytics_server_connectivity(self, *args, **kwargs):
        return self._call_func("test_threat_analytics_server_connectivity",
                               *args, **kwargs)

    def update_threat_analytics_moduleset(self, *args, **kwargs):
        return self._call_func("update_threat_analytics_moduleset", *args,
                               **kwargs)


class GridThreatprotection(InfobloxObject):
    """ GridThreatprotection: The Grid threat protection object.
    Corresponds to WAPI object 'grid:threatprotection'

    The Grid threat protection settings.

    Attributes:
        current_ruleset: The current Grid ruleset.
        disable_multiple_dns_tcp_request: Determines if multiple BIND
            responses via TCP connection are disabled.
        enable_accel_resp_before_threat_protection: Determines if DNS
            responses are sent from acceleration cache before applying
            Threat Protection rules. Recommended for better performance
            when using DNS Cache Acceleration.
        enable_auto_download: Determines if auto download service is
            enabled.
        enable_nat_rules: Determines if NAT (Network Address
            Translation) mapping for threat protection is enabled or
            not.
        enable_scheduled_download: Determines if scheduled download is
            enabled. The default frequency is once in every 24 hours if
            it is disabled.
        events_per_second_per_rule: The number of events logged per
            second per rule.
        grid_name: The Grid name.
        last_checked_for_update: The time when the Grid last checked for
            updates.
        last_rule_update_timestamp: The last rule update timestamp.
        last_rule_update_version: The version of last rule update.
        nat_rules: The list of NAT mapping rules for threat protection.
        outbound_settings: Outbound settings for ATP events.
        rule_update_policy: The update rule policy.
        scheduled_download: The schedule setting for automatic rule
            update.
    """
    _infoblox_type = 'grid:threatprotection'
    _fields = ['current_ruleset', 'disable_multiple_dns_tcp_request',
               'enable_accel_resp_before_threat_protection',
               'enable_auto_download', 'enable_nat_rules',
               'enable_scheduled_download', 'events_per_second_per_rule',
               'grid_name', 'last_checked_for_update',
               'last_rule_update_timestamp', 'last_rule_update_version',
               'nat_rules', 'outbound_settings', 'rule_update_policy',
               'scheduled_download']
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
    """ GridX509Certificate: X509Certificate object.
    Corresponds to WAPI object 'grid:x509certificate'

    In the X.509 system, a certification authority issues a certificate
    binding a public key to a particular distinguished name in the X.500
    tradition, or to an alternative name such as an e-mail address or a
    DNS entry.

    Attributes:
        issuer: Certificate issuer.
        serial: X509Certificate serial number.
        subject: A Distinguished Name that is made of multiple relative
            distinguished names (RDNs).
        valid_not_after: Certificate expiry date.
        valid_not_before: Certificate validity start date.
    """
    _infoblox_type = 'grid:x509certificate'
    _fields = ['issuer', 'serial', 'subject', 'valid_not_after',
               'valid_not_before']
    _search_for_update_fields = ['issuer', 'serial', 'subject']
    _updateable_search_fields = []
    _all_searchable_fields = ['issuer', 'serial', 'subject', 'valid_not_after',
                              'valid_not_before']
    _return_fields = ['issuer', 'serial', 'subject']
    _remap = {}
    _shadow_fields = ['_ref']


class Hostnamerewritepolicy(InfobloxObject):
    """ Hostnamerewritepolicy: Hostname rewrite policy object.
    Corresponds to WAPI object 'hostnamerewritepolicy'

    A hostname rewrite policy object represents the set of valid
    characters as well as replacement characters for names that do not
    conform to the policy.

    Attributes:
        is_default: True if the policy is the Grid default.
        name: The name of a hostname rewrite policy object.
        pre_defined: Determines whether the policy is a predefined one.
        replacement_character: The replacement character for symbols in
            hostnames that do not conform to the hostname policy.
        valid_characters: The set of valid characters represented in
            string format.
    """
    _infoblox_type = 'hostnamerewritepolicy'
    _fields = ['is_default', 'name', 'pre_defined', 'replacement_character',
               'valid_characters']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name']
    _return_fields = ['name', 'replacement_character', 'valid_characters']
    _remap = {}
    _shadow_fields = ['_ref']


class HsmAllgroups(InfobloxObject):
    """ HsmAllgroups: All Hardware Security Module groups object.
    Corresponds to WAPI object 'hsm:allgroups'

    The All Hardware Security Module (HSM) groups object is used to
    retrieve all HSM groups configured on the appliance.

    Attributes:
        groups: The list of HSM groups configured on the appliance.
    """
    _infoblox_type = 'hsm:allgroups'
    _fields = ['groups']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['groups']
    _remap = {}
    _shadow_fields = ['_ref']


class HsmSafenetgroup(InfobloxObject):
    """ HsmSafenetgroup: The Hardware Security Module SafeNet group
    object.
    Corresponds to WAPI object 'hsm:safenetgroup'

    You can integrate a Grid with a third-party, network-attached
    Hardware Security Modules (HSMs) for secure private key storage and
    generation, and zone-signing offloading. Infoblox appliances support
    integration with either SafeNet HSMs or Thales HSMs. When using a
    network-attached HSM, you can provide tight physical access control,
    allowing only selected security personnel to physically access the
    HSM that stores the DNSSEC keys.

    The Hardware Security Module (HSM) SafeNet group represents the
    collection of HSM SafeeNet devices that are used for private key
    storage and generation.

    Note that you can create one HSM SafeNet group in the Grid.

    Attributes:
        comment: The HSM SafeNet group comment.
        group_sn: The HSM SafeNet group serial number.
        hsm_safenet: The list of HSM SafeNet devices.
        hsm_version: The HSM SafeNet version.
        name: The HSM SafeNet group name.
        pass_phrase: The pass phrase used to unlock the HSM SafeNet
            keystore.
        status: The status of all HSM SafeNet devices in the group.
    """
    _infoblox_type = 'hsm:safenetgroup'
    _fields = ['comment', 'group_sn', 'hsm_safenet', 'hsm_version', 'name',
               'pass_phrase', 'status']
    _search_for_update_fields = ['name']
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
    """ HsmThalesgroup: The Thales Harware Security Module group object.
    Corresponds to WAPI object 'hsm:thalesgroup'

    You can integrate a Grid with a third-party, network-attached
    Hardware Security Modules (HSMs) for secure private key storage and
    generation, and zone-signing offloading. Infoblox appliances support
    integration with either SafeNet HSMs or Thales HSMs. When using a
    network-attached HSM, you can provide tight physical access control,
    allowing only selected security personnel to physically access the
    HSM that stores the DNSSEC keys.

    The Thales Hardware Security Module (HSM) group represents the
    collection of Thales HSM devices that are used for private key
    storage and generation.

    Note that you can create one Thales HSM group in the Grid.

    Attributes:
        card_name: The Thales HSM softcard name.
        comment: The Thales HSM group comment.
        key_server_ip: The remote file server (RFS) IPv4 Address.
        key_server_port: The remote file server (RFS) port.
        name: The Thales HSM group name.
        pass_phrase: The password phrase used to unlock the Thales HSM
            keystore.
        protection: The level of protection that the HSM group uses for
            the DNSSEC key data.
        status: The status of all Thales HSM devices in the group.
        thales_hsm: The list of Thales HSM devices.
    """
    _infoblox_type = 'hsm:thalesgroup'
    _fields = ['card_name', 'comment', 'key_server_ip', 'key_server_port',
               'name', 'pass_phrase', 'protection', 'status', 'thales_hsm']
    _search_for_update_fields = ['name']
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
    """ IpamStatistics: IPAM statistics object.
    Corresponds to WAPI object 'ipam:statistics'

    A synthetic object used to view the IPAM statistics of the network
    or network container in an Infoblox appliance

    Attributes:
        cidr: The network CIDR.
        conflict_count: The number of conflicts discovered via network
            discovery. This attribute is only valid for a Network
            object.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        network: The network address.
        network_view: The network view.
        unmanaged_count: The number of unmanaged IP addresses as
            discovered by network discovery. This attribute is only
            valid for a Network object.
        utilization: The network utilization in percentage.
        utilization_update: The time that the utilization statistics
            were updated last. This attribute is only valid for a
            Network object. For a Network Container object, the return
            value is undefined.
    """
    _infoblox_type = 'ipam:statistics'
    _fields = ['cidr', 'conflict_count', 'ms_ad_user_data', 'network',
               'network_view', 'unmanaged_count', 'utilization',
               'utilization_update']
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
    """ IPv4Address: IPAM IPv4Address object.
    Corresponds to WAPI object 'ipv4address'

    This object is created only as part of the record.host object , it
    cannot be created directly.

    Attributes:
        comment: Comment for the address; maximum 256 characters.
        conflict_types: Types of the conflict.
        dhcp_client_identifier: The client unique identifier.
        discover_now_status: Discover now status for this address.
        discovered_data: The discovered data for this address.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        fingerprint: DHCP fingerprint for the address.
        ip_address: The IP address.
        is_conflict: If set to True, the IP address has either a MAC
            address conflict or a DHCP lease conflict detected through a
            network discovery.
        is_invalid_mac: This flag reflects whether the MAC address for
            this address is invalid.
        lease_state: The lease state of the address.
        mac_address: The MAC address.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        names: The DNS names. For example, if the IP address belongs to
            a host record, this field contains the hostname. This field
            supports both single and array search.
        network: The network to which this address belongs, in FQDN/CIDR
            format.
        network_view: The name of the network view.
        objects: The objects associated with the IP address.
        reserved_port: The reserved port for the address.
        status: The current status of the address.
        types: The types of associated objects. This field supports both
            single and array search.
        usage: Indicates whether the IP address is configured for DNS or
            DHCP. This field supports both single and array search.
        username: The name of the user who created or modified the
            record.
    """
    _infoblox_type = 'ipv4address'
    _fields = ['comment', 'conflict_types', 'dhcp_client_identifier',
               'discover_now_status', 'discovered_data', 'extattrs',
               'fingerprint', 'ip_address', 'is_conflict', 'is_invalid_mac',
               'lease_state', 'mac_address', 'ms_ad_user_data', 'names',
               'network', 'network_view', 'objects', 'reserved_port', 'status',
               'types', 'usage', 'username']
    _search_for_update_fields = ['dhcp_client_identifier', 'ip_address',
                                 'is_conflict', 'lease_state', 'mac_address',
                                 'names', 'network', 'network_view', 'status',
                                 'types', 'usage', 'username']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'dhcp_client_identifier',
                              'fingerprint', 'ip_address', 'is_conflict',
                              'lease_state', 'mac_address', 'names', 'network',
                              'network_view', 'status', 'types', 'usage',
                              'username']
    _return_fields = ['dhcp_client_identifier', 'extattrs', 'ip_address',
                      'is_conflict', 'lease_state', 'mac_address', 'names',
                      'network', 'network_view', 'objects', 'status', 'types',
                      'usage', 'username']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4


class IPv6Address(IPAddress):
    """ IPv6Address: IPAM IPv6Address object.
    Corresponds to WAPI object 'ipv6address'

    This object is created only as part of the record.host object , it
    cannot be created directly.

    Attributes:
        comment: Comment for the address; maximum 256 characters.
        conflict_types: Types of the conflict.
        discover_now_status: Discover now status for this address.
        discovered_data: The discovered data for this address.
        duid: DHCPv6 Unique Identifier (DUID) of the address object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        fingerprint: DHCP fingerprint for the address.
        ip_address: IPv6 addresses of the address object.
        is_conflict: IP address has either a duid conflict or a DHCP
            lease conflict detected through a network discovery.
        lease_state: The lease state of the address.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        names: The DNS names. For example, if the IP address belongs to
            a host record, this field contains the hostname. This field
            supports both single and array search.
        network: The network to which this address belongs, in FQDN/CIDR
            format.
        network_view: The name of the network view.
        objects: The objects associated with the IP address.
        reserved_port: The reserved port for the address.
        status: The current status of the address.
        types: The types of associated objects. This field supports both
            single and array search.
        usage: Indicates whether the IP address is configured for DNS or
            DHCP. This field supports both single and array search.
    """
    _infoblox_type = 'ipv6address'
    _fields = ['comment', 'conflict_types', 'discover_now_status',
               'discovered_data', 'duid', 'extattrs', 'fingerprint',
               'ip_address', 'is_conflict', 'lease_state', 'ms_ad_user_data',
               'names', 'network', 'network_view', 'objects', 'reserved_port',
               'status', 'types', 'usage']
    _search_for_update_fields = ['duid', 'ip_address', 'is_conflict',
                                 'lease_state', 'names', 'network',
                                 'network_view', 'status', 'types', 'usage']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'duid', 'fingerprint', 'ip_address',
                              'is_conflict', 'lease_state', 'names', 'network',
                              'network_view', 'status', 'types', 'usage']
    _return_fields = ['duid', 'extattrs', 'ip_address', 'is_conflict',
                      'lease_state', 'names', 'network', 'network_view',
                      'objects', 'status', 'types', 'usage']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6


class Ipv6Filteroption(InfobloxObject):
    """ Ipv6Filteroption: DHCP filter option object.
    Corresponds to WAPI object 'ipv6filteroption'

    In the ISC DHCP terms, it defines a class of clients that match a
    particular (option, value) pair. To define an option filter, add an
    Option to the IPv6 DHCP Filter object.

    Only superuser can add/modify/delete IPv6 option filters.

    Attributes:
        apply_as_class: Determines if apply as class is enabled or not.
            If this flag is set to "true" the filter is treated as
            global DHCP class, e.g it is written to DHCPv6 configuration
            file even if it is not present in any DHCP range.
        comment: The descriptive comment of a DHCP IPv6 filter option
            object.
        expression: The conditional expression of a DHCP IPv6 filter
            option object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        lease_time: Determines the lease time of a DHCP IPv6 filter
            option object.
        name: The name of a DHCP IPv6 option filter object.
        option_list: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        option_space: The option space of a DHCP IPv6 filter option
            object.
    """
    _infoblox_type = 'ipv6filteroption'
    _fields = ['apply_as_class', 'comment', 'expression', 'extattrs',
               'lease_time', 'name', 'option_list', 'option_space']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'option_list': DhcpOption.from_dict,
    }


class Network(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return NetworkV4

    @classmethod
    def get_v6_class(cls):
        return NetworkV6


class NetworkV4(Network):
    """ NetworkV4: DHCP Network object.
    Corresponds to WAPI object 'network'

    When DHCP services are configured on an appliance, the network that
    it serves must be defined. After a network is created, you can
    either create all the subnets individually, or create a parent
    network that encompasses the subnets.

    Attributes:
        authority: Authority for the DHCP network.
        auto_create_reversezone: This flag controls whether reverse
            zones are automatically created when the network is added.
        bootfile: The bootfile name for the network. You can configure
            the DHCP server to support clients that use the boot file
            name option in their DHCPREQUEST messages.
        bootserver: The bootserver address for the network. You can
            specify the name and/or IP address of the boot server that
            the host needs to boot.The boot server IPv4 Address or name
            in FQDN format.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the network, maximum 256 characters.
        conflict_count: The number of conflicts discovered via network
            discovery.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this network.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        ddns_server_always_updates: This field controls whether only the
            DHCP server is allowed to update DNS, regardless of the DHCP
            clients requests. Note that changes for this field take
            effect only if ddns_use_option81 is True.
        ddns_ttl: The DNS update Time to Live (TTL) value of a DHCP
            network object.The TTL is a 32-bit unsigned integer that
            represents the duration, in seconds, for which the update is
            cached. Zero indicates that the update is not cached.
        ddns_update_fixed_addresses: By default, the DHCP server does
            not update DNS when it allocates a fixed address to a
            client. You can configure the DHCP server to update the A
            and PTR records of a client with a fixed address. When this
            feature is enabled and the DHCP server adds A and PTR
            records for a fixed address, the DHCP server never discards
            the records.
        ddns_use_option81: The support for DHCP Option 81 at the network
            level.
        delete_reason: The reason for deleting the RIR registration
            request.
        deny_bootp: If set to true, BOOTP settings are disabled and
            BOOTP requests will be denied.
        dhcp_utilization: The percentage of the total DHCP utilization
            of the network multiplied by 1000. This is the percentage of
            the total number of available IP addresses belonging to the
            network versus the total number of all IP addresses in
            network.
        dhcp_utilization_status: A string describing the utilization
            level of the network.
        disable: Determines whether a network is disabled or not. When
            this is set to False, the network is enabled.
        discover_now_status: Discover now status for this network.
        discovered_bgp_as: Number of the discovered BGP AS.When multiple
            BGP autonomous systems are discovered in the network, this
            field displays "Multiple".
        discovered_bridge_domain: Discovered bridge domain.
        discovered_tenant: Discovered tenant.
        discovered_vlan_id: The identifier of the discovered VLAN.When
            multiple VLANs are discovered in the network, this field
            displays "Multiple".
        discovered_vlan_name: The name of the discovered VLAN.When
            multiple VLANs are discovered in the network, this field
            displays "Multiple".
        discovered_vrf_description: Description of the discovered
            VRF.When multiple VRFs are discovered in the network, this
            field displays "Multiple".
        discovered_vrf_name: The name of the discovered VRF.When
            multiple VRFs are discovered in the network, this field
            displays "Multiple".
        discovered_vrf_rd: Route distinguisher of the discovered
            VRF.When multiple VRFs are discovered in the network, this
            field displays "Multiple".
        discovery_basic_poll_settings: The discovery basic poll settings
            for this network.
        discovery_blackout_setting: The discovery blackout setting for
            this network.
        discovery_engine_type: The network discovery engine type.
        discovery_member: The member that will run discovery for this
            network.
        dynamic_hosts: The total number of DHCP leases issued for the
            network.
        email_list: The e-mail lists to which the appliance sends DHCP
            threshold alarm e-mail messages.
        enable_ddns: The dynamic DNS updates flag of a DHCP network
            object. If set to True, the DHCP server sends DDNS updates
            to DNS servers in the same Grid, and to external DNS
            servers.
        enable_dhcp_thresholds: Determines if DHCP thresholds are
            enabled for the network.
        enable_discovery: Determines whether a discovery is enabled or
            not for this network. When this is set to False, the network
            discovery is disabled.
        enable_email_warnings: Determines if DHCP threshold warnings are
            sent through email.
        enable_ifmap_publishing: Determines if IFMAP publishing is
            enabled for the network.
        enable_immediate_discovery: Determines if the discovery for the
            network should be immediately enabled.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients.
        enable_snmp_warnings: Determines if DHCP threshold warnings are
            send through SNMP.
        endpoint_sources: The endpoints that provides data for the DHCP
            Network object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        high_water_mark: The percentage of DHCP network usage threshold
            above which network usage is not expected and may warrant
            your attention. When the high watermark is reached, the
            Infoblox appliance generates a syslog message and sends a
            warning (if enabled).A number that specifies the percentage
            of allocated addresses. The range is from 1 to 100.
        high_water_mark_reset: The percentage of DHCP network usage
            below which the corresponding SNMP trap is reset.A number
            that specifies the percentage of allocated addresses. The
            range is from 1 to 100. The high watermark reset value must
            be lower than the high watermark value.
        ignore_dhcp_option_list_request: If this field is set to False,
            the appliance returns all DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        ignore_id: Indicates whether the appliance will ignore DHCP
            client IDs or MAC addresses. Valid values are "NONE",
            "CLIENT", or "MACADDR". The default is "NONE".
        ignore_mac_addresses: A list of MAC addresses the appliance will
            ignore.
        ipam_email_addresses: The e-mail lists to which the appliance
            sends IPAM threshold alarm e-mail messages.
        ipam_threshold_settings: The IPAM Threshold settings for this
            network.
        ipam_trap_settings: The IPAM Trap settings for this network.
        ipv4addr: The IPv4 Address of the network.
        last_rir_registration_update_sent: The timestamp when the last
            RIR registration update was sent.
        last_rir_registration_update_status: Last RIR registration
            update status.
        lease_scavenge_time: An integer that specifies the period of
            time (in seconds) that frees and backs up leases remained in
            the database before they are automatically deleted. To
            disable lease scavenging, set the parameter to -1. The
            minimum positive value must be greater than 86400 seconds (1
            day).
        logic_filter_rules: This field contains the logic filters to be
            applied on the this network.This list corresponds to the
            match rules that are written to the dhcpd configuration
            file.
        low_water_mark: The percentage of DHCP network usage below which
            the Infoblox appliance generates a syslog message and sends
            a warning (if enabled).A number that specifies the
            percentage of allocated addresses. The range is from 1 to
            100.
        low_water_mark_reset: The percentage of DHCP network usage
            threshold below which network usage is not expected and may
            warrant your attention. When the low watermark is crossed,
            the Infoblox appliance generates a syslog message and sends
            a warning (if enabled).A number that specifies the
            percentage of allocated addresses. The range is from 1 to
            100. The low watermark reset value must be higher than the
            low watermark value.
        members: A list of members or Microsoft (r) servers that serve
            DHCP for this network.
        mgm_private: This field controls whether this object is
            synchronized with the Multi-Grid Master. If this field is
            set to True, objects are not synchronized.
        mgm_private_overridable: This field is assumed to be True unless
            filled by any conforming objects, such as Network, IPv6
            Network, Network Container, IPv6 Network Container, and
            Network View. This value is set to False if mgm_private is
            set to True in the parent object.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        netmask: The netmask of the network in CIDR format.
        network: The network address in IPv4 Address/CIDR format. For
            regular expression searches, only the IPv4 Address portion
            is supported. Searches for the CIDR portion is always an
            exact match.For example, both network containers 10.0.0.0/8
            and 20.1.0.0/16 are matched by expression '.0' and only
            20.1.0.0/16 is matched by '.0/16'.
        network_container: The network container to which this network
            belongs (if any).
        network_view: The name of the network view in which this network
            resides.
        nextserver: The name in FQDN and/or IPv4 Address of the next
            server that the host needs to boot.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        port_control_blackout_setting: The port control blackout setting
            for this network.
        pxe_lease_time: The PXE lease time value of a DHCP Network
            object. Some hosts use PXE (Preboot Execution Environment)
            to boot remotely from a server. To better manage your IP
            resources, set a different lease time for PXE boot requests.
            You can configure the DHCP server to allocate an IP address
            with a shorter lease time to hosts that send PXE boot
            requests, so IP addresses are not leased longer than
            necessary.A 32-bit unsigned integer that represents the
            duration, in seconds, for which the update is cached. Zero
            indicates that the update is not cached.
        recycle_leases: If the field is set to True, the leases are kept
            in the Recycle Bin until one week after expiration.
            Otherwise, the leases are permanently deleted.
        restart_if_needed: Restarts the member service.
        rir: The registry (RIR) that allocated the network address
            space.
        rir_organization: The RIR organization assoicated with the
            network.
        rir_registration_action: The RIR registration action.
        rir_registration_status: The registration status of the network
            in RIR.
        same_port_control_discovery_blackout: If the field is set to
            True, the discovery blackout setting will be used for port
            control blackout setting.
        send_rir_request: Determines whether to send the RIR
            registration request.
        static_hosts: The number of static DHCP addresses configured in
            the network.
        subscribe_settings: The DHCP Network Cisco ISE subscribe
            settings.
        template: If set on creation, the network is created according
            to the values specified in the selected template.
        total_hosts: The total number of DHCP addresses configured in
            the network.
        unmanaged: Determines whether the DHCP IPv4 Network is unmanaged
            or not.
        unmanaged_count: The number of unmanaged IP addresses as
            discovered by network discovery.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_authority: Use flag for: authority
        use_blackout_setting: Use flag for: discovery_blackout_setting ,
            port_control_blackout_setting,
            same_port_control_discovery_blackout
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_ddns_ttl: Use flag for: ddns_ttl
        use_ddns_update_fixed_addresses: Use flag for:
            ddns_update_fixed_addresses
        use_ddns_use_option81: Use flag for: ddns_use_option81
        use_deny_bootp: Use flag for: deny_bootp
        use_discovery_basic_polling_settings: Use flag for:
            discovery_basic_poll_settings
        use_email_list: Use flag for: email_list
        use_enable_ddns: Use flag for: enable_ddns
        use_enable_dhcp_thresholds: Use flag for: enable_dhcp_thresholds
        use_enable_discovery: Use flag for: discovery_member ,
            enable_discovery
        use_enable_ifmap_publishing: Use flag for:
            enable_ifmap_publishing
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_ignore_id: Use flag for: ignore_id
        use_ipam_email_addresses: Use flag for: ipam_email_addresses
        use_ipam_threshold_settings: Use flag for:
            ipam_threshold_settings
        use_ipam_trap_settings: Use flag for: ipam_trap_settings
        use_lease_scavenge_time: Use flag for: lease_scavenge_time
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_mgm_private: Use flag for: mgm_private
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_pxe_lease_time: Use flag for: pxe_lease_time
        use_recycle_leases: Use flag for: recycle_leases
        use_subscribe_settings: Use flag for: subscribe_settings
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
        use_zone_associations: Use flag for: zone_associations
        utilization: The network utilization in percentage.
        utilization_update: The timestamp when the utilization
            statistics were last updated.
        vlans: List of VLANs assigned to Network.
        zone_associations: The list of zones associated with this
            network.
    """
    _infoblox_type = 'network'
    _fields = ['authority', 'auto_create_reversezone', 'bootfile',
               'bootserver', 'cloud_info', 'comment', 'conflict_count',
               'ddns_domainname', 'ddns_generate_hostname',
               'ddns_server_always_updates', 'ddns_ttl',
               'ddns_update_fixed_addresses', 'ddns_use_option81',
               'delete_reason', 'deny_bootp', 'dhcp_utilization',
               'dhcp_utilization_status', 'disable', 'discover_now_status',
               'discovered_bgp_as', 'discovered_bridge_domain',
               'discovered_tenant', 'discovered_vlan_id',
               'discovered_vlan_name', 'discovered_vrf_description',
               'discovered_vrf_name', 'discovered_vrf_rd',
               'discovery_basic_poll_settings', 'discovery_blackout_setting',
               'discovery_engine_type', 'discovery_member', 'dynamic_hosts',
               'email_list', 'enable_ddns', 'enable_dhcp_thresholds',
               'enable_discovery', 'enable_email_warnings',
               'enable_ifmap_publishing', 'enable_immediate_discovery',
               'enable_pxe_lease_time', 'enable_snmp_warnings',
               'endpoint_sources', 'extattrs', 'high_water_mark',
               'high_water_mark_reset', 'ignore_dhcp_option_list_request',
               'ignore_id', 'ignore_mac_addresses', 'ipam_email_addresses',
               'ipam_threshold_settings', 'ipam_trap_settings', 'ipv4addr',
               'last_rir_registration_update_sent',
               'last_rir_registration_update_status', 'lease_scavenge_time',
               'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset',
               'members', 'mgm_private', 'mgm_private_overridable',
               'ms_ad_user_data', 'netmask', 'network', 'network_container',
               'network_view', 'nextserver', 'options',
               'port_control_blackout_setting', 'pxe_lease_time',
               'recycle_leases', 'restart_if_needed', 'rir',
               'rir_organization', 'rir_registration_action',
               'rir_registration_status',
               'same_port_control_discovery_blackout', 'send_rir_request',
               'static_hosts', 'subscribe_settings', 'template', 'total_hosts',
               'unmanaged', 'unmanaged_count', 'update_dns_on_lease_renewal',
               'use_authority', 'use_blackout_setting', 'use_bootfile',
               'use_bootserver', 'use_ddns_domainname',
               'use_ddns_generate_hostname', 'use_ddns_ttl',
               'use_ddns_update_fixed_addresses', 'use_ddns_use_option81',
               'use_deny_bootp', 'use_discovery_basic_polling_settings',
               'use_email_list', 'use_enable_ddns',
               'use_enable_dhcp_thresholds', 'use_enable_discovery',
               'use_enable_ifmap_publishing',
               'use_ignore_dhcp_option_list_request', 'use_ignore_id',
               'use_ipam_email_addresses', 'use_ipam_threshold_settings',
               'use_ipam_trap_settings', 'use_lease_scavenge_time',
               'use_logic_filter_rules', 'use_mgm_private', 'use_nextserver',
               'use_options', 'use_pxe_lease_time', 'use_recycle_leases',
               'use_subscribe_settings', 'use_update_dns_on_lease_renewal',
               'use_zone_associations', 'utilization', 'utilization_update',
               'vlans', 'zone_associations']
    _search_for_update_fields = ['network', 'network_view']
    _updateable_search_fields = ['comment', 'discovered_bridge_domain',
                                 'discovered_tenant', 'ipv4addr', 'network',
                                 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovered_bgp_as',
                              'discovered_bridge_domain', 'discovered_tenant',
                              'discovered_vlan_id', 'discovered_vlan_name',
                              'discovered_vrf_description',
                              'discovered_vrf_name', 'discovered_vrf_rd',
                              'discovery_engine_type', 'ipv4addr', 'network',
                              'network_container', 'network_view', 'rir',
                              'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'extattrs', 'network', 'network_view']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'members': Dhcpmember.from_dict,
        'options': DhcpOption.from_dict,
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
    """ NetworkV6: DHCP IPv6Network object.
    Corresponds to WAPI object 'ipv6network'

    When DHCP services are configured on an appliance, the network that
    it serves must be defined. After a network is created, you can
    either create all the subnets individually, or create a parent
    network that encompasses the subnets.

    Attributes:
        auto_create_reversezone: This flag controls whether reverse
            zones are automatically created when the network is added.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the network; maximum 256 characters.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this network.
        ddns_enable_option_fqdn: Use this method to set or retrieve the
            ddns_enable_option_fqdn flag of a DHCP IPv6 Network object.
            This method controls whether the FQDN option sent by the
            client is to be used, or if the server can automatically
            generate the FQDN. This setting overrides the upper-level
            settings.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        ddns_server_always_updates: This field controls whether only the
            DHCP server is allowed to update DNS, regardless of the DHCP
            clients requests. Note that changes for this field take
            effect only if ddns_enable_option_fqdn is True.
        ddns_ttl: The DNS update Time to Live (TTL) value of a DHCP
            network object.The TTL is a 32-bit unsigned integer that
            represents the duration, in seconds, for which the update is
            cached. Zero indicates that the update is not cached.
        delete_reason: The reason for deleting the RIR registration
            request.
        disable: Determines whether a network is disabled or not. When
            this is set to False, the network is enabled.
        discover_now_status: Discover now status for this network.
        discovered_bgp_as: Number of the discovered BGP AS.When multiple
            BGP autonomous systems are discovered in the network, this
            field displays "Multiple".
        discovered_bridge_domain: Discovered bridge domain.
        discovered_tenant: Discovered tenant.
        discovered_vlan_id: The identifier of the discovered VLAN.When
            multiple VLANs are discovered in the network, this field
            displays "Multiple".
        discovered_vlan_name: The name of the discovered VLAN.When
            multiple VLANs are discovered in the network, this field
            displays "Multiple".
        discovered_vrf_description: Description of the discovered
            VRF.When multiple VRFs are discovered in the network, this
            field displays "Multiple".
        discovered_vrf_name: The name of the discovered VRF.When
            multiple VRFs are discovered in the network, this field
            displays "Multiple".
        discovered_vrf_rd: Route distinguisher of the discovered
            VRF.When multiple VRFs are discovered in the network, this
            field displays "Multiple".
        discovery_basic_poll_settings: The discovery basic poll settings
            for this network.
        discovery_blackout_setting: The discovery blackout setting for
            this network.
        discovery_engine_type: The network discovery engine type.
        discovery_member: The member that will run discovery for this
            network.
        domain_name: Use this method to set or retrieve the domain_name
            value of a DHCP IPv6 Network object.
        domain_name_servers: Use this method to set or retrieve the
            dynamic DNS updates flag of a DHCP IPv6 Network object. The
            DHCP server can send DDNS updates to DNS servers in the same
            Grid and to external DNS servers. This setting overrides the
            member level settings.
        enable_ddns: The dynamic DNS updates flag of a DHCP IPv6 network
            object. If set to True, the DHCP server sends DDNS updates
            to DNS servers in the same Grid, and to external DNS
            servers.
        enable_discovery: Determines whether a discovery is enabled or
            not for this network. When this is set to False, the network
            discovery is disabled.
        enable_ifmap_publishing: Determines if IFMAP publishing is
            enabled for the network.
        enable_immediate_discovery: Determines if the discovery for the
            network should be immediately enabled.
        endpoint_sources: The endpoints that provides data for the DHCP
            IPv6 Network object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        last_rir_registration_update_sent: The timestamp when the last
            RIR registration update was sent.
        last_rir_registration_update_status: Last RIR registration
            update status.
        logic_filter_rules: This field contains the logic filters to be
            applied on this IPv6 network.This list corresponds to the
            match rules that are written to the DHCPv6 configuration
            file.
        members: A list of members servers that serve DHCP for the
            network.All members in the array must be of the same type.
            The struct type must be indicated in each element, by
            setting the "_struct" member to the struct type.
        mgm_private: This field controls whether this object is
            synchronized with the Multi-Grid Master. If this field is
            set to True, objects are not synchronized.
        mgm_private_overridable: This field is assumed to be True unless
            filled by any conforming objects, such as Network, IPv6
            Network, Network Container, IPv6 Network Container, and
            Network View. This value is set to False if mgm_private is
            set to True in the parent object.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        network: The network address in IPv6 Address/CIDR format. For
            regular expression searches, only the IPv6 Address portion
            is supported. Searches for the CIDR portion is always an
            exact match.For example, both network containers 16::0/28
            and 26::0/24 are matched by expression '.6' and only
            26::0/24 is matched by '.6/24'.
        network_container: The network container to which this network
            belongs, if any.
        network_view: The name of the network view in which this network
            resides.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        port_control_blackout_setting: The port control blackout setting
            for this network.
        preferred_lifetime: Use this method to set or retrieve the
            preferred lifetime value of a DHCP IPv6 Network object.
        recycle_leases: If the field is set to True, the leases are kept
            in the Recycle Bin until one week after expiration.
            Otherwise, the leases are permanently deleted.
        restart_if_needed: Restarts the member service.
        rir: The registry (RIR) that allocated the IPv6 network address
            space.
        rir_organization: The RIR organization associated with the IPv6
            network.
        rir_registration_action: The RIR registration action.
        rir_registration_status: The registration status of the IPv6
            network in RIR.
        same_port_control_discovery_blackout: If the field is set to
            True, the discovery blackout setting will be used for port
            control blackout setting.
        send_rir_request: Determines whether to send the RIR
            registration request.
        subscribe_settings: The DHCP IPv6 Network Cisco ISE subscribe
            settings.
        template: If set on creation, the network is created according
            to the values specified in the selected template.
        unmanaged: Determines whether the DHCP IPv6 Network is unmanaged
            or not.
        unmanaged_count: The number of unmanaged IP addresses as
            discovered by network discovery.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_blackout_setting: Use flag for: discovery_blackout_setting ,
            port_control_blackout_setting,
            same_port_control_discovery_blackout
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_enable_option_fqdn: Use flag for:
            ddns_enable_option_fqdn
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_ddns_ttl: Use flag for: ddns_ttl
        use_discovery_basic_polling_settings: Use flag for:
            discovery_basic_poll_settings
        use_domain_name: Use flag for: domain_name
        use_domain_name_servers: Use flag for: domain_name_servers
        use_enable_ddns: Use flag for: enable_ddns
        use_enable_discovery: Use flag for: discovery_member ,
            enable_discovery
        use_enable_ifmap_publishing: Use flag for:
            enable_ifmap_publishing
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_mgm_private: Use flag for: mgm_private
        use_options: Use flag for: options
        use_preferred_lifetime: Use flag for: preferred_lifetime
        use_recycle_leases: Use flag for: recycle_leases
        use_subscribe_settings: Use flag for: subscribe_settings
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
        use_valid_lifetime: Use flag for: valid_lifetime
        use_zone_associations: Use flag for: zone_associations
        valid_lifetime: Use this method to set or retrieve the valid
            lifetime value of a DHCP IPv6 Network object.
        vlans: List of VLANs assigned to Network.
        zone_associations: The list of zones associated with this
            network.
    """
    _infoblox_type = 'ipv6network'
    _fields = ['auto_create_reversezone', 'cloud_info', 'comment',
               'ddns_domainname', 'ddns_enable_option_fqdn',
               'ddns_generate_hostname', 'ddns_server_always_updates',
               'ddns_ttl', 'delete_reason', 'disable', 'discover_now_status',
               'discovered_bgp_as', 'discovered_bridge_domain',
               'discovered_tenant', 'discovered_vlan_id',
               'discovered_vlan_name', 'discovered_vrf_description',
               'discovered_vrf_name', 'discovered_vrf_rd',
               'discovery_basic_poll_settings', 'discovery_blackout_setting',
               'discovery_engine_type', 'discovery_member', 'domain_name',
               'domain_name_servers', 'enable_ddns', 'enable_discovery',
               'enable_ifmap_publishing', 'enable_immediate_discovery',
               'endpoint_sources', 'extattrs',
               'last_rir_registration_update_sent',
               'last_rir_registration_update_status', 'logic_filter_rules',
               'members', 'mgm_private', 'mgm_private_overridable',
               'ms_ad_user_data', 'network', 'network_container',
               'network_view', 'options', 'port_control_blackout_setting',
               'preferred_lifetime', 'recycle_leases', 'restart_if_needed',
               'rir', 'rir_organization', 'rir_registration_action',
               'rir_registration_status',
               'same_port_control_discovery_blackout', 'send_rir_request',
               'subscribe_settings', 'template', 'unmanaged',
               'unmanaged_count', 'update_dns_on_lease_renewal',
               'use_blackout_setting', 'use_ddns_domainname',
               'use_ddns_enable_option_fqdn', 'use_ddns_generate_hostname',
               'use_ddns_ttl', 'use_discovery_basic_polling_settings',
               'use_domain_name', 'use_domain_name_servers', 'use_enable_ddns',
               'use_enable_discovery', 'use_enable_ifmap_publishing',
               'use_logic_filter_rules', 'use_mgm_private', 'use_options',
               'use_preferred_lifetime', 'use_recycle_leases',
               'use_subscribe_settings', 'use_update_dns_on_lease_renewal',
               'use_valid_lifetime', 'use_zone_associations', 'valid_lifetime',
               'vlans', 'zone_associations']
    _search_for_update_fields = ['network', 'network_view']
    _updateable_search_fields = ['comment', 'discovered_bridge_domain',
                                 'discovered_tenant', 'network',
                                 'network_view', 'rir_organization',
                                 'unmanaged']
    _all_searchable_fields = ['comment', 'discovered_bgp_as',
                              'discovered_bridge_domain', 'discovered_tenant',
                              'discovered_vlan_id', 'discovered_vlan_name',
                              'discovered_vrf_description',
                              'discovered_vrf_name', 'discovered_vrf_rd',
                              'discovery_engine_type', 'network',
                              'network_container', 'network_view', 'rir',
                              'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'extattrs', 'network', 'network_view']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 6

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'members': Dhcpmember.from_dict,
        'options': DhcpOption.from_dict,
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
    """ NetworkContainerV4: DHCP Network Container object.
    Corresponds to WAPI object 'networkcontainer'

    A network can contain child networks. The network that contains
    child networks is called a network container. This object
    encapsulates an IPv4 network container object.

    Attributes:
        authority: Authority for the DHCP network container.
        auto_create_reversezone: This flag controls whether reverse
            zones are automatically created when the network is added.
        bootfile: The boot server IPv4 Address or name in FQDN format
            for the network container. You can specify the name and/or
            IP address of the boot server that the host needs to boot.
        bootserver: The bootserver address for the network container.
            You can specify the name and/or IP address of the boot
            server that the host needs to boot.The boot server IPv4
            Address or name in FQDN format.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the network container; maximum 256
            characters.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this network container.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        ddns_server_always_updates: This field controls whether the DHCP
            server is allowed to update DNS, regardless of the DHCP
            client requests. Note that changes for this field take
            effect only if ddns_use_option81 is True.
        ddns_ttl: The DNS update Time to Live (TTL) value of a DHCP
            network container object.The TTL is a 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the update is cached. Zero indicates that the update is not
            cached.
        ddns_update_fixed_addresses: By default, the DHCP server does
            not update DNS when it allocates a fixed address to a
            client. You can configure the DHCP server to update the A
            and PTR records of a client with a fixed address. When this
            feature is enabled and the DHCP server adds A and PTR
            records for a fixed address, the DHCP server never discards
            the records.
        ddns_use_option81: The support for DHCP Option 81 at the network
            container level.
        delete_reason: The reason for deleting the RIR registration
            request.
        deny_bootp: If set to True, BOOTP settings are disabled and
            BOOTP requests will be denied.
        discover_now_status: Discover now status for this network
            container.
        discovery_basic_poll_settings: The discovery basic poll settings
            for this network container.
        discovery_blackout_setting: The discovery blackout setting for
            this network container.
        discovery_engine_type: The network discovery engine type.
        discovery_member: The member that will run discovery for this
            network container.
        email_list: The e-mail lists to which the appliance sends DHCP
            threshold alarm e-mail messages.
        enable_ddns: The dynamic DNS updates flag of a DHCP network
            container object. If set to True, the DHCP server sends DDNS
            updates to DNS servers in the same Grid, and to external DNS
            servers.
        enable_dhcp_thresholds: Determines if DHCP thresholds are
            enabled for the network container.
        enable_discovery: Determines whether a discovery is enabled or
            not for this network container. When this is set to False,
            the network container discovery is disabled.
        enable_email_warnings: Determines if DHCP threshold warnings are
            sent through email.
        enable_immediate_discovery: Determines if the discovery for the
            network container should be immediately enabled.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients.
        enable_snmp_warnings: Determines if DHCP threshold warnings are
            send through SNMP.
        endpoint_sources: The endpoints that provides data for the DHCP
            Network Container object.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        high_water_mark: The percentage of DHCP network container usage
            threshold above which network container usage is not
            expected and may warrant your attention. When the high
            watermark is reached, the Infoblox appliance generates a
            syslog message and sends a warning (if enabled).A number
            that specifies the percentage of allocated addresses. The
            range is from 1 to 100.
        high_water_mark_reset: The percentage of DHCP network container
            usage below which the corresponding SNMP trap is reset.A
            number that specifies the percentage of allocated addresses.
            The range is from 1 to 100. The high watermark reset value
            must be lower than the high watermark value.
        ignore_dhcp_option_list_request: If this field is set to False,
            the appliance returns all DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        ignore_id: Indicates whether the appliance will ignore DHCP
            client IDs or MAC addresses.
        ignore_mac_addresses: A list of MAC addresses the appliance will
            ignore.
        ipam_email_addresses: The e-mail lists to which the appliance
            sends IPAM threshold alarm e-mail messages.
        ipam_threshold_settings: The IPAM Threshold settings for this
            network container.
        ipam_trap_settings: The IPAM Trap settings for this network
            container.
        last_rir_registration_update_sent: The timestamp when the last
            RIR registration update was sent.
        last_rir_registration_update_status: Last RIR registration
            update status.
        lease_scavenge_time: An integer that specifies the period of
            time (in seconds) that frees and backs up leases remained in
            the database before they are automatically deleted. To
            disable lease scavenging, set the parameter to -1. The
            minimum positive value must be greater than 86400 seconds (1
            day).
        logic_filter_rules: This field contains the logic filters to be
            applied on the this network container.This list corresponds
            to the match rules that are written to the dhcpd
            configuration file.
        low_water_mark: The percentage of DHCP network container usage
            below which the Infoblox appliance generates a syslog
            message and sends a warning (if enabled).A number that
            specifies the percentage of allocated addresses. The range
            is from 1 to 100.
        low_water_mark_reset: The percentage of DHCP network container
            usage threshold below which network container usage is not
            expected and may warrant your attention. When the low
            watermark is crossed, the Infoblox appliance generates a
            syslog message and sends a warning (if enabled).A number
            that specifies the percentage of allocated addresses. The
            range is from 1 to 100. The low watermark reset value must
            be higher than the low watermark value.
        mgm_private: This field controls whether this object is
            synchronized with the Multi-Grid Master. If this field is
            set to True, objects are not synchronized.
        mgm_private_overridable: This field is assumed to be True unless
            filled by any conforming objects, such as Network, IPv6
            Network, Network Container, IPv6 Network Container, and
            Network View. This value is set to False if mgm_private is
            set to True in the parent object.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        network: The network address in IPv4 Address/CIDR format. For
            regular expression searches, only the IPv4 Address portion
            is supported. Searches for the CIDR portion is always an
            exact match.For example, both network containers 10.0.0.0/8
            and 20.1.0.0/16 are matched by expression '.0' and only
            20.1.0.0/16 is matched by '.0/16'.
        network_container: The network container to which this network
            belongs, if any.
        network_view: The name of the network view in which this network
            resides.
        nextserver: The name in FQDN and/or IPv4 Address of the next
            server that the host needs to boot.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        port_control_blackout_setting: The port control blackout setting
            for this network container.
        pxe_lease_time: The PXE lease time value of a DHCP Network
            container object. Some hosts use PXE (Preboot Execution
            Environment) to boot remotely from a server. To better
            manage your IP resources, set a different lease time for PXE
            boot requests. You can configure the DHCP server to allocate
            an IP address with a shorter lease time to hosts that send
            PXE boot requests, so IP addresses are not leased longer
            than necessary.A 32-bit unsigned integer that represents the
            duration, in seconds, for which the update is cached. Zero
            indicates that the update is not cached.
        recycle_leases: If the field is set to True, the leases are kept
            in the Recycle Bin until one week after expiration.
            Otherwise, the leases are permanently deleted.
        restart_if_needed: Restarts the member service.
        rir: The registry (RIR) that allocated the network container
            address space.
        rir_organization: The RIR organization assoicated with the
            network container.
        rir_registration_action: The RIR registration action.
        rir_registration_status: The registration status of the network
            container in RIR.
        same_port_control_discovery_blackout: If the field is set to
            True, the discovery blackout setting will be used for port
            control blackout setting.
        send_rir_request: Determines whether to send the RIR
            registration request.
        subscribe_settings: The DHCP Network Container Cisco ISE
            subscribe settings.
        unmanaged: Determines whether the network container is unmanaged
            or not.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_authority: Use flag for: authority
        use_blackout_setting: Use flag for: discovery_blackout_setting ,
            port_control_blackout_setting,
            same_port_control_discovery_blackout
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_ddns_ttl: Use flag for: ddns_ttl
        use_ddns_update_fixed_addresses: Use flag for:
            ddns_update_fixed_addresses
        use_ddns_use_option81: Use flag for: ddns_use_option81
        use_deny_bootp: Use flag for: deny_bootp
        use_discovery_basic_polling_settings: Use flag for:
            discovery_basic_poll_settings
        use_email_list: Use flag for: email_list
        use_enable_ddns: Use flag for: enable_ddns
        use_enable_dhcp_thresholds: Use flag for: enable_dhcp_thresholds
        use_enable_discovery: Use flag for: discovery_member ,
            enable_discovery
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_ignore_id: Use flag for: ignore_id
        use_ipam_email_addresses: Use flag for: ipam_email_addresses
        use_ipam_threshold_settings: Use flag for:
            ipam_threshold_settings
        use_ipam_trap_settings: Use flag for: ipam_trap_settings
        use_lease_scavenge_time: Use flag for: lease_scavenge_time
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_mgm_private: Use flag for: mgm_private
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_pxe_lease_time: Use flag for: pxe_lease_time
        use_recycle_leases: Use flag for: recycle_leases
        use_subscribe_settings: Use flag for: subscribe_settings
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
        use_zone_associations: Use flag for: zone_associations
        utilization: The network container utilization in percentage.
        zone_associations: The list of zones associated with this
            network.
    """
    _infoblox_type = 'networkcontainer'
    _fields = ['authority', 'auto_create_reversezone', 'bootfile',
               'bootserver', 'cloud_info', 'comment', 'ddns_domainname',
               'ddns_generate_hostname', 'ddns_server_always_updates',
               'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81',
               'delete_reason', 'deny_bootp', 'discover_now_status',
               'discovery_basic_poll_settings', 'discovery_blackout_setting',
               'discovery_engine_type', 'discovery_member', 'email_list',
               'enable_ddns', 'enable_dhcp_thresholds', 'enable_discovery',
               'enable_email_warnings', 'enable_immediate_discovery',
               'enable_pxe_lease_time', 'enable_snmp_warnings',
               'endpoint_sources', 'extattrs', 'high_water_mark',
               'high_water_mark_reset', 'ignore_dhcp_option_list_request',
               'ignore_id', 'ignore_mac_addresses', 'ipam_email_addresses',
               'ipam_threshold_settings', 'ipam_trap_settings',
               'last_rir_registration_update_sent',
               'last_rir_registration_update_status', 'lease_scavenge_time',
               'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset',
               'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data',
               'network', 'network_container', 'network_view', 'nextserver',
               'options', 'port_control_blackout_setting', 'pxe_lease_time',
               'recycle_leases', 'remove_subnets', 'restart_if_needed', 'rir',
               'rir_organization', 'rir_registration_action',
               'rir_registration_status',
               'same_port_control_discovery_blackout', 'send_rir_request',
               'subscribe_settings', 'unmanaged',
               'update_dns_on_lease_renewal', 'use_authority',
               'use_blackout_setting', 'use_bootfile', 'use_bootserver',
               'use_ddns_domainname', 'use_ddns_generate_hostname',
               'use_ddns_ttl', 'use_ddns_update_fixed_addresses',
               'use_ddns_use_option81', 'use_deny_bootp',
               'use_discovery_basic_polling_settings', 'use_email_list',
               'use_enable_ddns', 'use_enable_dhcp_thresholds',
               'use_enable_discovery', 'use_ignore_dhcp_option_list_request',
               'use_ignore_id', 'use_ipam_email_addresses',
               'use_ipam_threshold_settings', 'use_ipam_trap_settings',
               'use_lease_scavenge_time', 'use_logic_filter_rules',
               'use_mgm_private', 'use_nextserver', 'use_options',
               'use_pxe_lease_time', 'use_recycle_leases',
               'use_subscribe_settings', 'use_update_dns_on_lease_renewal',
               'use_zone_associations', 'utilization', 'zone_associations']
    _search_for_update_fields = ['network', 'network_view']
    _updateable_search_fields = ['comment', 'rir_organization', 'unmanaged']
    _all_searchable_fields = ['comment', 'discovery_engine_type', 'network',
                              'network_container', 'network_view', 'rir',
                              'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'extattrs', 'network', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': DhcpOption.from_dict,
        'zone_associations': Zoneassociation.from_dict,
    }

    def next_available_network(self, *args, **kwargs):
        return self._call_func("next_available_network", *args, **kwargs)

    def resize(self, *args, **kwargs):
        return self._call_func("resize", *args, **kwargs)


class NetworkContainerV6(NetworkContainer):
    """ NetworkContainerV6: DHCP IPv6NetworkContainer object.
    Corresponds to WAPI object 'ipv6networkcontainer'

    A network can contain child networks. The network that contains
    child networks is called a network container. This object
    encapsulates an IPv6 network container object.

    Attributes:
        auto_create_reversezone: This flag controls whether reverse
            zones are automatically created when the network is added.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the network; maximum 256 characters.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this network container.
        ddns_enable_option_fqdn: Use this method to set or retrieve the
            ddns_enable_option_fqdn flag of a DHCP IPv6 Network
            Container object. This method controls whether the FQDN
            option sent by the client is to be used, or if the server
            can automatically generate the FQDN. This setting overrides
            the upper-level settings.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        ddns_server_always_updates: This field controls whether the DHCP
            server is allowed to update DNS, regardless of the DHCP
            client requests. Note that changes for this field take
            effect only if ddns_enable_option_fqdn is True.
        ddns_ttl: The DNS update Time to Live (TTL) value of a DHCP
            network container object.The TTL is a 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the update is cached. Zero indicates that the update is not
            cached.
        delete_reason: The reason for deleting the RIR registration
            request.
        discover_now_status: Discover now status for this network
            container.
        discovery_basic_poll_settings: The discovery basic poll settings
            for this network container.
        discovery_blackout_setting: The discovery blackout setting for
            this network container.
        discovery_engine_type: The network discovery engine type.
        discovery_member: The member that will run discovery for this
            network container.
        domain_name_servers: Use this method to set or retrieve the
            dynamic DNS updates flag of a DHCP IPv6 Network Container
            object. The DHCP server can send DDNS updates to DNS servers
            in the same Grid and to external DNS servers. This setting
            overrides the member level settings.
        enable_ddns: The dynamic DNS updates flag of a DHCP IPv6 network
            container object. If set to True, the DHCP server sends DDNS
            updates to DNS servers in the same Grid, and to external DNS
            servers.
        enable_discovery: Determines whether a discovery is enabled or
            not for this network container. When this is set to False,
            the network container discovery is disabled.
        enable_immediate_discovery: Determines if the discovery for the
            network container should be immediately enabled.
        endpoint_sources: The endpoints that provides data for the DHCP
            IPv6 Network Container.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        last_rir_registration_update_sent: The timestamp when the last
            RIR registration update was sent.
        last_rir_registration_update_status: Last RIR registration
            update status.
        logic_filter_rules: This field contains the logic filters to be
            applied on the this network container.This list corresponds
            to the match rules that are written to the dhcpd
            configuration file.
        mgm_private: This field controls whether this object is
            synchronized with the Multi-Grid Master. If this field is
            set to True, objects are not synchronized.
        mgm_private_overridable: This field is assumed to be True unless
            filled by any conforming objects, such as Network, IPv6
            Network, Network Container, IPv6 Network Container, and
            Network View. This value is set to False if mgm_private is
            set to True in the parent object.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        network: The network address in IPv6 Address/CIDR format. For
            regular expression searches, only the IPv6 Address portion
            is supported. Searches for the CIDR portion is always an
            exact match.For example, both network containers 16::0/28
            and 26::0/24 are matched by expression '.6' and only
            26::0/24 is matched by '.6/24'.
        network_container: The network container to which this network
            belongs, if any.
        network_view: The name of the network view in which this network
            resides.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        port_control_blackout_setting: The port control blackout setting
            for this network container.
        preferred_lifetime: Use this method to set or retrieve the
            preferred lifetime value of a DHCP IPv6 Network Container
            object.
        restart_if_needed: Restarts the member service.
        rir: The registry (RIR) that allocated the IPv6 network
            container address space.
        rir_organization: The RIR organization associated with the IPv6
            network container.
        rir_registration_action: The RIR registration action.
        rir_registration_status: The registration status of the IPv6
            network container in RIR.
        same_port_control_discovery_blackout: If the field is set to
            True, the discovery blackout setting will be used for port
            control blackout setting.
        send_rir_request: Determines whether to send the RIR
            registration request.
        subscribe_settings: The DHCP IPv6 Network Container Cisco ISE
            subscribe settings.
        unmanaged: Determines whether the network container is unmanaged
            or not.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_blackout_setting: Use flag for: discovery_blackout_setting ,
            port_control_blackout_setting,
            same_port_control_discovery_blackout
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_enable_option_fqdn: Use flag for:
            ddns_enable_option_fqdn
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_ddns_ttl: Use flag for: ddns_ttl
        use_discovery_basic_polling_settings: Use flag for:
            discovery_basic_poll_settings
        use_domain_name_servers: Use flag for: domain_name_servers
        use_enable_ddns: Use flag for: enable_ddns
        use_enable_discovery: Use flag for: discovery_member ,
            enable_discovery
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_mgm_private: Use flag for: mgm_private
        use_options: Use flag for: options
        use_preferred_lifetime: Use flag for: preferred_lifetime
        use_subscribe_settings: Use flag for: subscribe_settings
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
        use_valid_lifetime: Use flag for: valid_lifetime
        use_zone_associations: Use flag for: zone_associations
        utilization: The network container utilization in percentage.
        valid_lifetime: Use this method to set or retrieve the valid
            lifetime value of a DHCP IPv6 Network Container object.
        zone_associations: The list of zones associated with this
            network container.
    """
    _infoblox_type = 'ipv6networkcontainer'
    _fields = ['auto_create_reversezone', 'cloud_info', 'comment',
               'ddns_domainname', 'ddns_enable_option_fqdn',
               'ddns_generate_hostname', 'ddns_server_always_updates',
               'ddns_ttl', 'delete_reason', 'discover_now_status',
               'discovery_basic_poll_settings', 'discovery_blackout_setting',
               'discovery_engine_type', 'discovery_member',
               'domain_name_servers', 'enable_ddns', 'enable_discovery',
               'enable_immediate_discovery', 'endpoint_sources', 'extattrs',
               'last_rir_registration_update_sent',
               'last_rir_registration_update_status', 'logic_filter_rules',
               'mgm_private', 'mgm_private_overridable', 'ms_ad_user_data',
               'network', 'network_container', 'network_view', 'options',
               'port_control_blackout_setting', 'preferred_lifetime',
               'remove_subnets', 'restart_if_needed', 'rir',
               'rir_organization', 'rir_registration_action',
               'rir_registration_status',
               'same_port_control_discovery_blackout', 'send_rir_request',
               'subscribe_settings', 'unmanaged',
               'update_dns_on_lease_renewal', 'use_blackout_setting',
               'use_ddns_domainname', 'use_ddns_enable_option_fqdn',
               'use_ddns_generate_hostname', 'use_ddns_ttl',
               'use_discovery_basic_polling_settings',
               'use_domain_name_servers', 'use_enable_ddns',
               'use_enable_discovery', 'use_logic_filter_rules',
               'use_mgm_private', 'use_options', 'use_preferred_lifetime',
               'use_subscribe_settings', 'use_update_dns_on_lease_renewal',
               'use_valid_lifetime', 'use_zone_associations', 'utilization',
               'valid_lifetime', 'zone_associations']
    _search_for_update_fields = ['network', 'network_view']
    _updateable_search_fields = ['comment', 'network_view', 'rir_organization',
                                 'unmanaged']
    _all_searchable_fields = ['comment', 'discovery_engine_type', 'network',
                              'network_container', 'network_view', 'rir',
                              'rir_organization', 'unmanaged']
    _return_fields = ['comment', 'extattrs', 'network', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': DhcpOption.from_dict,
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
    """ NetworkTemplateV4: DHCP Network template object.
    Corresponds to WAPI object 'networktemplate'

    The network template used to create networks in a quick and
    consistent way. Networks created from a network template inherit all
    the properties defined in the network template, except for the
    comment and netmask that can be defined in the network.

    Attributes:
        allow_any_netmask: This flag controls whether the template
            allows any netmask. You must specify a netmask when creating
            a network using this template. If you set this parameter to
            false, you must specify the "netmask" field for the network
            template object.
        authority: Authority for the DHCP network.
        auto_create_reversezone: This flag controls whether reverse
            zones are automatically created when the network is added.
        bootfile: The boot server IPv4 Address or name in FQDN format
            for the network. You can specify the name and/or IP address
            of the boot server that the host needs to boot.
        bootserver: The bootserver address for the network. You can
            specify the name and/or IP address of the boot server that
            the host needs to boot.The boot server IPv4 Address or name
            in FQDN format.
        cloud_api_compatible: This flag controls whether this template
            can be used to create network objects in a cloud-computing
            deployment.
        comment: Comment for the network; maximum 256 characters.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this network.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        ddns_server_always_updates: This field controls whether the DHCP
            server is allowed to update DNS, regardless of the DHCP
            client requests. Note that changes for this field take
            effect only if ddns_use_option81 is True.
        ddns_ttl: The DNS update Time to Live (TTL) value of a DHCP
            network object.The TTL is a 32-bit unsigned integer that
            represents the duration, in seconds, for which the update is
            cached. Zero indicates that the update is not cached.
        ddns_update_fixed_addresses: By default, the DHCP server does
            not update DNS when it allocates a fixed address to a
            client. You can configure the DHCP server to update the A
            and PTR records of a client with a fixed address. When this
            feature is enabled and the DHCP server adds A and PTR
            records for a fixed address, the DHCP server never discards
            the records.
        ddns_use_option81: The support for DHCP Option 81 at the network
            level.
        delegated_member: Reference the Cloud Platform Appliance to
            which authority of the object should be delegated when the
            object is created using the template.
        deny_bootp: If set to True, BOOTP settings are disabled and
            BOOTP requests will be denied.
        email_list: The e-mail lists to which the appliance sends DHCP
            threshold alarm e-mail messages.
        enable_ddns: The dynamic DNS updates flag of a DHCP network
            object. If set to True, the DHCP server sends DDNS updates
            to DNS servers in the same Grid, and to external DNS
            servers.
        enable_dhcp_thresholds: Determines if DHCP thresholds are
            enabled for the network.
        enable_email_warnings: Determines if DHCP threshold warnings are
            sent through email.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients.
        enable_snmp_warnings: Determines if DHCP threshold warnings are
            send through SNMP.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        fixed_address_templates: The list of fixed address templates
            assigned to this network template object. When you create a
            network based on a network template object that contains
            fixed address templates, the fixed addresses are created
            based on the associated fixed address templates.
        high_water_mark: The percentage of DHCP network usage threshold
            above which network usage is not expected and may warrant
            your attention. When the high watermark is reached, the
            Infoblox appliance generates a syslog message and sends a
            warning (if enabled).A number that specifies the percentage
            of allocated addresses. The range is from 1 to 100.
        high_water_mark_reset: The percentage of DHCP network usage
            below which the corresponding SNMP trap is reset.A number
            that specifies the percentage of allocated addresses. The
            range is from 1 to 100. The high watermark reset value must
            be lower than the high watermark value.
        ignore_dhcp_option_list_request: If this field is set to False,
            the appliance returns all DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        ipam_email_addresses: The e-mail lists to which the appliance
            sends IPAM threshold alarm e-mail messages.
        ipam_threshold_settings: The IPAM Threshold settings for this
            network template.
        ipam_trap_settings: The IPAM Trap settings for this network
            template.
        lease_scavenge_time: An integer that specifies the period of
            time (in seconds) that frees and backs up leases remained in
            the database before they are automatically deleted. To
            disable lease scavenging, set the parameter to -1. The
            minimum positive value must be greater than 86400 seconds (1
            day).
        logic_filter_rules: This field contains the logic filters to be
            applied on the this network template.This list corresponds
            to the match rules that are written to the dhcpd
            configuration file.
        low_water_mark: The percentage of DHCP network usage below which
            the Infoblox appliance generates a syslog message and sends
            a warning (if enabled).A number that specifies the
            percentage of allocated addresses. The range is from 1 to
            100.
        low_water_mark_reset: The percentage of DHCP network usage
            threshold below which network usage is not expected and may
            warrant your attention. When the low watermark is crossed,
            the Infoblox appliance generates a syslog message and sends
            a warning (if enabled).A number that specifies the
            percentage of allocated addresses. The range is from 1 to
            100. The low watermark reset value must be higher than the
            low watermark value.
        members: A list of members or Microsoft (r) servers that serve
            DHCP for this network.
        name: The name of this network template.
        netmask: The netmask of the network in CIDR format.
        nextserver: The name in FQDN and/or IPv4 Address of the next
            server that the host needs to boot.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        pxe_lease_time: The PXE lease time value of a DHCP Network
            object. Some hosts use PXE (Preboot Execution Environment)
            to boot remotely from a server. To better manage your IP
            resources, set a different lease time for PXE boot requests.
            You can configure the DHCP server to allocate an IP address
            with a shorter lease time to hosts that send PXE boot
            requests, so IP addresses are not leased longer than
            necessary.A 32-bit unsigned integer that represents the
            duration, in seconds, for which the update is cached. Zero
            indicates that the update is not cached.
        range_templates: The list of IP address range templates assigned
            to this network template object. When you create a network
            based on a network template object that contains range
            templates, the IP address ranges are created based on the
            associated IP address range templates.
        recycle_leases: If the field is set to True, the leases are kept
            in the Recycle Bin until one week after expiration.
            Otherwise, the leases are permanently deleted.
        rir: THe registry (RIR) that allocated the network address
            space.
        rir_organization: The RIR organization assoicated with the
            network.
        rir_registration_action: The RIR registration action.
        rir_registration_status: The registration status of the network
            in RIR.
        send_rir_request: Determines whether to send the RIR
            registration request.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_authority: Use flag for: authority
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_ddns_ttl: Use flag for: ddns_ttl
        use_ddns_update_fixed_addresses: Use flag for:
            ddns_update_fixed_addresses
        use_ddns_use_option81: Use flag for: ddns_use_option81
        use_deny_bootp: Use flag for: deny_bootp
        use_email_list: Use flag for: email_list
        use_enable_ddns: Use flag for: enable_ddns
        use_enable_dhcp_thresholds: Use flag for: enable_dhcp_thresholds
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_ipam_email_addresses: Use flag for: ipam_email_addresses
        use_ipam_threshold_settings: Use flag for:
            ipam_threshold_settings
        use_ipam_trap_settings: Use flag for: ipam_trap_settings
        use_lease_scavenge_time: Use flag for: lease_scavenge_time
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_pxe_lease_time: Use flag for: pxe_lease_time
        use_recycle_leases: Use flag for: recycle_leases
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
    """
    _infoblox_type = 'networktemplate'
    _fields = ['allow_any_netmask', 'authority', 'auto_create_reversezone',
               'bootfile', 'bootserver', 'cloud_api_compatible', 'comment',
               'ddns_domainname', 'ddns_generate_hostname',
               'ddns_server_always_updates', 'ddns_ttl',
               'ddns_update_fixed_addresses', 'ddns_use_option81',
               'delegated_member', 'deny_bootp', 'email_list', 'enable_ddns',
               'enable_dhcp_thresholds', 'enable_email_warnings',
               'enable_pxe_lease_time', 'enable_snmp_warnings', 'extattrs',
               'fixed_address_templates', 'high_water_mark',
               'high_water_mark_reset', 'ignore_dhcp_option_list_request',
               'ipam_email_addresses', 'ipam_threshold_settings',
               'ipam_trap_settings', 'lease_scavenge_time',
               'logic_filter_rules', 'low_water_mark', 'low_water_mark_reset',
               'members', 'name', 'netmask', 'nextserver', 'options',
               'pxe_lease_time', 'range_templates', 'recycle_leases', 'rir',
               'rir_organization', 'rir_registration_action',
               'rir_registration_status', 'send_rir_request',
               'update_dns_on_lease_renewal', 'use_authority', 'use_bootfile',
               'use_bootserver', 'use_ddns_domainname',
               'use_ddns_generate_hostname', 'use_ddns_ttl',
               'use_ddns_update_fixed_addresses', 'use_ddns_use_option81',
               'use_deny_bootp', 'use_email_list', 'use_enable_ddns',
               'use_enable_dhcp_thresholds',
               'use_ignore_dhcp_option_list_request',
               'use_ipam_email_addresses', 'use_ipam_threshold_settings',
               'use_ipam_trap_settings', 'use_lease_scavenge_time',
               'use_logic_filter_rules', 'use_nextserver', 'use_options',
               'use_pxe_lease_time', 'use_recycle_leases',
               'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name', 'rir_organization']
    _all_searchable_fields = ['comment', 'name', 'rir', 'rir_organization']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'members': Dhcpmember.from_dict,
        'options': DhcpOption.from_dict,
    }


class NetworkTemplateV6(NetworkTemplate):
    """ NetworkTemplateV6: DHCP IPv6 network template object.
    Corresponds to WAPI object 'ipv6networktemplate'

    The IPv6 network template used to create IPv6 networks in a quick
    and consistent way. IPv6 networks created from an IPv6 network
    template inherit all the properties defined in the IPv6 network
    template, except for the comment and CIDR that can be defined in the
    IPv6 network.

    Attributes:
        allow_any_netmask: This flag controls whether the template
            allows any netmask. You must specify a netmask when creating
            a network using this template. If you set this parameter to
            False, you must specify the "cidr" field for the network
            template object.
        auto_create_reversezone: This flag controls whether reverse
            zones are automatically created when the network is added.
        cidr: The CIDR of the network in CIDR format.
        cloud_api_compatible: This flag controls whether this template
            can be used to create network objects in a cloud-computing
            deployment.
        comment: Comment for the network; maximum 256 characters.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this network.
        ddns_enable_option_fqdn: Use this method to set or retrieve the
            ddns_enable_option_fqdn flag of a DHCP IPv6 Network object.
            This method controls whether the FQDN option sent by the
            client is to be used, or if the server can automatically
            generate the FQDN. This setting overrides the upper-level
            settings.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        ddns_server_always_updates: This field controls whether the DHCP
            server is allowed to update DNS, regardless of the DHCP
            client requests. Note that changes for this field take
            effect only if ddns_enable_option_fqdn is True.
        ddns_ttl: The DNS update Time to Live (TTL) value of a DHCP
            network object.The TTL is a 32-bit unsigned integer that
            represents the duration, in seconds, for which the update is
            cached. Zero indicates that the update is not cached.
        delegated_member: Reference the Cloud Platform Appliance to
            which authority of the object should be delegated when the
            object is created using the template.
        domain_name: Use this method to set or retrieve the domain_name
            value of a DHCP IPv6 Network object.
        domain_name_servers: Use this method to set or retrieve the
            dynamic DNS updates flag of a DHCP IPv6 Network object. The
            DHCP server can send DDNS updates to DNS servers in the same
            Grid and to external DNS servers. This setting overrides the
            member level settings.
        enable_ddns: The dynamic DNS updates flag of a DHCP IPv6 network
            object. If set to True, the DHCP server sends DDNS updates
            to DNS servers in the same Grid, and to external DNS
            servers.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        fixed_address_templates: The list of IPv6 fixed address
            templates assigned to this IPv6 network template object.
            When you create an IPv6 network based on an IPv6 network
            template object that contains IPv6 fixed address templates,
            the IPv6 fixed addresses are created based on the associated
            IPv6 fixed address templates.
        ipv6prefix: The IPv6 Address prefix of the DHCP IPv6 network.
        logic_filter_rules: This field contains the logic filters to be
            applied on this IPv6 network template.This list corresponds
            to the match rules that are written to the DHCPv6
            configuration file.
        members: A list of members that serve DHCP for the network.All
            members in the array must be of the same type. The struct
            type must be indicated in each element, by setting the
            "_struct" member to the struct type.
        name: The name of this IPv6 network template.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        preferred_lifetime: Use this method to set or retrieve the
            preferred lifetime value of a DHCP IPv6 Network object.
        range_templates: The list of IPv6 address range templates
            assigned to this IPv6 network template object. When you
            create an IPv6 network based on an IPv6 network template
            object that contains IPv6 range templates, the IPv6 address
            ranges are created based on the associated IPv6 address
            range templates.
        recycle_leases: If the field is set to True, the leases are kept
            in the Recycle Bin until one week after expiration.
            Otherwise, the leases are permanently deleted.
        rir: The registry (RIR) that allocated the IPv6 network address
            space.
        rir_organization: The RIR organization associated with the IPv6
            network.
        rir_registration_action: The action for the RIR registration.
        rir_registration_status: The registration status of the IPv6
            network in RIR.
        send_rir_request: Determines whether to send the RIR
            registration request.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_enable_option_fqdn: Use flag for:
            ddns_enable_option_fqdn
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_ddns_ttl: Use flag for: ddns_ttl
        use_domain_name: Use flag for: domain_name
        use_domain_name_servers: Use flag for: domain_name_servers
        use_enable_ddns: Use flag for: enable_ddns
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_options: Use flag for: options
        use_preferred_lifetime: Use flag for: preferred_lifetime
        use_recycle_leases: Use flag for: recycle_leases
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
        use_valid_lifetime: Use flag for: valid_lifetime
        valid_lifetime: Use this method to set or retrieve the valid
            lifetime value of a DHCP IPv6 Network object.
    """
    _infoblox_type = 'ipv6networktemplate'
    _fields = ['allow_any_netmask', 'auto_create_reversezone', 'cidr',
               'cloud_api_compatible', 'comment', 'ddns_domainname',
               'ddns_enable_option_fqdn', 'ddns_generate_hostname',
               'ddns_server_always_updates', 'ddns_ttl', 'delegated_member',
               'domain_name', 'domain_name_servers', 'enable_ddns', 'extattrs',
               'fixed_address_templates', 'ipv6prefix', 'logic_filter_rules',
               'members', 'name', 'options', 'preferred_lifetime',
               'range_templates', 'recycle_leases', 'rir', 'rir_organization',
               'rir_registration_action', 'rir_registration_status',
               'send_rir_request', 'update_dns_on_lease_renewal',
               'use_ddns_domainname', 'use_ddns_enable_option_fqdn',
               'use_ddns_generate_hostname', 'use_ddns_ttl', 'use_domain_name',
               'use_domain_name_servers', 'use_enable_ddns',
               'use_logic_filter_rules', 'use_options',
               'use_preferred_lifetime', 'use_recycle_leases',
               'use_update_dns_on_lease_renewal', 'use_valid_lifetime',
               'valid_lifetime']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'ipv6prefix', 'name',
                                 'rir_organization']
    _all_searchable_fields = ['comment', 'ipv6prefix', 'name', 'rir',
                              'rir_organization']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'members': Dhcpmember.from_dict,
        'options': DhcpOption.from_dict,
    }


class IPRange(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return IPRangeV4

    @classmethod
    def get_v6_class(cls):
        return IPRangeV6


class IPRangeV4(IPRange):
    """ IPRangeV4: DHCP Range object.
    Corresponds to WAPI object 'range'

    A DHCP range defines the specified range of IP addresses in a
    network. A DHCP range should be added for a network so the Infoblox
    appliance can assign IP addresses within that specified range to
    DHCP clients. If the client is on a network that is assigned a DHCP
    range, the device distributes an available IP address from that
    range to the DHCP client, or to a DHCP relay agent if the request
    came through an agent. The DHCP range should also be assigned with a
    device. If devices are in a grid, the particular member serving DHCP
    for the DHCP range must be specified. If the server is an
    independent device, this device must be specified as the member that
    serves the DHCP range.

    Attributes:
        always_update_dns: This field controls whether only the DHCP
            server is allowed to update DNS, regardless of the DHCP
            clients requests.
        bootfile: The bootfile name for the range. You can configure the
            DHCP server to support clients that use the boot file name
            option in their DHCPREQUEST messages.
        bootserver: The bootserver address for the range. You can
            specify the name and/or IP address of the boot server that
            the host needs to boot.The boot server IPv4 Address or name
            in FQDN format.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the range; maximum 256 characters.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this range.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        deny_all_clients: If True, send NAK forcing the client to take
            the new address.
        deny_bootp: If set to true, BOOTP settings are disabled and
            BOOTP requests will be denied.
        dhcp_utilization: The percentage of the total DHCP utilization
            of the range multiplied by 1000. This is the percentage of
            the total number of available IP addresses belonging to the
            range versus the total number of all IP addresses in the
            range.
        dhcp_utilization_status: A string describing the utilization
            level of the range.
        disable: Determines whether a range is disabled or not. When
            this is set to False, the range is enabled.
        discover_now_status: Discover now status for this range.
        discovery_basic_poll_settings: The discovery basic poll settings
            for this range.
        discovery_blackout_setting: The discovery blackout setting for
            this range.
        discovery_member: The member that will run discovery for this
            range.
        dynamic_hosts: The total number of DHCP leases issued for the
            range.
        email_list: The e-mail lists to which the appliance sends DHCP
            threshold alarm e-mail messages.
        enable_ddns: The dynamic DNS updates flag of a DHCP range
            object. If set to True, the DHCP server sends DDNS updates
            to DNS servers in the same Grid, and to external DNS
            servers.
        enable_dhcp_thresholds: Determines if DHCP thresholds are
            enabled for the range.
        enable_discovery: Determines whether a discovery is enabled or
            not for this range. When this is set to False, the discovery
            for this range is disabled.
        enable_email_warnings: Determines if DHCP threshold warnings are
            sent through email.
        enable_ifmap_publishing: Determines if IFMAP publishing is
            enabled for the range.
        enable_immediate_discovery: Determines if the discovery for the
            range should be immediately enabled.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients.
        enable_snmp_warnings: Determines if DHCP threshold warnings are
            send through SNMP.
        end_addr: The IPv4 Address end address of the range.
        endpoint_sources: The endpoints that provides data for the DHCP
            Range object.
        exclude: These are ranges of IP addresses that the appliance
            does not use to assign to clients. You can use these
            exclusion addresses as static IP addresses. They contain the
            start and end addresses of the exclusion range, and
            optionally, information about this exclusion range.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        failover_association: The name of the failover association: the
            server in this failover association will serve the IPv4
            range in case the main server is out of service.
        fingerprint_filter_rules: This field contains the fingerprint
            filters for this DHCP range.The appliance uses matching
            rules in these filters to select the address range from
            which it assigns a lease.
        high_water_mark: The percentage of DHCP range usage threshold
            above which range usage is not expected and may warrant your
            attention. When the high watermark is reached, the Infoblox
            appliance generates a syslog message and sends a warning (if
            enabled).A number that specifies the percentage of allocated
            addresses. The range is from 1 to 100.
        high_water_mark_reset: The percentage of DHCP range usage below
            which the corresponding SNMP trap is reset.A number that
            specifies the percentage of allocated addresses. The range
            is from 1 to 100. The high watermark reset value must be
            lower than the high watermark value.
        ignore_dhcp_option_list_request: If this field is set to False,
            the appliance returns all DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        ignore_id: Indicates whether the appliance will ignore DHCP
            client IDs or MAC addresses. Valid values are "NONE",
            "CLIENT", or "MACADDR". The default is "NONE".
        ignore_mac_addresses: A list of MAC addresses the appliance will
            ignore.
        is_split_scope: This field will be 'true' if this particular
            range is part of a split scope.
        known_clients: Permission for known clients. This can be 'Allow'
            or 'Deny'. If set to 'Deny' known clients will be denied IP
            addresses.Known clients include roaming hosts and clients
            with fixed addresses or DHCP host entries. Unknown clients
            include clients that are not roaming hosts and clients that
            do not have fixed addresses or DHCP host entries.
        lease_scavenge_time: An integer that specifies the period of
            time (in seconds) that frees and backs up leases remained in
            the database before they are automatically deleted. To
            disable lease scavenging, set the parameter to -1. The
            minimum positive value must be greater than 86400 seconds (1
            day).
        logic_filter_rules: This field contains the logic filters to be
            applied to this range.This list corresponds to the match
            rules that are written to the dhcpd configuration file.
        low_water_mark: The percentage of DHCP range usage below which
            the Infoblox appliance generates a syslog message and sends
            a warning (if enabled).A number that specifies the
            percentage of allocated addresses. The range is from 1 to
            100.
        low_water_mark_reset: The percentage of DHCP range usage
            threshold below which range usage is not expected and may
            warrant your attention. When the low watermark is crossed,
            the Infoblox appliance generates a syslog message and sends
            a warning (if enabled).A number that specifies the
            percentage of allocated addresses. The range is from 1 to
            100. The low watermark reset value must be higher than the
            low watermark value.
        mac_filter_rules: This field contains the MAC filters to be
            applied to this range.The appliance uses the matching rules
            of these filters to select the address range from which it
            assigns a lease.
        member: The member that will provide service for this range.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        ms_options: This field contains the Microsoft DHCP options for
            this range.
        ms_server: The Microsoft server that will provide service for
            this range.
        nac_filter_rules: This field contains the NAC filters to be
            applied to this range.The appliance uses the matching rules
            of these filters to select the address range from which it
            assigns a lease.
        name: This field contains the name of the Microsoft scope.
        network: The network to which this range belongs, in IPv4
            Address/CIDR format.
        network_view: The name of the network view in which this range
            resides.
        nextserver: The name in FQDN and/or IPv4 Address of the next
            server that the host needs to boot.
        option_filter_rules: This field contains the Option filters to
            be applied to this range.The appliance uses the matching
            rules of these filters to select the address range from
            which it assigns a lease.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        port_control_blackout_setting: The port control blackout setting
            for this range.
        pxe_lease_time: The PXE lease time value of a DHCP Range object.
            Some hosts use PXE (Preboot Execution Environment) to boot
            remotely from a server. To better manage your IP resources,
            set a different lease time for PXE boot requests. You can
            configure the DHCP server to allocate an IP address with a
            shorter lease time to hosts that send PXE boot requests, so
            IP addresses are not leased longer than necessary.A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the update is cached. Zero indicates that the
            update is not cached.
        recycle_leases: If the field is set to True, the leases are kept
            in the Recycle Bin until one week after expiration.
            Otherwise, the leases are permanently deleted.
        relay_agent_filter_rules: This field contains the Relay Agent
            filters to be applied to this range.The appliance uses the
            matching rules of these filters to select the address range
            from which it assigns a lease.
        restart_if_needed: Restarts the member service.
        same_port_control_discovery_blackout: If the field is set to
            True, the discovery blackout setting will be used for port
            control blackout setting.
        server_association_type: The type of server that is going to
            serve the range.
        split_member: The Microsoft member to which the split scope is
            assigned. See split_scope_exclusion_percent for more
            information
        split_scope_exclusion_percent: This field controls the
            percentage used when creating a split scope.Valid values are
            numbers between 1 and 99. If the value is 40, it means that
            the top 40% of the exclusion will be created on the DHCP
            range assigned to ms_server and the lower 60% of the range
            will be assigned to DHCP range assigned to split_member
        start_addr: The IPv4 Address starting address of the range.
        static_hosts: The number of static DHCP addresses configured in
            the range.
        subscribe_settings: The DHCP Range Cisco ISE subscribe settings.
        template: If set on creation, the range will be created
            according to the values specified in the named template.
        total_hosts: The total number of DHCP addresses configured in
            the range.
        unknown_clients: Permission for unknown clients. This can be
            'Allow' or 'Deny'. If set to 'Deny', unknown clients will be
            denied IP addresses.Known clients include roaming hosts and
            clients with fixed addresses or DHCP host entries. Unknown
            clients include clients that are not roaming hosts and
            clients that do not have fixed addresses or DHCP host
            entries.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_blackout_setting: Use flag for: discovery_blackout_setting ,
            port_control_blackout_setting,
            same_port_control_discovery_blackout
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_deny_bootp: Use flag for: deny_bootp
        use_discovery_basic_polling_settings: Use flag for:
            discovery_basic_poll_settings
        use_email_list: Use flag for: email_list
        use_enable_ddns: Use flag for: enable_ddns
        use_enable_dhcp_thresholds: Use flag for: enable_dhcp_thresholds
        use_enable_discovery: Use flag for: discovery_member ,
            enable_discovery
        use_enable_ifmap_publishing: Use flag for:
            enable_ifmap_publishing
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_ignore_id: Use flag for: ignore_id
        use_known_clients: Use flag for: known_clients
        use_lease_scavenge_time: Use flag for: lease_scavenge_time
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_ms_options: Use flag for: ms_options
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_pxe_lease_time: Use flag for: pxe_lease_time
        use_recycle_leases: Use flag for: recycle_leases
        use_subscribe_settings: Use flag for: subscribe_settings
        use_unknown_clients: Use flag for: unknown_clients
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
    """
    _infoblox_type = 'range'
    _fields = ['always_update_dns', 'bootfile', 'bootserver', 'cloud_info',
               'comment', 'ddns_domainname', 'ddns_generate_hostname',
               'deny_all_clients', 'deny_bootp', 'dhcp_utilization',
               'dhcp_utilization_status', 'disable', 'discover_now_status',
               'discovery_basic_poll_settings', 'discovery_blackout_setting',
               'discovery_member', 'dynamic_hosts', 'email_list',
               'enable_ddns', 'enable_dhcp_thresholds', 'enable_discovery',
               'enable_email_warnings', 'enable_ifmap_publishing',
               'enable_immediate_discovery', 'enable_pxe_lease_time',
               'enable_snmp_warnings', 'end_addr', 'endpoint_sources',
               'exclude', 'extattrs', 'failover_association',
               'fingerprint_filter_rules', 'high_water_mark',
               'high_water_mark_reset', 'ignore_dhcp_option_list_request',
               'ignore_id', 'ignore_mac_addresses', 'is_split_scope',
               'known_clients', 'lease_scavenge_time', 'logic_filter_rules',
               'low_water_mark', 'low_water_mark_reset', 'mac_filter_rules',
               'member', 'ms_ad_user_data', 'ms_options', 'ms_server',
               'nac_filter_rules', 'name', 'network', 'network_view',
               'nextserver', 'option_filter_rules', 'options',
               'port_control_blackout_setting', 'pxe_lease_time',
               'recycle_leases', 'relay_agent_filter_rules',
               'restart_if_needed', 'same_port_control_discovery_blackout',
               'server_association_type', 'split_member',
               'split_scope_exclusion_percent', 'start_addr', 'static_hosts',
               'subscribe_settings', 'template', 'total_hosts',
               'unknown_clients', 'update_dns_on_lease_renewal',
               'use_blackout_setting', 'use_bootfile', 'use_bootserver',
               'use_ddns_domainname', 'use_ddns_generate_hostname',
               'use_deny_bootp', 'use_discovery_basic_polling_settings',
               'use_email_list', 'use_enable_ddns',
               'use_enable_dhcp_thresholds', 'use_enable_discovery',
               'use_enable_ifmap_publishing',
               'use_ignore_dhcp_option_list_request', 'use_ignore_id',
               'use_known_clients', 'use_lease_scavenge_time',
               'use_logic_filter_rules', 'use_ms_options', 'use_nextserver',
               'use_options', 'use_pxe_lease_time', 'use_recycle_leases',
               'use_subscribe_settings', 'use_unknown_clients',
               'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['end_addr', 'network', 'network_view',
                                 'start_addr']
    _updateable_search_fields = ['comment', 'end_addr', 'failover_association',
                                 'member', 'ms_server', 'network',
                                 'network_view', 'server_association_type',
                                 'start_addr']
    _all_searchable_fields = ['comment', 'end_addr', 'failover_association',
                              'member', 'ms_server', 'network', 'network_view',
                              'server_association_type', 'start_addr']
    _return_fields = ['comment', 'end_addr', 'extattrs', 'network',
                      'network_view', 'start_addr']
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
        'options': DhcpOption.from_dict,
        'relay_agent_filter_rules': Filterrule.from_dict,
    }

    def next_available_ip(self, *args, **kwargs):
        return self._call_func("next_available_ip", *args, **kwargs)


class IPRangeV6(IPRange):
    """ IPRangeV6: DHCP IPv6 Range object.
    Corresponds to WAPI object 'ipv6range'

    A DHCP IPv6 range defines the specified range of IP addresses in an
    IPv6 network. A DHCP IPv6 range should be added for an IPv6 network
    so the Infoblox appliance can assign IP addresses within that
    specified range to DHCP clients. If the client is on an IPv6 network
    that is assigned a DHCP IPv6 range, the device distributes an
    available IP address from that range to the DHCP client, or to a
    DHCP relay agent if the request came through an agent. The DHCP IPv6
    range should also be assigned with a device. If devices are in a
    grid, the particular member serving DHCP for the DHCP IPv6 range
    must be specified. If the server is an independent device, this
    device must be specified as the member that serves the DHCP IPv6
    range.

    Attributes:
        address_type: Type of a DHCP IPv6 Range object. Valid values are
            "ADDRESS", "PREFIX", or "BOTH". When the address type is
            "ADDRESS", values for the 'start_addr' and 'end_addr'
            members are required. When the address type is "PREFIX",
            values for 'ipv6_start_prefix', 'ipv6_end_prefix', and
            'ipv6_prefix_bits' are required. When the address type is
            "BOTH", values for 'start_addr', 'end_addr',
            'ipv6_start_prefix', 'ipv6_end_prefix', and
            'ipv6_prefix_bits' are all required.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the range; maximum 256 characters.
        disable: Determines whether a range is disabled or not. When
            this is set to False, the range is enabled.
        discover_now_status: Discover now status for this range.
        discovery_basic_poll_settings: The discovery basic poll settings
            for this range.
        discovery_blackout_setting: The discovery blackout setting for
            this range.
        discovery_member: The member that will run discovery for this
            range.
        enable_discovery: Determines whether a discovery is enabled or
            not for this range. When this is set to False, the discovery
            for this range is disabled.
        enable_immediate_discovery: Determines if the discovery for the
            range should be immediately enabled.
        end_addr: The IPv6 Address end address of the DHCP IPv6 range.
        endpoint_sources: The endpoints that provides data for the DHCP
            IPv6 Range object.
        exclude: These are ranges of IP addresses that the appliance
            does not use to assign to clients. You can use these
            exclusion addresses as static IP addresses. They contain the
            start and end addresses of the exclusion range, and
            optionally,information about this exclusion range.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv6_end_prefix: The IPv6 Address end prefix of the DHCP IPv6
            range.
        ipv6_prefix_bits: Prefix bits of the DHCP IPv6 range.
        ipv6_start_prefix: The IPv6 Address starting prefix of the DHCP
            IPv6 range.
        logic_filter_rules: This field contains the logic filters to be
            applied to this IPv6 range. This list corresponds to the
            match rules that are written to the DHCPv6 configuration
            file.
        member: The member that will provide service for this range.
        name: This field contains the name of the Microsoft scope.
        network: The network this range belongs to, in IPv6 Address/CIDR
            format.
        network_view: The name of the network view in which this range
            resides.
        option_filter_rules: This field contains the Option filters to
            be applied to this IPv6 range. The appliance uses the
            matching rules of these filters to select the address range
            from which it assigns a lease.
        port_control_blackout_setting: The port control blackout setting
            for this range.
        recycle_leases: If the field is set to True, the leases are kept
            in the Recycle Bin until one week after expiration.
            Otherwise, the leases are permanently deleted.
        restart_if_needed: Restarts the member service.
        same_port_control_discovery_blackout: If the field is set to
            True, the discovery blackout setting will be used for port
            control blackout setting.
        server_association_type: The type of server that is going to
            serve the range. Valid values are:
        start_addr: The IPv6 Address starting address of the DHCP IPv6
            range.
        subscribe_settings: The DHCP IPv6 Range Cisco ISE subscribe
            settings.
        template: If set on creation, the range will be created
            according to the values specified in the named template.
        use_blackout_setting: Use flag for: discovery_blackout_setting ,
            port_control_blackout_setting,
            same_port_control_discovery_blackout
        use_discovery_basic_polling_settings: Use flag for:
            discovery_basic_poll_settings
        use_enable_discovery: Use flag for: discovery_member ,
            enable_discovery
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_recycle_leases: Use flag for: recycle_leases
        use_subscribe_settings: Use flag for: subscribe_settings
    """
    _infoblox_type = 'ipv6range'
    _fields = ['address_type', 'cloud_info', 'comment', 'disable',
               'discover_now_status', 'discovery_basic_poll_settings',
               'discovery_blackout_setting', 'discovery_member',
               'enable_discovery', 'enable_immediate_discovery', 'end_addr',
               'endpoint_sources', 'exclude', 'extattrs', 'ipv6_end_prefix',
               'ipv6_prefix_bits', 'ipv6_start_prefix', 'logic_filter_rules',
               'member', 'name', 'network', 'network_view',
               'option_filter_rules', 'port_control_blackout_setting',
               'recycle_leases', 'restart_if_needed',
               'same_port_control_discovery_blackout',
               'server_association_type', 'start_addr', 'subscribe_settings',
               'template', 'use_blackout_setting',
               'use_discovery_basic_polling_settings', 'use_enable_discovery',
               'use_logic_filter_rules', 'use_recycle_leases',
               'use_subscribe_settings']
    _search_for_update_fields = ['end_addr', 'network', 'network_view',
                                 'start_addr']
    _updateable_search_fields = ['address_type', 'comment', 'end_addr',
                                 'ipv6_end_prefix', 'ipv6_prefix_bits',
                                 'ipv6_start_prefix', 'member', 'name',
                                 'network', 'network_view',
                                 'server_association_type', 'start_addr']
    _all_searchable_fields = ['address_type', 'comment', 'end_addr',
                              'ipv6_end_prefix', 'ipv6_prefix_bits',
                              'ipv6_start_prefix', 'member', 'name', 'network',
                              'network_view', 'server_association_type',
                              'start_addr']
    _return_fields = ['comment', 'end_addr', 'extattrs', 'network',
                      'network_view', 'start_addr']
    _remap = {'cidr': 'network'}
    _shadow_fields = ['_ref', 'cidr']
    _ip_version = 6

    _custom_field_processing = {
        'exclude': Exclusionrange.from_dict,
        'logic_filter_rules': Logicfilterrule.from_dict,
        'option_filter_rules': Filterrule.from_dict,
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
    """ RangeTemplateV4: DHCP Range template object.
    Corresponds to WAPI object 'rangetemplate'

    The range template used to create a range objects in a quick and
    consistant way. Range object created from a range template will
    inherit most properties defined in range template object so most of
    the range template properties are the same as the range object
    properties.

    Attributes:
        bootfile: The bootfile name for the range. You can configure the
            DHCP server to support clients that use the boot file name
            option in their DHCPREQUEST messages.
        bootserver: The bootserver address for the range. You can
            specify the name and/or IP address of the boot server that
            the host needs to boot.The boot server IPv4 Address or name
            in FQDN format.
        cloud_api_compatible: This flag controls whether this template
            can be used to create network objects in a cloud-computing
            deployment.
        comment: A descriptive comment of a range template object.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this range.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        delegated_member: The vconnector member that the object should
            be delegated to when created from this range template.
        deny_all_clients: If True, send NAK forcing the client to take
            the new address.
        deny_bootp: Determines if BOOTP settings are disabled and BOOTP
            requests will be denied.
        email_list: The e-mail lists to which the appliance sends DHCP
            threshold alarm e-mail messages.
        enable_ddns: Determines if the DHCP server sends DDNS updates to
            DNS servers in the same Grid, and to external DNS servers.
        enable_dhcp_thresholds: Determines if DHCP thresholds are
            enabled for the range.
        enable_email_warnings: Determines if DHCP threshold warnings are
            sent through email.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients.
        enable_snmp_warnings: Determines if DHCP threshold warnings are
            sent through SNMP.
        exclude: These are ranges of IP addresses that the appliance
            does not use to assign to clients. You can use these
            exclusion addresses as static IP addresses. They contain the
            start and end addresses of the exclusion range, and
            optionally, information about this exclusion range.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        failover_association: The name of the failover association: the
            server in this failover association will serve the IPv4
            range in case the main server is out of service.
        fingerprint_filter_rules: This field contains the fingerprint
            filters for this DHCP range.The appliance uses matching
            rules in these filters to select the address range from
            which it assigns a lease.
        high_water_mark: The percentage of DHCP range usage threshold
            above which range usage is not expected and may warrant your
            attention. When the high watermark is reached, the Infoblox
            appliance generates a syslog message and sends a warning (if
            enabled).A number that specifies the percentage of allocated
            addresses. The range is from 1 to 100.
        high_water_mark_reset: The percentage of DHCP range usage below
            which the corresponding SNMP trap is reset.A number that
            specifies the percentage of allocated addresses. The range
            is from 1 to 100. The high watermark reset value must be
            lower than the high watermark value.
        ignore_dhcp_option_list_request: If this field is set to False,
            the appliance returns all DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        known_clients: Permission for known clients. If set to 'Deny'
            known clients will be denied IP addresses.Known clients
            include roaming hosts and clients with fixed addresses or
            DHCP host entries. Unknown clients include clients that are
            not roaming hosts and clients that do not have fixed
            addresses or DHCP host entries.
        lease_scavenge_time: An integer that specifies the period of
            time (in seconds) that frees and backs up leases remained in
            the database before they are automatically deleted. To
            disable lease scavenging, set the parameter to -1. The
            minimum positive value must be greater than 86400 seconds (1
            day).
        logic_filter_rules: This field contains the logic filters to be
            applied on this range.This list corresponds to the match
            rules that are written to the dhcpd configuration file.
        low_water_mark: The percentage of DHCP range usage below which
            the Infoblox appliance generates a syslog message and sends
            a warning (if enabled).A number that specifies the
            percentage of allocated addresses. The range is from 1 to
            100.
        low_water_mark_reset: The percentage of DHCP range usage
            threshold below which range usage is not expected and may
            warrant your attention. When the low watermark is crossed,
            the Infoblox appliance generates a syslog message and sends
            a warning (if enabled).A number that specifies the
            percentage of allocated addresses. The range is from 1 to
            100. The low watermark reset value must be higher than the
            low watermark value.
        mac_filter_rules: This field contains the MAC filters to be
            applied to this range.The appliance uses the matching rules
            of these filters to select the address range from which it
            assigns a lease.
        member: The member that will provide service for this range.
        ms_options: The Microsoft DHCP options for this range.
        ms_server: The Microsoft server that will provide service for
            this range.
        nac_filter_rules: This field contains the NAC filters to be
            applied to this range.The appliance uses the matching rules
            of these filters to select the address range from which it
            assigns a lease.
        name: The name of a range template object.
        nextserver: The name in FQDN and/or IPv4 Address format of the
            next server that the host needs to boot.
        number_of_addresses: The number of addresses for this range.
        offset: The start address offset for this range.
        option_filter_rules: This field contains the Option filters to
            be applied to this range.The appliance uses the matching
            rules of these filters to select the address range from
            which it assigns a lease.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        pxe_lease_time: The PXE lease time value for a range object.
            Some hosts use PXE (Preboot Execution Environment) to boot
            remotely from a server. To better manage your IP resources,
            set a different lease time for PXE boot requests. You can
            configure the DHCP server to allocate an IP address with a
            shorter lease time to hosts that send PXE boot requests, so
            IP addresses are not leased longer than necessary.A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the update is cached. Zero indicates that the
            update is not cached.
        recycle_leases: If the field is set to True, the leases are kept
            in the Recycle Bin until one week after expiration.
            Otherwise, the leases are permanently deleted.
        relay_agent_filter_rules: This field contains the Relay Agent
            filters to be applied to this range.The appliance uses the
            matching rules of these filters to select the address range
            from which it assigns a lease.
        server_association_type: The type of server that is going to
            serve the range.
        unknown_clients: Permission for unknown clients. If set to
            'Deny' unknown clients will be denied IP addresses.Known
            clients include roaming hosts and clients with fixed
            addresses or DHCP host entries. Unknown clients include
            clients that are not roaming hosts and clients that do not
            have fixed addresses or DHCP host entries.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_deny_bootp: Use flag for: deny_bootp
        use_email_list: Use flag for: email_list
        use_enable_ddns: Use flag for: enable_ddns
        use_enable_dhcp_thresholds: Use flag for: enable_dhcp_thresholds
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_known_clients: Use flag for: known_clients
        use_lease_scavenge_time: Use flag for: lease_scavenge_time
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_ms_options: Use flag for: ms_options
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_pxe_lease_time: Use flag for: pxe_lease_time
        use_recycle_leases: Use flag for: recycle_leases
        use_unknown_clients: Use flag for: unknown_clients
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
    """
    _infoblox_type = 'rangetemplate'
    _fields = ['bootfile', 'bootserver', 'cloud_api_compatible', 'comment',
               'ddns_domainname', 'ddns_generate_hostname', 'delegated_member',
               'deny_all_clients', 'deny_bootp', 'email_list', 'enable_ddns',
               'enable_dhcp_thresholds', 'enable_email_warnings',
               'enable_pxe_lease_time', 'enable_snmp_warnings', 'exclude',
               'extattrs', 'failover_association', 'fingerprint_filter_rules',
               'high_water_mark', 'high_water_mark_reset',
               'ignore_dhcp_option_list_request', 'known_clients',
               'lease_scavenge_time', 'logic_filter_rules', 'low_water_mark',
               'low_water_mark_reset', 'mac_filter_rules', 'member',
               'ms_options', 'ms_server', 'nac_filter_rules', 'name',
               'nextserver', 'number_of_addresses', 'offset',
               'option_filter_rules', 'options', 'pxe_lease_time',
               'recycle_leases', 'relay_agent_filter_rules',
               'server_association_type', 'unknown_clients',
               'update_dns_on_lease_renewal', 'use_bootfile', 'use_bootserver',
               'use_ddns_domainname', 'use_ddns_generate_hostname',
               'use_deny_bootp', 'use_email_list', 'use_enable_ddns',
               'use_enable_dhcp_thresholds',
               'use_ignore_dhcp_option_list_request', 'use_known_clients',
               'use_lease_scavenge_time', 'use_logic_filter_rules',
               'use_ms_options', 'use_nextserver', 'use_options',
               'use_pxe_lease_time', 'use_recycle_leases',
               'use_unknown_clients', 'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'failover_association', 'member',
                                 'ms_server', 'name',
                                 'server_association_type']
    _all_searchable_fields = ['comment', 'failover_association', 'member',
                              'ms_server', 'name', 'server_association_type']
    _return_fields = ['comment', 'extattrs', 'name', 'number_of_addresses',
                      'offset']
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
        'options': DhcpOption.from_dict,
        'relay_agent_filter_rules': Filterrule.from_dict,
    }


class RangeTemplateV6(RangeTemplate):
    """ RangeTemplateV6: IPv6 DHCP Range template object.
    Corresponds to WAPI object 'ipv6rangetemplate'

    The IPv6 range template used to create an IPv6 range object in a
    quick and consistent way. The DHCP IPv6 range created from the DHCP
    IPv6 range template will inherit the properties defined in this
    template.

    Attributes:
        cloud_api_compatible: Determines whether the IPv6 DHCP range
            template can be used to create network objects in a cloud-
            computing deployment.
        comment: The IPv6 DHCP range template descriptive comment.
        delegated_member: The vConnector member that the object should
            be delegated to when created from the IPv6 DHCP range
            template. I assume that vConnector refers to VMware
            vConnector.
        exclude: These are ranges of IPv6 addresses that the appliance
            does not use to assign to clients. You can use these
            excluded addresses as static IPv6 addresses. They contain
            the start and end addresses of the excluded range, and
            optionally, information about this excluded range.
        logic_filter_rules: This field contains the logic filters to be
            applied on this IPv6 range.This list corresponds to the
            match rules that are written to the DHCPv6 configuration
            file.
        member: The member that will provide service for the IPv6 DHCP
            range.Set server_association_type to 'MEMBER' if you want
            the server specified here to serve the range. For searching
            by this field, use an HTTP method that contains a body (POST
            or PUT) with MS DHCP server structure and the request should
            have option _method=GET.
        name: Name of the IPv6 DHCP range template.
        number_of_addresses: The number of addresses for the IPv6 DHCP
            range.
        offset: The start address offset for the IPv6 DHCP range.
        option_filter_rules: This field contains the Option filters to
            be applied to this IPv6 range. The appliance uses the
            matching rules of these filters to select the address range
            from which it assigns a lease.
        recycle_leases: Determines whether the leases are kept in
            Recycle Bin until one week after expiry. If this is set to
            False, the leases are permanently deleted.
        server_association_type: The type of server that is going to
            serve the IPv6 DHCP range.
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_recycle_leases: Use flag for: recycle_leases
    """
    _infoblox_type = 'ipv6rangetemplate'
    _fields = ['cloud_api_compatible', 'comment', 'delegated_member',
               'exclude', 'logic_filter_rules', 'member', 'name',
               'number_of_addresses', 'offset', 'option_filter_rules',
               'recycle_leases', 'server_association_type',
               'use_logic_filter_rules', 'use_recycle_leases']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'member', 'name',
                                 'server_association_type']
    _all_searchable_fields = ['comment', 'member', 'name',
                              'server_association_type']
    _return_fields = ['comment', 'name', 'number_of_addresses', 'offset']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'exclude': Exclusionrangetemplate.from_dict,
        'logic_filter_rules': Logicfilterrule.from_dict,
        'option_filter_rules': Filterrule.from_dict,
    }


class SharedNetwork(InfobloxObject):
    @classmethod
    def get_v4_class(cls):
        return SharedNetworkV4

    @classmethod
    def get_v6_class(cls):
        return SharedNetworkV6


class SharedNetworkV4(SharedNetwork):
    """ SharedNetworkV4: DHCP Shared Network object.
    Corresponds to WAPI object 'sharednetwork'

    A shared network is a network segment to which you assign two or
    more subnets. When subnets in a shared network contain IP addresses
    that are available for dynamic allocation, the addresses are put
    into a common pool for allocation when client requests arise. When
    you create a shared network, the DHCP server can assign IP addresses
    to client requests from any subnet (that resides on the same network
    interface) in the shared network.

    Attributes:
        authority: Authority for the shared network.
        bootfile: The bootfile name for the shared network. You can
            configure the DHCP server to support clients that use the
            boot file name option in their DHCPREQUEST messages.
        bootserver: The bootserver address for the shared network. You
            can specify the name and/or IP address of the boot server
            that the host needs to boot.The boot server IPv4 Address or
            name in FQDN format.
        comment: Comment for the shared network, maximum 256 characters.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        ddns_server_always_updates: This field controls whether only the
            DHCP server is allowed to update DNS, regardless of the DHCP
            clients requests. Note that changes for this field take
            effect only if ddns_use_option81 is True.
        ddns_ttl: The DNS update Time to Live (TTL) value of a shared
            network object.The TTL is a 32-bit unsigned integer that
            represents the duration, in seconds, for which the update is
            cached. Zero indicates that the update is not cached.
        ddns_update_fixed_addresses: By default, the DHCP server does
            not update DNS when it allocates a fixed address to a
            client. You can configure the DHCP server to update the A
            and PTR records of a client with a fixed address. When this
            feature is enabled and the DHCP server adds A and PTR
            records for a fixed address, the DHCP server never discards
            the records.
        ddns_use_option81: The support for DHCP Option 81 at the shared
            network level.
        deny_bootp: If set to true, BOOTP settings are disabled and
            BOOTP requests will be denied.
        dhcp_utilization: The percentage of the total DHCP utilization
            of the networks belonging to the shared network multiplied
            by 1000. This is the percentage of the total number of
            available IP addresses from all the networks belonging to
            the shared network versus the total number of all IP
            addresses in all of the networks in the shared network.
        dhcp_utilization_status: A string describing the utilization
            level of the shared network.
        disable: Determines whether a shared network is disabled or not.
            When this is set to False, the shared network is enabled.
        dynamic_hosts: The total number of DHCP leases issued for the
            shared network.
        enable_ddns: The dynamic DNS updates flag of a shared network
            object. If set to True, the DHCP server sends DDNS updates
            to DNS servers in the same Grid, and to external DNS
            servers.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ignore_client_identifier: If set to true, the client identifier
            will be ignored.
        ignore_dhcp_option_list_request: If this field is set to False,
            the appliance returns all DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        ignore_id: Indicates whether the appliance will ignore DHCP
            client IDs or MAC addresses. Valid values are "NONE",
            "CLIENT", or "MACADDR". The default is "NONE".
        ignore_mac_addresses: A list of MAC addresses the appliance will
            ignore.
        lease_scavenge_time: An integer that specifies the period of
            time (in seconds) that frees and backs up leases remained in
            the database before they are automatically deleted. To
            disable lease scavenging, set the parameter to -1. The
            minimum positive value must be greater than 86400 seconds (1
            day).
        logic_filter_rules: This field contains the logic filters to be
            applied on the this shared network.This list corresponds to
            the match rules that are written to the dhcpd configuration
            file.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: The name of the IPv6 Shared Network.
        network_view: The name of the network view in which this shared
            network resides.
        networks: A list of networks belonging to the shared networkEach
            individual list item must be specified as an object
            containing a '_ref' parameter to a network reference, for
            example:if the reference of the wanted network is not known,
            it is possible to specify search parameters for the network
            instead in the following way:note that in this case the
            search must match exactly one network for the assignment to
            be successful.
        nextserver: The name in FQDN and/or IPv4 Address of the next
            server that the host needs to boot.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        pxe_lease_time: The PXE lease time value of a shared network
            object. Some hosts use PXE (Preboot Execution Environment)
            to boot remotely from a server. To better manage your IP
            resources, set a different lease time for PXE boot requests.
            You can configure the DHCP server to allocate an IP address
            with a shorter lease time to hosts that send PXE boot
            requests, so IP addresses are not leased longer than
            necessary.A 32-bit unsigned integer that represents the
            duration, in seconds, for which the update is cached. Zero
            indicates that the update is not cached.
        static_hosts: The number of static DHCP addresses configured in
            the shared network.
        total_hosts: The total number of DHCP addresses configured in
            the shared network.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_authority: Use flag for: authority
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_ddns_ttl: Use flag for: ddns_ttl
        use_ddns_update_fixed_addresses: Use flag for:
            ddns_update_fixed_addresses
        use_ddns_use_option81: Use flag for: ddns_use_option81
        use_deny_bootp: Use flag for: deny_bootp
        use_enable_ddns: Use flag for: enable_ddns
        use_ignore_client_identifier: Use flag for:
            ignore_client_identifier
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_ignore_id: Use flag for: ignore_id
        use_lease_scavenge_time: Use flag for: lease_scavenge_time
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_pxe_lease_time: Use flag for: pxe_lease_time
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
    """
    _infoblox_type = 'sharednetwork'
    _fields = ['authority', 'bootfile', 'bootserver', 'comment',
               'ddns_generate_hostname', 'ddns_server_always_updates',
               'ddns_ttl', 'ddns_update_fixed_addresses', 'ddns_use_option81',
               'deny_bootp', 'dhcp_utilization', 'dhcp_utilization_status',
               'disable', 'dynamic_hosts', 'enable_ddns',
               'enable_pxe_lease_time', 'extattrs', 'ignore_client_identifier',
               'ignore_dhcp_option_list_request', 'ignore_id',
               'ignore_mac_addresses', 'lease_scavenge_time',
               'logic_filter_rules', 'ms_ad_user_data', 'name', 'network_view',
               'networks', 'nextserver', 'options', 'pxe_lease_time',
               'static_hosts', 'total_hosts', 'update_dns_on_lease_renewal',
               'use_authority', 'use_bootfile', 'use_bootserver',
               'use_ddns_generate_hostname', 'use_ddns_ttl',
               'use_ddns_update_fixed_addresses', 'use_ddns_use_option81',
               'use_deny_bootp', 'use_enable_ddns',
               'use_ignore_client_identifier',
               'use_ignore_dhcp_option_list_request', 'use_ignore_id',
               'use_lease_scavenge_time', 'use_logic_filter_rules',
               'use_nextserver', 'use_options', 'use_pxe_lease_time',
               'use_update_dns_on_lease_renewal']
    _search_for_update_fields = ['name', 'network_view']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name', 'network_view']
    _return_fields = ['comment', 'extattrs', 'name', 'network_view',
                      'networks']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': DhcpOption.from_dict,
    }


class SharedNetworkV6(SharedNetwork):
    """ SharedNetworkV6: DHCP IPv6 Shared Network object.
    Corresponds to WAPI object 'ipv6sharednetwork'

    A shared network is a network segment to which you assign two or
    more subnets. When subnets in a shared network contain IP addresses
    that are available for dynamic allocation, the addresses are put
    into a common pool for allocation when client requests arise. When
    you create a shared network, the DHCP server can assign IP addresses
    to client requests from any subnet (that resides on the same network
    interface) in the shared network.

    Attributes:
        comment: Comment for the IPv6 shared network, maximum 256
            characters.
        ddns_domainname: The dynamic DNS domain name the appliance uses
            specifically for DDNS updates for this network.
        ddns_generate_hostname: If this field is set to True, the DHCP
            server generates a hostname and updates DNS with it when the
            DHCP client request does not contain a hostname.
        ddns_server_always_updates: This field controls whether only the
            DHCP server is allowed to update DNS, regardless of the DHCP
            clients requests. Note that changes for this field take
            effect only if ddns_use_option81 is True.
        ddns_ttl: The DNS update Time to Live (TTL) value of an IPv6
            shared network object.The TTL is a 32-bit unsigned integer
            that represents the duration, in seconds, for which the
            update is cached. Zero indicates that the update is not
            cached.
        ddns_use_option81: The support for DHCP Option 81 at the IPv6
            shared network level.
        disable: Determines whether an IPv6 shared network is disabled
            or not. When this is set to False, the IPv6 shared network
            is enabled.
        domain_name: Use this method to set or retrieve the domain_name
            value of a DHCP IPv6 Shared Network object.
        domain_name_servers: Use this method to set or retrieve the
            dynamic DNS updates flag of a DHCP IPv6 Shared Network
            object. The DHCP server can send DDNS updates to DNS servers
            in the same Grid and to external DNS servers. This setting
            overrides the member level settings.
        enable_ddns: The dynamic DNS updates flag of an IPv6 shared
            network object. If set to True, the DHCP server sends DDNS
            updates to DNS servers in the same Grid, and to external DNS
            servers.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        logic_filter_rules: This field contains the logic filters to be
            applied on the this IPv6 shared network.This list
            corresponds to the match rules that are written to the
            DHCPv6 configuration file.
        name: The name of the IPv6 Shared Network.
        network_view: The name of the network view in which this IPv6
            shared network resides.
        networks: A list of IPv6 networks belonging to the shared
            networkEach individual list item must be specified as an
            object containing a '_ref' parameter to a network reference,
            for example:if the reference of the wanted network is not
            known, it is possible to specify search parameters for the
            network instead in the following way:note that in this case
            the search must match exactly one network for the assignment
            to be successful.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        preferred_lifetime: Use this method to set or retrieve the
            preferred lifetime value of a DHCP IPv6 Shared Network
            object.
        update_dns_on_lease_renewal: This field controls whether the
            DHCP server updates DNS when a DHCP lease is renewed.
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_ddns_ttl: Use flag for: ddns_ttl
        use_ddns_use_option81: Use flag for: ddns_use_option81
        use_domain_name: Use flag for: domain_name
        use_domain_name_servers: Use flag for: domain_name_servers
        use_enable_ddns: Use flag for: enable_ddns
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_options: Use flag for: options
        use_preferred_lifetime: Use flag for: preferred_lifetime
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
        use_valid_lifetime: Use flag for: valid_lifetime
        valid_lifetime: Use this method to set or retrieve the valid
            lifetime value of a DHCP IPv6 Shared Network object.
    """
    _infoblox_type = 'ipv6sharednetwork'
    _fields = ['comment', 'ddns_domainname', 'ddns_generate_hostname',
               'ddns_server_always_updates', 'ddns_ttl', 'ddns_use_option81',
               'disable', 'domain_name', 'domain_name_servers', 'enable_ddns',
               'extattrs', 'logic_filter_rules', 'name', 'network_view',
               'networks', 'options', 'preferred_lifetime',
               'update_dns_on_lease_renewal', 'use_ddns_domainname',
               'use_ddns_generate_hostname', 'use_ddns_ttl',
               'use_ddns_use_option81', 'use_domain_name',
               'use_domain_name_servers', 'use_enable_ddns',
               'use_logic_filter_rules', 'use_options',
               'use_preferred_lifetime', 'use_update_dns_on_lease_renewal',
               'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['name', 'network_view']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name', 'network_view']
    _return_fields = ['comment', 'extattrs', 'name', 'network_view',
                      'networks']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': DhcpOption.from_dict,
    }


class Kerberoskey(InfobloxObject):
    """ Kerberoskey: Kerberos key object.
    Corresponds to WAPI object 'kerberoskey'

    GSS-TSIG (Generic Security Service Algorithm for Secret Key
    Transaction) is used to authenticate DDNS updates. It is a modified
    form of TSIG authentication that uses Kerberos v5 authentication
    system.

    You can configure the appliance to accept GSS-TSIG signed DDNS
    updates from a single client or multiple clients that belong to
    different AD domains in which each domain have a unique GSS-TSIG
    key. You can also configure the appliance to support one or multiple
    GSS-TSIG keys for each of Grid members.

    The Kerberos key object represents the GSS-TSIG key used to
    authenticate clients for GSS-TSIG signed DDNS updates.

    Attributes:
        domain: The Kerberos domain name.
        enctype: The Kerberos key encryption type.
        in_use: Determines whether the Kerberos key is assigned to the
            Grid or Grid member.
        members: The list of hostnames and services of Grid members
            where the key is assigned or Grid/DHCP4 or Grid/DHCP6 or
            Grid/DNS.
        principal: The principal of the Kerberos key object.
        upload_timestamp: The timestamp of the Kerberos key upload
            operation.
        version: The Kerberos key version number (KVNO).
    """
    _infoblox_type = 'kerberoskey'
    _fields = ['domain', 'enctype', 'in_use', 'members', 'principal',
               'upload_timestamp', 'version']
    _search_for_update_fields = ['domain', 'enctype', 'in_use', 'principal',
                                 'version']
    _updateable_search_fields = []
    _all_searchable_fields = ['domain', 'enctype', 'in_use', 'principal',
                              'version']
    _return_fields = ['domain', 'enctype', 'in_use', 'principal', 'version']
    _remap = {}
    _shadow_fields = ['_ref']


class LdapAuthService(InfobloxObject):
    """ LdapAuthService: The LDAP authentication service object.
    Corresponds to WAPI object 'ldap_auth_service'

    LDAP (Lightweight Directory Access Protocol) is an internet protocol
    for accessing distributed directory services. The appliance can
    authenticate admin accounts by verifying user names and passwords
    against LDAP. This object is used to configure the LDAP
    authentication service.

    Attributes:
        comment: The LDAP descriptive comment.
        disable: Determines if the LDAP authentication service is
            disabled.
        ea_mapping: The mapping LDAP fields to extensible attributes.
        ldap_group_attribute: The name of the LDAP attribute that
            defines group membership.
        ldap_group_authentication_type: The LDAP group authentication
            type.
        ldap_user_attribute: The LDAP userid attribute that is used for
            search.
        mode: The LDAP authentication mode.
        name: The LDAP authentication service name.
        recovery_interval: The period of time in seconds to wait before
            trying to contact a LDAP server that has been marked as
            'DOWN'.
        retries: The maximum number of LDAP authentication attempts.
        search_scope: The starting point of the LDAP search.
        servers: The list of LDAP servers used for authentication.
        timeout: The LDAP authentication timeout in seconds.
    """
    _infoblox_type = 'ldap_auth_service'
    _fields = ['comment', 'disable', 'ea_mapping', 'ldap_group_attribute',
               'ldap_group_authentication_type', 'ldap_user_attribute', 'mode',
               'name', 'recovery_interval', 'retries', 'search_scope',
               'servers', 'timeout']
    _search_for_update_fields = ['mode', 'name']
    _updateable_search_fields = ['comment', 'mode', 'name', 'search_scope']
    _all_searchable_fields = ['comment', 'mode', 'name', 'search_scope']
    _return_fields = ['comment', 'disable', 'ldap_user_attribute', 'mode',
                      'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ea_mapping': LdapEamapping.from_dict,
        'servers': LdapServer.from_dict,
    }

    def check_ldap_server_settings(self, *args, **kwargs):
        return self._call_func("check_ldap_server_settings", *args, **kwargs)


class DHCPLease(InfobloxObject):
    """ DHCPLease: DHCP Lease object.
    Corresponds to WAPI object 'lease'

    A DHCP lease is an IP address that the Infoblox appliance assigns to
    a DHCP client for a certain amount of time. When the appliance
    assigns a lease, it also assignes other information, such as the
    time when the appliance issued or freed an IP address, the MAC
    address and host name of the client that received the IP address,
    and the Grid member that supplied the lease.  The DHCP Lease object
    allows the appliance to store and correlate DHCP lease information
    over the lifetime of a lease.

    Note that deleting a lease object only clears the lease, it does not
    remove the actual object.

    Attributes:
        address: The IPv4 Address or IPv6 Address of the lease.
        billing_class: The billing_class value of a DHCP Lease object.
            This field specifies the class to which this lease is
            currently billed. This field is for IPv4 leases only.
        binding_state: The binding state for the current lease.
            Following are some of the values this field can be set to:
        client_hostname: The client_hostname of a DHCP Lease object.
            This field specifies the host name that the DHCP client
            sends to the Infoblox appliance using DHCP option 12.
        cltt: The CLTT (Client Last Transaction Time) value of a DHCP
            Lease object. This field specifies the time of the last
            transaction with the DHCP client for this lease.
        discovered_data: The discovered data for this lease.
        ends: The end time value of a DHCP Lease object. This field
            specifies the time when a lease ended.
        fingerprint: DHCP fingerprint for the lease.
        hardware: The hardware type of a DHCP Lease object. This field
            specifies the MAC address of the network interface on which
            the lease will be used. This field is for IPv4 leases only.
        ipv6_duid: The DUID value for this lease. This field is only
            applicable for IPv6 leases.
        ipv6_iaid: The interface ID of an IPv6 address that the Infoblox
            appliance leased to the DHCP client. This field is for IPv6
            leases only.
        ipv6_preferred_lifetime: The preferred lifetime value of an IPv6
            address that the Infoblox appliance leased to the DHCP
            client. This field is for IPv6 leases only.
        ipv6_prefix_bits: Prefix bits for this lease. This field is for
            IPv6 leases only.
        is_invalid_mac: This flag reflects whether the MAC address for
            this lease is invalid.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        network: The network, in "network/netmask" format, with which
            this lease is associated.
        network_view: The name of the network view in which this lease
            resides.
        never_ends: If this field is set to True, the lease does not
            have an end time.
        never_starts: If this field is set to True, the lease does not
            have a start time.
        next_binding_state: The subsequent binding state when the
            current lease expires. This field is for IPv4 leases only.
            Following are some of the values this field can be set to:
        on_commit: The list of commands to be executed when the lease is
            granted.
        on_expiry: The list of commands to be executed when the lease
            expires.
        on_release: The list of commands to be executed when the lease
            is released.
        option: The option value of a DHCP Lease object. This field
            specifies the agent circuit ID and remote ID sent by a DHCP
            relay agent in DHCP option 82. This field is for IPv4 leases
            only.
        protocol: This field determines whether the lease is an IPv4 or
            IPv6 address.
        remote_id: This field represents the "Remote ID" sub-option of
            DHCP option 82.Remote ID can be in ASCII form (e.g. "abcd")
            or in colon-separated HEX form (e.g. 1:2:ab:cd). HEX
            representation is used only when the sub-option value
            contains unprintable characters. If a remote ID sub-option
            value is in ASCII form, it is always enclosed in quotes to
            prevent ambiguous values (e.g. "10:20" - ASCII 5-byte
            string; 10:20 - HEX 2-byte value).NIOS does not support the
            convertion between HEX and ASCII formats. Searches are
            performed using the exact same format and value as the sub-
            option is represented.Query examples assume the following
            leases are stored in the database:Expected results:
        served_by: The IP address of the server that sends an active
            lease to a client.
        server_host_name: The host name of the Grid member or Microsoft
            DHCP server that issues the lease.
        starts: The start time of a DHCP Lease object. This field
            specifies the time when the lease starts.
        tsfp: The TSFP (Time Sent From Partner) value of a DHCP Lease
            object. This field specifies the time that the current lease
            state ends, from the point of view of a remote DHCP failover
            peer. This field is for IPv4 leases only.
        tstp: The TSTP (Time Sent To Partner) value of a DHCP Lease
            object. This field specifies the time that the current lease
            state ends, from the point of view of a local DHCP failover
            peer. This field is for IPv4 leases only.
        uid: The UID (User ID) value of a DHCP Lease object. This field
            specifies the client identifier that the DHCP client sends
            the Infoblox appliance (in DHCP option 61) when it acquires
            the lease. Not all DHCP clients send a UID. This field is
            for IPv4 leases only.
        username: The user name that the server has associated with a
            DHCP Lease object.
        variable: The variable value of a DHCP Lease object. This field
            keeps all variables related to the DDNS update of the DHCP
            lease. The variables related to the DDNS updates of the DHCP
            lease. The variables can be one of the following:ddns-text:
            The ddns-text variable is used to record the value of the
            client's TXT identification record when the interim DDNS
            update style has been used to update the DNS service for a
            particular lease.ddns-fwd-name: When a DDNS update was
            successfully completed, the ddns-fwd-name variable records
            the value of the name used when the client's A record was
            updated. The server may have used this name when it updated
            the client's PTR record.ddns-client-fqdn: If the server is
            configured to use the interim DDNS update style and is also
            configured to allow clients to update their own FQDNs, the
            ddns-client-fqdn variable records the name that the client
            used when it updated its own FQDN. This is also the name
            that the server used to update the client's PTR record.ddns-
            rev-name: If the server successfully updates the client's
            PTR record, this variable will record the name that the DHCP
            server used for the PTR record. The name to which the PTR
            record points will be either the ddns-fwd-name or the ddns-
            client-fqdn.
    """
    _infoblox_type = 'lease'
    _fields = ['address', 'billing_class', 'binding_state', 'client_hostname',
               'cltt', 'discovered_data', 'ends', 'fingerprint', 'hardware',
               'ipv6_duid', 'ipv6_iaid', 'ipv6_preferred_lifetime',
               'ipv6_prefix_bits', 'is_invalid_mac', 'ms_ad_user_data',
               'network', 'network_view', 'never_ends', 'never_starts',
               'next_binding_state', 'on_commit', 'on_expiry', 'on_release',
               'option', 'protocol', 'remote_id', 'served_by',
               'server_host_name', 'starts', 'tsfp', 'tstp', 'uid', 'username',
               'variable']
    _search_for_update_fields = ['address', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['address', 'client_hostname', 'fingerprint',
                              'hardware', 'ipv6_duid', 'ipv6_prefix_bits',
                              'network', 'network_view', 'protocol',
                              'remote_id', 'username']
    _return_fields = ['address', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']


class LicenseGridwide(InfobloxObject):
    """ LicenseGridwide: Gridwide license object.
    Corresponds to WAPI object 'license:gridwide'

    This object represents the Grid-wide license.

    Attributes:
        expiration_status: The license expiration status.
        expiry_date: The expiration timestamp of the license.
        key: The license string.
        limit: The license limit value.
        limit_context: The license limit context.
        type: The license type.
    """
    _infoblox_type = 'license:gridwide'
    _fields = ['expiration_status', 'expiry_date', 'key', 'limit',
               'limit_context', 'type']
    _search_for_update_fields = ['type']
    _updateable_search_fields = []
    _all_searchable_fields = ['key', 'limit', 'type']
    _return_fields = ['type']
    _remap = {}
    _shadow_fields = ['_ref']


class LocaluserAuthservice(InfobloxObject):
    """ LocaluserAuthservice: Local user authentication service object.
    Corresponds to WAPI object 'localuser:authservice'

    The object represents a local authentication service for
    authenticating users against the local database.

    Note that read by reference is not supported.

    Attributes:
        comment: The local user authentication service comment.
        disabled: Flag that indicates whether the local user
            authentication service is enabled or not.
        name: The name of the local user authentication service.
    """
    _infoblox_type = 'localuser:authservice'
    _fields = ['comment', 'disabled', 'name']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['comment', 'disabled', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Macfilteraddress(InfobloxObject):
    """ Macfilteraddress: MAC Filter Address object.
    Corresponds to WAPI object 'macfilteraddress'

    MAC filter address is part of the MAC filter.

    Attributes:
        authentication_time: The absolute UNIX time (in seconds) since
            the address was last authenticated.
        comment: Comment for the MAC filter address; maximum 256
            characters.
        expiration_time: The absolute UNIX time (in seconds) until the
            address expires.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        filter: Name of the MAC filter to which this address belongs.
        fingerprint: DHCP fingerprint for the address.
        guest_custom_field1: Guest custom field 1.
        guest_custom_field2: Guest custom field 2.
        guest_custom_field3: Guest custom field 3.
        guest_custom_field4: Guest custom field 4.
        guest_email: Guest e-mail.
        guest_first_name: Guest first name.
        guest_last_name: Guest last name.
        guest_middle_name: Guest middle name.
        guest_phone: Guest phone number.
        is_registered_user: Determines if the user has been
            authenticated or not.
        mac: MAC Address.
        never_expires: Determines if MAC address expiration is enabled
            or disabled.
        reserved_for_infoblox: Reserved for future use.
        username: Username for authenticated DHCP purposes.
    """
    _infoblox_type = 'macfilteraddress'
    _fields = ['authentication_time', 'comment', 'expiration_time', 'extattrs',
               'filter', 'fingerprint', 'guest_custom_field1',
               'guest_custom_field2', 'guest_custom_field3',
               'guest_custom_field4', 'guest_email', 'guest_first_name',
               'guest_last_name', 'guest_middle_name', 'guest_phone',
               'is_registered_user', 'mac', 'never_expires',
               'reserved_for_infoblox', 'username']
    _search_for_update_fields = ['authentication_time', 'expiration_time',
                                 'filter', 'guest_custom_field1',
                                 'guest_custom_field2', 'guest_custom_field3',
                                 'guest_custom_field4', 'guest_email',
                                 'guest_first_name', 'guest_last_name',
                                 'guest_middle_name', 'guest_phone', 'mac',
                                 'never_expires', 'reserved_for_infoblox',
                                 'username']
    _updateable_search_fields = ['authentication_time', 'comment',
                                 'expiration_time', 'filter',
                                 'guest_custom_field1', 'guest_custom_field2',
                                 'guest_custom_field3', 'guest_custom_field4',
                                 'guest_email', 'guest_first_name',
                                 'guest_last_name', 'guest_middle_name',
                                 'guest_phone', 'mac', 'never_expires',
                                 'reserved_for_infoblox', 'username']
    _all_searchable_fields = ['authentication_time', 'comment',
                              'expiration_time', 'filter', 'fingerprint',
                              'guest_custom_field1', 'guest_custom_field2',
                              'guest_custom_field3', 'guest_custom_field4',
                              'guest_email', 'guest_first_name',
                              'guest_last_name', 'guest_middle_name',
                              'guest_phone', 'mac', 'never_expires',
                              'reserved_for_infoblox', 'username']
    _return_fields = ['authentication_time', 'comment', 'expiration_time',
                      'extattrs', 'filter', 'guest_custom_field1',
                      'guest_custom_field2', 'guest_custom_field3',
                      'guest_custom_field4', 'guest_email', 'guest_first_name',
                      'guest_last_name', 'guest_middle_name', 'guest_phone',
                      'is_registered_user', 'mac', 'never_expires',
                      'reserved_for_infoblox', 'username']
    _remap = {}
    _shadow_fields = ['_ref']


class Mastergrid(InfobloxObject):
    """ Mastergrid: Master Grid object.
    Corresponds to WAPI object 'mastergrid'

    This object represents the Master Grid. The Master Grid object is
    automatically generated when a Grid successfully joins the Master
    Grid.

    Attributes:
        address: The domain name or IP address for the Master Grid.
        connection_disabled: Determines if the sub-grid is currently
            disabled.
        connection_timestamp: The timestamp that indicates when the
            connection to the Master Grid was established.
        detached: The detached flag for the Master Grid.
        enable: Determines if the Master Grid is enabled.
        joined: The flag shows if the Grid has joined the Master Grid.
        last_event: The Master Grid's last event.
        last_event_details: The details of the Master Grid's last event.
        last_sync_timestamp: The timestamp or the last synchronization
            operation with the Master Grid.
        port: The Master Grid port to which the Grid connects.
        status: The Master Grid's status.
        use_mgmt_port: The flag shows if the MGMT port was used to join
            the Grid.
    """
    _infoblox_type = 'mastergrid'
    _fields = ['address', 'connection_disabled', 'connection_timestamp',
               'detached', 'enable', 'joined', 'last_event',
               'last_event_details', 'last_sync_timestamp', 'port', 'status',
               'use_mgmt_port']
    _search_for_update_fields = ['address', 'port']
    _updateable_search_fields = ['address', 'port']
    _all_searchable_fields = ['address', 'port']
    _return_fields = ['address', 'enable', 'port']
    _remap = {}
    _shadow_fields = ['_ref']


class Member(InfobloxObject):
    """ Member: Member object.
    Corresponds to WAPI object 'member'

    This object represents the Infoblox Grid Member.

    Attributes:
        active_position: The active server of a Grid member.
        additional_ip_list: The additional IP list of a Grid member.
            This list contains additional interface information that can
            be used at the member level.Note that interface structure(s)
            with interface type set to 'MGMT' are not supported.
        automated_traffic_capture_setting: Member level settings for
            automated traffic capture.
        bgp_as: The BGP configuration for anycast for a Grid member.
        comment: A descriptive comment of the Grid member.
        config_addr_type: Address configuration type.
        csp_access_key: CSP portal on-prem host access key
        csp_member_setting: csp setting at member level
        dns_resolver_setting: DNS resolver setting for member.
        dscp: The DSCP (Differentiated Services Code Point) value.
        email_setting: The email setting for member.
        enable_ha: If set to True, the member has two physical nodes (HA
            pair).
        enable_lom: Determines if the LOM functionality is enabled or
            not.
        enable_member_redirect: Determines if the member will redirect
            GUI connections to the Grid Master or not.
        enable_ro_api_access: If set to True and the member object is a
            Grid Master Candidate, then read-only API access is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        external_syslog_backup_servers: The list of external syslog
            backup servers.
        external_syslog_server_enable: Determines if external syslog
            servers should be enabled.
        host_name: The host name of the Grid member.
        ipv6_setting: IPV6 setting for member.
        ipv6_static_routes: List of IPv6 static routes.
        is_dscp_capable: Determines if a Grid member supports DSCP
            (Differentiated Services Code Point).
        lan2_enabled: If this is set to "true", the LAN2 port is enabled
            as an independent port or as a port for failover purposes.
        lan2_port_setting: Settings for the Grid member LAN2 port if
            'lan2_enabled' is set to "true".
        lcd_input: Determines if the Liquid Crystal Display (LCD) input
            buttons on the front panel of the appliance are enabled or
            not.
        lom_network_config: The Network configurations for LOM.
        lom_users: The list of LOM users.
        master_candidate: Determines if a Grid member is a Grid Master
            Candidate or not. This flag enables the Grid member to
            assume the role of the Grid Master as a disaster recovery
            measure.
        member_service_communication: Configure communication type for
            various services.
        mgmt_port_setting: Settings for the member MGMT port.
        mmdb_ea_build_time: Extensible attributes Topology database
            build time.
        mmdb_geoip_build_time: GeoIP Topology database build time.
        nat_setting: NAT settings for the member.
        node_info: The node information list with detailed status report
            on the operations of the Grid Member.
        ntp_setting: The member Network Time Protocol (NTP) settings.
        ospf_list: The OSPF area configuration (for anycast) list for a
            Grid member.
        passive_ha_arp_enabled: The ARP protocol setting on the passive
            node of an HA pair. If you do not specify a value, the
            default value is "false". You can only set this value to
            "true" if the member is an HA pair.
        platform: Hardware Platform.
        pre_provisioning: Pre-provisioning information.
        preserve_if_owns_delegation: Set this flag to "true" to prevent
            the deletion of the member if any delegated object remains
            attached to it.
        remote_console_access_enable: If set to True, superuser admins
            can access the Infoblox CLI from a remote location using an
            SSH (Secure Shell) v2 client.
        router_id: Virutal router identifier. Provide this ID if
            "ha_enabled" is set to "true". This is a unique VRID number
            (from 1 to 255) for the local subnet.
        service_status: The service status list of a grid member.
        service_type_configuration: Configure all services to the given
            type.
        snmp_setting: The Grid Member SNMP settings.
        static_routes: List of static routes.
        support_access_enable: Determines if support access for the Grid
            member should be enabled.
        support_access_info: The information string for support access.
        syslog_proxy_setting: The Grid Member syslog proxy settings.
        syslog_servers: The list of external syslog servers.
        syslog_size: The maximum size for the syslog file expressed in
            megabytes.
        threshold_traps: Determines the list of threshold traps. The
            user can only change the values for each trap or remove
            traps.
        time_zone: The time zone of the Grid member. The UTC string that
            represents the time zone, such as "(UTC - 5:00) Eastern Time
            (US and Canada)".
        traffic_capture_auth_dns_setting: Grid level settings for
            enabling authoritative DNS latency thresholds for automated
            traffic capture.
        traffic_capture_chr_setting: Member level settings for enabling
            DNS cache hit ratio threshold for automated traffic capture.
        traffic_capture_qps_setting: Member level settings for enabling
            DNS query per second threshold for automated traffic
            capture.
        traffic_capture_rec_dns_setting: Grid level settings for
            enabling recursive DNS latency thresholds for automated
            traffic capture.
        traffic_capture_rec_queries_setting: Grid level settings for
            enabling count for concurrent outgoing recursive queries for
            automated traffic capture.
        trap_notifications: Determines configuration of the trap
            notifications.
        upgrade_group: The name of the upgrade group to which this Grid
            member belongs.
        use_automated_traffic_capture: This flag is the use flag for
            enabling automated traffic capture based on DNS cache ratio
            thresholds.
        use_dns_resolver_setting: Use flag for: dns_resolver_setting
        use_dscp: Use flag for: dscp
        use_email_setting: Use flag for: email_setting
        use_enable_lom: Use flag for: enable_lom
        use_enable_member_redirect: Use flag for: enable_member_redirect
        use_external_syslog_backup_servers: Use flag for:
            external_syslog_backup_servers
        use_lcd_input: Use flag for: lcd_input
        use_remote_console_access_enable: Use flag for:
            remote_console_access_enable
        use_snmp_setting: Use flag for: snmp_setting
        use_support_access_enable: Use flag for: support_access_enable
        use_syslog_proxy_setting: Use flag for:
            external_syslog_server_enable , syslog_servers,
            syslog_proxy_setting, syslog_size
        use_threshold_traps: Use flag for: threshold_traps
        use_time_zone: Use flag for: time_zone
        use_traffic_capture_auth_dns: This flag is the use flag for
            enabling automated traffic capture based on authorative DNS
            latency.
        use_traffic_capture_chr: This flag is the use flag for automated
            traffic capture settings at member level.
        use_traffic_capture_qps: This flag is the use flag for enabling
            automated traffic capture based on DNS querie per second
            thresholds.
        use_traffic_capture_rec_dns: This flag is the use flag for
            enabling automated traffic capture based on recursive DNS
            latency.
        use_traffic_capture_rec_queries: This flag is the use flag for
            enabling automated traffic capture based on outgoing
            recursive queries.
        use_trap_notifications: Use flag for: trap_notifications
        use_v4_vrrp: Specify "true" to use VRRPv4 or "false" to use
            VRRPv6.
        vip_setting: The network settings for the Grid member.
        vpn_mtu: The VPN maximum transmission unit (MTU).
    """
    _infoblox_type = 'member'
    _fields = ['active_position', 'additional_ip_list',
               'automated_traffic_capture_setting', 'bgp_as', 'comment',
               'config_addr_type', 'csp_access_key', 'csp_member_setting',
               'dns_resolver_setting', 'dscp', 'email_setting', 'enable_ha',
               'enable_lom', 'enable_member_redirect', 'enable_ro_api_access',
               'extattrs', 'external_syslog_backup_servers',
               'external_syslog_server_enable', 'host_name', 'ipv6_setting',
               'ipv6_static_routes', 'is_dscp_capable', 'lan2_enabled',
               'lan2_port_setting', 'lcd_input', 'lom_network_config',
               'lom_users', 'master_candidate', 'member_service_communication',
               'mgmt_port_setting', 'mmdb_ea_build_time',
               'mmdb_geoip_build_time', 'nat_setting', 'node_info',
               'ntp_setting', 'ospf_list', 'passive_ha_arp_enabled',
               'platform', 'pre_provisioning', 'preserve_if_owns_delegation',
               'remote_console_access_enable', 'router_id', 'service_status',
               'service_type_configuration', 'snmp_setting', 'static_routes',
               'support_access_enable', 'support_access_info',
               'syslog_proxy_setting', 'syslog_servers', 'syslog_size',
               'threshold_traps', 'time_zone',
               'traffic_capture_auth_dns_setting',
               'traffic_capture_chr_setting', 'traffic_capture_qps_setting',
               'traffic_capture_rec_dns_setting',
               'traffic_capture_rec_queries_setting', 'trap_notifications',
               'upgrade_group', 'use_automated_traffic_capture',
               'use_dns_resolver_setting', 'use_dscp', 'use_email_setting',
               'use_enable_lom', 'use_enable_member_redirect',
               'use_external_syslog_backup_servers', 'use_lcd_input',
               'use_remote_console_access_enable', 'use_snmp_setting',
               'use_support_access_enable', 'use_syslog_proxy_setting',
               'use_threshold_traps', 'use_time_zone',
               'use_traffic_capture_auth_dns', 'use_traffic_capture_chr',
               'use_traffic_capture_qps', 'use_traffic_capture_rec_dns',
               'use_traffic_capture_rec_queries', 'use_trap_notifications',
               'use_v4_vrrp', 'vip_setting', 'vpn_mtu', 'ipv4_address',
               'ipv6_address']
    _search_for_update_fields = ['config_addr_type', 'host_name', 'platform',
                                 'service_type_configuration', 'ipv4_address',
                                 'ipv6_address']
    _updateable_search_fields = ['comment', 'config_addr_type', 'enable_ha',
                                 'enable_ro_api_access', 'host_name',
                                 'master_candidate', 'platform',
                                 'preserve_if_owns_delegation', 'router_id',
                                 'service_type_configuration']
    _all_searchable_fields = ['comment', 'config_addr_type', 'enable_ha',
                              'enable_ro_api_access', 'host_name',
                              'master_candidate', 'platform',
                              'preserve_if_owns_delegation', 'router_id',
                              'service_type_configuration', 'ipv4_address',
                              'ipv6_address']
    _return_fields = ['config_addr_type', 'extattrs', 'host_name', 'platform',
                      'service_type_configuration']
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
    """ MemberDhcpproperties: Member DHCP properties object.
    Corresponds to WAPI object 'member:dhcpproperties'

    This object represents a subset of the Infoblox Member DHCP
    properties.

    Attributes:
        auth_server_group: The Authentication Server Group object
            associated with this member.
        authn_captive_portal: The captive portal responsible for
            authenticating this DHCP member.
        authn_captive_portal_authenticated_filter: The MAC filter
            representing the authenticated range.
        authn_captive_portal_enabled: The flag that controls if this
            DHCP member is enabled for captive portal authentication.
        authn_captive_portal_guest_filter: The MAC filter representing
            the guest range.
        authn_server_group_enabled: The flag that controls if this DHCP
            member can send authentication requests to an authentication
            server group.
        authority: The authority flag of a Grid member. This flag
            specifies if a DHCP server is authoritative for a domain.
        bootfile: The name of a file that DHCP clients need to boot.
            This setting overrides the Grid level setting.
        bootserver: The name of the server on which a boot file is
            stored. This setting overrides the Grid level setting.
        ddns_domainname: The member DDNS domain name value.
        ddns_generate_hostname: Determines the ability of a member DHCP
            server to generate a host name and update DNS with this host
            name when it receives a DHCP REQUEST message that does not
            include a host name.
        ddns_retry_interval: Determines the retry interval when the
            member DHCP server makes repeated attempts to send DDNS
            updates to a DNS server.
        ddns_server_always_updates: Determines that only the DHCP server
            is allowed to update DNS, regardless of the requests from
            the DHCP clients. This setting overrides the Grid level
            setting.
        ddns_ttl: The DDNS TTL (Dynamic DNS Time To Live) value
            specifies the number of seconds an IP address for the name
            is cached.
        ddns_update_fixed_addresses: Determines if the member DHCP
            server's ability to update the A and PTR records with a
            fixed address is enabled or not.
        ddns_use_option81: Determines if support for option 81 is
            enabled or not.
        ddns_zone_primaries: An ordered list of zone primaries that will
            receive DDNS updates.
        deny_bootp: Determines if a BOOTP server denies BOOTP request or
            not. This setting overrides the Grid level setting.
        dhcp_utilization: The percentage of the total DHCP utilization
            of DHCP objects belonging to the Grid Member multiplied by
            1000. This is the percentage of the total number of
            available IP addresses from all the DHCP objects belonging
            to the Grid Member versus the total number of all IP
            addresses in all of the DHCP objects on the Grid Member.
        dhcp_utilization_status: A string describing the utilization
            level of DHCP objects that belong to the Grid Member.
        dns_update_style: The update style for dynamic DNS updates.
        dynamic_hosts: The total number of DHCP leases issued for the
            DHCP objects on the Grid Member.
        email_list: The email_list value of a member DHCP server.
        enable_ddns: Determines if the member DHCP server's ability to
            send DDNS updates is enabled or not.
        enable_dhcp: Determines if the DHCP service of a member is
            enabled or not.
        enable_dhcp_on_ipv6_lan2: Determines if the DHCP service on the
            IPv6 LAN2 interface is enabled or not.
        enable_dhcp_on_lan2: Determines if the DHCP service on the LAN2
            interface is enabled or not.
        enable_dhcp_thresholds: Represents the watermarks above or below
            which address usage in a network is unexpected and might
            warrant your attention. This setting overrides the Grid
            level setting.
        enable_dhcpv6_service: Determines if DHCPv6 service for the
            member is enabled or not.
        enable_email_warnings: Determines if e-mail warnings are enabled
            or disabled. When DHCP threshold is enabled and DHCP address
            usage crosses a watermark threshold, the appliance sends an
            e-mail notification to an administrator.
        enable_fingerprint: Determines if fingerprint feature is enabled
            on this member. If you enable this feature, the server will
            match a fingerprint for incoming lease requests.
        enable_gss_tsig: Determines whether the appliance is enabled to
            receive GSS-TSIG authenticated updates from DHCP clients.
        enable_hostname_rewrite: Determines if the Grid member's host
            name rewrite feature is enabled or not.
        enable_leasequery: Determines if lease query is allowed or not.
            This setting overrides the Grid-level setting.
        enable_snmp_warnings: Determines if SNMP warnings are enabled or
            disabled on this DHCP member. When DHCP threshold is enabled
            and DHCP address usage crosses a watermark threshold, the
            appliance sends an SNMP trap to the trap receiver that was
            defined for the Grid member level.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        gss_tsig_keys: The list of GSS-TSIG keys for a member DHCP
            object.
        high_water_mark: Determines the high watermark value of a member
            DHCP server. If the percentage of allocated addresses
            exceeds this watermark, the appliance makes a syslog entry
            and sends an e-mail notification (if enabled).Specifies the
            percentage of allocated addresses. The range is from 1 to
            100.
        high_water_mark_reset: Determines the high watermark reset value
            of a member DHCP server. If the percentage of allocated
            addresses drops below this value, a corresponding SNMP trap
            is reset.Specifies the percentage of allocated addresses.
            The range is from 1 to 100. The high watermark reset value
            must be lower than the high watermark value.
        host_name: Host name of the Grid member.
        hostname_rewrite_policy: The hostname rewrite policy that is in
            the protocol hostname rewrite policies array of the Grid
            DHCP object. This attribute is mandatory if
            enable_hostname_rewrite is "true".
        ignore_dhcp_option_list_request: Determines if the ignore DHCP
            option list request flag of a Grid member DHCP is enabled or
            not. If this flag is set to true all available DHCP options
            will be returned to the client.
        ignore_id: Indicates whether the appliance will ignore DHCP
            client IDs or MAC addresses. Valid values are "NONE",
            "CLIENT", or "MACADDR". The default is "NONE".
        ignore_mac_addresses: A list of MAC addresses the appliance will
            ignore.
        immediate_fa_configuration: Determines if the Immediate Fixed
            address configuration apply feature for the DHCP member is
            enabled or not.
        ipv4addr: The IPv4 Address of the Grid member.
        ipv6_ddns_domainname: The member DDNS IPv6 domain name value.
        ipv6_ddns_enable_option_fqdn: Controls whether the FQDN option
            sent by the DHCPv6 client is to be used, or if the server
            can automatically generate the FQDN.
        ipv6_ddns_hostname: The member IPv6 DDNS hostname value.
        ipv6_ddns_server_always_updates: Determines if the server always
            updates DNS or updates only if requested by the client.
        ipv6_ddns_ttl: The member IPv6 DDNS TTL value.
        ipv6_dns_update_style: The update style for dynamic DHCPv6 DNS
            updates.
        ipv6_domain_name: The IPv6 domain name.
        ipv6_domain_name_servers: The comma separated list of domain
            name server addresses in IPv6 address format.
        ipv6_enable_ddns: Determines if sending DDNS updates by the
            member DHCPv6 server is enabled or not.
        ipv6_enable_gss_tsig: Determines whether the appliance is
            enabled to receive GSS-TSIG authenticated updates from
            DHCPv6 clients.
        ipv6_enable_lease_scavenging: Indicates whether DHCPv6 lease
            scavenging is enabled or disabled.
        ipv6_enable_retry_updates: Determines if the DHCPv6 server
            retries failed dynamic DNS updates or not.
        ipv6_generate_hostname: Determines if the server generates the
            hostname if it is not sent by the client.
        ipv6_gss_tsig_keys: The list of GSS-TSIG keys for a member
            DHCPv6 object.
        ipv6_kdc_server: Determines the IPv6 address or FQDN of the
            Kerberos server for DHCPv6 GSS-TSIG authentication. This
            setting overrides the Grid level setting.
        ipv6_lease_scavenging_time: The member-level grace period (in
            seconds) to keep an expired lease before it is deleted by
            the scavenging process.
        ipv6_microsoft_code_page: The Microsoft client DHCP IPv6 code
            page value of a Grid member. This value is the hostname
            translation code page for Microsoft DHCP IPv6 clients and
            overrides the Grid level Microsoft DHCP IPv6 client code
            page.
        ipv6_options: An array of DHCP option structs that lists the
            DHCPv6 options associated with the object.
        ipv6_recycle_leases: Determines if the IPv6 recycle leases
            feature is enabled or not. If the feature is enabled, leases
            are kept in the Recycle Bin until one week after lease
            expiration. When the feature is disabled, the leases are
            irrecoverably deleted.
        ipv6_remember_expired_client_association: Enable binding for
            expired DHCPv6 leases.
        ipv6_retry_updates_interval: Determines the retry interval when
            the member DHCPv6 server makes repeated attempts to send
            DDNS updates to a DNS server.
        ipv6_server_duid: The server DHCPv6 unique identifier (DUID) for
            the Grid member.
        ipv6_update_dns_on_lease_renewal: Controls whether the DHCPv6
            server updates DNS when an IPv6 DHCP lease is renewed.
        ipv6addr: The IPv6 Address of the Grid member.
        kdc_server: The IPv4 address or FQDN of the Kerberos server for
            DHCPv4 GSS-TSIG authentication. This setting overrides the
            Grid level setting.
        lease_per_client_settings: Defines how the appliance releases
            DHCP leases. Valid values are "RELEASE_MACHING_ID",
            "NEVER_RELEASE", or "ONE_LEASE_PER_CLIENT". The default is
            "RELEASE_MATCHING_ID".
        lease_scavenge_time: Determines the lease scavenging time value.
            When this field is set, the appliance permanently deletes
            the free and backup leases that remain in the database
            beyond a specified period of time.To disable lease
            scavenging, set the parameter to -1. The minimum positive
            value must be greater than 86400 seconds (1 day).
        log_lease_events: This value specifies whether the grid member
            logs lease events. This setting overrides the Grid level
            setting.
        logic_filter_rules: This field contains the logic filters to be
            applied on the Grid member.This list corresponds to the
            match rules that are written to the dhcpd configuration
            file.
        low_water_mark: Determines the low watermark value. If the
            percent of allocated addresses drops below this watermark,
            the appliance makes a syslog entry and sends an e-mail
            notification (if enabled).
        low_water_mark_reset: Determines the low watermark reset value.
            If the percentage of allocated addresses exceeds this value,
            a corresponding SNMP trap is reset.A number that specifies
            the percentage of allocated addresses. The range is from 1
            to 100. The low watermark reset value must be higher than
            the low watermark value.
        microsoft_code_page: The Microsoft client DHCP IPv4 code page
            value of a grid member. This value is the hostname
            translation code page for Microsoft DHCP IPv4 clients and
            overrides the Grid level Microsoft DHCP IPv4 client code
            page.
        nextserver: The next server value of a member DHCP server. This
            value is the IP address or name of the boot file server on
            which the boot file is stored.
        option60_match_rules: The list of option 60 match rules.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        ping_count: Specifies the number of pings that the Infoblox
            appliance sends to an IP address to verify that it is not in
            use. Values are from 0 to 10, where 0 disables pings.
        ping_timeout: Indicates the number of milliseconds the appliance
            waits for a response to its ping.Valid values are 100, 500,
            1000, 2000, 3000, 4000 and 5000 milliseconds.
        preferred_lifetime: The preferred lifetime value.
        prefix_length_mode: The Prefix length mode for DHCPv6.
        pxe_lease_time: Specifies the duration of time it takes a host
            to connect to a boot server, such as a TFTP server, and
            download the file it needs to boot.A 32-bit unsigned integer
            that represents the duration, in seconds, for which the
            update is cached. Zero indicates that the update is not
            cached.
        recycle_leases: Determines if the recycle leases feature is
            enabled or not. If you enabled this feature and then delete
            a DHCP range, the appliance stores active leases from this
            range up to one week after the leases expires.
        retry_ddns_updates: Indicates whether the DHCP server makes
            repeated attempts to send DDNS updates to a DNS server.
        static_hosts: The number of static DHCP addresses configured in
            DHCP objects that belong to the Grid Member.
        syslog_facility: The syslog facility is the location on the
            syslog server to which you want to sort the syslog messages.
        total_hosts: The total number of DHCP addresses configured in
            DHCP objects that belong to the Grid Member.
        update_dns_on_lease_renewal: Controls whether the DHCP server
            updates DNS when a DHCP lease is renewed.
        use_authority: Use flag for: authority
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_ddns_domainname: Use flag for: ddns_domainname
        use_ddns_generate_hostname: Use flag for: ddns_generate_hostname
        use_ddns_ttl: Use flag for: ddns_ttl
        use_ddns_update_fixed_addresses: Use flag for:
            ddns_update_fixed_addresses
        use_ddns_use_option81: Use flag for: ddns_use_option81
        use_deny_bootp: Use flag for: deny_bootp
        use_dns_update_style: Use flag for: dns_update_style
        use_email_list: Use flag for: email_list
        use_enable_ddns: Use flag for: enable_ddns
        use_enable_dhcp_thresholds: Use flag for: enable_dhcp_thresholds
            , high_water_mark, high_water_mark_reset, low_water_mark,
            low_water_mark_reset
        use_enable_fingerprint: Use flag for: enable_fingerprint
        use_enable_gss_tsig: Use flag for: kdc_server , enable_gss_tsig
        use_enable_hostname_rewrite: Use flag for:
            enable_hostname_rewrite , hostname_rewrite_policy
        use_enable_leasequery: Use flag for: enable_leasequery
        use_enable_one_lease_per_client: Use flag for:
            enable_one_lease_per_client
        use_gss_tsig_keys: Use flag for: gss_tsig_keys
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_ignore_id: Use flag for: ignore_id
        use_immediate_fa_configuration: Use flag for:
            immediate_fa_configuration
        use_ipv6_ddns_domainname: Use flag for: ipv6_ddns_domainname
        use_ipv6_ddns_enable_option_fqdn: Use flag for:
            ipv6_ddns_enable_option_fqdn
        use_ipv6_ddns_hostname: Use flag for: ipv6_ddns_hostname
        use_ipv6_ddns_ttl: Use flag for: ipv6_ddns_ttl
        use_ipv6_dns_update_style: Use flag for: ipv6_dns_update_style
        use_ipv6_domain_name: Use flag for: ipv6_domain_name
        use_ipv6_domain_name_servers: Use flag for:
            ipv6_domain_name_servers
        use_ipv6_enable_ddns: Use flag for: ipv6_enable_ddns
        use_ipv6_enable_gss_tsig: Use flag for: ipv6_kdc_server ,
            ipv6_enable_gss_tsig
        use_ipv6_enable_retry_updates: Use flag for:
            ipv6_enable_retry_updates , ipv6_retry_updates_interval
        use_ipv6_generate_hostname: Use flag for: ipv6_generate_hostname
        use_ipv6_gss_tsig_keys: Use flag for: ipv6_gss_tsig_keys
        use_ipv6_lease_scavenging: Use flag for:
            ipv6_enable_lease_scavenging , ipv6_lease_scavenging_time,
            ipv6_remember_expired_client_association
        use_ipv6_microsoft_code_page: Use flag for:
            ipv6_microsoft_code_page
        use_ipv6_options: Use flag for: ipv6_options
        use_ipv6_recycle_leases: Use flag for: ipv6_recycle_leases
        use_ipv6_update_dns_on_lease_renewal: Use flag for:
            ipv6_update_dns_on_lease_renewal
        use_lease_per_client_settings: Use flag for:
            lease_per_client_settings
        use_lease_scavenge_time: Use flag for: lease_scavenge_time
        use_log_lease_events: Use flag for: log_lease_events
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_microsoft_code_page: Use flag for: microsoft_code_page
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_ping_count: Use flag for: ping_count
        use_ping_timeout: Use flag for: ping_timeout
        use_preferred_lifetime: Use flag for: preferred_lifetime
        use_prefix_length_mode: Use flag for: prefix_length_mode
        use_pxe_lease_time: Use flag for: pxe_lease_time
        use_recycle_leases: Use flag for: recycle_leases
        use_retry_ddns_updates: Use flag for: ddns_retry_interval ,
            retry_ddns_updates
        use_syslog_facility: Use flag for: syslog_facility
        use_update_dns_on_lease_renewal: Use flag for:
            update_dns_on_lease_renewal
        use_valid_lifetime: Use flag for: valid_lifetime
        valid_lifetime: The valid lifetime for Grid Member DHCP.
            Specifies the length of time addresses that are assigned to
            DHCPv6 clients remain in the valid state.
    """
    _infoblox_type = 'member:dhcpproperties'
    _fields = ['auth_server_group', 'authn_captive_portal',
               'authn_captive_portal_authenticated_filter',
               'authn_captive_portal_enabled',
               'authn_captive_portal_guest_filter',
               'authn_server_group_enabled', 'authority', 'bootfile',
               'bootserver', 'ddns_domainname', 'ddns_generate_hostname',
               'ddns_retry_interval', 'ddns_server_always_updates', 'ddns_ttl',
               'ddns_update_fixed_addresses', 'ddns_use_option81',
               'ddns_zone_primaries', 'deny_bootp', 'dhcp_utilization',
               'dhcp_utilization_status', 'dns_update_style', 'dynamic_hosts',
               'email_list', 'enable_ddns', 'enable_dhcp',
               'enable_dhcp_on_ipv6_lan2', 'enable_dhcp_on_lan2',
               'enable_dhcp_thresholds', 'enable_dhcpv6_service',
               'enable_email_warnings', 'enable_fingerprint',
               'enable_gss_tsig', 'enable_hostname_rewrite',
               'enable_leasequery', 'enable_snmp_warnings', 'extattrs',
               'gss_tsig_keys', 'high_water_mark', 'high_water_mark_reset',
               'host_name', 'hostname_rewrite_policy',
               'ignore_dhcp_option_list_request', 'ignore_id',
               'ignore_mac_addresses', 'immediate_fa_configuration',
               'ipv4addr', 'ipv6_ddns_domainname',
               'ipv6_ddns_enable_option_fqdn', 'ipv6_ddns_hostname',
               'ipv6_ddns_server_always_updates', 'ipv6_ddns_ttl',
               'ipv6_dns_update_style', 'ipv6_domain_name',
               'ipv6_domain_name_servers', 'ipv6_enable_ddns',
               'ipv6_enable_gss_tsig', 'ipv6_enable_lease_scavenging',
               'ipv6_enable_retry_updates', 'ipv6_generate_hostname',
               'ipv6_gss_tsig_keys', 'ipv6_kdc_server',
               'ipv6_lease_scavenging_time', 'ipv6_microsoft_code_page',
               'ipv6_options', 'ipv6_recycle_leases',
               'ipv6_remember_expired_client_association',
               'ipv6_retry_updates_interval', 'ipv6_server_duid',
               'ipv6_update_dns_on_lease_renewal', 'ipv6addr', 'kdc_server',
               'lease_per_client_settings', 'lease_scavenge_time',
               'log_lease_events', 'logic_filter_rules', 'low_water_mark',
               'low_water_mark_reset', 'microsoft_code_page', 'nextserver',
               'option60_match_rules', 'options', 'ping_count', 'ping_timeout',
               'preferred_lifetime', 'prefix_length_mode', 'pxe_lease_time',
               'recycle_leases', 'retry_ddns_updates', 'static_hosts',
               'syslog_facility', 'total_hosts', 'update_dns_on_lease_renewal',
               'use_authority', 'use_bootfile', 'use_bootserver',
               'use_ddns_domainname', 'use_ddns_generate_hostname',
               'use_ddns_ttl', 'use_ddns_update_fixed_addresses',
               'use_ddns_use_option81', 'use_deny_bootp',
               'use_dns_update_style', 'use_email_list', 'use_enable_ddns',
               'use_enable_dhcp_thresholds', 'use_enable_fingerprint',
               'use_enable_gss_tsig', 'use_enable_hostname_rewrite',
               'use_enable_leasequery', 'use_enable_one_lease_per_client',
               'use_gss_tsig_keys', 'use_ignore_dhcp_option_list_request',
               'use_ignore_id', 'use_immediate_fa_configuration',
               'use_ipv6_ddns_domainname', 'use_ipv6_ddns_enable_option_fqdn',
               'use_ipv6_ddns_hostname', 'use_ipv6_ddns_ttl',
               'use_ipv6_dns_update_style', 'use_ipv6_domain_name',
               'use_ipv6_domain_name_servers', 'use_ipv6_enable_ddns',
               'use_ipv6_enable_gss_tsig', 'use_ipv6_enable_retry_updates',
               'use_ipv6_generate_hostname', 'use_ipv6_gss_tsig_keys',
               'use_ipv6_lease_scavenging', 'use_ipv6_microsoft_code_page',
               'use_ipv6_options', 'use_ipv6_recycle_leases',
               'use_ipv6_update_dns_on_lease_renewal',
               'use_lease_per_client_settings', 'use_lease_scavenge_time',
               'use_log_lease_events', 'use_logic_filter_rules',
               'use_microsoft_code_page', 'use_nextserver', 'use_options',
               'use_ping_count', 'use_ping_timeout', 'use_preferred_lifetime',
               'use_prefix_length_mode', 'use_pxe_lease_time',
               'use_recycle_leases', 'use_retry_ddns_updates',
               'use_syslog_facility', 'use_update_dns_on_lease_renewal',
               'use_valid_lifetime', 'valid_lifetime']
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
        'ipv6_options': DhcpOption.from_dict,
        'logic_filter_rules': Logicfilterrule.from_dict,
        'option60_match_rules': Option60Matchrule.from_dict,
        'options': DhcpOption.from_dict,
    }

    def clear_nac_auth_cache(self, *args, **kwargs):
        return self._call_func("clear_nac_auth_cache", *args, **kwargs)

    def purge_ifmap_data(self, *args, **kwargs):
        return self._call_func("purge_ifmap_data", *args, **kwargs)


class MemberDns(InfobloxObject):
    """ MemberDns: Member DNS object.
    Corresponds to WAPI object 'member:dns'

    The Grid Member DNS object can be used to configure DNS properties
    for a Grid member, including enabling or disabling DNS services and
    other DNS service related parameters. Grid service configurations
    are inherited by all members.

    Attributes:
        add_client_ip_mac_options: Add custom IP, MAC and DNS View name
            ENDS0 options to outgoing recursive queries.
        additional_ip_list: The list of additional IP addresses on which
            DNS is enabled for a Grid member. Only one of
            "additional_ip_list" or "additional_ip_list_struct" should
            be set when modifying the object.
        additional_ip_list_struct: The list of additional IP addresses
            and IP Space Discriminator short names on which DNS is
            enabled for a Grid member. Only one of "additional_ip_list"
            or "additional_ip_list_struct" should be set when modifying
            the object.
        allow_gss_tsig_zone_updates: Determines whether the GSS-TSIG
            zone updates is enabled for the Grid member.
        allow_query: Determines if queries from specified IPv4 or IPv6
            addresses and networks are enabled or not. The appliance can
            also use Transaction Signature (TSIG) keys to authenticate
            the queries. This setting overrides the Grid query settings.
        allow_recursive_query: Determines if the responses to recursive
            queries is enabled or not. This setting overrides Grid
            recursive query settings.
        allow_transfer: Allows or rejects zone transfers from specified
            IPv4 or IPv6 addresses and networks or allows transfers from
            hosts authenticated by Transaction signature (TSIG) key.
            This setting overrides the Grid zone transfer settings.
        allow_update: Allows or rejects dynamic updates from specified
            IPv4 or IPv6 addresses, networks or from host authenticated
            by TSIG key. This setting overrides Grid update settings.
        anonymize_response_logging: The flag that indicates whether the
            anonymization of captured DNS responses is enabled or
            disabled.
        atc_fwd_enable: Enable DNS recursive query forwarding to Active
            Trust Cloud.
        attack_mitigation: Mitigation settings for DNS attacks.
        auto_blackhole: The auto blackhole settings.
        auto_create_a_and_ptr_for_lan2: Determines if the auto-
            generation of A and PTR records for the LAN2 IP address is
            enabled or not, if DNS service is enabled on LAN2.
        auto_create_aaaa_and_ipv6ptr_for_lan2: Determines if auto-
            generation of AAAA and IPv6 PTR records for LAN2 IPv6
            address is enabled or not.
        auto_sort_views: Determines if a Grid member to automatically
            sort DNS views is enabled or not. The order of the DNS views
            determines the order in which the appliance checks the match
            lists.
        bind_check_names_policy: The BIND check names policy, which
            indicates the action the appliance takes when it encounters
            host names that do not comply with the Strict Hostname
            Checking policy. This method applies only if the host name
            restriction policy is set to 'Strict Hostname Checking'.
        bind_hostname_directive: The value of the hostname directive for
            BIND.
        bind_hostname_directive_fqdn: The value of the user-defined
            hostname directive for BIND. To enable user-defined hostname
            directive, you must set the bind_hostname_directive to
            "USER_DEFINED".
        blackhole_list: The list of IPv4 or IPv6 addresses and networks
            from which DNS queries are blocked. This setting overrides
            the Grid blackhole_list.
        blacklist_action: The action to perform when a domain name
            matches the pattern defined in a rule that is specified by
            the blacklist_ruleset method.
        blacklist_log_query: Determines if blacklist redirection queries
            are logged or not.
        blacklist_redirect_addresses: The IP addresses the appliance
            includes in the response it sends in place of a blacklisted
            IP address.
        blacklist_redirect_ttl: The TTL value of the synthetic DNS
            responses that result from blacklist redirection.
        blacklist_rulesets: The DNS Ruleset object names assigned at the
            Grid level for blacklist redirection.
        capture_dns_queries_on_all_domains: The flag that indicates
            whether the capture of DNS queries for all domains is
            enabled or disabled.
        check_names_for_ddns_and_zone_transfer: Determines whether the
            application of BIND check-names for zone transfers and DDNS
            updates are enabled.
        copy_client_ip_mac_options: Copy custom IP, MAC and DNS View
            name ENDS0 options from incoming to outgoing recursive
            queries.
        copy_xfer_to_notify: Copies the allowed IPs from the zone
            transfer list into the also-notify statement in the
            named.conf file.
        custom_root_name_servers: The list of custom root name servers.
            You can either select and use Internet root name servers or
            specify custom root name servers by providing a host name
            and IP address to which the Infoblox appliance can send
            queries.
        disable_edns: The EDNS0 support for queries that require
            recursive resolution on Grid members.
        dns64_groups: The list of DNS64 synthesis groups associated with
            this member.
        dns_cache_acceleration_status: The DNS cache acceleration
            status.
        dns_cache_acceleration_ttl: The minimum TTL value, in seconds,
            that a DNS record must have in order for it to be cached by
            the DNS Cache Acceleration service.An integer from 1 to
            65000 that represents the TTL in seconds.
        dns_health_check_anycast_control: The flag that indicates
            whether the anycast failure (BFD session down) is enabled on
            member failure or not.
        dns_health_check_domain_list: The list of domain names for the
            DNS health check.
        dns_health_check_interval: The time interval (in seconds) for
            DNS health check.
        dns_health_check_recursion_flag: The flag that indicates whether
            the recursive DNS health check is enabled or not.
        dns_health_check_retries: The number of DNS health check
            retries.
        dns_health_check_timeout: The DNS health check timeout interval
            (in seconds).
        dns_notify_transfer_source: Determines which IP address is used
            as the source for DDNS notify and transfer operations.
        dns_notify_transfer_source_address: The source address used if
            dns_notify_transfer_source type is "IP".
        dns_over_tls_service: Enables DNS over TLS service.
        dns_query_capture_file_time_limit: The time limit (in minutes)
            for the DNS query capture file.
        dns_query_source_address: The source address used if
            dns_query_source_interface type is "IP".
        dns_query_source_interface: Determines which IP address is used
            as the source for DDNS query operations.
        dns_view_address_settings: Array of notify/query source settings
            for views.
        dnssec_blacklist_enabled: Determines if the blacklist rules for
            DNSSEC-enabled clients are enabled or not.
        dnssec_dns64_enabled: Determines if the DNS64 groups for DNSSEC-
            enabled clients are enabled or not.
        dnssec_enabled: Determines if the DNS security extension is
            enabled or not.
        dnssec_expired_signatures_enabled: Determines when the DNS
            member accepts expired signatures.
        dnssec_negative_trust_anchors: A list of zones for which the
            server does not perform DNSSEC validation.
        dnssec_nxdomain_enabled: Determines if the NXDOMAIN rules for
            DNSSEC-enabled clients are enabled or not.
        dnssec_rpz_enabled: Determines if the RPZ policies for DNSSEC-
            enabled clients are enabled or not.
        dnssec_trusted_keys: The list of trusted keys for the DNSSEC
            feature.
        dnssec_validation_enabled: Determines if the DNS security
            validation is enabled or not.
        dnstap_setting: The DNSTAP settings.
        doh_https_session_duration: DNS over HTTPS sessions duration.
        doh_service: Enables DNS over HTTPS service.
        domains_to_capture_dns_queries: The list of domains for DNS
            query capture.
        dtc_dns_queries_specific_behavior: Setting to control specific
            behavior for DTC DNS responses for incoming lbdn matched
            queries.
        dtc_edns_prefer_client_subnet: Determines whether to prefer the
            client address from the edns-client-subnet option for DTC or
            not.
        dtc_health_source: The health check source type.
        dtc_health_source_address: The source address used if
            dtc_health_source type is "IP".
        edns_udp_size: Advertises the EDNS0 buffer size to the upstream
            server. The value should be between 512 and 4096 bytes. The
            recommended value is between 512 and 1220 bytes.
        enable_blackhole: Determines if the blocking of DNS queries is
            enabled or not. This setting overrides the Grid
            enable_blackhole settings.
        enable_blacklist: Determines if a blacklist is enabled or not on
            the Grid member.
        enable_capture_dns_queries: The flag that indicates whether the
            capture of DNS queries is enabled or disabled.
        enable_capture_dns_responses: The flag that indicates whether
            the capture of DNS responses is enabled or disabled.
        enable_dns: Determines if the DNS service of a member is enabled
            or not.
        enable_dns64: Determines if the DNS64 support is enabled or not
            for this member.
        enable_dns_cache_acceleration: Determines if the DNS Cache
            Acceleration service is enabled or not for a member.
        enable_dns_health_check: The flag that indicates whether the DNS
            health check is enabled or not.
        enable_dnstap_queries: Determines whether the query messages
            need to be forwarded to DNSTAP or not.
        enable_dnstap_responses: Determines whether the response
            messages need to be forwarded to DNSTAP or not.
        enable_excluded_domain_names: The flag that indicates whether
            excluding domain names from captured DNS queries and
            responses is enabled or disabled.
        enable_fixed_rrset_order_fqdns: Determines if the fixed RRset
            order FQDN is enabled or not.
        enable_ftc: Determines whether Fault Tolerant Caching (FTC) is
            enabled.
        enable_gss_tsig: Determines whether the appliance is enabled to
            receive GSS-TSIG authenticated updates from DHCP clients.
        enable_notify_source_port: Determines if the notify source port
            for a member is enabled or not.
        enable_query_rewrite: Determines if the DNS query rewrite is
            enabled or not for this member.
        enable_query_source_port: Determines if the query source port
            for a memer is enabled or not.
        excluded_domain_names: The list of domains that are excluded
            from DNS query and response capture.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        file_transfer_setting: The DNS capture file transfer settings.
            Include the specified parameter to set the attribute value.
            Omit the parameter to retrieve the attribute value.
        filter_aaaa: The type of AAAA filtering for this member DNS
            object.
        filter_aaaa_list: The list of IPv4 addresses and networks from
            which queries are received. AAAA filtering is applied to
            these addresses.
        fixed_rrset_order_fqdns: The fixed RRset order FQDN. If this
            field does not contain an empty value, the appliance will
            automatically set the enable_fixed_rrset_order_fqdns field
            to 'true', unless the same request sets the enable field to
            'false'.
        forward_only: Permits this member to send queries to forwarders
            only. When the value is "true", the member sends queries to
            forwarders only, and not to other internal or Internet root
            servers.
        forward_updates: Allows secondary servers to forward updates to
            the DNS server. This setting overrides grid update settings.
        forwarders: The forwarders for the member. A forwarder is
            essentially a name server to which other name servers first
            send all of their off-site queries. The forwarder builds up
            a cache of information, avoiding the need for the other name
            servers to send queries off-site. This setting overrides the
            Grid level setting.
        ftc_expired_record_timeout: The timeout interval (in seconds)
            after which the expired Fault Tolerant Caching (FTC)record
            is stale and no longer valid.
        ftc_expired_record_ttl: The TTL value (in seconds) of the
            expired Fault Tolerant Caching (FTC) record in DNS
            responses.
        glue_record_addresses: The list of glue record addresses.
        gss_tsig_keys: The list of GSS-TSIG keys for a member DNS
            object.
        host_name: The host name of the Grid member.
        ipv4addr: The IPv4 Address of the Grid member.
        ipv6_glue_record_addresses: The list of IPv6 glue record
            addresses.
        ipv6addr: The IPv6 Address of the Grid member.
        is_unbound_capable: The flag that indicates whether member DNS
            supports Unbound as the recursive resolver or not.
        lame_ttl: The number of seconds to cache lame delegations or
            lame servers.
        logging_categories: The logging categories for this DNS member.
        max_cache_ttl: The maximum time (in seconds) for which the
            server will cache positive answers.
        max_cached_lifetime: The maximum time in seconds a DNS response
            can be stored in the hardware acceleration cache.Valid
            values are unsigned integer between 60 and 86400, inclusive.
        max_ncache_ttl: The maximum time (in seconds) for which the
            server will cache negative (NXDOMAIN) responses.The maximum
            allowed value is 604800.
        max_udp_size: The value is used by authoritative DNS servers to
            never send DNS responses larger than the configured value.
            The value should be between 512 and 4096 bytes. The
            recommended value is between 512 and 1220 bytes.
        minimal_resp: Enables the ability to return a minimal amount of
            data in response to a query. This capability speeds up the
            DNS services provided by the appliance.
        notify_delay: Specifies the number of seconds of delay the
            notify messages are sent to secondaries.
        notify_source_port: The source port for notify messages. When
            requesting zone transfers from the primary server, some
            secondary DNS servers use the source port number (the
            primary server used to send the notify message) as the
            destination port number in the zone transfer request. This
            setting overrides Grid static source port settings.Valid
            values are between 1 and 63999. The default is selected by
            BIND.
        nxdomain_log_query: Determines if NXDOMAIN redirection queries
            are logged or not.
        nxdomain_redirect: Enables NXDOMAIN redirection.
        nxdomain_redirect_addresses: The IPv4 NXDOMAIN redirection
            addresses.
        nxdomain_redirect_addresses_v6: The IPv6 NXDOMAIN redirection
            addresses.
        nxdomain_redirect_ttl: The TTL value of synthetic DNS responses
            that result from NXDOMAIN redirection.
        nxdomain_rulesets: The names of the Ruleset objects assigned at
            the Grid level for NXDOMAIN redirection.
        query_source_port: The source port for queries. Specifying a
            source port number for recursive queries ensures that a
            firewall will allow the response.Valid values are between 1
            and 63999. The default is selected by BIND.
        record_name_policy: The record name restriction policy.
        recursive_client_limit: A limit on the number of concurrent
            recursive clients.
        recursive_query_list: The list of IPv4 or IPv6 addresses,
            networks or hosts authenticated by Transaction signature
            (TSIG) key from which recursive queries are allowed or
            denied.
        recursive_resolver: The recursive resolver for member DNS.
        resolver_query_timeout: The recursive query timeout for the
            member. The value must be 0 or between 10 and 30.
        response_rate_limiting: The response rate limiting settings for
            the member.
        root_name_server_type: Determines the type of root name servers.
        rpz_disable_nsdname_nsip: Enables NSDNAME and NSIP resource
            records from RPZ feeds at member level.
        rpz_drop_ip_rule_enabled: Enables the appliance to ignore RPZ-IP
            triggers with prefix lengths less than the specified minimum
            prefix length.
        rpz_drop_ip_rule_min_prefix_length_ipv4: The minimum prefix
            length for IPv4 RPZ-IP triggers. The appliance ignores RPZ-
            IP triggers with prefix lengths less than the specified
            minimum IPv4 prefix length.
        rpz_drop_ip_rule_min_prefix_length_ipv6: The minimum prefix
            length for IPv6 RPZ-IP triggers. The appliance ignores RPZ-
            IP triggers with prefix lengths less than the specified
            minimum IPv6 prefix length.
        rpz_qname_wait_recurse: The flag that indicates whether
            recursive RPZ lookups are enabled.
        serial_query_rate: The number of maximum concurrent SOA queries
            per second for the member.
        server_id_directive: The value of the server-id directive for
            BIND and Unbound DNS.
        server_id_directive_string: The value of the user-defined
            hostname directive for BIND and UNBOUND DNS. To enable user-
            defined hostname directive, you must set the
            bind_hostname_directive to "USER_DEFINED".
        skip_in_grid_rpz_queries: Determines if RPZ rules are applied to
            queries originated from this member and received by other
            Grid members.
        sortlist: A sort list determines the order of addresses in
            responses made to DNS queries. This setting overrides Grid
            sort list settings.
        store_locally: The flag that indicates whether the storage of
            query capture reports on the appliance is enabled or
            disabled.
        syslog_facility: The syslog facility. This is the location on
            the syslog server to which you want to sort the DNS logging
            messages. This setting overrides the Grid logging facility
            settings.
        tcp_idle_timeout: TCP Idle timeout for DNS over TLS connections.
        tls_session_duration: DNS over TLS sessions duration.
        transfer_excluded_servers: Excludes specified DNS servers during
            zone transfers.
        transfer_format: The BIND format for a zone transfer. This
            provides tracking capabilities for single or multiple
            transfers and their associated servers.
        transfers_in: The number of maximum concurrent transfers for the
            member.
        transfers_out: The number of maximum outbound concurrent zone
            transfers for the member.
        transfers_per_ns: The number of maximum concurrent transfers per
            member for the member.
        unbound_logging_level: Logging level for the Unbound recursive
            resolver.
        use_add_client_ip_mac_options: Use flag for:
            add_client_ip_mac_options
        use_allow_query: Use flag for: allow_query
        use_allow_transfer: Use flag for: allow_transfer
        use_attack_mitigation: Use flag for: attack_mitigation
        use_auto_blackhole: Use flag for: auto_blackhole
        use_bind_hostname_directive: Use flag for:
            bind_hostname_directive
        use_blackhole: Use flag for: enable_blackhole
        use_blacklist: Use flag for: blackhole_list , blacklist_action,
            blacklist_log_query, blacklist_redirect_addresses,
            blacklist_redirect_ttl, blacklist_rulesets, enable_blacklist
        use_capture_dns_queries_on_all_domains: Use flag for:
            capture_dns_queries_on_all_domains
        use_copy_client_ip_mac_options: Use flag for:
            copy_client_ip_mac_options
        use_copy_xfer_to_notify: Use flag for: copy_xfer_to_notify
        use_disable_edns: Use flag for: disable_edns
        use_dns64: Use flag for: enable_dns64 , dns64_groups
        use_dns_cache_acceleration_ttl: Use flag for:
            dns_cache_acceleration_ttl
        use_dns_health_check: Use flag for: dns_health_check_domain_list
            , dns_health_check_recursion_flag,
            dns_health_check_anycast_control, enable_dns_health_check,
            dns_health_check_interval, dns_health_check_timeout,
            dns_health_check_retries
        use_dnssec: Use flag for: dnssec_enabled ,
            dnssec_expired_signatures_enabled,
            dnssec_validation_enabled, dnssec_trusted_keys
        use_dnstap_setting: Use flag for: enable_dnstap_queries ,
            enable_dnstap_responses, dnstap_setting
        use_dtc_dns_queries_specific_behavior: Use flag for:
            dtc_dns_queries_specific_behavior
        use_dtc_edns_prefer_client_subnet: Use flag for:
            dtc_edns_prefer_client_subnet
        use_edns_udp_size: Use flag for: edns_udp_size
        use_enable_capture_dns: Use flag for: enable_capture_dns_queries
            , enable_capture_dns_responses
        use_enable_excluded_domain_names: Use flag for:
            enable_excluded_domain_names
        use_enable_gss_tsig: Use flag for: enable_gss_tsig
        use_enable_query_rewrite: Use flag for: enable_query_rewrite
        use_filter_aaaa: Use flag for: filter_aaaa , filter_aaaa_list
        use_fixed_rrset_order_fqdns: Use flag for:
            fixed_rrset_order_fqdns , enable_fixed_rrset_order_fqdns
        use_forward_updates: Use flag for: forward_updates
        use_forwarders: Use flag for: forwarders , forward_only
        use_ftc: Use flag for: enable_ftc , ftc_expired_record_ttl,
            ftc_expired_record_timeout
        use_gss_tsig_keys: Use flag for: gss_tsig_keys
        use_lame_ttl: Use flag for: lame_ttl
        use_lan2_ipv6_port: Determines if the DNS service on the IPv6
            LAN2 port is enabled or not.
        use_lan2_port: Determines if the DNS service on the LAN2 port is
            enabled or not.
        use_lan_ipv6_port: Determines if the DNS service on the IPv6 LAN
            port is enabled or not.
        use_lan_port: Determines the status of the use of DNS services
            on the IPv4 LAN1 port.
        use_logging_categories: Use flag for: logging_categories
        use_max_cache_ttl: Use flag for: max_cache_ttl
        use_max_cached_lifetime: Use flag for: max_cached_lifetime
        use_max_ncache_ttl: Use flag for: max_ncache_ttl
        use_max_udp_size: Use flag for: max_udp_size
        use_mgmt_ipv6_port: Determines if the DNS services on the IPv6
            MGMT port is enabled or not.
        use_mgmt_port: Determines if the DNS services on the MGMT port
            is enabled or not.
        use_notify_delay: Use flag for: notify_delay
        use_nxdomain_redirect: Use flag for: nxdomain_redirect ,
            nxdomain_redirect_addresses, nxdomain_redirect_addresses_v6,
            nxdomain_redirect_ttl, nxdomain_log_query, nxdomain_rulesets
        use_record_name_policy: Use flag for: record_name_policy
        use_recursive_client_limit: Use flag for: recursive_client_limit
        use_recursive_query_setting: Use flag for: allow_recursive_query
            , recursive_query_list
        use_resolver_query_timeout: Use flag for: resolver_query_timeout
        use_response_rate_limiting: Use flag for: response_rate_limiting
        use_root_name_server: Use flag for: root_name_server_type ,
            custom_root_name_servers, use_root_server_for_all_views
        use_root_server_for_all_views: Determines if root name servers
            should be applied to all views or only to Default view.
        use_rpz_disable_nsdname_nsip: Use flag for:
            rpz_disable_nsdname_nsip
        use_rpz_drop_ip_rule: Use flag for: rpz_drop_ip_rule_enabled ,
            rpz_drop_ip_rule_min_prefix_length_ipv4,
            rpz_drop_ip_rule_min_prefix_length_ipv6
        use_rpz_qname_wait_recurse: Use flag for: rpz_qname_wait_recurse
        use_serial_query_rate: Use flag for: serial_query_rate
        use_server_id_directive: Use flag for: server_id_directive
        use_sortlist: Use flag for: sortlist
        use_source_ports: Use flag for: enable_notify_source_port ,
            notify_source_port, enable_query_source_port,
            query_source_port
        use_syslog_facility: Use flag for: syslog_facility
        use_transfers_in: Use flag for: transfers_in
        use_transfers_out: Use flag for: transfers_out
        use_transfers_per_ns: Use flag for: transfers_per_ns
        use_update_setting: Use flag for: allow_update ,
            allow_gss_tsig_zone_updates
        use_zone_transfer_format: Use flag for:
            transfer_excluded_servers , transfer_format
        views: The list of views associated with this member.
    """
    _infoblox_type = 'member:dns'
    _fields = ['add_client_ip_mac_options', 'additional_ip_list',
               'additional_ip_list_struct', 'allow_gss_tsig_zone_updates',
               'allow_query', 'allow_recursive_query', 'allow_transfer',
               'allow_update', 'anonymize_response_logging', 'atc_fwd_enable',
               'attack_mitigation', 'auto_blackhole',
               'auto_create_a_and_ptr_for_lan2',
               'auto_create_aaaa_and_ipv6ptr_for_lan2', 'auto_sort_views',
               'bind_check_names_policy', 'bind_hostname_directive',
               'bind_hostname_directive_fqdn', 'blackhole_list',
               'blacklist_action', 'blacklist_log_query',
               'blacklist_redirect_addresses', 'blacklist_redirect_ttl',
               'blacklist_rulesets', 'capture_dns_queries_on_all_domains',
               'check_names_for_ddns_and_zone_transfer',
               'copy_client_ip_mac_options', 'copy_xfer_to_notify',
               'custom_root_name_servers', 'disable_edns', 'dns64_groups',
               'dns_cache_acceleration_status', 'dns_cache_acceleration_ttl',
               'dns_health_check_anycast_control',
               'dns_health_check_domain_list', 'dns_health_check_interval',
               'dns_health_check_recursion_flag', 'dns_health_check_retries',
               'dns_health_check_timeout', 'dns_notify_transfer_source',
               'dns_notify_transfer_source_address', 'dns_over_tls_service',
               'dns_query_capture_file_time_limit', 'dns_query_source_address',
               'dns_query_source_interface', 'dns_view_address_settings',
               'dnssec_blacklist_enabled', 'dnssec_dns64_enabled',
               'dnssec_enabled', 'dnssec_expired_signatures_enabled',
               'dnssec_negative_trust_anchors', 'dnssec_nxdomain_enabled',
               'dnssec_rpz_enabled', 'dnssec_trusted_keys',
               'dnssec_validation_enabled', 'dnstap_setting',
               'doh_https_session_duration', 'doh_service',
               'domains_to_capture_dns_queries',
               'dtc_dns_queries_specific_behavior',
               'dtc_edns_prefer_client_subnet', 'dtc_health_source',
               'dtc_health_source_address', 'edns_udp_size',
               'enable_blackhole', 'enable_blacklist',
               'enable_capture_dns_queries', 'enable_capture_dns_responses',
               'enable_dns', 'enable_dns64', 'enable_dns_cache_acceleration',
               'enable_dns_health_check', 'enable_dnstap_queries',
               'enable_dnstap_responses', 'enable_excluded_domain_names',
               'enable_fixed_rrset_order_fqdns', 'enable_ftc',
               'enable_gss_tsig', 'enable_notify_source_port',
               'enable_query_rewrite', 'enable_query_source_port',
               'excluded_domain_names', 'extattrs', 'file_transfer_setting',
               'filter_aaaa', 'filter_aaaa_list', 'fixed_rrset_order_fqdns',
               'forward_only', 'forward_updates', 'forwarders',
               'ftc_expired_record_timeout', 'ftc_expired_record_ttl',
               'glue_record_addresses', 'gss_tsig_keys', 'host_name',
               'ipv4addr', 'ipv6_glue_record_addresses', 'ipv6addr',
               'is_unbound_capable', 'lame_ttl', 'logging_categories',
               'max_cache_ttl', 'max_cached_lifetime', 'max_ncache_ttl',
               'max_udp_size', 'minimal_resp', 'notify_delay',
               'notify_source_port', 'nxdomain_log_query', 'nxdomain_redirect',
               'nxdomain_redirect_addresses', 'nxdomain_redirect_addresses_v6',
               'nxdomain_redirect_ttl', 'nxdomain_rulesets',
               'query_source_port', 'record_name_policy',
               'recursive_client_limit', 'recursive_query_list',
               'recursive_resolver', 'resolver_query_timeout',
               'response_rate_limiting', 'root_name_server_type',
               'rpz_disable_nsdname_nsip', 'rpz_drop_ip_rule_enabled',
               'rpz_drop_ip_rule_min_prefix_length_ipv4',
               'rpz_drop_ip_rule_min_prefix_length_ipv6',
               'rpz_qname_wait_recurse', 'serial_query_rate',
               'server_id_directive', 'server_id_directive_string',
               'skip_in_grid_rpz_queries', 'sortlist', 'store_locally',
               'syslog_facility', 'tcp_idle_timeout', 'tls_session_duration',
               'transfer_excluded_servers', 'transfer_format', 'transfers_in',
               'transfers_out', 'transfers_per_ns', 'unbound_logging_level',
               'use_add_client_ip_mac_options', 'use_allow_query',
               'use_allow_transfer', 'use_attack_mitigation',
               'use_auto_blackhole', 'use_bind_hostname_directive',
               'use_blackhole', 'use_blacklist',
               'use_capture_dns_queries_on_all_domains',
               'use_copy_client_ip_mac_options', 'use_copy_xfer_to_notify',
               'use_disable_edns', 'use_dns64',
               'use_dns_cache_acceleration_ttl', 'use_dns_health_check',
               'use_dnssec', 'use_dnstap_setting',
               'use_dtc_dns_queries_specific_behavior',
               'use_dtc_edns_prefer_client_subnet', 'use_edns_udp_size',
               'use_enable_capture_dns', 'use_enable_excluded_domain_names',
               'use_enable_gss_tsig', 'use_enable_query_rewrite',
               'use_filter_aaaa', 'use_fixed_rrset_order_fqdns',
               'use_forward_updates', 'use_forwarders', 'use_ftc',
               'use_gss_tsig_keys', 'use_lame_ttl', 'use_lan2_ipv6_port',
               'use_lan2_port', 'use_lan_ipv6_port', 'use_lan_port',
               'use_logging_categories', 'use_max_cache_ttl',
               'use_max_cached_lifetime', 'use_max_ncache_ttl',
               'use_max_udp_size', 'use_mgmt_ipv6_port', 'use_mgmt_port',
               'use_notify_delay', 'use_nxdomain_redirect',
               'use_record_name_policy', 'use_recursive_client_limit',
               'use_recursive_query_setting', 'use_resolver_query_timeout',
               'use_response_rate_limiting', 'use_root_name_server',
               'use_root_server_for_all_views', 'use_rpz_disable_nsdname_nsip',
               'use_rpz_drop_ip_rule', 'use_rpz_qname_wait_recurse',
               'use_serial_query_rate', 'use_server_id_directive',
               'use_sortlist', 'use_source_ports', 'use_syslog_facility',
               'use_transfers_in', 'use_transfers_out', 'use_transfers_per_ns',
               'use_update_setting', 'use_zone_transfer_format', 'views']
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
    """ MemberFiledistribution: Grid member file distribution object.
    Corresponds to WAPI object 'member:filedistribution'

    The Grid member file distribution object is used to configure file
    distribution services such as TFTP, FTP and HTTP, and access control
    lists (ACL) that determine which clients are granted access to the
    service (TFTP, FTP, HTTP), and which clients are denied access to
    the service.

    Attributes:
        allow_uploads: Determines whether uploads to the Grid member are
            allowed.
        comment: The Grid member descriptive comment.
        enable_ftp: Determines whether the FTP prtocol is enabled for
            file distribution.
        enable_ftp_filelist: Determines whether the LIST command for FTP
            is enabled.
        enable_ftp_passive: Determines whether the passive mode for FTP
            is enabled.
        enable_http: Determines whether the HTTP prtocol is enabled for
            file distribution.
        enable_http_acl: Determines whether the HTTP prtocol access
            control (AC) settings are enabled.
        enable_tftp: Determines whether the TFTP prtocol is enabled for
            file distribution.
        ftp_acls: Access control (AC) settings for the FTP protocol.
        ftp_port: The network port used by the FTP protocol.
        ftp_status: The FTP protocol status.
        host_name: The Grid member host name.
        http_acls: Access control (AC) settings for the HTTP protocol.
        http_status: The HTTP protocol status.
        ipv4_address: The IPv4 address of the Grid member.
        ipv6_address: The IPv6 address of the Grid member.
        status: The Grid member file distribution status.
        tftp_acls: The access control (AC) settings for the TFTP
            protocol.
        tftp_port: The network port used by the TFTP protocol.
        tftp_status: The TFTP protocol status.
        use_allow_uploads: Use flag for: allow_uploads
    """
    _infoblox_type = 'member:filedistribution'
    _fields = ['allow_uploads', 'comment', 'enable_ftp', 'enable_ftp_filelist',
               'enable_ftp_passive', 'enable_http', 'enable_http_acl',
               'enable_tftp', 'ftp_acls', 'ftp_port', 'ftp_status',
               'host_name', 'http_acls', 'http_status', 'ipv4_address',
               'ipv6_address', 'status', 'tftp_acls', 'tftp_port',
               'tftp_status', 'use_allow_uploads']
    _search_for_update_fields = ['host_name', 'ipv4_address', 'ipv6_address']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'host_name', 'ipv4_address',
                              'ipv6_address']
    _return_fields = ['host_name', 'ipv4_address', 'ipv6_address', 'status']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ftp_acls': Addressac.from_dict,
        'http_acls': Addressac.from_dict,
        'tftp_acls': Addressac.from_dict,
    }


class MemberLicense(InfobloxObject):
    """ MemberLicense: Member License object.
    Corresponds to WAPI object 'member:license'

    This object represents the member license.

    Attributes:
        expiration_status: The license expiration status.
        expiry_date: The expiration timestamp of the license.
        hwid: The hardware ID of the physical node on which the license
            is installed.
        key: License string.
        kind: The overall type of license: static or dynamic.
        limit: The license limit value.
        limit_context: The license limit context.
        type: The license type.
    """
    _infoblox_type = 'member:license'
    _fields = ['expiration_status', 'expiry_date', 'hwid', 'key', 'kind',
               'limit', 'limit_context', 'type']
    _search_for_update_fields = ['type']
    _updateable_search_fields = []
    _all_searchable_fields = ['hwid', 'key', 'kind', 'limit', 'type']
    _return_fields = ['type']
    _remap = {}
    _shadow_fields = ['_ref']


class MemberParentalcontrol(InfobloxObject):
    """ MemberParentalcontrol: Member mobile security properties object.
    Corresponds to WAPI object 'member:parentalcontrol'

    This object represents a set of parental control properties for the
    Grid member.

    Attributes:
        enable_service: Determines if the parental control service is
            enabled.
        name: The parental control member hostname.
    """
    _infoblox_type = 'member:parentalcontrol'
    _fields = ['enable_service', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = []
    _all_searchable_fields = ['name']
    _return_fields = ['enable_service', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class MemberThreatanalytics(InfobloxObject):
    """ MemberThreatanalytics: Grid member threat analytics object.
    Corresponds to WAPI object 'member:threatanalytics'

    To mitigate DNS data exfiltration, Infoblox DNS threat analytics
    employs analytics algorithms that analyze incoming DNS queries and
    responses to detect DNS tunneling traffic.

    The Grid member threat analytics object contains facilities for
    starting and stopping the DNS threat analytics routines as well as
    for monitoring the current status of the threat analytics service.

    Attributes:
        comment: The Grid member descriptive comment.
        enable_service: Determines whether the threat analytics service
            is enabled.
        host_name: The Grid member host name.
        ipv4_address: The IPv4 Address address of the Grid member.
        ipv6_address: The IPv6 Address address of the Grid member.
        status: The Grid member threat analytics status.
    """
    _infoblox_type = 'member:threatanalytics'
    _fields = ['comment', 'enable_service', 'host_name', 'ipv4_address',
               'ipv6_address', 'status']
    _search_for_update_fields = ['host_name', 'ipv4_address', 'ipv6_address']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'host_name', 'ipv4_address',
                              'ipv6_address']
    _return_fields = ['host_name', 'ipv4_address', 'ipv6_address', 'status']
    _remap = {}
    _shadow_fields = ['_ref']


class MemberThreatprotection(InfobloxObject):
    """ MemberThreatprotection: Member threat protection object.
    Corresponds to WAPI object 'member:threatprotection'

    This object provides information about the member threat protection
    settings.

    Attributes:
        comment: The human readable comment for member threat protection
            properties.
        current_ruleset: The ruleset used for threat protection.
        disable_multiple_dns_tcp_request: Determines if multiple BIND
            responses via TCP connection is enabled or not.
        enable_accel_resp_before_threat_protection: Determines if DNS
            responses are sent from acceleration cache before applying
            Threat Protection rules. Recommended for better performance
            when using DNS Cache Acceleration.
        enable_nat_rules: Determines if NAT (Network Address
            Translation) mapping for threat protection is enabled or
            not.
        enable_service: Determines if the Threat protection service is
            enabled or not.
        events_per_second_per_rule: The number of events logged per
            second per rule.
        hardware_model: The hardware model of the member.
        hardware_type: The hardware type of the member.
        host_name: A Grid member name.
        ipv4address: The IPv4 address of member threat protection
            service.
        ipv6address: The IPv6 address of member threat protection
            service.
        nat_rules: The list of NAT rules.
        outbound_settings: Outbound settings for ATP events.
        profile: The Threat Protection profile associated with the
            member.
        use_current_ruleset: Use flag for: current_ruleset
        use_disable_multiple_dns_tcp_request: Use flag for:
            disable_multiple_dns_tcp_request
        use_enable_accel_resp_before_threat_protection: Use flag for:
            enable_accel_resp_before_threat_protection
        use_enable_nat_rules: Use flag for: enable_nat_rules
        use_events_per_second_per_rule: Use flag for:
            events_per_second_per_rule
        use_outbound_settings: Use flag for: outbound_settings
    """
    _infoblox_type = 'member:threatprotection'
    _fields = ['comment', 'current_ruleset',
               'disable_multiple_dns_tcp_request',
               'enable_accel_resp_before_threat_protection',
               'enable_nat_rules', 'enable_service',
               'events_per_second_per_rule', 'hardware_model', 'hardware_type',
               'host_name', 'ipv4address', 'ipv6address', 'nat_rules',
               'outbound_settings', 'profile', 'use_current_ruleset',
               'use_disable_multiple_dns_tcp_request',
               'use_enable_accel_resp_before_threat_protection',
               'use_enable_nat_rules', 'use_events_per_second_per_rule',
               'use_outbound_settings']
    _search_for_update_fields = []
    _updateable_search_fields = ['current_ruleset', 'profile']
    _all_searchable_fields = ['comment', 'current_ruleset', 'hardware_model',
                              'hardware_type', 'host_name', 'ipv4address',
                              'ipv6address', 'profile']
    _return_fields = []
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'nat_rules': ThreatprotectionNatrule.from_dict,
    }


class Memberdfp(InfobloxObject):
    """ Memberdfp: Memberdfp object.
    Corresponds to WAPI object 'memberdfp'

    This object represnts DFP fields at member level

    Attributes:
        dfp_forward_first: Option to resolve DNS query if resolution
            over Active Trust Cloud failed.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        host_name: Host name of the parent Member
        is_dfp_override: DFP override lock'.
    """
    _infoblox_type = 'memberdfp'
    _fields = ['dfp_forward_first', 'extattrs', 'host_name', 'is_dfp_override']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['extattrs']
    _remap = {}
    _shadow_fields = ['_ref']


class Msserver(InfobloxObject):
    """ Msserver: Microsoft Server object.
    Corresponds to WAPI object 'msserver'

    This object represents the Microsoft Server.

    Attributes:
        ad_domain: The Active Directory domain to which this server
            belongs (if applicable).
        ad_sites: The Active Directory Sites information
        ad_user: The Active Directory User synchronization information.
        address: The address or FQDN of the server.
        comment: User comments for this Microsoft Server
        connection_status: Result of the last RPC connection attempt
            made
        connection_status_detail: Detail of the last connection attempt
            made
        dhcp_server: RW fields needed for DHCP purposes at Microsoft
            Server level
        disabled: Allow/forbids usage of this Microsoft Server
        dns_server: Structure containing DNS information
        dns_view: Reference to the DNS view
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        grid_member: eference to the assigned grid member
        last_seen: Timestamp of the last message received
        log_destination: Directs logging of sync messages either to
            syslog or mslog
        log_level: Log level for this Microsoft Server
        login_name: Microsoft Server login name, with optional
            domainname
        login_password: Microsoft Server login password
        managing_member: Hostname of grid member managing this Microsoft
            Server
        ms_max_connection: Maximum number of connections to MS server
        ms_rpc_timeout_in_seconds: Timeout in seconds of RPC connections
            for this MS Server
        network_view: Reference to the network view
        read_only: Enable read-only management for this Microsoft Server
        root_ad_domain: The root Active Directory domain to which this
            server belongs (if applicable).
        server_name: Gives the server name as reported by itself
        synchronization_min_delay: Minimum number of minutes between two
            synchronizations
        synchronization_status: Synchronization status summary
        synchronization_status_detail: Detail status if
            synchronization_status is ERROR
        use_log_destination: Override log_destination inherited from
            grid level
        use_ms_max_connection: Override grid ms_max_connection setting
        use_ms_rpc_timeout_in_seconds: Flag to override cluster RPC
            timeout
        version: Version of the Microsoft Server
    """
    _infoblox_type = 'msserver'
    _fields = ['ad_domain', 'ad_sites', 'ad_user', 'address', 'comment',
               'connection_status', 'connection_status_detail', 'dhcp_server',
               'disabled', 'dns_server', 'dns_view', 'extattrs', 'grid_member',
               'last_seen', 'log_destination', 'log_level', 'login_name',
               'login_password', 'managing_member', 'ms_max_connection',
               'ms_rpc_timeout_in_seconds', 'network_view', 'read_only',
               'root_ad_domain', 'server_name', 'synchronization_min_delay',
               'synchronization_status', 'synchronization_status_detail',
               'use_log_destination', 'use_ms_max_connection',
               'use_ms_rpc_timeout_in_seconds', 'version']
    _search_for_update_fields = ['address']
    _updateable_search_fields = ['address', 'grid_member']
    _all_searchable_fields = ['address', 'grid_member']
    _return_fields = ['address', 'extattrs']
    _remap = {}
    _shadow_fields = ['_ref']


class MsserverAdsitesDomain(InfobloxObject):
    """ MsserverAdsitesDomain: Active Directory Domain object.
    Corresponds to WAPI object 'msserver:adsites:domain'

    The object provides information about the Active Directory Domain.

    Attributes:
        ea_definition: The name of the Extensible Attribute Definition
            object that is linked to the Active Directory Sites Domain.
        ms_sync_master_name: The IP address or FQDN of the managing
            master for the MS server, if applicable.
        name: The name of the Active Directory Domain properties object.
        netbios: The NetBIOS name of the Active Directory Domain
            properties object.
        network_view: The name of the network view in which the Active
            Directory Domain resides.
        read_only: Determines whether the Active Directory Domain
            properties object is a read-only object.
    """
    _infoblox_type = 'msserver:adsites:domain'
    _fields = ['ea_definition', 'ms_sync_master_name', 'name', 'netbios',
               'network_view', 'read_only']
    _search_for_update_fields = ['name', 'netbios', 'network_view']
    _updateable_search_fields = []
    _all_searchable_fields = ['ea_definition', 'name', 'netbios',
                              'network_view']
    _return_fields = ['name', 'netbios', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']


class MsserverAdsitesSite(InfobloxObject):
    """ MsserverAdsitesSite: Active Directory Site object.
    Corresponds to WAPI object 'msserver:adsites:site'

    This object provides information about the Active Directory Site.

    Attributes:
        domain: The reference to the Active Directory Domain to which
            the site belongs.
        name: The name of the site properties object for the Active
            Directory Sites.
        networks: The list of networks to which the device interfaces
            belong.
    """
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
    """ MsserverDhcp: Microsoft Server DHCP properties object.
    Corresponds to WAPI object 'msserver:dhcp'

    This object represents a subset of the Microsoft Server DHCP
    properties.

    Attributes:
        address: The address or FQDN of the DHCP Microsoft Server.
        comment: Comment from Microsoft Server
        dhcp_utilization: The percentage of the total DHCP utilization
            of DHCP objects belonging to the DHCP Microsoft Server
            multiplied by 1000. This is the percentage of the total
            number of available IP addresses from all the DHCP objects
            belonging to the DHCP Microsoft Server versus the total
            number of all IP addresses in all of the DHCP objects on the
            DHCP Microsoft Server.
        dhcp_utilization_status: A string describing the utilization
            level of DHCP objects that belong to the DHCP Microsoft
            Server.
        dynamic_hosts: The total number of DHCP leases issued for the
            DHCP objects on the DHCP Microsoft Server.
        last_sync_ts: Timestamp of the last synchronization attempt
        login_name: The login name of the DHCP Microsoft Server.
        login_password: The login password of the DHCP Microsoft Server.
        network_view: Network view to update
        next_sync_control: Defines what control to apply on the DHCP
            server
        read_only: Whether Microsoft server is read only
        server_name: Microsoft server address
        static_hosts: The number of static DHCP addresses configured in
            DHCP objects that belong to the DHCP Microsoft Server.
        status: Status of the Microsoft DHCP Service
        status_detail: Detailed status of the DHCP status
        status_last_updated: Timestamp of the last update
        supports_failover: Flag indicating if the DHCP supports Failover
        synchronization_interval: The minimum number of minutes between
            two synchronizations.
        total_hosts: The total number of DHCP addresses configured in
            DHCP objects that belong to the DHCP Microsoft Server.
        use_login: Use flag for: login_name , login_password
        use_synchronization_interval: Use flag for:
            synchronization_interval
    """
    _infoblox_type = 'msserver:dhcp'
    _fields = ['address', 'comment', 'dhcp_utilization',
               'dhcp_utilization_status', 'dynamic_hosts', 'last_sync_ts',
               'login_name', 'login_password', 'network_view',
               'next_sync_control', 'read_only', 'server_name', 'static_hosts',
               'status', 'status_detail', 'status_last_updated',
               'supports_failover', 'synchronization_interval', 'total_hosts',
               'use_login', 'use_synchronization_interval']
    _search_for_update_fields = ['address']
    _updateable_search_fields = []
    _all_searchable_fields = ['address']
    _return_fields = ['address']
    _remap = {}
    _shadow_fields = ['_ref']


class MsserverDns(InfobloxObject):
    """ MsserverDns: Microsoft Server DNS properties object.
    Corresponds to WAPI object 'msserver:dns'

    This object represents a subset of the Microsoft Server DNS
    properties.

    Attributes:
        address: The address or FQDN of the DNS Microsoft Server.
        enable_dns_reports_sync: Determines if synchronization of DNS
            reporting data from the Microsoft server is enabled or not.
        login_name: The login name of the DNS Microsoft Server.
        login_password: The login password of the DNS Microsoft Server.
        synchronization_interval: The minimum number of minutes between
            two synchronizations.
        use_enable_dns_reports_sync: Use flag for:
            enable_dns_reports_sync
        use_login: Use flag for: login_name , login_password
        use_synchronization_interval: Use flag for:
            synchronization_interval
    """
    _infoblox_type = 'msserver:dns'
    _fields = ['address', 'enable_dns_reports_sync', 'login_name',
               'login_password', 'synchronization_interval',
               'use_enable_dns_reports_sync', 'use_login',
               'use_synchronization_interval']
    _search_for_update_fields = ['address']
    _updateable_search_fields = []
    _all_searchable_fields = ['address']
    _return_fields = ['address']
    _remap = {}
    _shadow_fields = ['_ref']


class Mssuperscope(InfobloxObject):
    """ Mssuperscope: Microsoft DHCP superscope object.
    Corresponds to WAPI object 'mssuperscope'

    This object represents a superscope feature of Microsoft DHCP
    server. You can use a superscope to group and activate multiple
    ranges via a single object.

    Attributes:
        comment: The superscope descriptive comment.
        dhcp_utilization: The percentage of the total DHCP usage of the
            ranges in the superscope.
        dhcp_utilization_status: Utilization level of the DHCP range
            objects that belong to the superscope.
        disable: Determines whether the superscope is disabled.
        dynamic_hosts: The total number of DHCP leases issued for the
            DHCP range objects that belong to the superscope.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        high_water_mark: The percentage value for DHCP range usage after
            which an alarm will be active.
        high_water_mark_reset: The percentage value for DHCP range usage
            after which an alarm will be reset.
        low_water_mark: The percentage value for DHCP range usage below
            which an alarm will be active.
        low_water_mark_reset: The percentage value for DHCP range usage
            below which an alarm will be reset.
        name: The name of the Microsoft DHCP superscope.
        network_view: The name of the network view in which the
            superscope resides.
        ranges: The list of DHCP ranges that are associated with the
            superscope.
        static_hosts: The number of static DHCP addresses configured in
            DHCP range objects that belong to the superscope.
        total_hosts: The total number of DHCP addresses configured in
            DHCP range objects that belong to the superscope.
    """
    _infoblox_type = 'mssuperscope'
    _fields = ['comment', 'dhcp_utilization', 'dhcp_utilization_status',
               'disable', 'dynamic_hosts', 'extattrs', 'high_water_mark',
               'high_water_mark_reset', 'low_water_mark',
               'low_water_mark_reset', 'name', 'network_view', 'ranges',
               'static_hosts', 'total_hosts']
    _search_for_update_fields = ['name', 'network_view']
    _updateable_search_fields = ['comment', 'name', 'network_view']
    _all_searchable_fields = ['comment', 'name', 'network_view']
    _return_fields = ['disable', 'extattrs', 'name', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']


class Namedacl(InfobloxObject):
    """ Namedacl: Named ACL object.
    Corresponds to WAPI object 'namedacl'

    A named ACL (Access Control List) is a list of IPv4/IPv6 addresses,
    networks, TSIG-based anonymous access controls, and other named
    ACLs, to which you can grant or deny permission for operations such
    as dynamic DNS updates or zone transfers.

    Attributes:
        access_list: The access control list of IPv4/IPv6 addresses,
            networks, TSIG-based anonymous access controls, and other
            named ACLs.
        comment: Comment for the named ACL; maximum 256 characters.
        exploded_access_list: The exploded access list for the named
            ACL. This list displays all the access control entries in a
            named ACL and its nested named ACLs, if applicable.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name of the named ACL.
    """
    _infoblox_type = 'namedacl'
    _fields = ['access_list', 'comment', 'exploded_access_list', 'extattrs',
               'name']
    _search_for_update_fields = ['name']
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
    """ Natgroup: Network Address Translation group object.
    Corresponds to WAPI object 'natgroup'

    NAT groups are necessary if the Grid master is behind a NAT device
    and there are members behind both side of the NAT device. Any member
    on the same side as the master goes into the same NAT group as the
    master and uses its interface address for Grid communication. Grid
    members on the other side of that NAT device do not go into the same
    NAT group as the master and use the master's NAT address for Grid
    communication.

    Attributes:
        comment: The NAT group descriptive comment.
        name: The name of a NAT group object.
    """
    _infoblox_type = 'natgroup'
    _fields = ['comment', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class NetworkDiscovery(InfobloxObject):
    """ NetworkDiscovery: Network discovery object.
    Corresponds to WAPI object 'network_discovery'

    This object can be used to control the network discovery process.

    Attributes:
    """
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
    """ Networkuser: Network User object.
    Corresponds to WAPI object 'networkuser'

    The DHCP Network User object provides information about Active
    Directory users such as user session for a specific IP address,
    domain, login and logout timestamps.

    Attributes:
        address: The IPv4 Address or IPv6 Address of the Network User.
        address_object: The reference of the IPAM IPv4Address or
            IPv6Address object describing the address of the Network
            User.
        data_source: The Network User data source.
        data_source_ip: The Network User data source IPv4 Address or
            IPv6 Address or FQDN address.
        domainname: The domain name of the Network User.
        first_seen_time: The first seen timestamp of the Network User.
        guid: The group identifier of the Network User.
        last_seen_time: The last seen timestamp of the Network User.
        last_updated_time: The last updated timestamp of the Network
            User.
        logon_id: The logon identifier of the Network User.
        logout_time: The logout timestamp of the Network User.
        name: The name of the Network User.
        network: The reference to the network to which the Network User
            belongs.
        network_view: The name of the network view in which this Network
            User resides.
        user_status: The status of the Network User.
    """
    _infoblox_type = 'networkuser'
    _fields = ['address', 'address_object', 'data_source', 'data_source_ip',
               'domainname', 'first_seen_time', 'guid', 'last_seen_time',
               'last_updated_time', 'logon_id', 'logout_time', 'name',
               'network', 'network_view', 'user_status']
    _search_for_update_fields = ['address', 'domainname', 'name',
                                 'network_view', 'user_status']
    _updateable_search_fields = ['address', 'domainname', 'guid', 'logon_id',
                                 'name', 'network_view']
    _all_searchable_fields = ['address', 'domainname', 'guid', 'logon_id',
                              'name', 'network_view', 'user_status']
    _return_fields = ['address', 'domainname', 'name', 'network_view',
                      'user_status']
    _remap = {}
    _shadow_fields = ['_ref']


class NetworkView(InfobloxObject):
    """ NetworkView: DHCP NetworkView object.
    Corresponds to WAPI object 'networkview'

    A network view is a single routing domain with its own networks and
    shared networks. A network view can contain both IPv4 and IPv6
    networks. All networks must belong to a network view.

    Attributes:
        associated_dns_views: The list of DNS views associated with this
            network view.
        associated_members: The list of members associated with a
            network view.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the network view; maximum 256 characters.
        ddns_dns_view: DNS views that will receive the updates if you
            enable the appliance to send updates to Grid members.
        ddns_zone_primaries: An array of Ddns Zone Primary structs that
            lists the information of primary zone to wich DDNS updates
            should be sent.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        internal_forward_zones: The list of linked authoritative DNS
            zones.
        is_default: The NIOS appliance provides one default network
            view. You can rename the default view and change its
            settings, but you cannot delete it. There must always be at
            least one network view in the appliance.
        mgm_private: This field controls whether this object is
            synchronized with the Multi-Grid Master. If this field is
            set to True, objects are not synchronized.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: Name of the network view.
        remote_forward_zones: The list of forward-mapping zones to which
            the DHCP server sends the updates.
        remote_reverse_zones: The list of reverse-mapping zones to which
            the DHCP server sends the updates.
    """
    _infoblox_type = 'networkview'
    _fields = ['associated_dns_views', 'associated_members', 'cloud_info',
               'comment', 'ddns_dns_view', 'ddns_zone_primaries', 'extattrs',
               'internal_forward_zones', 'is_default', 'mgm_private',
               'ms_ad_user_data', 'name', 'remote_forward_zones',
               'remote_reverse_zones']
    _search_for_update_fields = ['is_default', 'name']
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
    """ NotificationRestEndpoint: The notification RESTful endpoint
    object.
    Corresponds to WAPI object 'notification:rest:endpoint'

    The notification REST endpoint object represents settings of
    particular REST API endpoint.

    Attributes:
        client_certificate_subject: The client certificate subject of a
            notification REST endpoint.
        client_certificate_token: The token returned by the uploadinit
            function call in object fileop for a notification REST
            endpoit client certificate.
        client_certificate_valid_from: The timestamp when client
            certificate for a notification REST endpoint was created.
        client_certificate_valid_to: The timestamp when client
            certificate for a notification REST endpoint expires.
        comment: The comment of a notification REST endpoint.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        log_level: The log level for a notification REST endpoint.
        name: The name of a notification REST endpoint.
        outbound_member_type: The outbound member which will generate an
            event.
        outbound_members: The list of members for outbound events.
        password: The password of the user that can log into a
            notification REST endpoint.
        server_cert_validation: The server certificate validation type.
        sync_disabled: Determines if the sync process is disabled for a
            notification REST endpoint.
        template_instance: The notification REST template instance. The
            parameters of REST API endpoint template instance are
            prohibited to change.
        timeout: The timeout of session management (in seconds).
        uri: The URI of a notification REST endpoint.
        username: The username of the user that can log into a
            notification REST endpoint.
        vendor_identifier: The vendor identifier.
        wapi_user_name: The user name for WAPI integration.
        wapi_user_password: The user password for WAPI integration.
    """
    _infoblox_type = 'notification:rest:endpoint'
    _fields = ['client_certificate_subject', 'client_certificate_token',
               'client_certificate_valid_from', 'client_certificate_valid_to',
               'comment', 'extattrs', 'log_level', 'name',
               'outbound_member_type', 'outbound_members', 'password',
               'server_cert_validation', 'sync_disabled', 'template_instance',
               'timeout', 'uri', 'username', 'vendor_identifier',
               'wapi_user_name', 'wapi_user_password']
    _search_for_update_fields = ['name', 'outbound_member_type', 'uri']
    _updateable_search_fields = ['log_level', 'name', 'outbound_member_type',
                                 'uri', 'vendor_identifier']
    _all_searchable_fields = ['log_level', 'name', 'outbound_member_type',
                              'uri', 'vendor_identifier']
    _return_fields = ['extattrs', 'name', 'outbound_member_type', 'uri']
    _remap = {}
    _shadow_fields = ['_ref']

    def clear_outbound_worker_log(self, *args, **kwargs):
        return self._call_func("clear_outbound_worker_log", *args, **kwargs)

    def test_connection(self, *args, **kwargs):
        return self._call_func("test_connection", *args, **kwargs)


class NotificationRestTemplate(InfobloxObject):
    """ NotificationRestTemplate: The notification REST template object.
    Corresponds to WAPI object 'notification:rest:template'

    The notification REST template object represents settings of
    particular REST API template.

    Attributes:
        action_name: The action name.
        added_on: The time stamp when a template was added.
        comment: The comment for this REST API template.
        content: The JSON formatted content of a template. The data
            passed by content creates parameters for a template.
        event_type: The event type.
        name: The name of a notification REST template.
        outbound_type: The outbound type for the template.
        parameters: The notification REST template parameters.
        template_type: The template type.
        vendor_identifier: The vendor identifier.
    """
    _infoblox_type = 'notification:rest:template'
    _fields = ['action_name', 'added_on', 'comment', 'content', 'event_type',
               'name', 'outbound_type', 'parameters', 'template_type',
               'vendor_identifier']
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
    """ NotificationRule: Notification rule object.
    Corresponds to WAPI object 'notification:rule'

    Notification rule specifies the server to which this rule is
    applicable, certain conditions (i.e. triggers), and the action to be
    taken when the rule is hit. It also specifies where this rule engine
    is configured to be run.

    Attributes:
        all_members: Determines whether the notification rule is applied
            on all members or not. When this is set to False, the
            notification rule is applied only on selected_members.
        comment: The notification rule descriptive comment.
        disable: Determines whether a notification rule is disabled or
            not. When this is set to False, the notification rule is
            enabled.
        enable_event_deduplication: Determines whether the notification
            rule for event deduplication is enabled. Note that to enable
            event deduplication, you must set at least one deduplication
            field.
        enable_event_deduplication_log: Determines whether the
            notification rule for the event deduplication syslog is
            enabled.
        event_deduplication_fields: The list of fields that must be used
            in the notification rule for event deduplication.
        event_deduplication_lookback_period: The lookback period for the
            notification rule for event deduplication.
        event_priority: Event priority.
        event_type: The notification rule event type.
        expression_list: The notification rule expression list.
        name: The notification rule name.
        notification_action: The notification rule action is applied if
            expression list evaluates to True.
        notification_target: The notification target.
        publish_settings: The publish settings.
        scheduled_event: Schedule setting that must be specified if
            event_type is SCHEDULE.
        selected_members: The list of the members on which the
            notification rule is applied.
        template_instance: The notification REST template instance.
        use_publish_settings: Use flag for: publish_settings
    """
    _infoblox_type = 'notification:rule'
    _fields = ['all_members', 'comment', 'disable',
               'enable_event_deduplication', 'enable_event_deduplication_log',
               'event_deduplication_fields',
               'event_deduplication_lookback_period', 'event_priority',
               'event_type', 'expression_list', 'name', 'notification_action',
               'notification_target', 'publish_settings', 'scheduled_event',
               'selected_members', 'template_instance', 'use_publish_settings']
    _search_for_update_fields = ['event_type', 'name', 'notification_action',
                                 'notification_target']
    _updateable_search_fields = ['comment', 'event_priority', 'event_type',
                                 'notification_action', 'notification_target']
    _all_searchable_fields = ['comment', 'event_priority', 'event_type',
                              'name', 'notification_action',
                              'notification_target']
    _return_fields = ['event_type', 'name', 'notification_action',
                      'notification_target']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'expression_list': NotificationRuleexpressionop.from_dict,
    }

    def trigger_outbound(self, *args, **kwargs):
        return self._call_func("trigger_outbound", *args, **kwargs)


class Nsgroup(InfobloxObject):
    """ Nsgroup: DNS name server group object.
    Corresponds to WAPI object 'nsgroup'

    A name server group is a collection of one or more primary DNS
    servers and one or more secondary DNS servers. Grouping a commonly
    used set of primary and secondary DNS servers together simplifies
    zone creation, allowing you to specify a single name server group
    instead of specifying multiple name servers individually.

    Attributes:
        comment: Comment for the name server group; maximum 256
            characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        external_primaries: The list of external primary servers.
        external_secondaries: The list of external secondary servers.
        grid_primary: The grid primary servers for this group.
        grid_secondaries: The list with Grid members that are secondary
            servers for this group.
        is_grid_default: Determines if this name server group is the
            Grid default.
        is_multimaster: Determines if the "multiple DNS primaries"
            feature is enabled for the group.
        name: The name of this name server group.
        use_external_primary: This flag controls whether the group is
            using an external primary. Note that modification of this
            field requires passing values for "grid_secondaries" and
            "external_primaries".
    """
    _infoblox_type = 'nsgroup'
    _fields = ['comment', 'extattrs', 'external_primaries',
               'external_secondaries', 'grid_primary', 'grid_secondaries',
               'is_grid_default', 'is_multimaster', 'name',
               'use_external_primary']
    _search_for_update_fields = ['name']
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
    """ NsgroupDelegation: NS group delegation object.
    Corresponds to WAPI object 'nsgroup:delegation'

    The NS group delegation object provides delegation servers
    configuration for delegated zones. When you configure a name server
    group, you can now create a set of external name servers as a
    delegation name server group and assign it to delegated zones.
    Specifying a single delegation name server group instead of
    configuring multiple name servers individually for each delegated
    zones can significantly reduce configuration efforts.

    Attributes:
        comment: The comment for the delegated NS group.
        delegate_to: The list of delegated servers for the delegated NS
            group.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name of the delegated NS group.
    """
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
    """ NsgroupForwardingmember: Forwarding Member Name Server Group
    object.
    Corresponds to WAPI object 'nsgroup:forwardingmember'

    The Forwarding Member Name Server Group provides forwarding servers
    configuration for forward zones.

    Attributes:
        comment: Comment for the Forwarding Member Name Server Group;
            maximum 256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forwarding_servers: The list of forwarding member servers.
        name: The name of the Forwarding Member Name Server Group.
    """
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
    """ NsgroupForwardstubserver: Forward Stub Server Name Server Group
    object.
    Corresponds to WAPI object 'nsgroup:forwardstubserver'

    The Forward Stub Server Name Server Group allows configuring
    external servers for Forward Zone and Stub Zone.

    Attributes:
        comment: Comment for the Forward Stub Server Name Server Group;
            maximum 256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        external_servers: The list of external servers.
        name: The name of this Forward Stub Server Name Server Group.
    """
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
    """ NsgroupStubmember: Stub Member Name Server Group object.
    Corresponds to WAPI object 'nsgroup:stubmember'

    The Stub Member Name Server Group provides stub servers
    configuration for stub zones.

    Attributes:
        comment: Comment for the Stub Member Name Server Group; maximum
            256 characters.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name of the Stub Member Name Server Group.
        stub_members: The Grid member servers of this stub zone.Note
            that the lead/stealth/grid_replicate/
            preferred_primaries/override_preferred_primaries fields of
            the struct will be ignored when set in this field.
    """
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
    """ Orderedranges: Ordered DHCP ranges object.
    Corresponds to WAPI object 'orderedranges'

    An ordered DHCP ranges object contains an ordered list of DHCP range
    objects that belong to a network.

    Note that DHCP range object that have server association type set to
    'NONE' are excluded from ordered DHCP ranges object.

    Attributes:
        network: The reference to the network that contains ranges.
        ranges: The ordered list of references to ranges.
    """
    _infoblox_type = 'orderedranges'
    _fields = ['network', 'ranges']
    _search_for_update_fields = ['network']
    _updateable_search_fields = []
    _all_searchable_fields = ['network']
    _return_fields = ['network', 'ranges']
    _remap = {}
    _shadow_fields = ['_ref']


class Orderedresponsepolicyzones(InfobloxObject):
    """ Orderedresponsepolicyzones: Ordered Response Policy Zones
    object.
    Corresponds to WAPI object 'orderedresponsepolicyzones'

    An ordered list of Response Policy Zones in a DNS view. Server will
    reject zones that are disabled or zones without primary name server
    assigned.

    Attributes:
        rp_zones: An ordered list of Response Policy Zone names.
        view: The DNS View name.
    """
    _infoblox_type = 'orderedresponsepolicyzones'
    _fields = ['rp_zones', 'view']
    _search_for_update_fields = ['view']
    _updateable_search_fields = ['view']
    _all_searchable_fields = ['view']
    _return_fields = ['view']
    _remap = {}
    _shadow_fields = ['_ref']


class OutboundCloudclient(InfobloxObject):
    """ OutboundCloudclient: OutBoundCloudClient object.
    Corresponds to WAPI object 'outbound:cloudclient'

    You can use the outbound Cloud Client object to configure the
    detection and authentication of domains in the Cloud, and then apply
    them to on-premises DNS firewall RPZ zones within a configurable
    time frame.

    Attributes:
        enable: Determines whether the OutBound Cloud Client is enabled.
        grid_member: The  Grid member where our outbound is running.
        interval: The time interval (in seconds) for requesting newly
            detected domains by the Infoblox Outbound Cloud Client and
            applying them to the list of configured RPZs.
        outbound_cloud_client_events: List of event types to request
    """
    _infoblox_type = 'outbound:cloudclient'
    _fields = ['enable', 'grid_member', 'interval',
               'outbound_cloud_client_events']
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
    """ ParentalcontrolAvp: The parental control AVP object.
    Corresponds to WAPI object 'parentalcontrol:avp'

    The accounting attribute value pair object is used to extract
    accounting information from accounting protocols logs.

    Attributes:
        comment: The comment for the AVP.
        domain_types: The list of domains applicable to AVP.
        is_restricted: Determines if AVP is restricted to domains.
        name: The name of AVP.
        type: The type of AVP as per RFC 2865/2866.
        user_defined: Determines if AVP was defined by user.
        value_type: The type of value.
        vendor_id: The vendor ID as per RFC 2865/2866.
        vendor_type: The vendor type as per RFC 2865/2866.
    """
    _infoblox_type = 'parentalcontrol:avp'
    _fields = ['comment', 'domain_types', 'is_restricted', 'name', 'type',
               'user_defined', 'value_type', 'vendor_id', 'vendor_type']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name', 'vendor_id', 'vendor_type']
    _all_searchable_fields = ['comment', 'name', 'vendor_id', 'vendor_type']
    _return_fields = ['name', 'type', 'value_type']
    _remap = {}
    _shadow_fields = ['_ref']


class ParentalcontrolBlockingpolicy(InfobloxObject):
    """ ParentalcontrolBlockingpolicy: Parental control blocking policy
    object.
    Corresponds to WAPI object 'parentalcontrol:blockingpolicy'

    This object represents a set of parental control properties for
    blocking policy.

    Attributes:
        name: The name of the blocking policy.
        value: The 32 bit hex value of the blocking policy.
    """
    _infoblox_type = 'parentalcontrol:blockingpolicy'
    _fields = ['name', 'value']
    _search_for_update_fields = ['name', 'value']
    _updateable_search_fields = ['name', 'value']
    _all_searchable_fields = ['name', 'value']
    _return_fields = ['name', 'value']
    _remap = {}
    _shadow_fields = ['_ref']


class ParentalcontrolSubscriber(InfobloxObject):
    """ ParentalcontrolSubscriber: The parental control subscriber
    object.
    Corresponds to WAPI object 'parentalcontrol:subscriber'

    The parental control subscriber properties contains user defined
    RADIUS subscriber information which will be used by DNS/RPZ for
    reporting and logging violations.

    Attributes:
        alt_subscriber_id: The name of AVP to be used as an alternate
            subscriber ID for fixed lines.
        alt_subscriber_id_regexp: A character string to control aspects
            of rewriting of the fields.
        alt_subscriber_id_subexpression: The subexpression indicates
            which subexpression to extract. If zero, then the text
            matching the entire regular expression is extracted. If non-
            zero, then the regex must contain at least that many sub-
            expression groups. It takes values from 0 to 8.
        ancillaries: The list of ordered AVP Ancillary Fields.
        cat_acctname: Category content account name using the
            categorization service.
        cat_password: Category content account password to access the
            categorization service.
        cat_update_frequency: Category content updates every number of
            hours.
        category_url: Category content vendor url to download category
            data from and upload feedback to, configure for parental
            control.
        enable_mgmt_only_nas: Determines if NAS RADIUS traffic is
            accepted over MGMT only.
        enable_parental_control: Determines if parental control is
            enabled.
        interim_accounting_interval: The time for collector to be fully
            populated.Valid values are from 1 to 65535.
        ip_anchors: The ordered list of IP Anchors AVPs. The list
            content cannot be changed, but the order of elements.
        ip_space_disc_regexp: A character string to control aspects of
            rewriting of the fields.
        ip_space_disc_subexpression: The subexpression indicates which
            subexpression to extract. If zero, then the text matching
            the entire regular expression is extracted. If non-zero,
            then the regex must contain at least that many sub-
            expression groups. It takes values from 0 to 8.
        ip_space_discriminator: The name of AVP to be used as IP address
            discriminator.
        local_id: The name of AVP to be used as local ID.
        local_id_regexp: A character string to control aspects of
            rewriting of the fields.
        local_id_subexpression: The subexpression indicates which
            subexpression to extract. If zero, then the text matching
            the entire regular expression is extracted. If non-zero,
            then the regex must contain at least that many sub-
            expression groups. It takes values from 0 to 8.
        log_guest_lookups:
        nas_context_info: NAS contextual information AVP.
        pc_zone_name: The SOA to store parental control records.
        proxy_password: Proxy server password used for authentication.
        proxy_url: Proxy url to download category data from and upload
            feedback to, configure for parental control. The default
            value 'None' is no longer valid as it match url regex
            pattern "^http|https://". The new default value does not get
            saved in database, but rather used for comparision with
            object created in unit test cases.
        proxy_username: Proxy server username used for authentication.
        subscriber_id: The name of AVP to be used as a subscriber.
        subscriber_id_regexp: A character string to control aspects of
            rewriting of the fields.
        subscriber_id_subexpression: The subexpression indicates which
            subexpression to extract. If zero, then the text matching
            the entire regular expression is extracted. If non-zero,
            then the regex must contain at least that many sub-
            expression groups. It takes values from 0 to 8.
    """
    _infoblox_type = 'parentalcontrol:subscriber'
    _fields = ['alt_subscriber_id', 'alt_subscriber_id_regexp',
               'alt_subscriber_id_subexpression', 'ancillaries',
               'cat_acctname', 'cat_password', 'cat_update_frequency',
               'category_url', 'enable_mgmt_only_nas',
               'enable_parental_control', 'interim_accounting_interval',
               'ip_anchors', 'ip_space_disc_regexp',
               'ip_space_disc_subexpression', 'ip_space_discriminator',
               'local_id', 'local_id_regexp', 'local_id_subexpression',
               'log_guest_lookups', 'nas_context_info', 'pc_zone_name',
               'proxy_password', 'proxy_url', 'proxy_username',
               'subscriber_id', 'subscriber_id_regexp',
               'subscriber_id_subexpression']
    _search_for_update_fields = ['alt_subscriber_id', 'local_id',
                                 'subscriber_id']
    _updateable_search_fields = ['alt_subscriber_id', 'local_id',
                                 'subscriber_id']
    _all_searchable_fields = ['alt_subscriber_id', 'local_id', 'subscriber_id']
    _return_fields = ['alt_subscriber_id', 'local_id', 'subscriber_id']
    _remap = {}
    _shadow_fields = ['_ref']


class ParentalcontrolSubscriberrecord(InfobloxObject):
    """ ParentalcontrolSubscriberrecord: Parental control subscriber
    record object.
    Corresponds to WAPI object 'parentalcontrol:subscriberrecord'

    This object represents a set of parental control properties for
    subscriber record.

    Attributes:
        accounting_session_id: accounting_session_id
        alt_ip_addr: alt_ip_addr
        ans0: ans0
        ans1: ans1
        ans2: ans2
        ans3: ans3
        ans4: ans4
        black_list: black_list
        bwflag: bwflag
        dynamic_category_policy: dynamic_category_policy
        flags: flags
        ip_addr: ip_addr
        ipsd: ipsd
        localid: localid
        nas_contextual: nas_contextual
        parental_control_policy: parental_control_policy
        prefix: prefix
        proxy_all: proxy_all
        site: site
        subscriber_id: subscriber_id
        subscriber_secure_policy: subscriber_secure_policy
        unknown_category_policy: unknown_category_policy
        white_list: white_list
        wpc_category_policy: wpc_category_policy
    """
    _infoblox_type = 'parentalcontrol:subscriberrecord'
    _fields = ['accounting_session_id', 'alt_ip_addr', 'ans0', 'ans1', 'ans2',
               'ans3', 'ans4', 'black_list', 'bwflag',
               'dynamic_category_policy', 'flags', 'ip_addr', 'ipsd',
               'localid', 'nas_contextual', 'parental_control_policy',
               'prefix', 'proxy_all', 'site', 'subscriber_id',
               'subscriber_secure_policy', 'unknown_category_policy',
               'white_list', 'wpc_category_policy']
    _search_for_update_fields = ['ip_addr', 'ipsd', 'localid', 'prefix',
                                 'site', 'subscriber_id']
    _updateable_search_fields = ['ip_addr', 'ipsd', 'localid', 'prefix',
                                 'site', 'subscriber_id']
    _all_searchable_fields = ['ip_addr', 'ipsd', 'localid', 'prefix', 'site',
                              'subscriber_id']
    _return_fields = ['accounting_session_id', 'ip_addr', 'ipsd', 'localid',
                      'prefix', 'site', 'subscriber_id']
    _remap = {}
    _shadow_fields = ['_ref']


class ParentalcontrolSubscribersite(InfobloxObject):
    """ ParentalcontrolSubscribersite: Subscriber site parental control
    properties object.
    Corresponds to WAPI object 'parentalcontrol:subscribersite'

    This object represents a set of parental control properties for
    subscriber site.

    Attributes:
        abss: The list of ABS for the site.
        block_size: The size of the Deterministic NAT block-size.
        blocking_ipv4_vip1: The IPv4 Address of the blocking server.
        blocking_ipv4_vip2: The IPv4 Address of the blocking server.
        blocking_ipv6_vip1: The IPv6 Address of the blocking server.
        blocking_ipv6_vip2: The IPv6 Address of the blocking server.
        comment: The human readable comment for the site.
        dca_sub_bw_list: Enable/disable the DCA subscriber B/W list
            support.
        dca_sub_query_count: Enable/disable the DCA subscriber query
            count.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        first_port: The start of the first Deterministic block.
        maximum_subscribers: The max number of subscribers for the site.
            It is used to configure the cache size.
        members: The list of members for the site.
        msps: The list of MSP for the site.
        name: The name of the site.
        nas_gateways: The list of accounting log servers.
        nas_port: The port number to reach the collector.
        proxy_rpz_passthru: Enables Proxy RPZ PASSTGHRU.
        spms: The list of SPM for the site.
        stop_anycast: Stop the anycast service when the subscriber
            service is in the interim state.
        strict_nat: Restrict subscriber cache entries to NATed clients.
    """
    _infoblox_type = 'parentalcontrol:subscribersite'
    _fields = ['abss', 'block_size', 'blocking_ipv4_vip1',
               'blocking_ipv4_vip2', 'blocking_ipv6_vip1',
               'blocking_ipv6_vip2', 'comment', 'dca_sub_bw_list',
               'dca_sub_query_count', 'extattrs', 'first_port',
               'maximum_subscribers', 'members', 'msps', 'name',
               'nas_gateways', 'nas_port', 'proxy_rpz_passthru', 'spms',
               'stop_anycast', 'strict_nat']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['blocking_ipv4_vip1', 'blocking_ipv4_vip2',
                                 'blocking_ipv6_vip1', 'blocking_ipv6_vip2',
                                 'comment']
    _all_searchable_fields = ['blocking_ipv4_vip1', 'blocking_ipv4_vip2',
                              'blocking_ipv6_vip1', 'blocking_ipv6_vip2',
                              'comment', 'name']
    _return_fields = ['block_size', 'dca_sub_bw_list', 'dca_sub_query_count',
                      'extattrs', 'first_port', 'name', 'stop_anycast',
                      'strict_nat']
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
    """ Permission: Permissions object.
    Corresponds to WAPI object 'permission'

    Limited-access admin groups can access certain DHCP resources only
    if their administrative permissions are defined. By default, the
    appliance denies access when a limited-access admin group does not
    have defined permissions. You can grant admin groups read-only or
    read/write permission, or deny access by using this object.

    Attributes:
        group: The name of the admin group this permission applies to.
        object: A reference to a WAPI object, which will be the object
            this permission applies to.
        permission: The type of permission.
        resource_type: The type of resource this permission applies to.
            If 'object' is set, the permission is going to apply to
            child objects of the specified type, for example if 'object'
            was set to an authoritative zone reference and
            'resource_type' was set to 'A', the permission would apply
            to A Resource Records within the specified zone.
        role: The name of the role this permission applies to.
    """
    _infoblox_type = 'permission'
    _fields = ['group', 'object', 'permission', 'resource_type', 'role']
    _search_for_update_fields = ['group', 'permission', 'resource_type',
                                 'role']
    _updateable_search_fields = ['group', 'object', 'permission',
                                 'resource_type', 'role']
    _all_searchable_fields = ['group', 'object', 'permission', 'resource_type',
                              'role']
    _return_fields = ['group', 'permission', 'resource_type', 'role']
    _remap = {}
    _shadow_fields = ['_ref']


class PxgridEndpoint(InfobloxObject):
    """ PxgridEndpoint: The PXGrid endpoint object.
    Corresponds to WAPI object 'pxgrid:endpoint'

    The pxgrid endpoint object represents the settings of a particular
    PXGRID endpoint.

    Attributes:
        address: The pxgrid endpoint IPv4 Address or IPv6 Address or
            Fully-Qualified Domain Name (FQDN)
        client_certificate_subject: The Cisco ISE client certificate
            subject.
        client_certificate_token: The token returned by the uploadinit
            function call in object fileop for Cisco ISE client
            certificate.
        client_certificate_valid_from: The pxgrid endpoint client
            certificate valid from.
        client_certificate_valid_to: The pxgrid endpoint client
            certificate valid to.
        comment: The Cisco ISE endpoint descriptive comment.
        disable: Determines whether a Cisco ISE endpoint is disabled or
            not. When this is set to False, the Cisco ISE endpoint is
            enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        log_level: The log level for a notification pxgrid endpoint.
        name: The name of the pxgrid endpoint.
        network_view: The pxgrid network view name.
        outbound_member_type: The outbound member that will generate
            events.
        outbound_members: The list of members for outbound events.
        publish_settings: The Cisco ISE publish settings.
        subscribe_settings: The Cisco ISE subscribe settings.
        template_instance: The Pxgrid template instance. You cannot
            change the parameters of the pxgrid endpoint template
            instance.
        timeout: The timeout of session management (in seconds).
        vendor_identifier: The vendor identifier.
        wapi_user_name: The user name for WAPI integration.
        wapi_user_password: The user password for WAPI integration.
    """
    _infoblox_type = 'pxgrid:endpoint'
    _fields = ['address', 'client_certificate_subject',
               'client_certificate_token', 'client_certificate_valid_from',
               'client_certificate_valid_to', 'comment', 'disable', 'extattrs',
               'log_level', 'name', 'network_view', 'outbound_member_type',
               'outbound_members', 'publish_settings', 'subscribe_settings',
               'template_instance', 'timeout', 'vendor_identifier',
               'wapi_user_name', 'wapi_user_password']
    _search_for_update_fields = ['address', 'name', 'outbound_member_type']
    _updateable_search_fields = ['address', 'comment', 'log_level', 'name',
                                 'network_view', 'outbound_member_type',
                                 'vendor_identifier']
    _all_searchable_fields = ['address', 'comment', 'log_level', 'name',
                              'network_view', 'outbound_member_type',
                              'vendor_identifier']
    _return_fields = ['address', 'disable', 'extattrs', 'name',
                      'outbound_member_type']
    _remap = {}
    _shadow_fields = ['_ref']

    def test_connection(self, *args, **kwargs):
        return self._call_func("test_connection", *args, **kwargs)


class RadiusAuthservice(InfobloxObject):
    """ RadiusAuthservice: The RADIUS authentication service object.
    Corresponds to WAPI object 'radius:authservice'

    RADIUS provides authentication, accounting, and authorization
    functions.

    The NIOS appliance supports authentication using the following
    RADIUS servers: FreeRADIUS, Microsoft, Cisco, and Funk.

    When NIOS authenticates administrators against RADIUS servers, NIOS
    acts similarly to a network access server (NAS), which is a RADIUS
    client that sends authentication and accounting requests to a RADIUS
    server.

    To configure NIOS to use one or more RADIUS server groups to
    authenticate administrators, do the following: 1. Configure at least
    one RADIUS authentication server group (authentication service) 2.
    Define admin groups for the admins that are authenticated by the
    RADIUS servers and specify their privileges and settings 3. Add the
    RADIUS server groups and the admin groups that match those on RADIUS
    server to authentication policy.

    Attributes:
        acct_retries: The number of times to attempt to contact an
            accounting RADIUS server.
        acct_timeout: The number of seconds to wait for a response from
            the RADIUS server.
        auth_retries: The number of times to attempt to contact an
            authentication RADIUS server.
        auth_timeout: The number of seconds to wait for a response from
            the RADIUS server.
        cache_ttl: The TTL of cached authentication data in seconds.
        comment: The RADIUS descriptive comment.
        disable: Determines whether the RADIUS authentication service is
            disabled.
        enable_cache: Determines whether the authentication cache is
            enabled.
        mode: The way to contact the RADIUS server.
        name: The RADIUS authentication service name.
        recovery_interval: The time period to wait before retrying a
            server that has been marked as down.
        servers: The ordered list of RADIUS authentication servers.
    """
    _infoblox_type = 'radius:authservice'
    _fields = ['acct_retries', 'acct_timeout', 'auth_retries', 'auth_timeout',
               'cache_ttl', 'comment', 'disable', 'enable_cache', 'mode',
               'name', 'recovery_interval', 'servers']
    _search_for_update_fields = ['name']
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
    """ ARecord: DNS A record object.
    Corresponds to WAPI object 'record:a'

    An A (address) record maps a domain name to an IPv4 address. To
    define a specific name-to-address mapping, add an A record to a
    previously defined authoritative forward-mapping zone.

    On DELETE request, the boolean argument remove_associated_ptr
    indicates whether the associated PTR records should be removed while
    deleting the specified A record. The PTR record will be removed only
    if "Enable PTR record removal for A/AAAA records" is enabled in Grid
    DNS properties.

    Attributes:
        aws_rte53_record_info: Aws Route 53 record information.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        discovered_data: The discovered data for this A record.
        dns_name: The name for an A record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        ipv4addr: The IPv4 Address of the record.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: Name for A record in FQDN format. This value can be in
            unicode format.
        reclaimable: Determines if the record is reclaimable or not.
        shared_record_group: The name of the shared record group in
            which the record resides. This field exists only on
            db_objects if this record is a shared record.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:a'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal', 'ddns_protected',
               'disable', 'discovered_data', 'dns_name', 'extattrs',
               'forbid_reclamation', 'ipv4addr', 'last_queried',
               'ms_ad_user_data', 'name', 'reclaimable',
               'remove_associated_ptr', 'shared_record_group', 'ttl',
               'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv4addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal',
                                 'ipv4addr', 'name']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal',
                              'ipv4addr', 'name', 'reclaimable', 'view',
                              'zone']
    _return_fields = ['extattrs', 'ipv4addr', 'name', 'view']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 4


class AAAARecord(ARecordBase):
    """ AAAARecord: DNS AAAA record object.
    Corresponds to WAPI object 'record:aaaa'

    An AAAA (address) record maps a domain name to an IPv6 address. To
    define a specific name-to-address mapping, add an AAAA record to a
    previously defined authoritative forward-mapping zone.

    On DELETE request, the boolean argument remove_associated_ptr
    indicates whether the associated PTR records should be removed while
    deleting the specified AAAA record. The PTR record will be removed
    only if "Enable PTR record removal for A/AAAA records" is enabled in
    Grid DNS properties.

    Attributes:
        aws_rte53_record_info: Aws Route 53 record information.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        discovered_data: The discovered data for this AAAA record.
        dns_name: The name for an AAAA record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        ipv6addr: The IPv6 Address of the record.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: Name for the AAAA record in FQDN format. This value can be
            in unicode format.
        reclaimable: Determines if the record is reclaimable or not.
        shared_record_group: The name of the shared record group in
            which the record resides. This field exists only on
            db_objects if this record is a shared record.
        ttl: The Time To Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:aaaa'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal', 'ddns_protected',
               'disable', 'discovered_data', 'dns_name', 'extattrs',
               'forbid_reclamation', 'ipv6addr', 'last_queried',
               'ms_ad_user_data', 'name', 'reclaimable',
               'remove_associated_ptr', 'shared_record_group', 'ttl',
               'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv6addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal',
                                 'ipv6addr', 'name']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal',
                              'ipv6addr', 'name', 'reclaimable', 'view',
                              'zone']
    _return_fields = ['extattrs', 'ipv6addr', 'name', 'view']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ip']
    _ip_version = 6


class AliasRecord(InfobloxObject):
    """ AliasRecord: DNS Alias record object.
    Corresponds to WAPI object 'record:alias'

    Alias resource record  allows you to create typed aliases for
    standard DNS resource records which are resolved dynamically by an
    authoritative server. Unlike CNAME Alias can be created in the zone
    apex.

    Attributes:
        aws_rte53_record_info: Aws Route 53 record information.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creator: The record creator.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dns_name: The name for an Alias record in punycode format.
        dns_target_name: Target name in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name for an Alias record in FQDN format. This value
            can be in unicode format. Regular expression search is not
            supported for unicode values.
        target_name: Target name in FQDN format. This value can be in
            unicode format.
        target_type: Target type.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:alias'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment', 'creator',
               'disable', 'dns_name', 'dns_target_name', 'extattrs',
               'last_queried', 'name', 'target_name', 'target_type', 'ttl',
               'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'target_name', 'target_type', 'view']
    _updateable_search_fields = ['comment', 'name', 'target_name',
                                 'target_type', 'view']
    _all_searchable_fields = ['comment', 'name', 'target_name', 'target_type',
                              'view', 'zone']
    _return_fields = ['extattrs', 'name', 'target_name', 'target_type', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class CaaRecord(InfobloxObject):
    """ CaaRecord: DNS CAA record object.
    Corresponds to WAPI object 'record:caa'

    The Certification Authority Authorization (CAA) DNS resource record
    (RR) is used to specify which certificate authorities (CAs) are
    allowed to issue certificates for a domain. For further details see
    RFC-6844.

    Attributes:
        ca_flag: Flag of CAA record.
        ca_tag: Tag of CAA record.
        ca_value: Value of CAA record
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The creation time of the record.
        creator: The record creator. Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dns_name: The name of the CAA record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The CAA record name in FQDN format. This value can be in
            unicode format.
        reclaimable: Determines if the record is reclaimable or not.
        ttl: The Time to Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:caa'
    _fields = ['ca_flag', 'ca_tag', 'ca_value', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal', 'ddns_protected',
               'disable', 'dns_name', 'extattrs', 'forbid_reclamation',
               'last_queried', 'name', 'reclaimable', 'ttl', 'use_ttl', 'view',
               'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = ['ca_flag', 'ca_tag', 'ca_value', 'comment',
                                 'creator', 'ddns_principal', 'name', 'view']
    _all_searchable_fields = ['ca_flag', 'ca_tag', 'ca_value', 'comment',
                              'creator', 'ddns_principal', 'name',
                              'reclaimable', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class CNAMERecord(InfobloxObject):
    """ CNAMERecord: DNS CNAME record object.
    Corresponds to WAPI object 'record:cname'

    A CNAME record maps an alias to a canonical name. You can use CNAME
    records in both forward- and IPv4 reverse-mapping zones to serve two
    different purposes. (At this time, you cannot use CNAME records with
    IPv6 reverse-mapping zones.)

    In a forward-mapping zone, a CNAME record maps an alias to a
    canonical (or official) name. CNAME records are often more
    convenient to use than canonical names because they can be shorter
    or more descriptive.

    Attributes:
        aws_rte53_record_info: Aws Route 53 record information.
        canonical: Canonical name in FQDN format. This value can be in
            unicode format.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dns_canonical: Canonical name in punycode format.
        dns_name: The name for the CNAME record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name for a CNAME record in FQDN format. This value can
            be in unicode format. Regular expression search is not
            supported for unicode values.
        reclaimable: Determines if the record is reclaimable or not.
        shared_record_group: The name of the shared record group in
            which the record resides. This field exists only on
            db_objects if this record is a shared record.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:cname'
    _fields = ['aws_rte53_record_info', 'canonical', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal', 'ddns_protected',
               'disable', 'dns_canonical', 'dns_name', 'extattrs',
               'forbid_reclamation', 'last_queried', 'name', 'reclaimable',
               'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'creator',
                                 'ddns_principal', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'creator',
                              'ddns_principal', 'name', 'reclaimable', 'view',
                              'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DhcidRecord(InfobloxObject):
    """ DhcidRecord: DNS DHCID record object.
    Corresponds to WAPI object 'record:dhcid'

    The DHCID DNS resource record (RR) is used to associate the DNS
    domain names with the DHCP clients using the domain names.

    Attributes:
        creation_time: The creation time of the record.
        creator: The record creator.
        dhcid: The Base64 encoded DHCP client information.
        dns_name: The name for the DHCID record in punycode format.
        name: The name of the DHCID record in FQDN format.
        ttl: The Time To Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:dhcid'
    _fields = ['creation_time', 'creator', 'dhcid', 'dns_name', 'name', 'ttl',
               'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['creator', 'dhcid', 'name', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DnameRecord(InfobloxObject):
    """ DnameRecord: DNS DNAME record object.
    Corresponds to WAPI object 'record:dname'

    A DNAME record maps all the names in one domain to those in another
    domain, essentially substituting one domain name suffix with the
    other.

    Attributes:
        cloud_info: The structure containing all cloud API related
            information for this object.
        comment: The comment for the record.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed.
        disable: Determines if the record is disabled.
        dns_name: Name of a DNS DNAME record in punycode format.
        dns_target: The target domain name of the DNS DNAME record in
            punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if reclamation is allowed for the
            record.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name of the DNS DNAME record in FQDN format.
        reclaimable: Determines if the record is reclaimable.
        shared_record_group: The name of the shared record group in
            which the record resides. This field exists only on
            db_objects if this record is a shared record.
        target: The target domain name of the DNS DNAME record in FQDN
            format.
        ttl: Time To Live (TTL) value for the record. A 32-bit unsigned
            integer that represents the duration, in seconds, that the
            record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides, for
            example "external".
        zone: The name of the zone in which the record resides. For
            example: "zone.com". If a view is not specified when
            searching by zone, the default view is used.
    """
    _infoblox_type = 'record:dname'
    _fields = ['cloud_info', 'comment', 'creation_time', 'creator',
               'ddns_principal', 'ddns_protected', 'disable', 'dns_name',
               'dns_target', 'extattrs', 'forbid_reclamation', 'last_queried',
               'name', 'reclaimable', 'shared_record_group', 'target', 'ttl',
               'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'target', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal',
                                 'name', 'target']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'name',
                              'reclaimable', 'target', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'target', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DnskeyRecord(InfobloxObject):
    """ DnskeyRecord: DNS DNSKEY record object.
    Corresponds to WAPI object 'record:dnskey'

    The DNSKEY resource record stores public keys for the DNSSEC
    authentication process. The DNSKEY records are generated
    automatically when the corresponding authoritative zone is signed.
    The DNSKEY resource record object is read-only.

    The DNSKEY resource record is defined in RFC 4034.

    Attributes:
        algorithm: The public key encryption algorithm of a DNSKEY
            Record object.
        comment: The comment for the record.
        creation_time: The creation time of the record.
        creator: The record creator.
        dns_name: Name of a DNSKEY record in punycode format.
        flags: The flags field is a 16-bit unsigned integer. Currently,
            only two bits of this value are used: the least significant
            bit and bit 7. The other bits are reserved for future use
            and must be zero. If bit 7 is set to 1, the key is a DNS
            zone key. Otherwise, the key is not a zone key and cannot be
            used to verify zone data. The least significant bit
            indicates "secure entry point property". If it is not zero,
            the key is a key signing key (KSK type). Otherwise, the key
            type is ZSK.
        key_tag: The key tag identifying the public key of a DNSKEY
            Record object.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name of the DNSKEY record in FQDN format. It has to be
            the same as the zone, where the record resides.
        public_key: The public key. The format of the returned value
            depends on the key algorithm.
        ttl: The Time To Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:dnskey'
    _fields = ['algorithm', 'comment', 'creation_time', 'creator', 'dns_name',
               'flags', 'key_tag', 'last_queried', 'name', 'public_key', 'ttl',
               'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'comment', 'creator', 'flags',
                              'key_tag', 'name', 'public_key', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DsRecord(InfobloxObject):
    """ DsRecord: DNS DS record object.
    Corresponds to WAPI object 'record:ds'

    The DS key record is a part of the DNS security extension records.
    The DS RR contains a hash of a child zone's KSK and can be used as a
    trust anchor in some security-aware resolvers and to create a secure
    delegation point for a signed subzone in DNS servers. It is used to
    authorize the DNSKEY records of the child zone and thus to establish
    the DNSSEC chain of trust.

    The DS resource record is defined in RFC 4034.

    The DS resource records are automatically generated upon the signing
    of the child zone of an authoritative zone residing on the
    appliance.

    Attributes:
        algorithm: The algorithm of the DNSKEY RR to which this DS RR
            refers. It uses the same algorithm values and types as the
            corresponding DNSKEY RR.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: The comment for the record.
        creation_time: The creation time of the record.
        creator: Creator of the record.
        digest: The digest of the DNSKEY resource record that is stored
            in a DS Record object.
        digest_type: The algorithm used to construct the digest.
        dns_name: The name for the DS record in punycode format.
        key_tag: The key tag value that is used to determine which key
            to use to verify signatures.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name of the DNS DS record in FQDN format.
        ttl: The Time To Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:ds'
    _fields = ['algorithm', 'cloud_info', 'comment', 'creation_time',
               'creator', 'digest', 'digest_type', 'dns_name', 'key_tag',
               'last_queried', 'name', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'comment', 'creator', 'digest_type',
                              'key_tag', 'name', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class DtclbdnRecord(InfobloxObject):
    """ DtclbdnRecord: DTC LBDN object.
    Corresponds to WAPI object 'record:dtclbdn'

    Load Balanced Domain Name (LBDN) is a Load balanced domain name
    record type, which is served by Infoblox Name Servers. LBDN is a
    qualified domain name associated with a specific service such as
    ftp.abc.com or www.abc.com. A LBDN record must be associated to a
    zone for which Infoblox is authoritative for. User may assign
    multiple "Resource Pools" to a LBDN record. User may also assign one
    or more DNS Distribution (Load balancing) methods an LBDN record.
    User must not be able to create multiple LBDNs for the same name.

    Attributes:
        comment: The comment for the DTC LBDN record object; maximum 256
            characters.
        disable: Determines whether the DTC LBDN is disabled or not.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        lbdn: The DTC LBDN object.
        name: The display name of the DTC LBDN record.
        pattern: An FQDN pattern, LBDN wildcards can be used.
        view: The name of the DNS View in which the record resides.
        zone: The name of the zone in which the record resides.
    """
    _infoblox_type = 'record:dtclbdn'
    _fields = ['comment', 'disable', 'extattrs', 'last_queried', 'lbdn',
               'name', 'pattern', 'view', 'zone']
    _search_for_update_fields = ['name', 'view', 'zone']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'disable', 'name', 'pattern', 'view',
                              'zone']
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
    """ HostRecordV4: DNS Host record object.
    Corresponds to WAPI object 'record:host'

    A host record defines attributes for a node, such as the name-to-
    address and address-to-name mapping. This alleviates having to
    specify an A record and a PTR record separately for the same node. A
    host can also define aliases and DHCP fixed address nodes. The zone
    must be created first before adding a host record for the zone.

    Attributes:
        aliases: This is a list of aliases for the host. The aliases
            must be in FQDN format. This value can be in unicode format.
        allow_telnet: This field controls whether the credential is used
            for both the Telnet and SSH credentials. If set to False,
            the credential is used only for SSH.
        cli_credentials: The CLI credentials for the host record.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        configure_for_dns: When configure_for_dns is false, the host
            does not have parent zone information.
        creation_time: The time of the record creation in Epoch seconds
            format.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        device_description: The description of the device.
        device_location: The location of the device.
        device_type: The type of the device.
        device_vendor: The vendor of the device.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        disable_discovery: Determines if the discovery for the record is
            disabled or not. False means that the discovery is enabled.
        dns_aliases: The list of aliases for the host in punycode
            format.
        dns_name: The name for a host record in punycode format.
        enable_immediate_discovery: Determines if the discovery for the
            record should be immediately enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv4addrs: This is a list of IPv4 Addresses for the host.
        ipv6addrs: This is a list of IPv6 Addresses for the host.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: The host name in FQDN format This value can be in unicode
            format. Regular expression search is not supported for
            unicode values.
        network_view: The name of the network view in which the host
            record resides.
        restart_if_needed: Restarts the member service.
        rrset_order: The value of this field specifies the order in
            which resource record sets are returned.The possible values
            are "cyclic", "random" and "fixed".
        snmp3_credential: The SNMPv3 credential for a host record.
        snmp_credential: The SNMPv1 or SNMPv2 credential for a host
            record.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_cli_credentials: If set to true, the CLI credential will
            override member-level settings.
        use_snmp3_credential: Determines if the SNMPv3 credential should
            be used for the record.
        use_snmp_credential: If set to true, the SNMP credential will
            override member-level settings.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:host'
    _fields = ['aliases', 'allow_telnet', 'cli_credentials', 'cloud_info',
               'comment', 'configure_for_dns', 'creation_time',
               'ddns_protected', 'device_description', 'device_location',
               'device_type', 'device_vendor', 'disable', 'disable_discovery',
               'dns_aliases', 'dns_name', 'enable_immediate_discovery',
               'extattrs', 'ipv4addrs', 'last_queried', 'ms_ad_user_data',
               'name', 'network_view', 'restart_if_needed', 'rrset_order',
               'snmp3_credential', 'snmp_credential', 'ttl',
               'use_cli_credentials', 'use_snmp3_credential',
               'use_snmp_credential', 'use_ttl', 'view', 'zone', 'mac']
    _search_for_update_fields = ['name', 'view', 'mac', 'ipv4addr']
    _updateable_search_fields = ['comment', 'device_description',
                                 'device_location', 'device_type',
                                 'device_vendor', 'name', 'view']
    _all_searchable_fields = ['comment', 'device_description',
                              'device_location', 'device_type',
                              'device_vendor', 'name', 'network_view', 'view',
                              'zone', 'mac', 'ipv4addr']
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
        """:meta private:"""
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
    """ HostRecordV6: DNS Host record object.
    Corresponds to WAPI object 'record:host'

    A host record defines attributes for a node, such as the name-to-
    address and address-to-name mapping. This alleviates having to
    specify an A record and a PTR record separately for the same node. A
    host can also define aliases and DHCP fixed address nodes. The zone
    must be created first before adding a host record for the zone.

    Attributes:
        aliases: This is a list of aliases for the host. The aliases
            must be in FQDN format. This value can be in unicode format.
        allow_telnet: This field controls whether the credential is used
            for both the Telnet and SSH credentials. If set to False,
            the credential is used only for SSH.
        cli_credentials: The CLI credentials for the host record.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        configure_for_dns: When configure_for_dns is false, the host
            does not have parent zone information.
        creation_time: The time of the record creation in Epoch seconds
            format.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        device_description: The description of the device.
        device_location: The location of the device.
        device_type: The type of the device.
        device_vendor: The vendor of the device.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        disable_discovery: Determines if the discovery for the record is
            disabled or not. False means that the discovery is enabled.
        dns_aliases: The list of aliases for the host in punycode
            format.
        dns_name: The name for a host record in punycode format.
        enable_immediate_discovery: Determines if the discovery for the
            record should be immediately enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv4addrs: This is a list of IPv4 Addresses for the host.
        ipv6addrs: This is a list of IPv6 Addresses for the host.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: The host name in FQDN format This value can be in unicode
            format. Regular expression search is not supported for
            unicode values.
        network_view: The name of the network view in which the host
            record resides.
        restart_if_needed: Restarts the member service.
        rrset_order: The value of this field specifies the order in
            which resource record sets are returned.The possible values
            are "cyclic", "random" and "fixed".
        snmp3_credential: The SNMPv3 credential for a host record.
        snmp_credential: The SNMPv1 or SNMPv2 credential for a host
            record.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_cli_credentials: If set to true, the CLI credential will
            override member-level settings.
        use_snmp3_credential: Determines if the SNMPv3 credential should
            be used for the record.
        use_snmp_credential: If set to true, the SNMP credential will
            override member-level settings.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:host'
    _fields = ['aliases', 'allow_telnet', 'cli_credentials', 'cloud_info',
               'comment', 'configure_for_dns', 'creation_time',
               'ddns_protected', 'device_description', 'device_location',
               'device_type', 'device_vendor', 'disable', 'disable_discovery',
               'dns_aliases', 'dns_name', 'enable_immediate_discovery',
               'extattrs', 'ipv6addrs', 'last_queried', 'ms_ad_user_data',
               'name', 'network_view', 'restart_if_needed', 'rrset_order',
               'snmp3_credential', 'snmp_credential', 'ttl',
               'use_cli_credentials', 'use_snmp3_credential',
               'use_snmp_credential', 'use_ttl', 'view', 'zone', 'mac']
    _search_for_update_fields = ['name', 'view', 'mac', 'ipv6addr']
    _updateable_search_fields = ['comment', 'device_description',
                                 'device_location', 'device_type',
                                 'device_vendor', 'name', 'view']
    _all_searchable_fields = ['comment', 'device_description',
                              'device_location', 'device_type',
                              'device_vendor', 'name', 'network_view', 'view',
                              'zone', 'mac', 'ipv6addr']
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
        """:meta private:"""
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
    """ IPv4HostAddress: IPv4 Host address object.
    Corresponds to WAPI object 'record:host_ipv4addr'

    A Host Address is an object used to specify addresses in the
    record.host object .

    Fields other than ipv4addr, host and configure_for_dhcp are returned
    only when configure_for_dhcp is true.

    Attributes:
        bootfile: The name of the boot file the client must download.
        bootserver: The IP address or hostname of the boot file server
            where the boot file is stored.
        configure_for_dhcp: Set this to True to enable the DHCP
            configuration for this host address.
        deny_bootp: Set this to True to disable the BOOTP settings and
            deny BOOTP boot requests.
        discover_now_status: The discovery status of this Host Address.
        discovered_data: The discovered data for this Host Address.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients. You
            can specify the duration of time it takes a host to connect
            to a boot server, such as a TFTP server, and download the
            file it needs to boot. For example, set a longer lease time
            if the client downloads an OS (operating system) or
            configuration file, or set a shorter lease time if the
            client downloads only configuration changes. Enter the lease
            time for the preboot execution environment for hosts to boot
            remotely from a server.
        host: The host to which the host address belongs, in FQDN
            format. It is only present when the host address object is
            not returned as part of a host.
        ignore_client_requested_options: If this field is set to false,
            the appliance returns all DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        ipv4addr: The IPv4 Address of the host.
        is_invalid_mac: This flag reflects whether the MAC address for
            this host address is invalid.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        logic_filter_rules: This field contains the logic filters to be
            applied on the this host address.This list corresponds to
            the match rules that are written to the dhcpd configuration
            file.
        mac: The MAC address for this host address.
        match_client: Set this to 'MAC_ADDRESS' to assign the IP address
            to the selected host, provided that the MAC address of the
            requesting host matches the MAC address that you specify in
            the field.Set this to 'RESERVED' to reserve this particular
            IP address for future use, or if the IP address is
            statically configured on a system (the Infoblox server does
            not assign the address from a DHCP request).
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        network: The network of the host address, in FQDN/CIDR format.
        network_view: The name of the network view in which the host
            address resides.
        nextserver: The name in FQDN format and/or IPv4 Address of the
            next server that the host needs to boot.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        pxe_lease_time: The lease time for PXE clients, see
            enable_pxe_lease_time for more information.
        reserved_interface: The reference to the reserved interface to
            which the device belongs.
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_deny_bootp: Use flag for: deny_bootp
        use_for_ea_inheritance: Set this to True when using this host
            address for EA inheritance.
        use_ignore_client_requested_options: Use flag for:
            ignore_client_requested_options
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_pxe_lease_time: Use flag for: pxe_lease_time
    """
    _infoblox_type = 'record:host_ipv4addr'
    _fields = ['bootfile', 'bootserver', 'configure_for_dhcp', 'deny_bootp',
               'discover_now_status', 'discovered_data',
               'enable_pxe_lease_time', 'host',
               'ignore_client_requested_options', 'ipv4addr', 'is_invalid_mac',
               'last_queried', 'logic_filter_rules', 'mac', 'match_client',
               'ms_ad_user_data', 'network', 'network_view', 'nextserver',
               'options', 'pxe_lease_time', 'reserved_interface',
               'use_bootfile', 'use_bootserver', 'use_deny_bootp',
               'use_for_ea_inheritance', 'use_ignore_client_requested_options',
               'use_logic_filter_rules', 'use_nextserver', 'use_options',
               'use_pxe_lease_time']
    _search_for_update_fields = ['ipv4addr', 'mac']
    _updateable_search_fields = ['ipv4addr', 'mac']
    _all_searchable_fields = ['ipv4addr', 'mac', 'network_view']
    _return_fields = ['configure_for_dhcp', 'host', 'ipv4addr', 'mac']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ip']

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': DhcpOption.from_dict,
    }


class IPv6HostAddress(InfobloxObject):
    """ IPv6HostAddress: IPv6 Host address object.
    Corresponds to WAPI object 'record:host_ipv6addr'

    An IPv6 host address is an object used to specify addresses in the
    record.host object .

    Fields other than ipv6addr, host and configure_for_dhcp are returned
    only when configure_for_dhcp is set to True.

    Attributes:
        address_type: Type of the DHCP IPv6 Host Address object.
        configure_for_dhcp: Set this to True to enable the DHCP
            configuration for this IPv6 host address.
        discover_now_status: The discovery status of this IPv6 Host
            Address.
        discovered_data: The discovered data for this host address.
        domain_name: Use this method to set or retrieve the domain_name
            value of the DHCP IPv6 Host Address object.
        domain_name_servers: The IPv6 addresses of DNS recursive name
            servers to which the DHCP client can send name resolution
            requests. The DHCP server includes this information in the
            DNS Recursive Name Server option in Advertise, Rebind,
            Information-Request, and Reply messages.
        duid: DHCPv6 Unique Identifier (DUID) of the address object.
        host: The host to which the IPv6 host address belongs, in FQDN
            format. It is only present when the host address object is
            not returned as part of a host.
        ipv6addr: The IPv6 Address prefix of the DHCP IPv6 Host Address
            object.
        ipv6prefix: The IPv6 Address prefix of the DHCP IPv6 Host
            Address object.
        ipv6prefix_bits: Prefix bits of the DHCP IPv6 Host Address
            object.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        logic_filter_rules: This field contains the logic filters to be
            applied on the this host address.This list corresponds to
            the match rules that are written to the dhcpd configuration
            file.
        match_client: Set this to 'DUID' to assign the IP address to the
            selected host, provided that the DUID of the requesting host
            matches the DUID that you specify in the field.Set this to
            'RESERVED' to reserve this particular IP address for future
            use, or if the IP address is statically configured on a
            system (the Infoblox server does not assign the address from
            a DHCP request).
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        network: The network of the host address, in FQDN/CIDR format.
        network_view: The name of the network view in which the host
            address resides.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        preferred_lifetime: Use this method to set or retrieve the
            preferred lifetime value of the DHCP IPv6 Host Address
            object.
        reserved_interface: The reference to the reserved interface to
            which the device belongs.
        use_domain_name: Use flag for: domain_name
        use_domain_name_servers: Use flag for: domain_name_servers
        use_for_ea_inheritance: Set this to True when using this host
            address for EA inheritance.
        use_logic_filter_rules: Use flag for: logic_filter_rules
        use_options: Use flag for: options
        use_preferred_lifetime: Use flag for: preferred_lifetime
        use_valid_lifetime: Use flag for: valid_lifetime
        valid_lifetime: Use this method to set or retrieve the valid
            lifetime value of the DHCP IPv6 Host Address object.
    """
    _infoblox_type = 'record:host_ipv6addr'
    _fields = ['address_type', 'configure_for_dhcp', 'discover_now_status',
               'discovered_data', 'domain_name', 'domain_name_servers', 'duid',
               'host', 'ipv6addr', 'ipv6prefix', 'ipv6prefix_bits',
               'last_queried', 'logic_filter_rules', 'match_client',
               'ms_ad_user_data', 'network', 'network_view', 'options',
               'preferred_lifetime', 'reserved_interface', 'use_domain_name',
               'use_domain_name_servers', 'use_for_ea_inheritance',
               'use_logic_filter_rules', 'use_options',
               'use_preferred_lifetime', 'use_valid_lifetime',
               'valid_lifetime']
    _search_for_update_fields = ['duid', 'ipv6addr']
    _updateable_search_fields = ['duid', 'ipv6addr', 'ipv6prefix',
                                 'ipv6prefix_bits']
    _all_searchable_fields = ['duid', 'ipv6addr', 'ipv6prefix',
                              'ipv6prefix_bits', 'network_view']
    _return_fields = ['configure_for_dhcp', 'duid', 'host', 'ipv6addr']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ip']

    _custom_field_processing = {
        'logic_filter_rules': Logicfilterrule.from_dict,
        'options': DhcpOption.from_dict,
    }


class MXRecord(InfobloxObject):
    """ MXRecord: DNS MX record object.
    Corresponds to WAPI object 'record:mx'

    An MX (mail exchanger) record maps a domain name to a mail
    exchanger. A mail exchanger is a server that either delivers or
    forwards mail. You can specify one or more mail exchangers for a
    zone, as well as the preference for using each mail exchanger. A
    standard MX record applies to a particular domain or subdomain.

    Attributes:
        aws_rte53_record_info: Aws Route 53 record information.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dns_mail_exchanger: The Mail exchanger name in punycode format.
        dns_name: The name for a MX record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        mail_exchanger: Mail exchanger name in FQDN format. This value
            can be in unicode format.
        name: Name for the MX record in FQDN format. This value can be
            in unicode format.
        preference: Preference value, 0 to 65535 (inclusive) in 32-bit
            unsigned integer format.
        reclaimable: Determines if the record is reclaimable or not.
        shared_record_group: The name of the shared record group in
            which the record resides. This field exists only on
            db_objects if this record is a shared record.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:mx'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal', 'ddns_protected',
               'disable', 'dns_mail_exchanger', 'dns_name', 'extattrs',
               'forbid_reclamation', 'last_queried', 'mail_exchanger', 'name',
               'preference', 'reclaimable', 'shared_record_group', 'ttl',
               'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['mail_exchanger', 'name', 'preference',
                                 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal',
                                 'mail_exchanger', 'name', 'preference',
                                 'view']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal',
                              'mail_exchanger', 'name', 'preference',
                              'reclaimable', 'view', 'zone']
    _return_fields = ['extattrs', 'mail_exchanger', 'name', 'preference',
                      'view']
    _remap = {}
    _shadow_fields = ['_ref']


class NaptrRecord(InfobloxObject):
    """ NaptrRecord: DNS NAPTR record object.
    Corresponds to WAPI object 'record:naptr'

    A DNS NAPTR object represents a Naming Authority Pointer (NAPTR)
    resource record. This resource record specifies a regular
    expression-based rewrite rule that, when applied to an existing
    string, produces a new domain name or URI.

    Attributes:
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dns_name: The name of the NAPTR record in punycode format.
        dns_replacement: The replacement field of the NAPTR record in
            punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        flags: The flags used to control the interpretation of the
            fields for an NAPTR record object. Supported values for the
            flags field are "U", "S", "P" and "A".
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name of the NAPTR record in FQDN format. This value
            can be in unicode format.
        order: The order parameter of the NAPTR records. This parameter
            specifies the order in which the NAPTR rules are applied
            when multiple rules are present. Valid values are from 0 to
            65535 (inclusive), in 32-bit unsigned integer format.
        preference: The preference of the NAPTR record. The preference
            field determines the order NAPTR records are processed when
            multiple records with the same order parameter are present.
            Valid values are from 0 to 65535 (inclusive), in 32-bit
            unsigned integer format.
        reclaimable: Determines if the record is reclaimable or not.
        regexp: The regular expression-based rewriting rule of the NAPTR
            record. This should be a POSIX compliant regular expression,
            including the substitution rule and flags. Refer to RFC 2915
            for the field syntax details.
        replacement: The replacement field of the NAPTR record object.
            For nonterminal NAPTR records, this field specifies the next
            domain name to look up. This value can be in unicode format.
        services: The services field of the NAPTR record object; maximum
            128 characters. The services field contains protocol and
            service identifiers, such as "http+E2U" or "SIPS+D2T".
        ttl: The Time to Live (TTL) value for the NAPTR record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:naptr'
    _fields = ['cloud_info', 'comment', 'creation_time', 'creator',
               'ddns_principal', 'ddns_protected', 'disable', 'dns_name',
               'dns_replacement', 'extattrs', 'flags', 'forbid_reclamation',
               'last_queried', 'name', 'order', 'preference', 'reclaimable',
               'regexp', 'replacement', 'services', 'ttl', 'use_ttl', 'view',
               'zone']
    _search_for_update_fields = ['name', 'order', 'preference', 'replacement',
                                 'services', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal',
                                 'flags', 'name', 'order', 'preference',
                                 'replacement', 'services']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'flags',
                              'name', 'order', 'preference', 'reclaimable',
                              'replacement', 'services', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'order', 'preference', 'regexp',
                      'replacement', 'services', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class NsRecord(InfobloxObject):
    """ NsRecord: DNS NS record object.
    Corresponds to WAPI object 'record:ns'

    A DNS NS record identifies an authoritative DNS server for a domain.
    Each authoritative DNS server must have an NS record. The appliance
    automatically creates an NS record when you assign a grid member as
    the primary server for a zone. You can manually create NS records
    for other zones.

    Attributes:
        addresses: The list of zone name servers.
        cloud_info: Structure containing all cloud API related
            information for this object.
        creator: The record creator.
        dns_name: The name of the NS record in punycode format.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        ms_delegation_name: The MS delegation point name.
        name: The name of the NS record in FQDN format. This value can
            be in unicode format.
        nameserver: The domain name of an authoritative server for the
            redirected zone.
        policy: The host name policy for the record.
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:ns'
    _fields = ['addresses', 'cloud_info', 'creator', 'dns_name',
               'last_queried', 'ms_delegation_name', 'name', 'nameserver',
               'policy', 'view', 'zone']
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
    """ NsecRecord: DNS NSEC record object.
    Corresponds to WAPI object 'record:nsec'

    NSEC resource record is one of the resource records included in the
    DNS security extension mechanism (DNSSEC). This record is used to
    provide authenticated denial of existence of a resource record in
    response to a resolver query.

    NSEC resource records are defined in RFC 4034.

    NSEC records are automatically generated upon the signing of an
    authoritative zone.

    The name part of a DNS NSEC object reference has the following
    components:

    The name of the record.

    The name of the view.

    Example: record:nsec/ZG5zLmJpsaG9zdA:us.example.com/default.external

    Attributes:
        cloud_info: Structure containing all cloud API related
            information for this object.
        creation_time: Time that the record was created.
        creator: Creator of the record.
        dns_name: Name for an NSEC record in punycode format.
        dns_next_owner_name: Name of the next owner in punycode format.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name of the NSEC record in FQDN format.
        next_owner_name: Name of the next owner that has authoritative
            data or that contains a delegation point NS record.
        rrset_types: The RRSet types that exist at the original owner
            name of the NSEC RR.
        ttl: The Time To Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:nsec'
    _fields = ['cloud_info', 'creation_time', 'creator', 'dns_name',
               'dns_next_owner_name', 'last_queried', 'name',
               'next_owner_name', 'rrset_types', 'ttl', 'use_ttl', 'view',
               'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['creator', 'name', 'next_owner_name', 'view',
                              'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class Nsec3Record(InfobloxObject):
    """ Nsec3Record: DNS NSEC3 record object.
    Corresponds to WAPI object 'record:nsec3'

    When a name server receives a request for a domain name that does
    not exist in a zone, the name server sends an authenticated negative
    response in the form of an NSEC or NSEC3 RR. NSEC and NSEC3 records
    contain the next secure domain name in a zone and list the RR types
    present at the NSEC or NSEC3 RR's owner name. The difference between
    an NSEC and NSEC3 RRs is that the owner name in an NSEC3 RR is a
    cryptographic hash of the original owner name prepended to the name
    of the zone. NSEC3 RRs protect against zone enumeration.

    NSEC3 resource record is desribed in RFC 5155.

    NSEC3 records are automatically generated during signing of the
    corresponding zone.

    The name part of a DNS NSEC3 object reference has the following
    components:

    The name of the record.

    The name of the view.

    Example:
    record:nsec3/ZG5zLmJpsaG9zdA:us.example.com/default.external

    Attributes:
        algorithm: The hash algorithm that was used.
        cloud_info: Structure containing all cloud API related
            information for this object.
        creation_time: The creation time of the record.
        creator: Creator of the record.
        dns_name: Name for an NSEC3 record in punycode format.
        flags: The set of 8 one-bit flags, of which only one flag, the
            Opt-Out flag, is defined by RFC 5155. The Opt-Out flag
            indicates whether the NSEC3 record covers unsigned
            delegations.
        iterations: The number of times the hash function was performed.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name of the NSEC3 record in FQDN format.
        next_owner_name: The hashed next owner name that has
            authoritative data or that contains a delegation point NS
            record.
        rrset_types: The RRSet types that exist at the original owner
            name of the NSEC3 RR.
        salt: A series of case-insensitive hexadecimal digits. It is
            appended to the original owner name as protection against
            pre-calculated dictionary attacks. A new salt value is
            generated when ZSK rolls over. You can control the period of
            the rollover. For random salt values, the selected length is
            between one and 15 octets.
        ttl: The Time To Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:nsec3'
    _fields = ['algorithm', 'cloud_info', 'creation_time', 'creator',
               'dns_name', 'flags', 'iterations', 'last_queried', 'name',
               'next_owner_name', 'rrset_types', 'salt', 'ttl', 'use_ttl',
               'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'creator', 'flags', 'iterations',
                              'name', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class Nsec3ParamRecord(InfobloxObject):
    """ Nsec3ParamRecord: DNS NSEC3 record object.
    Corresponds to WAPI object 'record:nsec3param'

    An authoritative DNS server uses NSEC3PARAM RRs to determine which
    NSEC3 records it includes in its negative responses. An NSEC3PARAM
    RR contains the parameters that an authoritative server needs to
    calculate hashed owner names. As stated in RFC 5155, the presence of
    an NSEC3PARAM RR at a zone apex indicates that the specified
    parameters may be used by authoritative servers to choose an
    appropriate set of NSEC3 RRs for negative responses.

    The NSEC3PARAM resource record is desribed in RFC 5155.

    The NSEC3PARAM record is generated automatically upon the signing of
    the corresponding zone.

    The name part of a DNS NSEC3PARAM object reference has the following
    components:

    The name of the record.

    The name of the view.

    Example:
    record:nsec3param/ZG5zLmJpsaG9zdA:us.example.com/default.external

    Attributes:
        algorithm: The hash algorithm that was used.
        cloud_info: Structure containing all cloud API related
            information for this object.
        creation_time: The creation time of the record.
        creator: Creator of the record.
        dns_name: Name for an NSEC3PARAM record in punycode format.
        flags: The set of 8 one-bit flags, of which only one flag, the
            Opt-Out flag, is defined by RFC 5155. The Opt-Out flag
            indicates whether the NSEC3 record covers unsigned
            delegations.
        iterations: The number of times the hash function was performed.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name of the NSEC3PARAM record in FQDN format. It has
            to be the same as the zone, where the record resides.
        salt: A series of case-insensitive hexadecimal digits. It is
            appended to the original owner name as protection against
            pre-calculated dictionary attacks. A new salt value is
            generated when the ZSK rolls over, for which the user can
            control the period. For a random salt value, the selected
            length is between one and 15 octets.
        ttl: The Time To Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:nsec3param'
    _fields = ['algorithm', 'cloud_info', 'creation_time', 'creator',
               'dns_name', 'flags', 'iterations', 'last_queried', 'name',
               'salt', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'creator', 'flags', 'iterations',
                              'name', 'view', 'zone']
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
    """ PtrRecordV4: DNS PTR record object.
    Corresponds to WAPI object 'record:ptr'

    In a forward-mapping zone, a PTR (pointer) record maps a domain name
    to another domain name. In a reverse-mapping zone, a PTR (pointer)
    record maps an address to a domain name. To define a specific
    address-to-name mapping, add a PTR record to a previously defined
    authoritative reverse-mapping zone.

    Attributes:
        aws_rte53_record_info: Aws Route 53 record information.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        discovered_data: The discovered data for this PTR record.
        dns_name: The name for a DNS PTR record in punycode format.
        dns_ptrdname: The domain name of the DNS PTR record in punycode
            format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        ipv4addr: The IPv4 Address of the record.
        ipv6addr: The IPv6 Address of the record.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: The name of the DNS PTR record in FQDN format.
        ptrdname: The domain name of the DNS PTR record in FQDN format.
        reclaimable: Determines if the record is reclaimable or not.
        shared_record_group: The name of the shared record group in
            which the record resides. This field exists only on
            db_objects if this record is a shared record.
        ttl: Time To Live (TTL) value for the record. A 32-bit unsigned
            integer that represents the duration, in seconds, that the
            record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: Name of the DNS View in which the record resides, for
            example "external".
        zone: The name of the zone in which the record resides. For
            example: "zone.com".If a view is not specified when
            searching by zone, the default view is used.
    """
    _infoblox_type = 'record:ptr'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal', 'ddns_protected',
               'disable', 'discovered_data', 'dns_name', 'dns_ptrdname',
               'extattrs', 'forbid_reclamation', 'ipv4addr', 'last_queried',
               'ms_ad_user_data', 'name', 'ptrdname', 'reclaimable',
               'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ptrdname', 'view', 'ipv4addr']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal',
                                 'ipv4addr', 'name', 'ptrdname']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal',
                              'ipv4addr', 'name', 'ptrdname', 'reclaimable',
                              'view', 'zone']
    _return_fields = ['extattrs', 'ptrdname', 'view', 'ipv4addr']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ipv4addr']
    _ip_version = 4


class PtrRecordV6(PtrRecord):
    """ PtrRecordV6: DNS PTR record object.
    Corresponds to WAPI object 'record:ptr'

    In a forward-mapping zone, a PTR (pointer) record maps a domain name
    to another domain name. In a reverse-mapping zone, a PTR (pointer)
    record maps an address to a domain name. To define a specific
    address-to-name mapping, add a PTR record to a previously defined
    authoritative reverse-mapping zone.

    Attributes:
        aws_rte53_record_info: Aws Route 53 record information.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        discovered_data: The discovered data for this PTR record.
        dns_name: The name for a DNS PTR record in punycode format.
        dns_ptrdname: The domain name of the DNS PTR record in punycode
            format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        ipv4addr: The IPv4 Address of the record.
        ipv6addr: The IPv6 Address of the record.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        ms_ad_user_data: The Microsoft Active Directory user related
            information.
        name: The name of the DNS PTR record in FQDN format.
        ptrdname: The domain name of the DNS PTR record in FQDN format.
        reclaimable: Determines if the record is reclaimable or not.
        shared_record_group: The name of the shared record group in
            which the record resides. This field exists only on
            db_objects if this record is a shared record.
        ttl: Time To Live (TTL) value for the record. A 32-bit unsigned
            integer that represents the duration, in seconds, that the
            record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: Name of the DNS View in which the record resides, for
            example "external".
        zone: The name of the zone in which the record resides. For
            example: "zone.com".If a view is not specified when
            searching by zone, the default view is used.
    """
    _infoblox_type = 'record:ptr'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal', 'ddns_protected',
               'disable', 'discovered_data', 'dns_name', 'dns_ptrdname',
               'extattrs', 'forbid_reclamation', 'ipv6addr', 'last_queried',
               'ms_ad_user_data', 'name', 'ptrdname', 'reclaimable',
               'shared_record_group', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ptrdname', 'view', 'ipv6addr']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal',
                                 'ipv6addr', 'name', 'ptrdname']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal',
                              'ipv6addr', 'name', 'ptrdname', 'reclaimable',
                              'view', 'zone']
    _return_fields = ['extattrs', 'ptrdname', 'view', 'ipv6addr']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ipv6addr']
    _ip_version = 6


class RpzARecord(InfobloxObject):
    """ RpzARecord: Response Policy Zone Substitute A Record Rule
    object.
    Corresponds to WAPI object 'record:rpz:a'

    An RPZ Substitute (A Record) Rule maps a domain name to a substitute
    IPv4 address. To define a specific name-to-address mapping, add an
    Substitute (A Record) Rule to a previously defined Response Policy
    Zone.

    This record represents the substitution rule for DNS A records.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv4addr: The IPv4 Address of the substitute rule.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:a'
    _fields = ['comment', 'disable', 'extattrs', 'ipv4addr', 'name', 'rp_zone',
               'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv4addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'ipv4addr', 'name', 'view']
    _all_searchable_fields = ['comment', 'ipv4addr', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv4addr', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzAIpaddressRecord(InfobloxObject):
    """ RpzAIpaddressRecord: Response Policy Zone Substitute IPv4
    Address Rule object.
    Corresponds to WAPI object 'record:rpz:a:ipaddress'

    An RPZ AIpAddress is an Substitute (IPv4 Address) Rule that maps an
    IP address represented by a host name to a substitute IPv4 address.
    To define a specific address-to-address mapping, add an Substitute
    (IPv4 Address) Rule to a previously defined Response Policy Zone.

    This record represents the substitution rule for IP trigger policy.
    It matches IP addresses that would otherwise appear in A record in
    the "answer" section of DNS response.

    You should use this object to create IP address substitution rules
    instead usage CNAMEIpAddress object.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv4addr: The IPv4 Address of the substitute rule.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:a:ipaddress'
    _fields = ['comment', 'disable', 'extattrs', 'ipv4addr', 'name', 'rp_zone',
               'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv4addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'ipv4addr', 'name', 'view']
    _all_searchable_fields = ['comment', 'ipv4addr', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv4addr', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzAaaaRecord(InfobloxObject):
    """ RpzAaaaRecord: Response Policy Zone Substitute AAAA Record Rule
    object.
    Corresponds to WAPI object 'record:rpz:aaaa'

    An RPZ Substitute (AAAA Record) Rule, maps a domain name to a
    substitute IPv6 address. To define a specific name-to-address
    mapping, add an Substitute (AAAA Record) Rule to a previously
    defined Response Policy Zone.

    This record represents the substitution rule for DNS AAAA records.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv6addr: The IPv6 Address of the substitute rule.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:aaaa'
    _fields = ['comment', 'disable', 'extattrs', 'ipv6addr', 'name', 'rp_zone',
               'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv6addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'ipv6addr', 'name', 'view']
    _all_searchable_fields = ['comment', 'ipv6addr', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv6addr', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzAaaaIpaddressRecord(InfobloxObject):
    """ RpzAaaaIpaddressRecord: Response Policy Zone Substitute IPv6
    Address Rule object.
    Corresponds to WAPI object 'record:rpz:aaaa:ipaddress'

    An RPZ Substitute (IPv6 Address) Rule maps an IP address represented
    by a host name to a substitute IPv6 address. To define a specific
    address-to-address mapping, add an RPZ Substitute (IPv6 Address)
    Rule to a previously defined Response Policy Zone.

    This record represents the substitution rule for IP trigger policy.
    It matches IP addresses that would otherwise appear in AAAA record
    in the "answer" section of DNS response.

    You should use this object to create IP address substitution rules
    instead usage CNAMEIpAddress object.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv6addr: The IPv6 Address of the substitute rule.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:aaaa:ipaddress'
    _fields = ['comment', 'disable', 'extattrs', 'ipv6addr', 'name', 'rp_zone',
               'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ipv6addr', 'name', 'view']
    _updateable_search_fields = ['comment', 'ipv6addr', 'name', 'view']
    _all_searchable_fields = ['comment', 'ipv6addr', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'ipv6addr', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameRecord(InfobloxObject):
    """ RpzCnameRecord: DNS Response Policy Zone CNAME record object.
    Corresponds to WAPI object 'record:rpz:cname'

    An RPZ CNAME record represents different RPZ rules, depending on the
    value of the canonical name. The intention of this object is to
    support QNAME Trigger policy. The QNAME policy trigger applies to
    requested domain names (QNAME). This record represents Passthru
    Domain Name Rule, Block Domain Name (No Such Domain) Rule, Block
    Domain Name (No Data) Rule and Substitute (Domain Name) Rule.

    If canonical name is empty, it is a Block Domain Name (No Such
    Domain) Rule.

    If canonical name is asterisk, it is a Block Domain Name (No Data)
    Rule.

    If canonical name is the same as record name, it is a Passthru
    Domain Name Rule. If name of object starts with wildcard you must
    specify special value 'infoblox-passthru' in canonical name in order
    to create Wildcard Passthru Domain Name Rule, for more details
    please see the Infoblox Administrator Guide.

    If canonical name is not Block Domain Name (No Such Domain) Rule,
    Block Domain Name (No Data) Rule, or Passthru Domain Name Rule, it
    is a substitution rule.

    Attributes:
        canonical: The canonical name in FQDN format. This value can be
            in unicode format.
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:cname'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'name',
               'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameClientipaddressRecord(InfobloxObject):
    """ RpzCnameClientipaddressRecord: DNS RPZ CNAMEClientIpAddress
    record object.
    Corresponds to WAPI object 'record:rpz:cname:clientipaddress'

    A DNS RPZ CNAMEClientIpAddress record represents different RPZ
    rules, depending on the value of the canonical name. This record
    represents Passthru IP Address Rule, Block IP Address (No Such
    Domain) Rule, Block IP Address (No Data) Rule.

    This record represents the IP trigger policy. It matches IP
    addresses that would otherwise appear in A and AAAA records in the
    "answer" section of a DNS response.

    If canonical name is empty, it is a Block IP Address (No Such
    Domain) Rule.

    If canonical name is an asterisk, it is a Block IP Address (No Data)
    Rule.

    If canonical name is equal to 'rpz-passthru', it is a Passthru IP
    Address Rule.

    You cannot create Substitute (IPv4/IPv6 Address) Rule for this
    record see the record.rpz.a.ipaddress object or the
    record.rpz.aaaa.ipaddress object for details.

    Attributes:
        canonical: The canonical name in FQDN format. This value can be
            in unicode format.
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        is_ipv4: Indicates whether the record is an IPv4 record. If the
            return value is "true", it is an IPv4 record. Ohterwise, it
            is an IPv6 record.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:cname:clientipaddress'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'is_ipv4',
               'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameClientipaddressdnRecord(InfobloxObject):
    """ RpzCnameClientipaddressdnRecord: Substitute Domain Name Based on
    Client IP Address rule object.
    Corresponds to WAPI object 'record:rpz:cname:clientipaddressdn'

    A DNS Substitute Domain Name (Based on Client IP Address) rule
    represents different Response Policy Zone (RPZ) rules, depending on
    the value of the canonical name.

    This rule represents Substitute (Domain Name) Rule.

    Attributes:
        canonical: The canonical name in FQDN format. This value can be
            in unicode format.
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        is_ipv4: Indicates whether the record is an IPv4 record. If the
            return value is "true", it is an IPv4 record. Ohterwise, it
            is an IPv6 record.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:cname:clientipaddressdn'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'is_ipv4',
               'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameIpaddressRecord(InfobloxObject):
    """ RpzCnameIpaddressRecord: DNS RPZ CNAMEIpAddress record object.
    Corresponds to WAPI object 'record:rpz:cname:ipaddress'

    A DNS RPZ CNAMEIpAddress record represents different RPZ rules,
    depending on the value of the canonical name. This record represents
    Passthru IP Address Rule, Block IP Address (No Such Domain) Rule,
    Block IP Address (No Data) Rule.

    This record represents IP trigger policy. It matches IP addresses
    that would otherwise appear in A and AAAA records in the "answer"
    section of DNS response.

    If canonical name is empty, it is a Block IP Address (No Such
    Domain) Rule.

    If canonical name is an asterisk, it is a Block IP Address (No Data)
    Rule.

    If canonical name is the same as host name, it is a Passthru IP
    Address Rule.

    You cannot create Substitute (IPv4/IPv6 Address) Rule for this
    record see AIpAddress or AAAAIpAddress for details.

    Attributes:
        canonical: The canonical name in FQDN format. This value can be
            in unicode format.
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        is_ipv4: Indicates whether the record is an IPv4 record. If the
            return value is "true", it is an IPv4 record. Ohterwise, it
            is an IPv6 record.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:cname:ipaddress'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'is_ipv4',
               'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzCnameIpaddressdnRecord(InfobloxObject):
    """ RpzCnameIpaddressdnRecord: Substitute Domain Name Based on IP
    Address rule object.
    Corresponds to WAPI object 'record:rpz:cname:ipaddressdn'

    A DNS Substitute Domain Name (Based on IP Address) rule represents
    different Response Policy Zone (RPZ) rules, depending on the value
    of the canonical name.

    This rule represents Substitute (Domain Name) Rule.

    Attributes:
        canonical: The canonical name in FQDN format. This value can be
            in unicode format.
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        is_ipv4: Indicates whether the record is an IPv4 record. If the
            return value is "true", it is an IPv4 record. Ohterwise, it
            is an IPv6 record.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:cname:ipaddressdn'
    _fields = ['canonical', 'comment', 'disable', 'extattrs', 'is_ipv4',
               'name', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['canonical', 'name', 'view']
    _updateable_search_fields = ['canonical', 'comment', 'name', 'view']
    _all_searchable_fields = ['canonical', 'comment', 'name', 'view', 'zone']
    _return_fields = ['canonical', 'extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzMxRecord(InfobloxObject):
    """ RpzMxRecord: Response Policy Zone Substitute MX Record Rule
    object.
    Corresponds to WAPI object 'record:rpz:mx'

    An RPZ Substitute (MX Record) Rule maps a domain name to a mail
    exchanger. A mail exchanger is a server that either delivers or
    forwards mail.

    This record represents the substitution rule for DNS MX records.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        mail_exchanger: Mail exchanger name in FQDN format. This value
            can be in unicode format.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        preference: Preference value, 0 to 65535 (inclusive) in 32-bit
            unsigned integer format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:mx'
    _fields = ['comment', 'disable', 'extattrs', 'mail_exchanger', 'name',
               'preference', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['mail_exchanger', 'name', 'preference',
                                 'view']
    _updateable_search_fields = ['comment', 'mail_exchanger', 'name',
                                 'preference', 'view']
    _all_searchable_fields = ['comment', 'mail_exchanger', 'name',
                              'preference', 'view', 'zone']
    _return_fields = ['extattrs', 'mail_exchanger', 'name', 'preference',
                      'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzNaptrRecord(InfobloxObject):
    """ RpzNaptrRecord: Response Policy Zone Substitute NAPTR Record
    Rule object.
    Corresponds to WAPI object 'record:rpz:naptr'

    An RPZ Substitute (NAPTR Record) Rule object represents the
    substitution rule for DNS Naming Authority Pointer (NAPTR) records.
    This rule specifies a regular expression-based rewrite rule that,
    when applied to an existing string, produces a new domain name or
    URI.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        flags: The flags used to control the interpretation of the
            fields for a Substitute (NAPTR Record) Rule object.
            Supported values for the flags field are "U", "S", "P" and
            "A".
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        order: The order parameter of the Substitute (NAPTR Record) Rule
            records. This parameter specifies the order in which the
            NAPTR rules are applied when multiple rules are present.
            Valid values are from 0 to 65535 (inclusive), in 32-bit
            unsigned integer format.
        preference: The preference of the Substitute (NAPTR Record) Rule
            record. The preference field determines the order NAPTR
            records are processed when multiple records with the same
            order parameter are present. Valid values are from 0 to
            65535 (inclusive), in 32-bit unsigned integer format.
        regexp: The regular expression-based rewriting rule of the
            Substitute (NAPTR Record) Rule record. This should be a
            POSIX compliant regular expression, including the
            substitution rule and flags. Refer to RFC 2915 for the field
            syntax details.
        replacement: The replacement field of the Substitute (NAPTR
            Record) Rule object. For nonterminal NAPTR records, this
            field specifies the next domain name to look up. This value
            can be in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        services: The services field of the Substitute (NAPTR Record)
            Rule object; maximum 128 characters. The services field
            contains protocol and service identifiers, such as
            "http+E2U" or "SIPS+D2T".
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:naptr'
    _fields = ['comment', 'disable', 'extattrs', 'flags', 'last_queried',
               'name', 'order', 'preference', 'regexp', 'replacement',
               'rp_zone', 'services', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'order', 'preference', 'replacement',
                                 'services', 'view']
    _updateable_search_fields = ['comment', 'flags', 'name', 'order',
                                 'preference', 'replacement', 'services',
                                 'view']
    _all_searchable_fields = ['comment', 'flags', 'name', 'order',
                              'preference', 'replacement', 'services', 'view',
                              'zone']
    _return_fields = ['extattrs', 'name', 'order', 'preference', 'regexp',
                      'replacement', 'services', 'view']
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
    """ RpzPtrRecordV4: Response Policy Zone Substitute PTR Record Rule
    object.
    Corresponds to WAPI object 'record:rpz:ptr'

    An RPZ Substitute (PTR Record) Rule object represents a Pointer
    (PTR) resource record. To define a specific address-to-name mapping,
    add an RPZ Substitute (PTR Record) Rule to a previously defined
    Response Policy Zone.

    This record represents the substitution rule for DNS PTR records.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv4addr: The IPv4 Address of the substitute rule.
        ipv6addr: The IPv6 Address of the substitute rule.
        name: The name of the RPZ Substitute (PTR Record) Rule object in
            FQDN format.
        ptrdname: The domain name of the RPZ Substitute (PTR Record)
            Rule object in FQDN format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:ptr'
    _fields = ['comment', 'disable', 'extattrs', 'ipv4addr', 'name',
               'ptrdname', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ptrdname', 'view', 'ipv4addr']
    _updateable_search_fields = ['comment', 'ipv4addr', 'name', 'ptrdname',
                                 'view']
    _all_searchable_fields = ['comment', 'ipv4addr', 'name', 'ptrdname',
                              'view', 'zone']
    _return_fields = ['extattrs', 'ptrdname', 'view', 'ipv4addr']
    _remap = {'ip': 'ipv4addr'}
    _shadow_fields = ['_ref', 'ipv4addr']
    _ip_version = 4


class RpzPtrRecordV6(RpzPtrRecord):
    """ RpzPtrRecordV6: Response Policy Zone Substitute PTR Record Rule
    object.
    Corresponds to WAPI object 'record:rpz:ptr'

    An RPZ Substitute (PTR Record) Rule object represents a Pointer
    (PTR) resource record. To define a specific address-to-name mapping,
    add an RPZ Substitute (PTR Record) Rule to a previously defined
    Response Policy Zone.

    This record represents the substitution rule for DNS PTR records.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv4addr: The IPv4 Address of the substitute rule.
        ipv6addr: The IPv6 Address of the substitute rule.
        name: The name of the RPZ Substitute (PTR Record) Rule object in
            FQDN format.
        ptrdname: The domain name of the RPZ Substitute (PTR Record)
            Rule object in FQDN format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:ptr'
    _fields = ['comment', 'disable', 'extattrs', 'ipv6addr', 'name',
               'ptrdname', 'rp_zone', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['ptrdname', 'view', 'ipv6addr']
    _updateable_search_fields = ['comment', 'ipv6addr', 'name', 'ptrdname',
                                 'view']
    _all_searchable_fields = ['comment', 'ipv6addr', 'name', 'ptrdname',
                              'view', 'zone']
    _return_fields = ['extattrs', 'ptrdname', 'view', 'ipv6addr']
    _remap = {'ip': 'ipv6addr'}
    _shadow_fields = ['_ref', 'ipv6addr']
    _ip_version = 6


class RpzSrvRecord(InfobloxObject):
    """ RpzSrvRecord: Response Policy Zone Substitute SRV Record Rule
    object.
    Corresponds to WAPI object 'record:rpz:srv'

    An RPZ Substitute (SRV Record) Rule object represents the
    substitution rule for DNS SRV records.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        port: The port of the Substitute (SRV Record) Rule. Valid values
            are from 0 to 65535 (inclusive), in 32-bit unsigned integer
            format.
        priority: The priority of the Substitute (SRV Record) Rule.
            Valid values are from 0 to 65535 (inclusive), in 32-bit
            unsigned integer format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        target: The target of the Substitute (SRV Record) Rule in FQDN
            format. This value can be in unicode format.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        weight: The weight of the Substitute (SRV Record) Rule. Valid
            values are from 0 to 65535 (inclusive), in 32-bit unsigned
            integer format.
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:srv'
    _fields = ['comment', 'disable', 'extattrs', 'name', 'port', 'priority',
               'rp_zone', 'target', 'ttl', 'use_ttl', 'view', 'weight', 'zone']
    _search_for_update_fields = ['name', 'port', 'priority', 'target', 'view',
                                 'weight']
    _updateable_search_fields = ['comment', 'name', 'port', 'priority',
                                 'target', 'view', 'weight']
    _all_searchable_fields = ['comment', 'name', 'port', 'priority', 'target',
                              'view', 'weight', 'zone']
    _return_fields = ['extattrs', 'name', 'port', 'priority', 'target', 'view',
                      'weight']
    _remap = {}
    _shadow_fields = ['_ref']


class RpzTxtRecord(InfobloxObject):
    """ RpzTxtRecord: Response Policy Zone Substitute TXT Record Rule
    object.
    Corresponds to WAPI object 'record:rpz:txt'

    An RPZ Substitute (TXT Record) Rule object represents the
    substitution rule for DNS TXT records.

    Attributes:
        comment: The comment for the record; maximum 256 characters.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name for a record in FQDN format. This value cannot be
            in unicode format.
        rp_zone: The name of a response policy zone in which the record
            resides.
        text: Text associated with the record. It can contain up to 255
            bytes per substring, up to a total of 512 bytes. To enter
            leading, trailing, or embedded spaces in the text, add
            quotes around the text to preserve the spaces.
        ttl: The Time To Live (TTL) value for record. A 32-bit unsigned
            integer that represents the duration, in seconds, for which
            the record is valid (cached). Zero indicates that the record
            should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rpz:txt'
    _fields = ['comment', 'disable', 'extattrs', 'name', 'rp_zone', 'text',
               'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'text', 'view']
    _updateable_search_fields = ['comment', 'name', 'text', 'view']
    _all_searchable_fields = ['comment', 'name', 'text', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'text', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class RrsigRecord(InfobloxObject):
    """ RrsigRecord: DNS RRSIG record object.
    Corresponds to WAPI object 'record:rrsig'

    RRSIG records are one of the resource records in DNSSEC. These
    records store digital signatures of resource record sets (RRsets).
    Digital signatures are used to authenticate data that is in the
    signed RRsets.

    A signed zone has multiple RRsets, one for each record type and
    owner name. (The owner is the domain name of the RRset.) When an
    authoritative name server uses the private key of the ZSK pair to
    sign each RRset in a zone, the digital signature on each RRset is
    stored in an RRSIG record. Therefore, a signed zone contains an
    RRSIG record for each RRset.

    RRSIG resource records are defined in RFC 4034.

    RRSIG records are automatically generated upon the signing of an
    authoritative zone.

    The name part of a DNS RRSIG object reference has the following
    components:

    The name of the record.

    The name of the view.

    Example:
    record:rrsig/ZG5zLmJpsaG9zdA:us.example.com/default.external

    Attributes:
        algorithm: The cryptographic algorithm that was used to create
            the signature. It uses the same algorithm types as the
            DNSKEY record indicated in the key tag field.
        cloud_info: Structure containing all cloud API related
            information for this object.
        creation_time: The creation time of the record.
        creator: The record creator.
        dns_name: Name for an RRSIG record in punycode format.
        dns_signer_name: The domain name, in punycode format, of the
            zone that contains the signed RRset.
        expiration_time: The expiry time of an RRSIG record in Epoch
            seconds format.
        inception_time: The inception time of an RRSIG record in Epoch
            seconds format.
        key_tag: The key tag value of the DNSKEY RR that validates the
            signature.
        labels: The number of labels in the name of the RRset signed
            with the RRSIG object.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The name of the RRSIG record in FQDN format.
        original_ttl: The TTL value of the RRset covered by the RRSIG
            record.
        signature: The Base64 encoded cryptographic signature that
            covers the RRSIG RDATA of the RRSIG Record object.
        signer_name: The domain name of the zone in FQDN format that
            contains the signed RRset.
        ttl: The Time To Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        type_covered: The RR type covered by the RRSIG record.
        use_ttl: Use flag for: ttl
        view: The name of the DNS View in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:rrsig'
    _fields = ['algorithm', 'cloud_info', 'creation_time', 'creator',
               'dns_name', 'dns_signer_name', 'expiration_time',
               'inception_time', 'key_tag', 'labels', 'last_queried', 'name',
               'original_ttl', 'signature', 'signer_name', 'ttl',
               'type_covered', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['algorithm', 'creator', 'key_tag', 'labels',
                              'name', 'original_ttl', 'signer_name',
                              'type_covered', 'view', 'zone']
    _return_fields = ['name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class SRVRecord(InfobloxObject):
    """ SRVRecord: DNS SRV record object.
    Corresponds to WAPI object 'record:srv'

    A DNS SRV object represents an SRV resource record, which is also
    known as a service record. An SRV record provides information on
    available services.

    Attributes:
        aws_rte53_record_info: Aws Route 53 record information.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dns_name: The name for an SRV record in punycode format.
        dns_target: The name for a SRV record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: A name in FQDN format. This value can be in unicode
            format.
        port: The port of the SRV record. Valid values are from 0 to
            65535 (inclusive), in 32-bit unsigned integer format.
        priority: The priority of the SRV record. Valid values are from
            0 to 65535 (inclusive), in 32-bit unsigned integer format.
        reclaimable: Determines if the record is reclaimable or not.
        shared_record_group: The name of the shared record group in
            which the record resides. This field exists only on
            db_objects if this record is a shared record.
        target: The target of the SRV record in FQDN format. This value
            can be in unicode format.
        ttl: The Time to Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        weight: The weight of the SRV record. Valid values are from 0 to
            65535 (inclusive), in 32-bit unsigned integer format.
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:srv'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal', 'ddns_protected',
               'disable', 'dns_name', 'dns_target', 'extattrs',
               'forbid_reclamation', 'last_queried', 'name', 'port',
               'priority', 'reclaimable', 'shared_record_group', 'target',
               'ttl', 'use_ttl', 'view', 'weight', 'zone']
    _search_for_update_fields = ['name', 'port', 'priority', 'target', 'view',
                                 'weight']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal',
                                 'name', 'port', 'priority', 'target',
                                 'weight']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'name',
                              'port', 'priority', 'reclaimable', 'target',
                              'view', 'weight', 'zone']
    _return_fields = ['extattrs', 'name', 'port', 'priority', 'target', 'view',
                      'weight']
    _remap = {}
    _shadow_fields = ['_ref']


class TlsaRecord(InfobloxObject):
    """ TlsaRecord: DNS TLSA record object.
    Corresponds to WAPI object 'record:tlsa'

    The TLSA DNS resource record (RR) is used to associate a TLS server
    certificate or public key with the domain name where the record is
    found, thus forming a 'TLSA certificate association'. For further
    details see RFC-6698. Note that you must specify only one view for
    the attribute 'views'.

    Attributes:
        certificate_data: Hex dump of either raw data for matching type
            0, or the hash of the raw data for matching types 1 and 2.
        certificate_usage: Specifies the provided association that will
            be used to match the certificate presented in the TLS
            handshake. Based on RFC-6698.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creator: The record creator. Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dns_name: The name of the TLSA record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        matched_type: Specifies how the certificate association is
            presented. Based on RFC-6698.
        name: The TLSA record name in FQDN format. This value can be in
            unicode format.
        selector: Specifies which part of the TLS certificate presented
            by the server will be matched against the association data.
            Based on RFC-6698.
        ttl: The Time to Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:tlsa'
    _fields = ['certificate_data', 'certificate_usage', 'cloud_info',
               'comment', 'creator', 'disable', 'dns_name', 'extattrs',
               'last_queried', 'matched_type', 'name', 'selector', 'ttl',
               'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'name', 'view']
    _all_searchable_fields = ['comment', 'creator', 'name', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class TXTRecord(InfobloxObject):
    """ TXTRecord: DNS TXT record object.
    Corresponds to WAPI object 'record:txt'

    A TXT (text record) record contains supplemental information for a
    host. For example, if you have a sales server that serves only North
    America, you can create a text record stating this fact. You can
    create more than one text record for a domain name.

    Attributes:
        aws_rte53_record_info: Aws Route 53 record information.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creation_time: The time of the record creation in Epoch seconds
            format.
        creator: The record creator.Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        ddns_principal: The GSS-TSIG principal that owns this record.
        ddns_protected: Determines if the DDNS updates for this record
            are allowed or not.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        dns_name: The name for a TXT record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        forbid_reclamation: Determines if the reclamation is allowed for
            the record or not.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: Name for the TXT record in FQDN format. This value can be
            in unicode format.
        reclaimable: Determines if the record is reclaimable or not.
        shared_record_group: The name of the shared record group in
            which the record resides. This field exists only on
            db_objects if this record is a shared record.
        text: Text associated with the record. It can contain up to 255
            bytes per substring, up to a total of 512 bytes. To enter
            leading, trailing, or embedded spaces in the text, add
            quotes around the text to preserve the spaces.
        ttl: The Time To Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:txt'
    _fields = ['aws_rte53_record_info', 'cloud_info', 'comment',
               'creation_time', 'creator', 'ddns_principal', 'ddns_protected',
               'disable', 'dns_name', 'extattrs', 'forbid_reclamation',
               'last_queried', 'name', 'reclaimable', 'shared_record_group',
               'text', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'ddns_principal',
                                 'name', 'text', 'view']
    _all_searchable_fields = ['comment', 'creator', 'ddns_principal', 'name',
                              'reclaimable', 'text', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'text', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class UnknownRecord(InfobloxObject):
    """ UnknownRecord: DNS UNKNOWN record object.
    Corresponds to WAPI object 'record:unknown'

    An "RR of unknown type" is an RR whose RDATA format is not known to
    the DNS implementation at hand, and whose type is not an assigned
    QTYPE or Meta-TYPE as specified in 2929] nor within the range
    reserved in that section for assignment only to QTYPEs and Meta-
    TYPEs. The purpose of the Unknown resource record is to allow future
    DNS implementations to handle new RR types transparently. For
    further details see RFC-3597.

    Attributes:
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the record; maximum 256 characters.
        creator: The record creator. Note that changing creator from or
            to 'SYSTEM' value is not allowed.
        disable: Determines if the record is disabled or not. False
            means that the record is enabled.
        display_rdata: Standard textual representation of the RDATA.
        dns_name: The name of the unknown record in punycode format.
        enable_host_name_policy: Determines if host name policy is
            applicable for the record.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        last_queried: The time of the last DNS query in Epoch seconds
            format.
        name: The Unknown record name in FQDN format. This value can be
            in unicode format.
        policy: The host name policy for the record.
        record_type: Specifies type of unknown resource record.
        subfield_values: The list of rdata subfield values of unknown
            resource record.
        ttl: The Time to Live (TTL) value for the record. A 32-bit
            unsigned integer that represents the duration, in seconds,
            for which the record is valid (cached). Zero indicates that
            the record should not be cached.
        use_ttl: Use flag for: ttl
        view: The name of the DNS view in which the record resides.
            Example: "external".
        zone: The name of the zone in which the record resides. Example:
            "zone.com". If a view is not specified when searching by
            zone, the default view is used.
    """
    _infoblox_type = 'record:unknown'
    _fields = ['cloud_info', 'comment', 'creator', 'disable', 'display_rdata',
               'dns_name', 'enable_host_name_policy', 'extattrs',
               'last_queried', 'name', 'policy', 'record_type',
               'subfield_values', 'ttl', 'use_ttl', 'view', 'zone']
    _search_for_update_fields = ['name', 'view']
    _updateable_search_fields = ['comment', 'creator', 'name', 'record_type',
                                 'subfield_values', 'view']
    _all_searchable_fields = ['comment', 'creator', 'display_rdata', 'name',
                              'record_type', 'subfield_values', 'view', 'zone']
    _return_fields = ['extattrs', 'name', 'view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'subfield_values': Rdatasubfield.from_dict,
    }


class Recordnamepolicy(InfobloxObject):
    """ Recordnamepolicy: Record name policy object.
    Corresponds to WAPI object 'recordnamepolicy'

    You can enforce naming policy for the hostnames of A, AAAA, Host,
    MX, NS and bulk host records based on user-defined or default
    patterns. For MX and NS records, the hostname restrictions apply to
    the text in the RDATA field of the resource record name. Records
    that you created before you enabled the hostname checking policy
    need not to comply with the hostname restriction that you specify.

    The record name policy object contains configuration of the regular
    expression hostnames should comply with.

    Attributes:
        is_default: Determines whether the record name policy is Grid
            default.
        name: The name of the record name policy object.
        pre_defined: Determines whether the record name policy is a
            predefined one.
        regex: The POSIX regular expression the record names should
            match in order to comply with the record name policy.
    """
    _infoblox_type = 'recordnamepolicy'
    _fields = ['is_default', 'name', 'pre_defined', 'regex']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name']
    _return_fields = ['is_default', 'name', 'regex']
    _remap = {}
    _shadow_fields = ['_ref']


class Restartservicestatus(InfobloxObject):
    """ Restartservicestatus: Restart service status object.
    Corresponds to WAPI object 'restartservicestatus'

    This object represents the service status. Use the the
    requestrestartservicestatus function call in object grid or the
    requestrestartservicestatus function call in object member to
    refresh the status.

    Attributes:
        dhcp_status: The status of the DHCP service.
        dns_status: The status of the DNS service.
        member: The name of this Grid member in FQDN format.
        reporting_status: The status of the reporting service.
    """
    _infoblox_type = 'restartservicestatus'
    _fields = ['dhcp_status', 'dns_status', 'member', 'reporting_status']
    _search_for_update_fields = ['member']
    _updateable_search_fields = []
    _all_searchable_fields = ['member']
    _return_fields = ['dhcp_status', 'dns_status', 'member',
                      'reporting_status']
    _remap = {}
    _shadow_fields = ['_ref']


class Rir(InfobloxObject):
    """ Rir: Regional Internet Registry object.
    Corresponds to WAPI object 'rir'

    An RIR is an entity that manages the Internet number resources,
    which include IP addresses and autonomous system numbers, within a
    specific region of the world. RIRs use SWIP (Shared WHOIS Project)
    or RWhois (Referral WHOIS) servers to provide address allocation
    information for IP address blocks. Typically, an RIR determines the
    address blocks to be allocated for specific organizations (typically
    ISPs), while an ISP manages the allocated address blocks, associated
    organizations and corresponding RIR registrations. An organization
    can determine when to request for more address data with their RIRs
    every few months.

    The RIR object is used to configure Infoblox Grid communication
    settings to send registration update to RIPE (Reseaux IP Europeens)
    database as often as RIR data is updated on NIOS.

    Attributes:
        communication_mode: The communication mode for RIR.
        email: The e-mail address for RIR.
        name: The name of RIR.
        url: The WebAPI URL for RIR.
        use_email: Use flag for: email
        use_url: Use flag for: url
    """
    _infoblox_type = 'rir'
    _fields = ['communication_mode', 'email', 'name', 'url', 'use_email',
               'use_url']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['name']
    _return_fields = ['communication_mode', 'email', 'name', 'url']
    _remap = {}
    _shadow_fields = ['_ref']


class RirOrganization(InfobloxObject):
    """ RirOrganization: Regional Internet Registry organization object.
    Corresponds to WAPI object 'rir:organization'

    An RIR organization provides information about an entity that has
    registered a network resource in the RIPE database. This entity can
    be a company (such as an ISP), a nonprofit group, or an individual.
    You can add RIR organizations defined in the RIPE database and start
    managing their data through NIOS.

    Attributes:
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        id: The RIR organization identifier.
        maintainer: The RIR organization maintainer.
        name: The RIR organization name.
        password: The password for the maintainer of RIR organization.
        rir: The RIR associated with RIR organization.
        sender_email: The sender e-mail address for RIR organization.
    """
    _infoblox_type = 'rir:organization'
    _fields = ['extattrs', 'id', 'maintainer', 'name', 'password', 'rir',
               'sender_email']
    _search_for_update_fields = ['id', 'maintainer', 'name', 'rir',
                                 'sender_email']
    _updateable_search_fields = ['id', 'maintainer', 'name', 'rir',
                                 'sender_email']
    _all_searchable_fields = ['id', 'maintainer', 'name', 'rir',
                              'sender_email']
    _return_fields = ['extattrs', 'id', 'maintainer', 'name', 'rir',
                      'sender_email']
    _remap = {}
    _shadow_fields = ['_ref']


class DHCPRoamingHost(InfobloxObject):
    """ DHCPRoamingHost: DHCP Roaming Host object.
    Corresponds to WAPI object 'roaminghost'

    A roaming host is a specific host that a DHCP server always assigns
    when a lease request comes from a particular MAC address of the
    client.

    Attributes:
        address_type: The address type for this roaming host.
        bootfile: The bootfile name for the roaming host. You can
            configure the DHCP server to support clients that use the
            boot file name option in their DHCPREQUEST messages.
        bootserver: The boot server address for the roaming host. You
            can specify the name and/or IP address of the boot server
            that the host needs to boot.The boot server IPv4 Address or
            name in FQDN format.
        client_identifier_prepend_zero: This field controls whether
            there is a prepend for the dhcp-client-identifier of a
            roaming host.
        comment: Comment for the roaming host; maximum 256 characters.
        ddns_domainname: The DDNS domain name for this roaming host.
        ddns_hostname: The DDNS host name for this roaming host.
        deny_bootp: If set to true, BOOTP settings are disabled and
            BOOTP requests will be denied.
        dhcp_client_identifier: The DHCP client ID for the roaming host.
        disable: Determines whether a roaming host is disabled or not.
            When this is set to False, the roaming host is enabled.
        enable_ddns: The dynamic DNS updates flag of the roaming host
            object. If set to True, the DHCP server sends DDNS updates
            to DNS servers in the same Grid, and to external DNS
            servers.
        enable_pxe_lease_time: Set this to True if you want the DHCP
            server to use a different lease time for PXE clients.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        force_roaming_hostname: Set this to True to use the roaming host
            name as its ddns_hostname.
        ignore_dhcp_option_list_request: If this field is set to False,
            the appliance returns all the DHCP options the client is
            eligible to receive, rather than only the list of options
            the client has requested.
        ipv6_client_hostname: The client hostname of a DHCP roaming host
            object. This field specifies the host name that the DHCP
            client sends to the Infoblox appliance using DHCP option 12.
        ipv6_ddns_domainname: The IPv6 DDNS domain name for this roaming
            host.
        ipv6_ddns_hostname: The IPv6 DDNS host name for this roaming
            host.
        ipv6_domain_name: The IPv6 domain name for this roaming host.
        ipv6_domain_name_servers: The IPv6 addresses of DNS recursive
            name servers to which the DHCP client can send name
            resolution requests. The DHCP server includes this
            information in the DNS Recursive Name Server option in
            Advertise, Rebind, Information-Request, and Reply messages.
        ipv6_duid: The DUID value for this roaming host.
        ipv6_enable_ddns: Set this to True to enable IPv6 DDNS.
        ipv6_force_roaming_hostname: Set this to True to use the roaming
            host name as its ddns_hostname.
        ipv6_match_option: The identification method for an IPv6 or
            mixed IPv4/IPv6 roaming host. Currently, the only supported
            value for this field is "DUID", which corresponds to
            identification by DHCPv6 unique ID.
        ipv6_options: An array of DHCP option structs that lists the
            DHCP options associated with the object.
        ipv6_template: If set on creation, the roaming host will be
            created according to the values specified in the named IPv6
            roaming host template.
        mac: The MAC address for this roaming host.
        match_client: The match-client value for this roaming host.
            Valid values are:"MAC_ADDRESS": The fixed IP address is
            leased to the matching MAC address."CLIENT_ID": The fixed IP
            address is leased to the matching DHCP client identifier.
        name: The name of this roaming host.
        network_view: The name of the network view in which this roaming
            host resides.
        nextserver: The name in FQDN and/or IPv4 Address format of the
            next server that the host needs to boot.
        options: An array of DHCP option structs that lists the DHCP
            options associated with the object.
        preferred_lifetime: The preferred lifetime value for this
            roaming host object.
        pxe_lease_time: The PXE lease time value for this roaming host
            object. Some hosts use PXE (Preboot Execution Environment)
            to boot remotely from a server. To better manage your IP
            resources, set a different lease time for PXE boot requests.
            You can configure the DHCP server to allocate an IP address
            with a shorter lease time to hosts that send PXE boot
            requests, so IP addresses are not leased longer than
            necessary.A 32-bit unsigned integer that represents the
            duration, in seconds, for which the update is cached. Zero
            indicates that the update is not cached.
        template: If set on creation, the roaming host will be created
            according to the values specified in the named template.
        use_bootfile: Use flag for: bootfile
        use_bootserver: Use flag for: bootserver
        use_ddns_domainname: Use flag for: ddns_domainname
        use_deny_bootp: Use flag for: deny_bootp
        use_enable_ddns: Use flag for: enable_ddns
        use_ignore_dhcp_option_list_request: Use flag for:
            ignore_dhcp_option_list_request
        use_ipv6_ddns_domainname: Use flag for: ipv6_ddns_domainname
        use_ipv6_domain_name: Use flag for: ipv6_domain_name
        use_ipv6_domain_name_servers: Use flag for:
            ipv6_domain_name_servers
        use_ipv6_enable_ddns: Use flag for: ipv6_enable_ddns
        use_ipv6_options: Use flag for: ipv6_options
        use_nextserver: Use flag for: nextserver
        use_options: Use flag for: options
        use_preferred_lifetime: Use flag for: preferred_lifetime
        use_pxe_lease_time: Use flag for: pxe_lease_time
        use_valid_lifetime: Use flag for: valid_lifetime
        valid_lifetime: The valid lifetime value for this roaming host
            object.
    """
    _infoblox_type = 'roaminghost'
    _fields = ['address_type', 'bootfile', 'bootserver',
               'client_identifier_prepend_zero', 'comment', 'ddns_domainname',
               'ddns_hostname', 'deny_bootp', 'dhcp_client_identifier',
               'disable', 'enable_ddns', 'enable_pxe_lease_time', 'extattrs',
               'force_roaming_hostname', 'ignore_dhcp_option_list_request',
               'ipv6_client_hostname', 'ipv6_ddns_domainname',
               'ipv6_ddns_hostname', 'ipv6_domain_name',
               'ipv6_domain_name_servers', 'ipv6_duid', 'ipv6_enable_ddns',
               'ipv6_force_roaming_hostname', 'ipv6_match_option',
               'ipv6_options', 'ipv6_template', 'mac', 'match_client', 'name',
               'network_view', 'nextserver', 'options', 'preferred_lifetime',
               'pxe_lease_time', 'template', 'use_bootfile', 'use_bootserver',
               'use_ddns_domainname', 'use_deny_bootp', 'use_enable_ddns',
               'use_ignore_dhcp_option_list_request',
               'use_ipv6_ddns_domainname', 'use_ipv6_domain_name',
               'use_ipv6_domain_name_servers', 'use_ipv6_enable_ddns',
               'use_ipv6_options', 'use_nextserver', 'use_options',
               'use_preferred_lifetime', 'use_pxe_lease_time',
               'use_valid_lifetime', 'valid_lifetime']
    _search_for_update_fields = ['address_type', 'name', 'network_view']
    _updateable_search_fields = ['address_type', 'comment',
                                 'dhcp_client_identifier', 'ipv6_duid',
                                 'ipv6_match_option', 'mac', 'match_client',
                                 'name', 'network_view']
    _all_searchable_fields = ['address_type', 'comment',
                              'dhcp_client_identifier', 'ipv6_duid',
                              'ipv6_match_option', 'mac', 'match_client',
                              'name', 'network_view']
    _return_fields = ['address_type', 'extattrs', 'name', 'network_view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'ipv6_options': DhcpOption.from_dict,
        'options': DhcpOption.from_dict,
    }


class Ruleset(InfobloxObject):
    """ Ruleset: DNS Ruleset object.
    Corresponds to WAPI object 'ruleset'

    Represents a Ruleset object, which is a collection of rules that is
    used to match domain names.

    Attributes:
        comment: Descriptive comment about the Ruleset object.
        disabled: The flag that indicates if the Ruleset object is
            disabled.
        name: The name of this Ruleset object.
        nxdomain_rules: The list of Rules assigned to this Ruleset
            object. Rules can be set only when the Ruleset type is set
            to "NXDOMAIN".
        type: The type of this Ruleset object.
    """
    _infoblox_type = 'ruleset'
    _fields = ['comment', 'disabled', 'name', 'nxdomain_rules', 'type']
    _search_for_update_fields = ['disabled', 'name', 'type']
    _updateable_search_fields = ['comment', 'disabled', 'name', 'type']
    _all_searchable_fields = ['comment', 'disabled', 'name', 'type']
    _return_fields = ['comment', 'disabled', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'nxdomain_rules': Nxdomainrule.from_dict,
    }


class SamlAuthservice(InfobloxObject):
    """ SamlAuthservice: SAML authentication service object.
    Corresponds to WAPI object 'saml:authservice'

    This object represents SAML authentication service.

    Attributes:
        comment: The descriptive comment for the SAML authentication
            service.
        idp: The SAML Identity Provider to use for authentication.
        name: The name of the SAML authentication service.
        session_timeout: The session timeout in seconds.
    """
    _infoblox_type = 'saml:authservice'
    _fields = ['comment', 'idp', 'name', 'session_timeout']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']


class Scavengingtask(InfobloxObject):
    """ Scavengingtask: DNS scavenging task object.
    Corresponds to WAPI object 'scavengingtask'

    The DNS scavenging task object provides information on scavenging
    process state.

    Attributes:
        action: The scavenging action.
        associated_object: The reference to the object associated with
            the scavenging task.
        end_time: The scavenging process end time.
        processed_records: The number of processed during scavenging
            resource records.
        reclaimable_records: The number of resource records that are
            allowed to be reclaimed during the scavenging process.
        reclaimed_records: The number of reclaimed during the scavenging
            process resource records.
        start_time: The scavenging process start time.
        status: The scavenging process status. This is a read-only
            attribute.
    """
    _infoblox_type = 'scavengingtask'
    _fields = ['action', 'associated_object', 'end_time', 'processed_records',
               'reclaimable_records', 'reclaimed_records', 'start_time',
               'status']
    _search_for_update_fields = ['action', 'associated_object', 'status']
    _updateable_search_fields = []
    _all_searchable_fields = ['action', 'associated_object', 'status']
    _return_fields = ['action', 'associated_object', 'status']
    _remap = {}
    _shadow_fields = ['_ref']


class Scheduledtask(InfobloxObject):
    """ Scheduledtask: Scheduled Task object.
    Corresponds to WAPI object 'scheduledtask'

    This object represents a scheduled task.

    Attributes:
        approval_status: The approval status of the task.
        approver: The approver of the task.
        approver_comment: The comment specified by the approver of the
            task.
        automatic_restart: Indicates whether there will be an automatic
            restart when the appliance executes the task.
        changed_objects: A list of objects that are affected by the
            task.
        dependent_tasks: If this scheduled task has dependent tasks,
            their references will be returned in this field.
        execute_now: If this field is set to True the specified task
            will be executed immediately.
        execution_details: Messages generated by the execution of the
            scheduled task after its completion.
        execution_details_type: The type of details generated by the
            execution of the scheduled task after its completion.
        execution_status: The execution status of the task.
        execution_time: The time when the appliance executed the task.
        is_network_insight_task: Indicates whether this is a Network
            Insight scheduled task.
        member: The member where this task was created.
        predecessor_task: If this scheduled task has a predecessor task
            set, its reference will be returned in this field.
        re_execute_task: If set to True, if the scheduled task is a
            Network Insight task and it failed, a new task will be
            cloned from this task and re-executed.
        scheduled_time: The time when the task is scheduled to occur.
        submit_time: The time when the task was submitted.
        submitter: The submitter of the task.
        submitter_comment: The comment specified by the submitter of the
            task.
        task_id: The task ID.
        task_type: The task type.
        ticket_number: The task ticket number.
    """
    _infoblox_type = 'scheduledtask'
    _fields = ['approval_status', 'approver', 'approver_comment',
               'automatic_restart', 'changed_objects', 'dependent_tasks',
               'execute_now', 'execution_details', 'execution_details_type',
               'execution_status', 'execution_time', 'is_network_insight_task',
               'member', 'predecessor_task', 're_execute_task',
               'scheduled_time', 'submit_time', 'submitter',
               'submitter_comment', 'task_id', 'task_type', 'ticket_number']
    _search_for_update_fields = ['approval_status', 'execution_status',
                                 'task_id']
    _updateable_search_fields = ['approval_status', 'scheduled_time']
    _all_searchable_fields = ['approval_status', 'approver',
                              'execution_status', 'execution_time', 'member',
                              'scheduled_time', 'submit_time', 'submitter',
                              'task_id']
    _return_fields = ['approval_status', 'execution_status', 'task_id']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'changed_objects': Changedobject.from_dict,
    }


class Search(InfobloxObject):
    """ Search: Search object.
    Corresponds to WAPI object 'search'

    The search object is used to perform global searches for multiple
    object types in the database. This object contains only search
    parameters and returns objects that match the search criteria. The
    returned objects are base objects for the respective object types.

    Search is the only allowed operation for search objects.

    NOTE: Only one of the following can be used each time: 'address',
    'mac_address', 'duid' or 'fqdn'.

    Attributes:
    """
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
    """ ASharedRecord: DNS Shared A record object.
    Corresponds to WAPI object 'sharedrecord:a'

    A shared A (address) record is similar to a regular A record. It
    maps a domain name to an IPv4 address. The difference is that a
    shared A record should be added to a shared record group. If the
    shared record group is associated with other zones, the shared A
    record is shared among these zones.

    Attributes:
        comment: Comment for this shared record; maximum 256 characters.
        disable: Determines if this shared record is disabled or not.
            False means that the record is enabled.
        dns_name: The name for this shared record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv4addr: The IPv4 Address of the shared record.
        name: Name for this shared record. This value can be in unicode
            format.
        shared_record_group: The name of the shared record group in
            which the record resides.
        ttl: The Time To Live (TTL) value for this shared record. A
            32-bit unsigned integer that represents the duration, in
            seconds, for which the shared record is valid (cached). Zero
            indicates that the shared record should not be cached.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'sharedrecord:a'
    _fields = ['comment', 'disable', 'dns_name', 'extattrs', 'ipv4addr',
               'name', 'shared_record_group', 'ttl', 'use_ttl']
    _search_for_update_fields = ['ipv4addr', 'name']
    _updateable_search_fields = ['comment', 'ipv4addr', 'name']
    _all_searchable_fields = ['comment', 'ipv4addr', 'name']
    _return_fields = ['extattrs', 'ipv4addr', 'name', 'shared_record_group']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 4


class AAAASharedRecord(ASharedRecordBase):
    """ AAAASharedRecord: DNS Shared AAAA record object.
    Corresponds to WAPI object 'sharedrecord:aaaa'

    A shared AAAA (address) record is similar to a regular AAAA record.
    It maps a domain name to an IPv6 address. The difference is that a
    shared AAAA record should be added to a shared record group. If the
    shared record group is associated with other zones, the shared AAAA
    record is shared among these zones.

    Attributes:
        comment: Comment for this shared record; maximum 256 characters.
        disable: Determines if this shared record is disabled or not.
            False means that the record is enabled.
        dns_name: The name for this shared record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        ipv6addr: The IPv6 Address of the shared record.
        name: Name for this shared record. This value can be in unicode
            format.
        shared_record_group: The name of the shared record group in
            which the record resides.
        ttl: The Time To Live (TTL) value for this shared record. A
            32-bit unsigned integer that represents the duration, in
            seconds, for which the shared record is valid (cached). Zero
            indicates that the shared record should not be cached.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'sharedrecord:aaaa'
    _fields = ['comment', 'disable', 'dns_name', 'extattrs', 'ipv6addr',
               'name', 'shared_record_group', 'ttl', 'use_ttl']
    _search_for_update_fields = ['ipv6addr', 'name']
    _updateable_search_fields = ['comment', 'ipv6addr', 'name']
    _all_searchable_fields = ['comment', 'ipv6addr', 'name']
    _return_fields = ['extattrs', 'ipv6addr', 'name', 'shared_record_group']
    _remap = {}
    _shadow_fields = ['_ref']
    _ip_version = 6


class CNAMESharedRecord(InfobloxObject):
    """ CNAMESharedRecord: DNS Shared CNAME record object.
    Corresponds to WAPI object 'sharedrecord:cname'

    A shared CNAME (canonical name) record is similar to a regular CNAME
    record. The difference is that a shared CNAME record should be added
    to a shared record group. If the shared record group is associated
    with other zones, the shared CNAME record is shared among these
    zones.

    Attributes:
        canonical: Canonical name in FQDN format. This value can be in
            unicode format.
        comment: Comment for this shared record; maximum 256 characters.
        disable: Determines if this shared record is disabled or not.
            False means that the record is enabled.
        dns_canonical: Canonical name in punycode format.
        dns_name: The name for this shared record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: Name for this shared record. This value can be in unicode
            format.
        shared_record_group: The name of the shared record group in
            which the record resides.
        ttl: The Time To Live (TTL) value for this shared record. A
            32-bit unsigned integer that represents the duration, in
            seconds, for which the shared record is valid (cached). Zero
            indicates that the shared record should not be cached.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'sharedrecord:cname'
    _fields = ['canonical', 'comment', 'disable', 'dns_canonical', 'dns_name',
               'extattrs', 'name', 'shared_record_group', 'ttl', 'use_ttl']
    _search_for_update_fields = ['canonical', 'name']
    _updateable_search_fields = ['canonical', 'comment', 'name']
    _all_searchable_fields = ['canonical', 'comment', 'name']
    _return_fields = ['canonical', 'extattrs', 'name', 'shared_record_group']
    _remap = {}
    _shadow_fields = ['_ref']


class MXSharedRecord(InfobloxObject):
    """ MXSharedRecord: DNS Shared MX record object.
    Corresponds to WAPI object 'sharedrecord:mx'

    A shared MX (mail exchanger) record is similar to a regular MX
    record. It maps a domain name to a mail exchanger. The difference is
    that a shared MX record should be added to a shared record group. If
    the shared record group is associated with other zones, the shared
    MX record is shared among these zones.

    Attributes:
        comment: Comment for this shared record; maximum 256 characters.
        disable: Determines if this shared record is disabled or not.
            False means that the record is enabled.
        dns_mail_exchanger: The name of the mail exchanger in punycode
            format.
        dns_name: The name for this shared record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        mail_exchanger: The name of the mail exchanger in FQDN format.
            This value can be in unicode format.
        name: Name for this shared record. This value can be in unicode
            format.
        preference: The preference value. Valid values are from 0 to
            65535 (inclusive), in 32-bit unsigned integer format.
        shared_record_group: The name of the shared record group in
            which the record resides.
        ttl: The Time To Live (TTL) value for this shared record. A
            32-bit unsigned integer that represents the duration, in
            seconds, for which the shared record is valid (cached). Zero
            indicates that the shared record should not be cached.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'sharedrecord:mx'
    _fields = ['comment', 'disable', 'dns_mail_exchanger', 'dns_name',
               'extattrs', 'mail_exchanger', 'name', 'preference',
               'shared_record_group', 'ttl', 'use_ttl']
    _search_for_update_fields = ['mail_exchanger', 'name', 'preference']
    _updateable_search_fields = ['comment', 'mail_exchanger', 'name',
                                 'preference']
    _all_searchable_fields = ['comment', 'mail_exchanger', 'name',
                              'preference']
    _return_fields = ['extattrs', 'mail_exchanger', 'name', 'preference',
                      'shared_record_group']
    _remap = {}
    _shadow_fields = ['_ref']


class SRVSharedRecord(InfobloxObject):
    """ SRVSharedRecord: DNS Shared SRV record object.
    Corresponds to WAPI object 'sharedrecord:srv'

    A shared SRV (service) record is similar to a regular SRV record. It
    provides information about available services. The difference is
    that a shared SRV record should be added to a shared record group.
    If the shared record group is associated with other zones, the
    shared SRV record is shared among these zones.

    Attributes:
        comment: Comment for this shared record; maximum 256 characters.
        disable: Determines if this shared record is disabled or not.
            False means that the record is enabled.
        dns_name: The name for this shared record in punycode format.
        dns_target: The name for a shared SRV record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: Name for this shared record. This value can be in unicode
            format.
        port: The port of the shared SRV record. Valid values are from 0
            to 65535 (inclusive), in 32-bit unsigned integer format.
        priority: The priority of the shared SRV record. Valid values
            are from 0 to 65535 (inclusive), in 32-bit unsigned integer
            format.
        shared_record_group: The name of the shared record group in
            which the record resides.
        target: The target of the shared SRV record in FQDN format. This
            value can be in unicode format.
        ttl: The Time To Live (TTL) value for this shared record. A
            32-bit unsigned integer that represents the duration, in
            seconds, for which the shared record is valid (cached). Zero
            indicates that the shared record should not be cached.
        use_ttl: Use flag for: ttl
        weight: The weight of the shared SRV record. Valid values are
            from 0 to 65535 (inclusive), in 32-bit unsigned integer
            format.
    """
    _infoblox_type = 'sharedrecord:srv'
    _fields = ['comment', 'disable', 'dns_name', 'dns_target', 'extattrs',
               'name', 'port', 'priority', 'shared_record_group', 'target',
               'ttl', 'use_ttl', 'weight']
    _search_for_update_fields = ['name', 'port', 'priority', 'target',
                                 'weight']
    _updateable_search_fields = ['comment', 'name', 'port', 'priority',
                                 'target', 'weight']
    _all_searchable_fields = ['comment', 'name', 'port', 'priority', 'target',
                              'weight']
    _return_fields = ['extattrs', 'name', 'port', 'priority',
                      'shared_record_group', 'target', 'weight']
    _remap = {}
    _shadow_fields = ['_ref']


class TXTSharedRecord(InfobloxObject):
    """ TXTSharedRecord: DNS Shared TXT record object.
    Corresponds to WAPI object 'sharedrecord:txt'

    A shared TXT (text) record is similar to a regular TXT record. It
    contains supplemental information for a host. SPF (Sender Policy
    Framework) records are specialized TXT records that identify the
    servers that send mail from a domain. The difference is that a
    shared TXT record should be added to a shared record group. If the
    shared record group is associated with other zones, the shared TXT
    record is shared among these zones.

    Attributes:
        comment: Comment for this shared record; maximum 256 characters.
        disable: Determines if this shared record is disabled or not.
            False means that the record is enabled.
        dns_name: The name for this shared record in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: Name for this shared record. This value can be in unicode
            format.
        shared_record_group: The name of the shared record group in
            which the record resides.
        text: Text associated with the shared record. It can contain up
            to 255 bytes per substring and up a total of 512 bytes. To
            enter leading, trailing or embedded spaces in the text, add
            quotes (" ") around the text to preserve the spaces.
        ttl: The Time To Live (TTL) value for this shared record. A
            32-bit unsigned integer that represents the duration, in
            seconds, for which the shared record is valid (cached). Zero
            indicates that the shared record should not be cached.
        use_ttl: Use flag for: ttl
    """
    _infoblox_type = 'sharedrecord:txt'
    _fields = ['comment', 'disable', 'dns_name', 'extattrs', 'name',
               'shared_record_group', 'text', 'ttl', 'use_ttl']
    _search_for_update_fields = ['name', 'text']
    _updateable_search_fields = ['comment', 'name', 'text']
    _all_searchable_fields = ['comment', 'name', 'text']
    _return_fields = ['extattrs', 'name', 'shared_record_group', 'text']
    _remap = {}
    _shadow_fields = ['_ref']


class Sharedrecordgroup(InfobloxObject):
    """ Sharedrecordgroup: DNS Shared Record Group object.
    Corresponds to WAPI object 'sharedrecordgroup'

    A shared record group (SRG) is created to contain DNS shared records
    and share them between different zones. For example, if a group of
    DNS records needs to be in three different zones, you can include
    the records in a shared record group and assign the group to the
    three zones. For more information about shared record groups and
    shared records, please refer to Infoblox Administrator Guide.

    Attributes:
        comment: The descriptive comment of this shared record group.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name of this shared record group.
        record_name_policy: The record name policy of this shared record
            group.
        use_record_name_policy: Use flag for: record_name_policy
        zone_associations: The list of zones associated with this shared
            record group.
    """
    _infoblox_type = 'sharedrecordgroup'
    _fields = ['comment', 'extattrs', 'name', 'record_name_policy',
               'use_record_name_policy', 'zone_associations']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class SmartfolderChildren(InfobloxObject):
    """ SmartfolderChildren: Smart Folder children object.
    Corresponds to WAPI object 'smartfolder:children'

    The Smart Folder children object is used to read the objects that
    are associated with either a Smart Folder (global or personal) or a
    set of queries that users can make without saving a Smart Folder
    object on the appliance.

    The Smart Folder children object can be used for both "filtering"
    and "grouping" the results of Smart Folder associated objects.

    Attributes:
        resource: The object retuned by the Smart Folder query.
        value: The value returned by the Smart Folder query.
        value_type: The type of the returned value.
    """
    _infoblox_type = 'smartfolder:children'
    _fields = ['resource', 'value', 'value_type']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['resource', 'value', 'value_type']
    _remap = {}
    _shadow_fields = ['_ref']


class SmartfolderGlobal(InfobloxObject):
    """ SmartfolderGlobal: Global Smart Folder object.
    Corresponds to WAPI object 'smartfolder:global'

    Smart Folders are used to organize your core network services data.
    Depending on your administrative roles and business needs, you can
    filter your data object types, names, extensible attributes and
    discovered data and then place the filtered results in a Smart
    Folder.

    The global Smart Folders are created to be shared among
    administrators.

    Attributes:
        comment: The global Smart Folder descriptive comment.
        group_bys: Global Smart Folder grouping rules.
        name: The global Smart Folder name.
        query_items: The global Smart Folder filter queries.
    """
    _infoblox_type = 'smartfolder:global'
    _fields = ['comment', 'group_bys', 'name', 'query_items']
    _search_for_update_fields = ['name']
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
    """ SmartfolderPersonal: Personal Smart Folder object.
    Corresponds to WAPI object 'smartfolder:personal'

    Smart Folders are used to organize your core network services data.
    Depending on your administrative roles and business needs, you can
    filter your data object types, names, extensible attributes and
    discovered data and then place the filtered results in a Smart
    Folder.

    The personal Smart Folder is used to Smart Folders available only to
    a administrator that have created the Smart Folder.

    Attributes:
        comment: The personal Smart Folder descriptive comment.
        group_bys: The personal Smart Folder groupping rules.
        is_shortcut: Determines whether the personal Smart Folder is a
            shortcut.
        name: The personal Smart Folder name.
        query_items: The personal Smart Folder filter queries.
    """
    _infoblox_type = 'smartfolder:personal'
    _fields = ['comment', 'group_bys', 'is_shortcut', 'name', 'query_items']
    _search_for_update_fields = ['is_shortcut', 'name']
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
    """ Snmpuser: SNMP user object.
    Corresponds to WAPI object 'snmpuser'

    This object contains information related to SNMPv3 users.

    Attributes:
        authentication_password: Determines an authentication password
            for the user. This is a write-only attribute.
        authentication_protocol: The authentication protocol to be used
            for this user.
        comment: A descriptive comment for the SNMPv3 User.
        disable: Determines if SNMPv3 user is disabled or not.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: The name of the user.
        privacy_password: Determines a password for the privacy
            protocol.
        privacy_protocol: The privacy protocol to be used for this user.
    """
    _infoblox_type = 'snmpuser'
    _fields = ['authentication_password', 'authentication_protocol', 'comment',
               'disable', 'extattrs', 'name', 'privacy_password',
               'privacy_protocol']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Superhost(InfobloxObject):
    """ Superhost: SuperHost object.
    Corresponds to WAPI object 'superhost'

    The collection of correlated IPAM records which is related to single
    device.

    Attributes:
        comment: The comment for Super Host.
        delete_associated_objects: True if we have to delete all
            DNS/DHCP associated objects with Super Host, false by
            default.
        dhcp_associated_objects: A list of DHCP objects refs which are
            associated with Super Host.
        disabled: Disable all DNS/DHCP associated objects with Super
            Host if True, False by default.
        dns_associated_objects: A list of object refs of the DNS
            resource records which are associated with Super Host.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: Name of the Superhost.
    """
    _infoblox_type = 'superhost'
    _fields = ['comment', 'delete_associated_objects',
               'dhcp_associated_objects', 'disabled', 'dns_associated_objects',
               'extattrs', 'name']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'disabled', 'name']
    _all_searchable_fields = ['comment', 'disabled', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class Superhostchild(InfobloxObject):
    """ Superhostchild: Super Host Child object.
    Corresponds to WAPI object 'superhostchild'

    The superhostchild object is a read-only synthetic object used to
    retrieve records assigned to superhost.

    Since this is a synthetic object, it supports reading only by
    specifying search parameters, not by reference.

    Attributes:
        associated_object: The record object, if supported by the WAPI.
            Otherwise, the value is "None".
        comment: The record comment.
        creation_timestamp: Time at which DNS RR was created.
        data: Specific data of DNS/DHCP records.
        disabled: True if the child DNS/DHCP object is disabled.
        name: Name of the associated DNS/DHCP object.
        network_view: The name of the network view in which this network
            record resides.
        parent: Name of the Super Host object in which record resides.
        record_parent: Name of a parent zone/network.
        type: The record type. When searching for an unspecified record
            type, the search is performed for all records.
        view: Name of the DNS View in which the record resides.
    """
    _infoblox_type = 'superhostchild'
    _fields = ['associated_object', 'comment', 'creation_timestamp', 'data',
               'disabled', 'name', 'network_view', 'parent', 'record_parent',
               'type', 'view']
    _search_for_update_fields = ['data', 'name', 'network_view', 'parent',
                                 'record_parent', 'type', 'view']
    _updateable_search_fields = []
    _all_searchable_fields = ['comment', 'creation_timestamp', 'data', 'name',
                              'network_view', 'parent', 'record_parent',
                              'type', 'view']
    _return_fields = ['comment', 'data', 'name', 'network_view', 'parent',
                      'record_parent', 'type', 'view']
    _remap = {}
    _shadow_fields = ['_ref']


class SyslogEndpoint(InfobloxObject):
    """ SyslogEndpoint: The syslog endpoint object.
    Corresponds to WAPI object 'syslog:endpoint'

    The name part of the syslog:endpoint object reference has the
    following components:

    The name of an endpoint.

    Example: syslog:endpoint/b25lLmVuZHBvaW50JDMzOQ:wintermute

    Attributes:
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        log_level: The log level for a notification REST endpoint.
        name: The name of a Syslog endpoint.
        outbound_member_type: The outbound member that will generate
            events.
        outbound_members: The list of members for outbound events.
        syslog_servers: List of syslog servers
        template_instance: The Syslog template instance. You cannot
            change the parameters of the Syslog endpoint template
            instance.
        timeout: The timeout of session management (in seconds).
        vendor_identifier: The vendor identifier.
        wapi_user_name: The user name for WAPI integration.
        wapi_user_password: The user password for WAPI integration.
    """
    _infoblox_type = 'syslog:endpoint'
    _fields = ['extattrs', 'log_level', 'name', 'outbound_member_type',
               'outbound_members', 'syslog_servers', 'template_instance',
               'timeout', 'vendor_identifier', 'wapi_user_name',
               'wapi_user_password']
    _search_for_update_fields = ['name', 'outbound_member_type']
    _updateable_search_fields = ['log_level', 'name', 'outbound_member_type',
                                 'vendor_identifier']
    _all_searchable_fields = ['log_level', 'name', 'outbound_member_type',
                              'vendor_identifier']
    _return_fields = ['extattrs', 'name', 'outbound_member_type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'syslog_servers': SyslogEndpointServers.from_dict,
    }

    def test_syslog_connection(self, *args, **kwargs):
        return self._call_func("test_syslog_connection", *args, **kwargs)


class TacacsplusAuthservice(InfobloxObject):
    """ TacacsplusAuthservice: The TACACS+ authentication service
    object.
    Corresponds to WAPI object 'tacacsplus:authservice'

    This object is used to supply configuration for TACACS+
    authentication service.

    Attributes:
        acct_retries: The number of the accounting retries before giving
            up and moving on to the next server.
        acct_timeout: The accounting retry period in milliseconds.
        auth_retries: The number of the authentication/authorization
            retries before giving up and moving on to the next server.
        auth_timeout: The authentication/authorization timeout period in
            milliseconds.
        comment: The TACACS+ authentication service descriptive comment.
        disable: Determines whether the TACACS+ authentication service
            object is disabled.
        name: The TACACS+ authentication service name.
        servers: The list of the TACACS+ servers used for
            authentication.
    """
    _infoblox_type = 'tacacsplus:authservice'
    _fields = ['acct_retries', 'acct_timeout', 'auth_retries', 'auth_timeout',
               'comment', 'disable', 'name', 'servers']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'disable', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'servers': TacacsplusServer.from_dict,
    }

    def check_tacacsplus_server_settings(self, *args, **kwargs):
        return self._call_func("check_tacacsplus_server_settings", *args,
                               **kwargs)


class Taxii(InfobloxObject):
    """ Taxii: Taxii Member object.
    Corresponds to WAPI object 'taxii'

    The Taxii Member object provides information about Taxii service
    configuration such as the start/stop flag and RPZ (Response Policy
    Zone) configuration.

    Attributes:
        enable_service: Indicates whether the Taxii service is running
            on the given member or not.
        ipv4addr: The IPv4 Address of the Grid member.
        ipv6addr: The IPv6 Address of the Grid member.
        name: The name of the Taxii Member.
        taxii_rpz_config: Taxii service RPZ configuration list.
    """
    _infoblox_type = 'taxii'
    _fields = ['enable_service', 'ipv4addr', 'ipv6addr', 'name',
               'taxii_rpz_config']
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
    """ Tftpfiledir: TFTP file or directory object.
    Corresponds to WAPI object 'tftpfiledir'

    The TFTP file/directory object provides facilities for creating a
    directory structure for file distribution, modifying the directory
    name and permission, creating virtual TFTP root directories, and
    browsing the contents of the directories.

    Attributes:
        directory: The path to the directory that contains file or
            subdirectory.
        is_synced_to_gm: Determines whether the TFTP entity is
            synchronized to Grid Master.
        last_modify: The time when the file or directory was last
            modified.
        name: The TFTP directory or file name.
        type: The type of TFTP file system entity (directory or file).
        vtftp_dir_members: The replication members with TFTP client
            addresses where this virtual folder is applicable.
    """
    _infoblox_type = 'tftpfiledir'
    _fields = ['directory', 'is_synced_to_gm', 'last_modify', 'name', 'type',
               'vtftp_dir_members']
    _search_for_update_fields = ['directory', 'name', 'type']
    _updateable_search_fields = ['name']
    _all_searchable_fields = ['directory', 'name', 'type']
    _return_fields = ['directory', 'name', 'type']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'vtftp_dir_members': Vtftpdirmember.from_dict,
    }


class ThreatanalyticsAnalyticsWhitelist(InfobloxObject):
    """ ThreatanalyticsAnalyticsWhitelist: Threat analytics whitelist
    object.
    Corresponds to WAPI object 'threatanalytics:analytics_whitelist'

    The threat analytics whitelist object contains trusted domains on
    which NIOS allows DNS traffic.

    Attributes:
        version: Whitelist version string.
    """
    _infoblox_type = 'threatanalytics:analytics_whitelist'
    _fields = ['version']
    _search_for_update_fields = ['version']
    _updateable_search_fields = []
    _all_searchable_fields = ['version']
    _return_fields = ['version']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatanalyticsModuleset(InfobloxObject):
    """ ThreatanalyticsModuleset: Threat analytics module set object.
    Corresponds to WAPI object 'threatanalytics:moduleset'

    The threat analytics module set represents the installation or
    update of module information.

    Attributes:
        version: The version number of the threat analytics module set.
    """
    _infoblox_type = 'threatanalytics:moduleset'
    _fields = ['version']
    _search_for_update_fields = ['version']
    _updateable_search_fields = []
    _all_searchable_fields = ['version']
    _return_fields = ['version']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatanalyticsWhitelist(InfobloxObject):
    """ ThreatanalyticsWhitelist: Threat analytics whitelist object.
    Corresponds to WAPI object 'threatanalytics:whitelist'

    The threat analytics whitelist object contains trusted domains on
    which NIOS allows DNS traffic.

    Attributes:
        comment: The descriptive comment for the threat analytics
            whitelist.
        disable: Determines whether the threat analytics whitelist is
            disabled.
        fqdn: The FQDN of the threat analytics whitelist.
        type: The type of the threat analytics whitelist.
    """
    _infoblox_type = 'threatanalytics:whitelist'
    _fields = ['comment', 'disable', 'fqdn', 'type']
    _search_for_update_fields = ['fqdn']
    _updateable_search_fields = ['comment', 'fqdn']
    _all_searchable_fields = ['comment', 'fqdn', 'type']
    _return_fields = ['comment', 'disable', 'fqdn']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatinsightCloudclient(InfobloxObject):
    """ ThreatinsightCloudclient: Threat Insight Cloud Client object.
    Corresponds to WAPI object 'threatinsight:cloudclient'

    You can use the Threat Insight Cloud Client object to configure the
    detection and authentication of domains in the Cloud, and then apply
    them to on-premises DNS firewall RPZ zones within a configurable
    time frame.

    Attributes:
        blacklist_rpz_list: The RPZs to which you apply newly detected
            domains through the Infoblox Threat Insight Cloud Client.
        enable: Determines whether the Threat Insight in Cloud Client is
            enabled.
        force_refresh: Force a refresh if at least one RPZ is
            configured.
        interval: The time interval (in seconds) for requesting newly
            detected domains by the Infoblox Threat Insight Cloud Client
            and applying them to the list of configured RPZs.
    """
    _infoblox_type = 'threatinsight:cloudclient'
    _fields = ['blacklist_rpz_list', 'enable', 'force_refresh', 'interval']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['enable', 'interval']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionGridRule(InfobloxObject):
    """ ThreatprotectionGridRule: Threat protection custom rule object.
    Corresponds to WAPI object 'threatprotection:grid:rule'

    This object provides information about the threat protection custom
    rule settings.

    Attributes:
        allowed_actions: The list of allowed actions of the custom rule.
        category: The rule category the custom rule assigned to.
        comment: The human readable comment for the custom rule.
        config: The rule config of the template.
        description: The description of the custom rule.
        disabled: Determines if the custom rule is disabled.
        is_factory_reset_enabled: Determines if factory reset is enabled
            for the custom rule.
        name: The name of the rule custom rule concatenated with its
            rule config parameters.
        ruleset: The version of the ruleset the custom rule assigned to.
        sid: The Rule ID.
        template: The threat protection rule template used to create
            this rule.
        type: The type of the custom rule.
    """
    _infoblox_type = 'threatprotection:grid:rule'
    _fields = ['allowed_actions', 'category', 'comment', 'config',
               'description', 'disabled', 'is_factory_reset_enabled', 'name',
               'ruleset', 'sid', 'template', 'type']
    _search_for_update_fields = ['name', 'ruleset', 'sid']
    _updateable_search_fields = ['comment', 'template']
    _all_searchable_fields = ['category', 'comment', 'description', 'name',
                              'ruleset', 'sid', 'template', 'type']
    _return_fields = ['name', 'ruleset', 'sid']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionProfile(InfobloxObject):
    """ ThreatprotectionProfile: The Threat Protection profile object.
    Corresponds to WAPI object 'threatprotection:profile'

    The Threat Protection profile object facilitates configuring groups
    of Threat Protection members that have similar traffic properties. A
    member can be either associated with a Threat Protection profile or
    inherit the ruleset from the Grid or override the ruleset
    individually at the member level.

    Attributes:
        comment: The comment for the Threat Protection profile.
        current_ruleset: The current Threat Protection profile ruleset.
        disable_multiple_dns_tcp_request: Determines if multiple BIND
            responses via TCP connection are disabled.
        events_per_second_per_rule: The number of events logged per
            second per rule.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        members: The list of members that are associated with the
            profile.
        name: The name of the Threat Protection profile.
        source_member: The source member. It can be used only during the
            create operation for cloning a profile from an existing
            member.
        source_profile: The source profile. It can be used only during
            the create operation for cloning a profile from an existing
            profile.
        use_current_ruleset: Use flag for: current_ruleset
        use_disable_multiple_dns_tcp_request: Use flag for:
            disable_multiple_dns_tcp_request
        use_events_per_second_per_rule: Use flag for:
            events_per_second_per_rule
    """
    _infoblox_type = 'threatprotection:profile'
    _fields = ['comment', 'current_ruleset',
               'disable_multiple_dns_tcp_request',
               'events_per_second_per_rule', 'extattrs', 'members', 'name',
               'source_member', 'source_profile', 'use_current_ruleset',
               'use_disable_multiple_dns_tcp_request',
               'use_events_per_second_per_rule']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'current_ruleset',
                                 'disable_multiple_dns_tcp_request',
                                 'events_per_second_per_rule', 'name']
    _all_searchable_fields = ['comment', 'current_ruleset',
                              'disable_multiple_dns_tcp_request',
                              'events_per_second_per_rule', 'name']
    _return_fields = ['comment', 'extattrs', 'name']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionProfileRule(InfobloxObject):
    """ ThreatprotectionProfileRule: Threat Protection Profile Rule
    object.
    Corresponds to WAPI object 'threatprotection:profile:rule'

    This object provides information about the Threat protection profile
    rule settings.

    Attributes:
        config: The threat protection rule configuration.
        disable: Determines if the rule is enabled or not for the
            profile.
        profile: The name of the Threat protection profile.
        rule: The rule object name.
        sid: The snort rule ID.
        use_config: Use flag for: config
        use_disable: Use flag for: disable
    """
    _infoblox_type = 'threatprotection:profile:rule'
    _fields = ['config', 'disable', 'profile', 'rule', 'sid', 'use_config',
               'use_disable']
    _search_for_update_fields = ['profile', 'rule']
    _updateable_search_fields = []
    _all_searchable_fields = ['profile', 'rule', 'sid']
    _return_fields = ['profile', 'rule']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionRule(InfobloxObject):
    """ ThreatprotectionRule: Member Threat Protection Rule object.
    Corresponds to WAPI object 'threatprotection:rule'

    This object provides information about the member Threat protection
    rule settings.

    Attributes:
        config: The threat protection rule configuration.
        disable: Determines if the rule is enabled or not for the
            member.
        member: The name of the Threat protection member.
        rule: The rule object name.
        sid: The Rule ID.
        use_config: Use flag for: config
        use_disable: Use flag for: disable
    """
    _infoblox_type = 'threatprotection:rule'
    _fields = ['config', 'disable', 'member', 'rule', 'sid', 'use_config',
               'use_disable']
    _search_for_update_fields = ['member', 'rule']
    _updateable_search_fields = []
    _all_searchable_fields = ['member', 'rule', 'sid']
    _return_fields = ['member', 'rule']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionRulecategory(InfobloxObject):
    """ ThreatprotectionRulecategory: Threat protection rule category
    object.
    Corresponds to WAPI object 'threatprotection:rulecategory'

    This object provides information about the threat protection rule
    category settings.

    Attributes:
        is_factory_reset_enabled: Determines if factory reset is enabled
            for this rule category.
        name: The name of the rule category.
        ruleset: The version of the ruleset the category assigned to.
    """
    _infoblox_type = 'threatprotection:rulecategory'
    _fields = ['is_factory_reset_enabled', 'name', 'ruleset']
    _search_for_update_fields = ['name', 'ruleset']
    _updateable_search_fields = []
    _all_searchable_fields = ['name', 'ruleset']
    _return_fields = ['name', 'ruleset']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionRuleset(InfobloxObject):
    """ ThreatprotectionRuleset: The Grid threat protection ruleset
    object.
    Corresponds to WAPI object 'threatprotection:ruleset'

    This object represent the Grid protection ruleset information.

    Attributes:
        add_type: Determines the way the ruleset was added.
        added_time: The time when the ruleset was added.
        comment: The human readable comment for the ruleset.
        do_not_delete: Determines if the ruleset will not be deleted
            during upgrade.
        is_factory_reset_enabled: Determines if factory reset is enabled
            for this ruleset.
        used_by: The users of the ruleset.
        version: The ruleset version.
    """
    _infoblox_type = 'threatprotection:ruleset'
    _fields = ['add_type', 'added_time', 'comment', 'do_not_delete',
               'is_factory_reset_enabled', 'used_by', 'version']
    _search_for_update_fields = ['add_type', 'version']
    _updateable_search_fields = ['comment']
    _all_searchable_fields = ['add_type', 'comment', 'version']
    _return_fields = ['add_type', 'version']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionRuletemplate(InfobloxObject):
    """ ThreatprotectionRuletemplate: Threat protection rule template
    object.
    Corresponds to WAPI object 'threatprotection:ruletemplate'

    This object provides information about the threat protection rule
    template settings.

    Attributes:
        allowed_actions: The list of allowed actions of rhe rule
            template.
        category: The rule category this template assigned to.
        default_config: The rule config of this template.
        description: The description of the rule template.
        name: The name of the rule template.
        ruleset: The version of the ruleset the template assigned to.
        sid: The Rule ID.
    """
    _infoblox_type = 'threatprotection:ruletemplate'
    _fields = ['allowed_actions', 'category', 'default_config', 'description',
               'name', 'ruleset', 'sid']
    _search_for_update_fields = ['name', 'ruleset', 'sid']
    _updateable_search_fields = []
    _all_searchable_fields = ['category', 'description', 'name', 'ruleset',
                              'sid']
    _return_fields = ['name', 'ruleset', 'sid']
    _remap = {}
    _shadow_fields = ['_ref']


class ThreatprotectionStatistics(InfobloxObject):
    """ ThreatprotectionStatistics: Threat protection statistics object.
    Corresponds to WAPI object 'threatprotection:statistics'

    This object provides information about the threat protection
    statistics.

    Attributes:
        member: The Grid member name to get threat protection
            statistics. If nothing is specified then event statistics is
            returned for the Grid.
        stat_infos: The list of event statistical information for the
            Grid or particular members.
    """
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
    """ Upgradegroup: Upgrade group object.
    Corresponds to WAPI object 'upgradegroup'

    To minimize the impact of Grid upgrades on system operations, you
    can organize members into upgrade groups and schedule their software
    distributions. The upgrade group object provides configuration of
    upgrade and software distribution for members included in the
    upgrade group.

    Attributes:
        comment: The upgrade group descriptive comment.
        distribution_dependent_group: The distribution dependent group
            name.
        distribution_policy: The distribution scheduling policy.
        distribution_time: The time of the next scheduled distribution.
        members: The upgrade group members.
        name: The upgrade group name.
        time_zone: The time zone for scheduling operations.
        upgrade_dependent_group: The upgrade dependent group name.
        upgrade_policy: The upgrade scheduling policy.
        upgrade_time: The time of the next scheduled upgrade.
    """
    _infoblox_type = 'upgradegroup'
    _fields = ['comment', 'distribution_dependent_group',
               'distribution_policy', 'distribution_time', 'members', 'name',
               'time_zone', 'upgrade_dependent_group', 'upgrade_policy',
               'upgrade_time']
    _search_for_update_fields = ['name']
    _updateable_search_fields = ['comment', 'name']
    _all_searchable_fields = ['comment', 'name']
    _return_fields = ['comment', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'members': UpgradegroupMember.from_dict,
    }


class Upgradeschedule(InfobloxObject):
    """ Upgradeschedule: Upgrade schedule object.
    Corresponds to WAPI object 'upgradeschedule'

    You can schedule lite and full upgrades for certain NIOS versions.
    When you schedule an upgrade, you schedule the upgrade for the Grid
    Master and the upgrade groups, including the Default group. The Grid
    Master must always upgrade before the upgrade groups.

    The upgrade schedule object provides configuration of the scheduled
    upgrade, activation of the latest upgrade, as well as date and time
    settings for the upgrade.

    Attributes:
        active: Determines whether the upgrade schedule is active.
        start_time: The start time of the upgrade.
        time_zone: The time zone for upgrade start time.
        upgrade_groups: The upgrade groups scheduling settings.
    """
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
    """ Upgradestatus: The upgrade status object.
    Corresponds to WAPI object 'upgradestatus'

    The Upgrade Status object is used to view the upgrade status of
    Infoblox Grid elements.

    Attributes:
        allow_distribution: Determines if distribution is allowed for
            the Grid.
        allow_distribution_scheduling: Determines if distribution
            scheduling is allowed.
        allow_upgrade: Determines if upgrade is allowed for the Grid.
        allow_upgrade_cancel: Determines if the Grid is allowed to
            cancel an upgrade.
        allow_upgrade_pause: Determines if the Grid is allowed to pause
            an upgrade.
        allow_upgrade_resume: Determines if the Grid is allowed to
            resume an upgrade.
        allow_upgrade_scheduling: Determine if the Grid is allowed to
            schedule an upgrade.
        allow_upgrade_test: Determines if the Grid is allowed to test an
            upgrade.
        allow_upload: Determine if the Grid is allowed to upload a
            build.
        alternate_version: The alternative version.
        comment: Comment in readable format for an upgrade group a or
            virtual node.
        current_version: The current version.
        current_version_summary: Current version summary for the 'type'
            requested. This field can be requested for the Grid, a
            certain group that has virtual nodes as subelements, or for
            the overall group status.
        distribution_schedule_active: Determines if the distribution
            schedule is active for the Grid.
        distribution_schedule_time: The Grid master distribution
            schedule time.
        distribution_state: The current state of distribution process.
        distribution_version: The version that is distributed.
        distribution_version_summary: Distribution version summary for
            the 'type' requested. This field can be requested for the
            Grid, a certain group that has virtual nodes as subelements,
            or for the overall group status.
        element_status: The status of a certain element with regards to
            the type requested.
        grid_state: The state of the Grid.
        group_state: The state of a group.
        ha_status: Status of the HA pair.
        hotfixes: The list of hotfixes.
        ipv4_address: The IPv4 Address of virtual node or physical one.
        ipv6_address: The IPv6 Address of virtual node or physical one.
        member: Member that participates in the upgrade process.
        message: The Grid message.
        pnode_role: Status of the physical node in the HA pair.
        reverted: Determines if the upgrade process is reverted.
        status_time: The status time.
        status_value: Status of a certain group, virtual node or
            physical node.
        status_value_update_time: Timestamp of when the status was
            updated.
        steps: The list of upgrade process steps.
        steps_completed: The number of steps done.
        steps_total: Total number steps in the upgrade process.
        subelement_type: The type of subelements to be requested. If
            'type' is 'GROUP', or 'VNODE', then 'upgrade_group' or
            'member' should have proper values for an operation to
            return data specific for the values passed. Otherwise,
            overall data is returned for every group or physical node.
        subelements_completed: Number of subelements that have
            accomplished an upgrade.
        subelements_status: The upgrade process information of
            subelements.
        subelements_total: Number of subelements number in a certain
            group, virtual node, or the Grid.
        type: The type of upper level elements to be requested.
        upgrade_group: Upgrade group that participates in the upgrade
            process.
        upgrade_schedule_active: Determines if the upgrade schedule is
            active.
        upgrade_state: The upgrade state of the Grid.
        upgrade_test_status: The upgrade test status of the Grid.
        upload_version: The version that is uploaded.
        upload_version_summary: Upload version summary for the 'type'
            requested. This field can be requested for the Grid, a
            certain group that has virtual nodes as subelements, or
            overall group status.
    """
    _infoblox_type = 'upgradestatus'
    _fields = ['allow_distribution', 'allow_distribution_scheduling',
               'allow_upgrade', 'allow_upgrade_cancel', 'allow_upgrade_pause',
               'allow_upgrade_resume', 'allow_upgrade_scheduling',
               'allow_upgrade_test', 'allow_upload', 'alternate_version',
               'comment', 'current_version', 'current_version_summary',
               'distribution_schedule_active', 'distribution_schedule_time',
               'distribution_state', 'distribution_version',
               'distribution_version_summary', 'element_status', 'grid_state',
               'group_state', 'ha_status', 'hotfixes', 'ipv4_address',
               'ipv6_address', 'member', 'message', 'pnode_role', 'reverted',
               'status_time', 'status_value', 'status_value_update_time',
               'steps', 'steps_completed', 'steps_total', 'subelement_type',
               'subelements_completed', 'subelements_status',
               'subelements_total', 'type', 'upgrade_group',
               'upgrade_schedule_active', 'upgrade_state',
               'upgrade_test_status', 'upload_version',
               'upload_version_summary']
    _search_for_update_fields = ['member', 'type', 'upgrade_group']
    _updateable_search_fields = []
    _all_searchable_fields = ['member', 'subelement_type', 'type',
                              'upgrade_group']
    _return_fields = ['alternate_version', 'comment', 'current_version',
                      'distribution_version', 'element_status', 'grid_state',
                      'group_state', 'ha_status', 'hotfixes', 'ipv4_address',
                      'ipv6_address', 'member', 'message', 'pnode_role',
                      'reverted', 'status_value', 'status_value_update_time',
                      'steps', 'steps_completed', 'steps_total', 'type',
                      'upgrade_group', 'upgrade_state', 'upgrade_test_status',
                      'upload_version']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'hotfixes': Hotfix.from_dict,
        'steps': Upgradestep.from_dict,
    }


class Userprofile(InfobloxObject):
    """ Userprofile: User profile object.
    Corresponds to WAPI object 'userprofile'

    The user profile of the admin who has logged in.

    Attributes:
        active_dashboard_type: Determines the active dashboard type.
        admin_group: The Admin Group object to which the admin belongs.
            An admin user can belong to only one admin group at a time.
        days_to_expire: The number of days left before the admin's
            password expires.
        email: The email address of the admin.
        global_search_on_ea: Determines if extensible attribute values
            will be returned by global search or not.
        global_search_on_ni_data: Determines if global search will
            search for network insight devices and interfaces or not.
        grid_admin_groups: List of Admin Group objects that the current
            user is mapped to.
        last_login: The timestamp when the admin last logged in.
        lb_tree_nodes_at_gen_level: Determines how many nodes are
            displayed at generation levels.
        lb_tree_nodes_at_last_level: Determines how many nodes are
            displayed at the last level.
        max_count_widgets: The maximum count of widgets that can be
            added to one dashboard.
        name: The admin name.
        old_password: The current password that will be replaced by a
            new password. To change a password in the database, you must
            provide both the current and new password values. This is a
            write-only attribute.
        password: The new password of the admin. To change a password in
            the database, you must provide both the current and new
            password values. This is a write-only attribute.
        table_size: The number of lines of data a table or a single list
            view can contain.
        time_zone: The time zone of the admin user.
        use_time_zone: Use flag for: time_zone
        user_type: The admin type.
    """
    _infoblox_type = 'userprofile'
    _fields = ['active_dashboard_type', 'admin_group', 'days_to_expire',
               'email', 'global_search_on_ea', 'global_search_on_ni_data',
               'grid_admin_groups', 'last_login', 'lb_tree_nodes_at_gen_level',
               'lb_tree_nodes_at_last_level', 'max_count_widgets', 'name',
               'old_password', 'password', 'table_size', 'time_zone',
               'use_time_zone', 'user_type']
    _search_for_update_fields = []
    _updateable_search_fields = []
    _all_searchable_fields = []
    _return_fields = ['name']
    _remap = {}
    _shadow_fields = ['_ref']


class Vdiscoverytask(InfobloxObject):
    """ Vdiscoverytask: Discovery task object.
    Corresponds to WAPI object 'vdiscoverytask'

    This object represents vDiscovery Task.

    Attributes:
        allow_unsecured_connection: Allow unsecured connection over
            HTTPS and bypass validation of the remote SSL certificate.
        auto_consolidate_cloud_ea: Whether to insert or update cloud EAs
            with discovery data.
        auto_consolidate_managed_tenant: Whether to replace managed
            tenant with discovery tenant data.
        auto_consolidate_managed_vm: Whether to replace managed virtual
            machine with discovery vm data.
        auto_create_dns_hostname_template: Template string used to
            generate host name.
        auto_create_dns_record: Control whether to create or update DNS
            record using discovered data.
        auto_create_dns_record_type: Indicates the type of record to
            create if the auto create DNS record is enabled.
        comment: Comment on the task.
        credentials_type: Credentials type used for connecting to the
            cloud management platform.
        dns_view_private_ip: The DNS view name for private IPs.
        dns_view_public_ip: The DNS view name for public IPs.
        domain_name: The name of the domain to use with keystone v3.
        driver_type: Type of discovery driver.
        enabled: Whether to enabled the cloud discovery or not.
        fqdn_or_ip: FQDN or IP of the cloud management platform.
        identity_version: Identity service version.
        last_run: Timestamp of last run.
        member: Member on which cloud discovery will be run.
        merge_data: Whether to replace the old data with new or not.
        name: Name of this cloud discovery task. Uniquely identify a
            task.
        password: Password used for connecting to the cloud management
            platform.
        port: Connection port used for connecting to the cloud
            management platform.
        private_network_view: Network view for private IPs.
        private_network_view_mapping_policy: Mapping policy for the
            network view for private IPs in discovery data.
        protocol: Connection protocol used for connecting to the cloud
            management platform.
        public_network_view: Network view for public IPs.
        public_network_view_mapping_policy: Mapping policy for the
            network view for public IPs in discovery data.
        scheduled_run: Schedule setting for cloud discovery task.
        service_account_file: The service_account_file for GCP.
        state: Current state of this task.
        state_msg: State message of the complete discovery process.
        update_dns_view_private_ip: If set to true, the appliance uses a
            specific DNS view for private IPs.
        update_dns_view_public_ip: If set to true, the appliance uses a
            specific DNS view for public IPs.
        update_metadata: Whether to update metadata as a result of this
            network discovery.
        use_identity: If set true, all keystone connection will use
            "/identity" endpoint and port value will be ignored.
        username: Username used for connecting to the cloud management
            platform.
    """
    _infoblox_type = 'vdiscoverytask'
    _fields = ['allow_unsecured_connection', 'auto_consolidate_cloud_ea',
               'auto_consolidate_managed_tenant',
               'auto_consolidate_managed_vm',
               'auto_create_dns_hostname_template', 'auto_create_dns_record',
               'auto_create_dns_record_type', 'comment', 'credentials_type',
               'dns_view_private_ip', 'dns_view_public_ip', 'domain_name',
               'driver_type', 'enabled', 'fqdn_or_ip', 'identity_version',
               'last_run', 'member', 'merge_data', 'name', 'password', 'port',
               'private_network_view', 'private_network_view_mapping_policy',
               'protocol', 'public_network_view',
               'public_network_view_mapping_policy', 'scheduled_run',
               'service_account_file', 'state', 'state_msg',
               'update_dns_view_private_ip', 'update_dns_view_public_ip',
               'update_metadata', 'use_identity', 'username']
    _search_for_update_fields = ['name', 'state']
    _updateable_search_fields = ['dns_view_private_ip', 'dns_view_public_ip',
                                 'domain_name', 'driver_type', 'enabled',
                                 'fqdn_or_ip', 'identity_version', 'member',
                                 'name', 'port', 'private_network_view',
                                 'private_network_view_mapping_policy',
                                 'protocol', 'public_network_view',
                                 'public_network_view_mapping_policy',
                                 'service_account_file',
                                 'update_dns_view_private_ip',
                                 'update_dns_view_public_ip', 'use_identity',
                                 'username']
    _all_searchable_fields = ['dns_view_private_ip', 'dns_view_public_ip',
                              'domain_name', 'driver_type', 'enabled',
                              'fqdn_or_ip', 'identity_version', 'member',
                              'name', 'port', 'private_network_view',
                              'private_network_view_mapping_policy',
                              'protocol', 'public_network_view',
                              'public_network_view_mapping_policy',
                              'service_account_file', 'state',
                              'update_dns_view_private_ip',
                              'update_dns_view_public_ip', 'use_identity',
                              'username']
    _return_fields = ['name', 'state']
    _remap = {}
    _shadow_fields = ['_ref']

    def vdiscovery_control(self, *args, **kwargs):
        return self._call_func("vdiscovery_control", *args, **kwargs)


class DNSView(InfobloxObject):
    """ DNSView: DNS View object.
    Corresponds to WAPI object 'view'

    DNS views provide the ability to serve one version of DNS data to
    one set of clients and another version to another set of clients.
    With DNS views, the appliance can provide a different answer to the
    same query, depending on the source of the query.

    Attributes:
        blacklist_action: The action to perform when a domain name
            matches the pattern defined in a rule that is specified by
            the blacklist_ruleset method. Valid values are "REDIRECT" or
            "REFUSE". The default value is "REFUSE".
        blacklist_log_query: The flag that indicates whether blacklist
            redirection queries are logged. Specify "true" to enable
            logging, or "false" to disable it. The default value is
            "false".
        blacklist_redirect_addresses: The array of IP addresses the
            appliance includes in the response it sends in place of a
            blacklisted IP address.
        blacklist_redirect_ttl: The Time To Live (TTL) value of the
            synthetic DNS responses resulted from blacklist redirection.
            The TTL value is a 32-bit unsigned integer that represents
            the TTL in seconds.
        blacklist_rulesets: The name of the Ruleset object assigned at
            the Grid level for blacklist redirection.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the DNS view; maximum 64 characters.
        custom_root_name_servers: The list of customized root name
            servers. You can either select and use Internet root name
            servers or specify custom root name servers by providing a
            host name and IP address to which the Infoblox appliance can
            send queries. Include the specified parameter to set the
            attribute value. Omit the parameter to retrieve the
            attribute value.
        ddns_force_creation_timestamp_update: Defines whether creation
            timestamp of RR should be updated ' when DDNS update happens
            even if there is no change to ' the RR.
        ddns_principal_group: The DDNS Principal cluster group name.
        ddns_principal_tracking: The flag that indicates whether the
            DDNS principal track is enabled or disabled.
        ddns_restrict_patterns: The flag that indicates whether an
            option to restrict DDNS update request based on FQDN
            patterns is enabled or disabled.
        ddns_restrict_patterns_list: The unordered list of restriction
            patterns for an option of to restrict DDNS updates based on
            FQDN patterns.
        ddns_restrict_protected: The flag that indicates whether an
            option to restrict DDNS update request to protected resource
            records is enabled or disabled.
        ddns_restrict_secure: The flag that indicates whether DDNS
            update request for principal other than target resource
            record's principal is restricted.
        ddns_restrict_static: The flag that indicates whether an option
            to restrict DDNS update request to resource records which
            are marked as 'STATIC' is enabled or disabled.
        disable: Determines if the DNS view is disabled or not. When
            this is set to False, the DNS view is enabled.
        dns64_enabled: Determines if the DNS64 s enabled or not.
        dns64_groups: The list of DNS64 synthesis groups associated with
            this DNS view.
        dnssec_enabled: Determines if the DNS security extension is
            enabled or not.
        dnssec_expired_signatures_enabled: Determines if the DNS
            security extension accepts expired signatures or not.
        dnssec_negative_trust_anchors: A list of zones for which the
            server does not perform DNSSEC validation.
        dnssec_trusted_keys: The list of trusted keys for the DNS
            security extension.
        dnssec_validation_enabled: Determines if the DNS security
            validation is enabled or not.
        edns_udp_size: Advertises the EDNS0 buffer size to the upstream
            server. The value should be between 512 and 4096 bytes. The
            recommended value is between 512 and 1220 bytes.
        enable_blacklist: Determines if the blacklist in a DNS view is
            enabled or not.
        enable_fixed_rrset_order_fqdns: Determines if the fixed RRset
            order FQDN is enabled or not.
        enable_match_recursive_only: Determines if the 'match-recursive-
            only' option in a DNS view is enabled or not.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        filter_aaaa: The type of AAAA filtering for this DNS view
            object.
        filter_aaaa_list: Applies AAAA filtering to a named ACL, or to a
            list of IPv4/IPv6 addresses and networks from which queries
            are received. This field does not allow TSIG keys.
        fixed_rrset_order_fqdns: The fixed RRset order FQDN. If this
            field does not contain an empty value, the appliance will
            automatically set the enable_fixed_rrset_order_fqdns field
            to 'true', unless the same request sets the enable field to
            'false'.
        forward_only: Determines if this DNS view sends queries to
            forwarders only or not. When the value is True, queries are
            sent to forwarders only, and not to other internal or
            Internet root servers.
        forwarders: The list of forwarders for the DNS view. A forwarder
            is a name server to which other name servers first send
            their off-site queries. The forwarder builds up a cache of
            information, avoiding the need for other name servers to
            send queries off-site.
        is_default: The NIOS appliance provides one default DNS view.
            You can rename the default view and change its settings, but
            you cannot delete it. There must always be at least one DNS
            view in the appliance.
        lame_ttl: The number of seconds to cache lame delegations or
            lame servers.
        last_queried_acl: Determines last queried ACL for the specified
            IPv4 or IPv6 addresses and networks in scavenging settings.
        match_clients: A list of forwarders for the match clients. This
            list specifies a named ACL, or a list of IPv4/IPv6
            addresses, networks, TSIG keys of clients that are allowed
            or denied access to the DNS view.
        match_destinations: A list of forwarders for the match
            destinations. This list specifies a name ACL, or a list of
            IPv4/IPv6 addresses, networks, TSIG keys of clients that are
            allowed or denied access to the DNS view.
        max_cache_ttl: The maximum number of seconds to cache ordinary
            (positive) answers.
        max_ncache_ttl: The maximum number of seconds to cache negative
            (NXDOMAIN) answers.
        max_udp_size: The value is used by authoritative DNS servers to
            never send DNS responses larger than the configured value.
            The value should be between 512 and 4096 bytes. The
            recommended value is between 512 and 1220 bytes.
        name: Name of the DNS view.
        network_view: The name of the network view object associated
            with this DNS view.
        notify_delay: The number of seconds of delay the notify messages
            are sent to secondaries.
        nxdomain_log_query: The flag that indicates whether NXDOMAIN
            redirection queries are logged. Specify "true" to enable
            logging, or "false" to disable it. The default value is
            "false".
        nxdomain_redirect: Determines if NXDOMAIN redirection in a DNS
            view is enabled or not.
        nxdomain_redirect_addresses: The array with IPv4 addresses the
            appliance includes in the response it sends in place of an
            NXDOMAIN response.
        nxdomain_redirect_addresses_v6: The array with IPv6 addresses
            the appliance includes in the response it sends in place of
            an NXDOMAIN response.
        nxdomain_redirect_ttl: The Time To Live (TTL) value of the
            synthetic DNS responses resulted from NXDOMAIN redirection.
            The TTL value is a 32-bit unsigned integer that represents
            the TTL in seconds.
        nxdomain_rulesets: The names of the Ruleset objects assigned at
            the grid level for NXDOMAIN redirection.
        recursion: Determines if recursion is enabled or not.
        response_rate_limiting: The response rate limiting settings for
            the DNS View.
        root_name_server_type: Determines the type of root name servers.
        rpz_drop_ip_rule_enabled: Enables the appliance to ignore RPZ-IP
            triggers with prefix lengths less than the specified minimum
            prefix length.
        rpz_drop_ip_rule_min_prefix_length_ipv4: The minimum prefix
            length for IPv4 RPZ-IP triggers. The appliance ignores RPZ-
            IP triggers with prefix lengths less than the specified
            minimum IPv4 prefix length.
        rpz_drop_ip_rule_min_prefix_length_ipv6: The minimum prefix
            length for IPv6 RPZ-IP triggers. The appliance ignores RPZ-
            IP triggers with prefix lengths less than the specified
            minimum IPv6 prefix length.
        rpz_qname_wait_recurse: The flag that indicates whether
            recursive RPZ lookups are enabled.
        scavenging_settings: The scavenging settings.
        sortlist: A sort list that determines the order of IP addresses
            in responses sent to DNS queries.
        use_blacklist: Use flag for: blacklist_action ,
            blacklist_log_query, blacklist_redirect_addresses,
            blacklist_redirect_ttl, blacklist_rulesets, enable_blacklist
        use_ddns_force_creation_timestamp_update: Use flag for:
            ddns_force_creation_timestamp_update
        use_ddns_patterns_restriction: Use flag for:
            ddns_restrict_patterns_list , ddns_restrict_patterns
        use_ddns_principal_security: Use flag for: ddns_restrict_secure
            , ddns_principal_tracking, ddns_principal_group
        use_ddns_restrict_protected: Use flag for:
            ddns_restrict_protected
        use_ddns_restrict_static: Use flag for: ddns_restrict_static
        use_dns64: Use flag for: dns64_enabled , dns64_groups
        use_dnssec: Use flag for: dnssec_enabled ,
            dnssec_expired_signatures_enabled,
            dnssec_validation_enabled, dnssec_trusted_keys
        use_edns_udp_size: Use flag for: edns_udp_size
        use_filter_aaaa: Use flag for: filter_aaaa , filter_aaaa_list
        use_fixed_rrset_order_fqdns: Use flag for:
            fixed_rrset_order_fqdns , enable_fixed_rrset_order_fqdns
        use_forwarders: Use flag for: forwarders , forward_only
        use_lame_ttl: Use flag for: lame_ttl
        use_max_cache_ttl: Use flag for: max_cache_ttl
        use_max_ncache_ttl: Use flag for: max_ncache_ttl
        use_max_udp_size: Use flag for: max_udp_size
        use_nxdomain_redirect: Use flag for: nxdomain_redirect ,
            nxdomain_redirect_addresses, nxdomain_redirect_addresses_v6,
            nxdomain_redirect_ttl, nxdomain_log_query, nxdomain_rulesets
        use_recursion: Use flag for: recursion
        use_response_rate_limiting: Use flag for: response_rate_limiting
        use_root_name_server: Use flag for: custom_root_name_servers ,
            root_name_server_type
        use_rpz_drop_ip_rule: Use flag for: rpz_drop_ip_rule_enabled ,
            rpz_drop_ip_rule_min_prefix_length_ipv4,
            rpz_drop_ip_rule_min_prefix_length_ipv6
        use_rpz_qname_wait_recurse: Use flag for: rpz_qname_wait_recurse
        use_scavenging_settings: Use flag for: scavenging_settings ,
            last_queried_acl
        use_sortlist: Use flag for: sortlist
    """
    _infoblox_type = 'view'
    _fields = ['blacklist_action', 'blacklist_log_query',
               'blacklist_redirect_addresses', 'blacklist_redirect_ttl',
               'blacklist_rulesets', 'cloud_info', 'comment',
               'custom_root_name_servers',
               'ddns_force_creation_timestamp_update', 'ddns_principal_group',
               'ddns_principal_tracking', 'ddns_restrict_patterns',
               'ddns_restrict_patterns_list', 'ddns_restrict_protected',
               'ddns_restrict_secure', 'ddns_restrict_static', 'disable',
               'dns64_enabled', 'dns64_groups', 'dnssec_enabled',
               'dnssec_expired_signatures_enabled',
               'dnssec_negative_trust_anchors', 'dnssec_trusted_keys',
               'dnssec_validation_enabled', 'edns_udp_size',
               'enable_blacklist', 'enable_fixed_rrset_order_fqdns',
               'enable_match_recursive_only', 'extattrs', 'filter_aaaa',
               'filter_aaaa_list', 'fixed_rrset_order_fqdns', 'forward_only',
               'forwarders', 'is_default', 'lame_ttl', 'last_queried_acl',
               'match_clients', 'match_destinations', 'max_cache_ttl',
               'max_ncache_ttl', 'max_udp_size', 'name', 'network_view',
               'notify_delay', 'nxdomain_log_query', 'nxdomain_redirect',
               'nxdomain_redirect_addresses', 'nxdomain_redirect_addresses_v6',
               'nxdomain_redirect_ttl', 'nxdomain_rulesets', 'recursion',
               'response_rate_limiting', 'root_name_server_type',
               'rpz_drop_ip_rule_enabled',
               'rpz_drop_ip_rule_min_prefix_length_ipv4',
               'rpz_drop_ip_rule_min_prefix_length_ipv6',
               'rpz_qname_wait_recurse', 'scavenging_settings', 'sortlist',
               'use_blacklist', 'use_ddns_force_creation_timestamp_update',
               'use_ddns_patterns_restriction', 'use_ddns_principal_security',
               'use_ddns_restrict_protected', 'use_ddns_restrict_static',
               'use_dns64', 'use_dnssec', 'use_edns_udp_size',
               'use_filter_aaaa', 'use_fixed_rrset_order_fqdns',
               'use_forwarders', 'use_lame_ttl', 'use_max_cache_ttl',
               'use_max_ncache_ttl', 'use_max_udp_size',
               'use_nxdomain_redirect', 'use_recursion',
               'use_response_rate_limiting', 'use_root_name_server',
               'use_rpz_drop_ip_rule', 'use_rpz_qname_wait_recurse',
               'use_scavenging_settings', 'use_sortlist']
    _search_for_update_fields = ['is_default', 'name', 'network_view']
    _updateable_search_fields = ['blacklist_action', 'blacklist_log_query',
                                 'comment', 'dns64_enabled', 'dnssec_enabled',
                                 'dnssec_expired_signatures_enabled',
                                 'dnssec_validation_enabled',
                                 'enable_blacklist', 'filter_aaaa',
                                 'forward_only', 'name', 'network_view',
                                 'nxdomain_log_query', 'nxdomain_redirect',
                                 'recursion', 'root_name_server_type']
    _all_searchable_fields = ['blacklist_action', 'blacklist_log_query',
                              'comment', 'dns64_enabled', 'dnssec_enabled',
                              'dnssec_expired_signatures_enabled',
                              'dnssec_validation_enabled', 'enable_blacklist',
                              'filter_aaaa', 'forward_only', 'is_default',
                              'name', 'network_view', 'nxdomain_log_query',
                              'nxdomain_redirect', 'recursion',
                              'root_name_server_type']
    _return_fields = ['comment', 'extattrs', 'is_default', 'name']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'custom_root_name_servers': Extserver.from_dict,
        'dnssec_trusted_keys': Dnssectrustedkey.from_dict,
        'filter_aaaa_list': Addressac.from_dict,
        'fixed_rrset_order_fqdns': GridDnsFixedrrsetorderfqdn.from_dict,
        'last_queried_acl': Addressac.from_dict,
        'match_clients': Addressac.from_dict,
        'match_destinations': Addressac.from_dict,
        'sortlist': Sortlist.from_dict,
    }

    def run_scavenging(self, *args, **kwargs):
        return self._call_func("run_scavenging", *args, **kwargs)


class Vlan(InfobloxObject):
    """ Vlan: VLAN object.
    Corresponds to WAPI object 'vlan'

    Attributes:
        assigned_to: List of objects VLAN is assigned to.
        comment: A descriptive comment for this VLAN.
        contact: Contact information for person/team managing or using
            VLAN.
        department: Department where VLAN is used.
        description: Description for the VLAN object, may be potentially
            used for longer VLAN names.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        id: VLAN ID value.
        name: Name of the VLAN.
        parent: The VLAN View or VLAN Range to which this VLAN belongs.
        reserved: When set VLAN can only be assigned to IPAM object
            manually.
        status: Status of VLAN object. Can be Assigned, Unassigned,
            Reserved.
    """
    _infoblox_type = 'vlan'
    _fields = ['assigned_to', 'comment', 'contact', 'department',
               'description', 'extattrs', 'id', 'name', 'parent', 'reserved',
               'status']
    _search_for_update_fields = ['id', 'name', 'parent']
    _updateable_search_fields = ['comment', 'contact', 'department',
                                 'description', 'id', 'name', 'parent',
                                 'reserved']
    _all_searchable_fields = ['assigned_to', 'comment', 'contact',
                              'department', 'description', 'id', 'name',
                              'parent', 'reserved', 'status']
    _return_fields = ['extattrs', 'id', 'name', 'parent']
    _remap = {}
    _shadow_fields = ['_ref']


class Vlanrange(InfobloxObject):
    """ Vlanrange: VLAN Range object.
    Corresponds to WAPI object 'vlanrange'

    Attributes:
        comment: A descriptive comment for this VLAN Range.
        end_vlan_id: End ID for VLAN Range.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: Name of the VLAN Range.
        pre_create_vlan: If set on creation VLAN objects will be created
            once VLAN Range created.
        start_vlan_id: Start ID for VLAN Range.
        vlan_name_prefix: If set on creation prefix string will be used
            for VLAN name.
        vlan_view: The VLAN View to which this VLAN Range belongs.
    """
    _infoblox_type = 'vlanrange'
    _fields = ['comment', 'delete_vlans', 'end_vlan_id', 'extattrs', 'name',
               'pre_create_vlan', 'start_vlan_id', 'vlan_name_prefix',
               'vlan_view']
    _search_for_update_fields = ['end_vlan_id', 'name', 'start_vlan_id',
                                 'vlan_view']
    _updateable_search_fields = ['comment', 'end_vlan_id', 'name',
                                 'start_vlan_id', 'vlan_view']
    _all_searchable_fields = ['comment', 'end_vlan_id', 'name',
                              'start_vlan_id', 'vlan_view']
    _return_fields = ['end_vlan_id', 'extattrs', 'name', 'start_vlan_id',
                      'vlan_view']
    _remap = {}
    _shadow_fields = ['_ref']

    def next_available_vlan_id(self, *args, **kwargs):
        return self._call_func("next_available_vlan_id", *args, **kwargs)


class Vlanview(InfobloxObject):
    """ Vlanview: VLAN View object.
    Corresponds to WAPI object 'vlanview'

    Attributes:
        allow_range_overlapping: When set to true VLAN Ranges under VLAN
            View can have overlapping ID.
        comment: A descriptive comment for this VLAN View.
        end_vlan_id: End ID for VLAN View.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        name: Name of the VLAN View.
        pre_create_vlan: If set on creation VLAN objects will be created
            once VLAN View created.
        start_vlan_id: Start ID for VLAN View.
        vlan_name_prefix: If set on creation prefix string will be used
            for VLAN name.
    """
    _infoblox_type = 'vlanview'
    _fields = ['allow_range_overlapping', 'comment', 'end_vlan_id', 'extattrs',
               'name', 'pre_create_vlan', 'start_vlan_id', 'vlan_name_prefix']
    _search_for_update_fields = ['end_vlan_id', 'name', 'start_vlan_id']
    _updateable_search_fields = ['allow_range_overlapping', 'comment',
                                 'end_vlan_id', 'name', 'start_vlan_id']
    _all_searchable_fields = ['allow_range_overlapping', 'comment',
                              'end_vlan_id', 'name', 'start_vlan_id']
    _return_fields = ['end_vlan_id', 'extattrs', 'name', 'start_vlan_id']
    _remap = {}
    _shadow_fields = ['_ref']

    def next_available_vlan_id(self, *args, **kwargs):
        return self._call_func("next_available_vlan_id", *args, **kwargs)


class DNSZone(InfobloxObject):
    """ DNSZone: DNS Authoritative Zone object.
    Corresponds to WAPI object 'zone_auth'

    An authoritative zone is a zone for which the local (primary or
    secondary) server references its own data when responding to
    queries. The local server is authoritative for the data in this zone
    and responds to queries for this data without referencing another
    server.

    If operating in a Cloud API environment and if the zone is in a
    delegated network view, grid_primary is a required field.

    There are two types of authoritative zones:

    Forwarding-mapping: An authoritative forward-mapping zone is an area
    of domain name space for which one or more name servers have the
    responsibility to respond authoritatively to name-to-address
    queries.

    Reverse-mapping: A reverse-mapping zone is an area or network space
    for which one or more name servers have the responsibility to
    respond to address-to-name queries.

    Attributes:
        address: The IP address of the server that is serving this zone.
        allow_active_dir: This field allows the zone to receive GSS-TSIG
            authenticated DDNS updates from DHCP clients and servers in
            an AD domain.Note that addresses specified in this field
            ignore the permission set in the struct which will be set to
            'ALLOW'.
        allow_fixed_rrset_order: The flag that allows to enable or
            disable fixed RRset ordering for authoritative forward-
            mapping zones.
        allow_gss_tsig_for_underscore_zone: The flag that allows DHCP
            clients to perform GSS-TSIG signed updates for underscore
            zones.
        allow_gss_tsig_zone_updates: The flag that enables or disables
            the zone for GSS-TSIG updates.
        allow_query: Determines whether DNS queries are allowed from a
            named ACL, or from a list of IPv4/IPv6 addresses, networks,
            and TSIG keys for the hosts.
        allow_transfer: Determines whether zone transfers are allowed
            from a named ACL, or from a list of IPv4/IPv6 addresses,
            networks, and TSIG keys for the hosts.
        allow_update: Determines whether dynamic DNS updates are allowed
            from a named ACL, or from a list of IPv4/IPv6 addresses,
            networks, and TSIG keys for the hosts.
        allow_update_forwarding: The list with IP addresses, networks or
            TSIG keys for clients, from which forwarded dynamic updates
            are allowed.
        aws_rte53_zone_info: Additional information for Route53 zone.
        cloud_info: Structure containing all cloud API related
            information for this object.
        comment: Comment for the zone; maximum 256 characters.
        copy_xfer_to_notify: If this flag is set to True then copy
            allowed IPs from Allow Transfer to Also Notify.
        create_ptr_for_bulk_hosts: Determines if PTR records are created
            for hosts automatically, if necessary, when the zone data is
            imported. This field is meaningful only when import_from is
            set.
        create_ptr_for_hosts: Determines if PTR records are created for
            hosts automatically, if necessary, when the zone data is
            imported. This field is meaningful only when import_from is
            set.
        create_underscore_zones: Determines whether automatic creation
            of subzones is enabled or not.
        ddns_force_creation_timestamp_update: Defines whether creation
            timestamp of RR should be updated ' when DDNS update happens
            even if there is no change to ' the RR.
        ddns_principal_group: The DDNS Principal cluster group name.
        ddns_principal_tracking: The flag that indicates whether the
            DDNS principal track is enabled or disabled.
        ddns_restrict_patterns: The flag that indicates whether an
            option to restrict DDNS update request based on FQDN
            patterns is enabled or disabled.
        ddns_restrict_patterns_list: The unordered list of restriction
            patterns for an option of to restrict DDNS updates based on
            FQDN patterns.
        ddns_restrict_protected: The flag that indicates whether an
            option to restrict DDNS update request to protected resource
            records is enabled or disabled.
        ddns_restrict_secure: The flag that indicates whether DDNS
            update request for principal other than target resource
            record's principal is restricted.
        ddns_restrict_static: The flag that indicates whether an option
            to restrict DDNS update request to resource records which
            are marked as 'STATIC' is enabled or disabled.
        disable: Determines whether a zone is disabled or not. When this
            is set to False, the zone is enabled.
        disable_forwarding: Determines whether the name servers that
            host the zone should forward queries (ended with the domain
            name of the zone) to any configured forwarders.
        display_domain: The displayed name of the DNS zone.
        dns_fqdn: The name of this DNS zone in punycode format. For a
            reverse zone, this is in "address/cidr" format. For other
            zones, this is in FQDN format in punycode format.
        dns_integrity_enable: If this is set to True, DNS integrity
            check is enabled for this zone.
        dns_integrity_frequency: The frequency, in seconds, of DNS
            integrity checks for this zone.
        dns_integrity_member: The Grid member that performs DNS
            integrity checks for this zone.
        dns_integrity_verbose_logging: If this is set to True, more
            information is logged for DNS integrity checks for this
            zone.
        dns_soa_email: The SOA email for the zone in punycode format.
        dnssec_key_params: This structure contains the DNSSEC key
            parameters for this zone.
        dnssec_keys: A list of DNSSEC keys for the zone.
        dnssec_ksk_rollover_date: The rollover date for the Key Signing
            Key.
        dnssec_zsk_rollover_date: The rollover date for the Zone Signing
            Key.
        do_host_abstraction: Determines if hosts and bulk hosts are
            automatically created when the zone data is imported. This
            field is meaningful only when import_from is set.
        effective_check_names_policy: The value of the check names
            policy, which indicates the action the appliance takes when
            it encounters host names that do not comply with the Strict
            Hostname Checking policy. This value applies only if the
            host name restriction policy is set to "Strict Hostname
            Checking".
        effective_record_name_policy: The selected hostname policy for
            records under this zone.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        external_primaries: The list of external primary servers.
        external_secondaries: The list of external secondary servers.
        fqdn: The name of this DNS zone. For a reverse zone, this is in
            "address/cidr" format. For other zones, this is in FQDN
            format. This value can be in unicode format.Note that for a
            reverse zone, the corresponding zone_format value should be
            set.
        grid_primary: The grid primary servers for this zone.
        grid_primary_shared_with_ms_parent_delegation: Determines if the
            server is duplicated with parent delegation.
        grid_secondaries: The list with Grid members that are secondary
            servers for this zone.
        import_from: The IP address of the Infoblox appliance from which
            zone data is imported. Setting this address to
            '255.255.255.255' and do_host_abstraction to 'true' will
            create Host records from A records in this zone without
            importing zone data.
        is_dnssec_enabled: This flag is set to True if DNSSEC is enabled
            for the zone.
        is_dnssec_signed: Determines if the zone is DNSSEC signed.
        is_multimaster: Determines if multi-master DNS is enabled for
            the zone.
        last_queried: The time the zone was last queried on.
        last_queried_acl: Determines last queried ACL for the specified
            IPv4 or IPv6 addresses and networks in scavenging settings.
        locked: If you enable this flag, other administrators cannot
            make conflicting changes. This is for administration
            purposes only. The zone will continue to serve DNS data even
            when it is locked.
        locked_by: The name of a superuser or the administrator who
            locked this zone.
        mask_prefix: IPv4 Netmask or IPv6 prefix for this zone.
        member_soa_mnames: The list of per-member SOA MNAME information.
        member_soa_serials: The list of per-member SOA serial
            information.
        ms_ad_integrated: The flag that determines whether Active
            Directory is integrated or not. This field is valid only
            when ms_managed is "STUB", "AUTH_PRIMARY", or "AUTH_BOTH".
        ms_allow_transfer: The list of DNS clients that are allowed to
            perform zone transfers from a Microsoft DNS server.This
            setting applies only to zones with Microsoft DNS servers
            that are either primary or secondary servers. This setting
            does not inherit any value from the Grid or from any member
            that defines an allow_transfer value. This setting does not
            apply to any grid member. Use the allow_transfer field to
            control which DNS clients are allowed to perform zone
            transfers on Grid members.
        ms_allow_transfer_mode: Determines which DNS clients are allowed
            to perform zone transfers from a Microsoft DNS server.Valid
            values are:"ADDRESS_AC", to use ms_allow_transfer field for
            specifying IP addresses, networks and Transaction Signature
            (TSIG) keys for clients that are allowed to do zone
            transfers."ANY", to allow any client."ANY_NS", to allow only
            the nameservers listed in this zone."NONE", to deny all zone
            transfer requests.
        ms_dc_ns_record_creation: The list of domain controllers that
            are allowed to create NS records for authoritative zones.
        ms_ddns_mode: Determines whether an Active Directory-integrated
            zone with a Microsoft DNS server as primary allows dynamic
            updates. Valid values are:"SECURE" if the zone allows secure
            updates only."NONE" if the zone forbids dynamic
            updates."ANY" if the zone accepts both secure and nonsecure
            updates.This field is valid only if ms_managed is either
            "AUTH_PRIMARY" or "AUTH_BOTH". If the flag ms_ad_integrated
            is false, the value "SECURE" is not allowed.
        ms_managed: The flag that indicates whether the zone is assigned
            to a Microsoft DNS server. This flag returns the
            authoritative name server type of the Microsoft DNS server.
            Valid values are:"NONE" if the zone is not assigned to any
            Microsoft DNS server."STUB" if the zone is assigned to a
            Microsoft DNS server as a stub zone."AUTH_PRIMARY" if only
            the primary server of the zone is a Microsoft DNS
            server."AUTH_SECONDARY" if only the secondary server of the
            zone is a Microsoft DNS server."AUTH_BOTH" if both the
            primary and secondary servers of the zone are Microsoft DNS
            servers.
        ms_primaries: The list with the Microsoft DNS servers that are
            primary servers for the zone. Although a zone typically has
            just one primary name server, you can specify up to ten
            independent servers for a single zone.
        ms_read_only: Determines if a Grid member manages the zone
            served by a Microsoft DNS server in read-only mode. This
            flag is true when a Grid member manages the zone in read-
            only mode, false otherwise.When the zone has the
            ms_read_only flag set to True, no changes can be made to
            this zone.
        ms_secondaries: The list with the Microsoft DNS servers that are
            secondary servers for the zone.
        ms_sync_disabled: This flag controls whether this zone is
            synchronized with Microsoft DNS servers.
        ms_sync_master_name: The name of MS synchronization master for
            this zone.
        network_associations: The list with the associated
            network/network container information.
        network_view: The name of the network view in which this zone
            resides.
        notify_delay: The number of seconds in delay with which notify
            messages are sent to secondaries.
        ns_group: The name server group that serves DNS for this zone.
        parent: The parent zone of this zone.Note that when searching
            for reverse zones, the "in-addr.arpa" notation should be
            used.
        prefix: The RFC2317 prefix value of this DNS zone.Use this field
            only when the netmask is greater than 24 bits; that is, for
            a mask between 25 and 31 bits. Enter a prefix, such as the
            name of the allocated address block. The prefix can be
            alphanumeric characters, such as 128/26 , 128-189 , or
            sub-B.
        primary_type: The type of the primary server.
        record_name_policy: The hostname policy for records under this
            zone.
        records_monitored: Determines if this zone is also monitoring
            resource records.
        restart_if_needed: Restarts the member service.
        rr_not_queried_enabled_time: The time data collection for Not
            Queried Resource Record was enabled for this zone.
        scavenging_settings: The scavenging settings.
        set_soa_serial_number: The serial number in the SOA record
            incrementally changes every time the record is modified. The
            Infoblox appliance allows you to change the serial number
            (in the SOA record) for the primary server so it is higher
            than the secondary server, thereby ensuring zone transfers
            come from the primary server (as they should). To change the
            serial number you need to set a new value at
            "soa_serial_number" and pass "set_soa_serial_number" as
            True.
        soa_default_ttl: The Time to Live (TTL) value of the SOA record
            of this zone. This value is the number of seconds that data
            is cached.
        soa_email: The SOA email value for this zone. This value can be
            in unicode format.
        soa_expire: This setting defines the amount of time, in seconds,
            after which the secondary server stops giving out answers
            about the zone because the zone data is too old to be
            useful. The default is one week.
        soa_negative_ttl: The negative Time to Live (TTL) value of the
            SOA of the zone indicates how long a secondary server can
            cache data for "Does Not Respond" responses.
        soa_refresh: This indicates the interval at which a secondary
            server sends a message to the primary server for a zone to
            check that its data is current, and retrieve fresh data if
            it is not.
        soa_retry: This indicates how long a secondary server must wait
            before attempting to recontact the primary server after a
            connection failure between the two servers occurs.
        soa_serial_number: The serial number in the SOA record
            incrementally changes every time the record is modified. The
            Infoblox appliance allows you to change the serial number
            (in the SOA record) for the primary server so it is higher
            than the secondary server, thereby ensuring zone transfers
            come from the primary server (as they should). To change the
            serial number you need to set a new value at
            "soa_serial_number" and pass "set_soa_serial_number" as
            True.
        srgs: The associated shared record groups of a DNS zone.If a
            shared record group is associated with a zone, then all
            shared records in a shared record group will be shared in
            the zone.
        update_forwarding: Use this field to allow or deny dynamic DNS
            updates that are forwarded from specific IPv4/IPv6
            addresses, networks, or a named ACL. You can also provide
            TSIG keys for clients that are allowed or denied to perform
            zone updates. This setting overrides the member-level
            setting.
        use_allow_active_dir: Use flag for: allow_active_dir
        use_allow_query: Use flag for: allow_query
        use_allow_transfer: Use flag for: allow_transfer
        use_allow_update: Use flag for: allow_update
        use_allow_update_forwarding: Use flag for:
            allow_update_forwarding
        use_check_names_policy: Apply policy to dynamic updates and
            inbound zone transfers (This value applies only if the host
            name restriction policy is set to "Strict Hostname
            Checking".)
        use_copy_xfer_to_notify: Use flag for: copy_xfer_to_notify
        use_ddns_force_creation_timestamp_update: Use flag for:
            ddns_force_creation_timestamp_update
        use_ddns_patterns_restriction: Use flag for:
            ddns_restrict_patterns_list , ddns_restrict_patterns
        use_ddns_principal_security: Use flag for: ddns_restrict_secure
            , ddns_principal_tracking, ddns_principal_group
        use_ddns_restrict_protected: Use flag for:
            ddns_restrict_protected
        use_ddns_restrict_static: Use flag for: ddns_restrict_static
        use_dnssec_key_params: Use flag for: dnssec_key_params
        use_external_primary: This flag controls whether the zone is
            using an external primary.
        use_grid_zone_timer: Use flag for: soa_default_ttl , soa_expire,
            soa_negative_ttl, soa_refresh, soa_retry
        use_import_from: Use flag for: import_from
        use_notify_delay: Use flag for: notify_delay
        use_record_name_policy: Use flag for: record_name_policy
        use_scavenging_settings: Use flag for: scavenging_settings ,
            last_queried_acl
        use_soa_email: Use flag for: soa_email
        using_srg_associations: This is true if the zone is associated
            with a shared record group.
        view: The name of the DNS view in which the zone resides.
            Example "external".
        zone_format: Determines the format of this zone.
        zone_not_queried_enabled_time: The time when "DNS Zones Last
            Queried" was turned on for this zone.
    """
    _infoblox_type = 'zone_auth'
    _fields = ['address', 'allow_active_dir', 'allow_fixed_rrset_order',
               'allow_gss_tsig_for_underscore_zone',
               'allow_gss_tsig_zone_updates', 'allow_query', 'allow_transfer',
               'allow_update', 'allow_update_forwarding',
               'aws_rte53_zone_info', 'cloud_info', 'comment',
               'copy_xfer_to_notify', 'create_ptr_for_bulk_hosts',
               'create_ptr_for_hosts', 'create_underscore_zones',
               'ddns_force_creation_timestamp_update', 'ddns_principal_group',
               'ddns_principal_tracking', 'ddns_restrict_patterns',
               'ddns_restrict_patterns_list', 'ddns_restrict_protected',
               'ddns_restrict_secure', 'ddns_restrict_static', 'disable',
               'disable_forwarding', 'display_domain', 'dns_fqdn',
               'dns_integrity_enable', 'dns_integrity_frequency',
               'dns_integrity_member', 'dns_integrity_verbose_logging',
               'dns_soa_email', 'dnssec_key_params', 'dnssec_keys',
               'dnssec_ksk_rollover_date', 'dnssec_zsk_rollover_date',
               'do_host_abstraction', 'effective_check_names_policy',
               'effective_record_name_policy', 'extattrs',
               'external_primaries', 'external_secondaries', 'fqdn',
               'grid_primary', 'grid_primary_shared_with_ms_parent_delegation',
               'grid_secondaries', 'import_from', 'is_dnssec_enabled',
               'is_dnssec_signed', 'is_multimaster', 'last_queried',
               'last_queried_acl', 'locked', 'locked_by', 'mask_prefix',
               'member_soa_mnames', 'member_soa_serials', 'ms_ad_integrated',
               'ms_allow_transfer', 'ms_allow_transfer_mode',
               'ms_dc_ns_record_creation', 'ms_ddns_mode', 'ms_managed',
               'ms_primaries', 'ms_read_only', 'ms_secondaries',
               'ms_sync_disabled', 'ms_sync_master_name',
               'network_associations', 'network_view', 'notify_delay',
               'ns_group', 'parent', 'prefix', 'primary_type',
               'record_name_policy', 'records_monitored', 'restart_if_needed',
               'rr_not_queried_enabled_time', 'scavenging_settings',
               'set_soa_serial_number', 'soa_default_ttl', 'soa_email',
               'soa_expire', 'soa_negative_ttl', 'soa_refresh', 'soa_retry',
               'soa_serial_number', 'srgs', 'update_forwarding',
               'use_allow_active_dir', 'use_allow_query', 'use_allow_transfer',
               'use_allow_update', 'use_allow_update_forwarding',
               'use_check_names_policy', 'use_copy_xfer_to_notify',
               'use_ddns_force_creation_timestamp_update',
               'use_ddns_patterns_restriction', 'use_ddns_principal_security',
               'use_ddns_restrict_protected', 'use_ddns_restrict_static',
               'use_dnssec_key_params', 'use_external_primary',
               'use_grid_zone_timer', 'use_import_from', 'use_notify_delay',
               'use_record_name_policy', 'use_scavenging_settings',
               'use_soa_email', 'using_srg_associations', 'view',
               'zone_format', 'zone_not_queried_enabled_time']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'dnssec_ksk_rollover_date',
                              'dnssec_zsk_rollover_date', 'fqdn', 'parent',
                              'view', 'zone_format']
    _return_fields = ['extattrs', 'fqdn', 'view', 'ns_group', 'prefix',
                      'grid_primary', 'grid_secondaries']
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
        'last_queried_acl': Addressac.from_dict,
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
    """ ZoneAuthDiscrepancy: Zone discrepancy information object.
    Corresponds to WAPI object 'zone_auth_discrepancy'

    This object contains information about discrepancies found when
    performing a DNS integrity check for a zone.

    Attributes:
        description: Information about the discrepancy.
        severity: The severity of the discrepancy reported.
        timestamp: The time when the DNS integrity check was last run
            for this zone.
        zone: The reference of the zone during a search. Otherwise, this
            is the zone object of the zone to which the discrepancy
            refers.
    """
    _infoblox_type = 'zone_auth_discrepancy'
    _fields = ['description', 'severity', 'timestamp', 'zone']
    _search_for_update_fields = ['severity', 'zone']
    _updateable_search_fields = []
    _all_searchable_fields = ['severity', 'zone']
    _return_fields = ['description', 'severity', 'timestamp', 'zone']
    _remap = {}
    _shadow_fields = ['_ref']


class DNSZoneDelegated(InfobloxObject):
    """ DNSZoneDelegated: DNS Delegated Zone object.
    Corresponds to WAPI object 'zone_delegated'

    Instead of a local name server, remote name servers (which the local
    server knows) maintain delegated zone data. When the local name
    server receives a query for a delegated zone, it either responds
    with the NS record for the delegated zone server (if recursion is
    disabled on the local server) or it queries the delegated zone
    server on behalf of the resolver (if recursion is enabled).

    You can delegate a zone to one or more remote name servers, which
    are typically the authoritative primary and secondary servers for
    the zone. If recursion is enabled on the local name server, it
    queries multiple delegated name servers based on their round-trip
    times.

    Attributes:
        address: The IP address of the server that is serving this zone.
        comment: Comment for the zone; maximum 256 characters.
        delegate_to: This provides information for the remote name
            server that maintains data for the delegated zone. The
            Infoblox appliance redirects queries for data for the
            delegated zone to this remote name server.
        delegated_ttl: You can specify the Time to Live (TTL) values of
            auto-generated NS and glue records for a delegated zone.
            This value is the number of seconds that data is cached.
        disable: Determines whether a zone is disabled or not. When this
            is set to False, the zone is enabled.
        display_domain: The displayed name of the DNS zone.
        dns_fqdn: The name of this DNS zone in punycode format. For a
            reverse zone, this is in "address/cidr" format. For other
            zones, this is in FQDN format in punycode format.
        enable_rfc2317_exclusion: This flag controls whether automatic
            generation of RFC 2317 CNAMEs for delegated reverse zones
            overwrite existing PTR records. The default behavior is to
            overwrite all the existing records in the range; this
            corresponds to "allow_ptr_creation_in_parent" set to False.
            However, when this flag is set to True the existing PTR
            records are not overwritten.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        fqdn: The name of this DNS zone. For a reverse zone, this is in
            "address/cidr" format. For other zones, this is in FQDN
            format. This value can be in unicode format.Note that for a
            reverse zone, the corresponding zone_format value should be
            set.
        locked: If you enable this flag, other administrators cannot
            make conflicting changes. This is for administration
            purposes only. The zone will continue to serve DNS data even
            when it is locked.
        locked_by: The name of a superuser or the administrator who
            locked this zone.
        mask_prefix: IPv4 Netmask or IPv6 prefix for this zone.
        ms_ad_integrated: The flag that determines whether Active
            Directory is integrated or not. This field is valid only
            when ms_managed is "STUB", "AUTH_PRIMARY", or "AUTH_BOTH".
        ms_ddns_mode: Determines whether an Active Directory-integrated
            zone with a Microsoft DNS server as primary allows dynamic
            updates. Valid values are:"SECURE" if the zone allows secure
            updates only."NONE" if the zone forbids dynamic
            updates."ANY" if the zone accepts both secure and nonsecure
            updates.This field is valid only if ms_managed is either
            "AUTH_PRIMARY" or "AUTH_BOTH". If the flag ms_ad_integrated
            is false, the value "SECURE" is not allowed.
        ms_managed: The flag that indicates whether the zone is assigned
            to a Microsoft DNS server. This flag returns the
            authoritative name server type of the Microsoft DNS server.
            Valid values are:"NONE" if the zone is not assigned to any
            Microsoft DNS server."STUB" if the zone is assigned to a
            Microsoft DNS server as a stub zone."AUTH_PRIMARY" if only
            the primary server of the zone is a Microsoft DNS
            server."AUTH_SECONDARY" if only the secondary server of the
            zone is a Microsoft DNS server."AUTH_BOTH" if both the
            primary and secondary servers of the zone are Microsoft DNS
            servers.
        ms_read_only: Determines if a Grid member manages the zone
            served by a Microsoft DNS server in read-only mode. This
            flag is true when a Grid member manages the zone in read-
            only mode, false otherwise.When the zone has the
            ms_read_only flag set to True, no changes can be made to
            this zone.
        ms_sync_master_name: The name of MS synchronization master for
            this zone.
        ns_group: The delegation NS group bound with delegated zone.
        parent: The parent zone of this zone.Note that when searching
            for reverse zones, the "in-addr.arpa" notation should be
            used.
        prefix: The RFC2317 prefix value of this DNS zone.Use this field
            only when the netmask is greater than 24 bits; that is, for
            a mask between 25 and 31 bits. Enter a prefix, such as the
            name of the allocated address block. The prefix can be
            alphanumeric characters, such as 128/26 , 128-189 , or
            sub-B.
        use_delegated_ttl: Use flag for: delegated_ttl
        using_srg_associations: This is true if the zone is associated
            with a shared record group.
        view: The name of the DNS view in which the zone resides.
            Example "external".
        zone_format: Determines the format of this zone.
    """
    _infoblox_type = 'zone_delegated'
    _fields = ['address', 'comment', 'delegate_to', 'delegated_ttl', 'disable',
               'display_domain', 'dns_fqdn', 'enable_rfc2317_exclusion',
               'extattrs', 'fqdn', 'locked', 'locked_by', 'mask_prefix',
               'ms_ad_integrated', 'ms_ddns_mode', 'ms_managed',
               'ms_read_only', 'ms_sync_master_name', 'ns_group', 'parent',
               'prefix', 'use_delegated_ttl', 'using_srg_associations', 'view',
               'zone_format']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'fqdn', 'parent', 'view',
                              'zone_format']
    _return_fields = ['delegate_to', 'extattrs', 'fqdn', 'view']
    _remap = {}
    _shadow_fields = ['_ref']

    _custom_field_processing = {
        'delegate_to': Extserver.from_dict,
    }

    def lock_unlock_zone(self, *args, **kwargs):
        return self._call_func("lock_unlock_zone", *args, **kwargs)


class DNSZoneForward(InfobloxObject):
    """ DNSZoneForward: DNS Forward Zone object.
    Corresponds to WAPI object 'zone_forward'

    When you want to forward queries for data in a particular zone,
    define the zone as a forward zone and specify one or more name
    servers that can resolve queries for the zone. For example, define a
    forward zone so that the NIOS appliance forwards queries about a
    partners internal site to a name server, which the partner hosts,
    configured just for other partners to access.

    Attributes:
        address: The IP address of the server that is serving this zone.
        comment: Comment for the zone; maximum 256 characters.
        disable: Determines whether a zone is disabled or not. When this
            is set to False, the zone is enabled.
        disable_ns_generation: Determines whether a auto-generation of
            NS records in parent zone is disabled or not. When this is
            set to False, the auto-generation is enabled.
        display_domain: The displayed name of the DNS zone.
        dns_fqdn: The name of this DNS zone in punycode format. For a
            reverse zone, this is in "address/cidr" format. For other
            zones, this is in FQDN format in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        external_ns_group: A forward stub server name server group.
        forward_to: The information for the remote name servers to which
            you want the Infoblox appliance to forward queries for a
            specified domain name.
        forwarders_only: Determines if the appliance sends queries to
            forwarders only, and not to other internal or Internet root
            servers.
        forwarding_servers: The information for the Grid members to
            which you want the Infoblox appliance to forward queries for
            a specified domain name.
        fqdn: The name of this DNS zone. For a reverse zone, this is in
            "address/cidr" format. For other zones, this is in FQDN
            format. This value can be in unicode format.Note that for a
            reverse zone, the corresponding zone_format value should be
            set.
        locked: If you enable this flag, other administrators cannot
            make conflicting changes. This is for administration
            purposes only. The zone will continue to serve DNS data even
            when it is locked.
        locked_by: The name of a superuser or the administrator who
            locked this zone.
        mask_prefix: IPv4 Netmask or IPv6 prefix for this zone.
        ms_ad_integrated: The flag that determines whether Active
            Directory is integrated or not. This field is valid only
            when ms_managed is "STUB", "AUTH_PRIMARY", or "AUTH_BOTH".
        ms_ddns_mode: Determines whether an Active Directory-integrated
            zone with a Microsoft DNS server as primary allows dynamic
            updates. Valid values are:"SECURE" if the zone allows secure
            updates only."NONE" if the zone forbids dynamic
            updates."ANY" if the zone accepts both secure and nonsecure
            updates.This field is valid only if ms_managed is either
            "AUTH_PRIMARY" or "AUTH_BOTH". If the flag ms_ad_integrated
            is false, the value "SECURE" is not allowed.
        ms_managed: The flag that indicates whether the zone is assigned
            to a Microsoft DNS server. This flag returns the
            authoritative name server type of the Microsoft DNS server.
            Valid values are:"NONE" if the zone is not assigned to any
            Microsoft DNS server."STUB" if the zone is assigned to a
            Microsoft DNS server as a stub zone."AUTH_PRIMARY" if only
            the primary server of the zone is a Microsoft DNS
            server."AUTH_SECONDARY" if only the secondary server of the
            zone is a Microsoft DNS server."AUTH_BOTH" if both the
            primary and secondary servers of the zone are Microsoft DNS
            servers.
        ms_read_only: Determines if a Grid member manages the zone
            served by a Microsoft DNS server in read-only mode. This
            flag is true when a Grid member manages the zone in read-
            only mode, false otherwise.When the zone has the
            ms_read_only flag set to True, no changes can be made to
            this zone.
        ms_sync_master_name: The name of MS synchronization master for
            this zone.
        ns_group: A forwarding member name server group.
        parent: The parent zone of this zone.Note that when searching
            for reverse zones, the "in-addr.arpa" notation should be
            used.
        prefix: The RFC2317 prefix value of this DNS zone.Use this field
            only when the netmask is greater than 24 bits; that is, for
            a mask between 25 and 31 bits. Enter a prefix, such as the
            name of the allocated address block. The prefix can be
            alphanumeric characters, such as 128/26 , 128-189 , or
            sub-B.
        using_srg_associations: This is true if the zone is associated
            with a shared record group.
        view: The name of the DNS view in which the zone resides.
            Example "external".
        zone_format: Determines the format of this zone.
    """
    _infoblox_type = 'zone_forward'
    _fields = ['address', 'comment', 'disable', 'disable_ns_generation',
               'display_domain', 'dns_fqdn', 'extattrs', 'external_ns_group',
               'forward_to', 'forwarders_only', 'forwarding_servers', 'fqdn',
               'locked', 'locked_by', 'mask_prefix', 'ms_ad_integrated',
               'ms_ddns_mode', 'ms_managed', 'ms_read_only',
               'ms_sync_master_name', 'ns_group', 'parent', 'prefix',
               'using_srg_associations', 'view', 'zone_format']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'fqdn', 'parent', 'view',
                              'zone_format']
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
    """ ZoneRp: DNS Response Policy Zone object.
    Corresponds to WAPI object 'zone_rp'

    DNS RPZs (Response Policy Zones), a technology developed by ISC
    (Internet System Consortium) for allowing reputable sources to
    dynamically communicate domain name reputation so you can implement
    policy controls for DNS lookups. You can configure RPZs and define
    RPZ rules to block DNS resolution for malicious or unauthorized
    domain names, or redirect clients to a walled garden by substituting
    responses. You can assign actions to RPZ rules. For example, abc.com
    can have an action of pass thru or substitute (domain) with the
    domain xyz.com. You can also configure a Grid member to act as a
    lead secondary that receives RPZ updates from external reputation
    sources and redistributes the updates to other Grid members.

    Attributes:
        address: The IP address of the server that is serving this zone.
        comment: Comment for the zone; maximum 256 characters.
        disable: Determines whether a zone is disabled or not. When this
            is set to False, the zone is enabled.
        display_domain: The displayed name of the DNS zone.
        dns_soa_email: The SOA email for the zone in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        external_primaries: The list of external primary servers.
        external_secondaries: The list of external secondary servers.
        fireeye_rule_mapping: Rules to map fireeye alerts.
        fqdn: The name of this DNS zone in FQDN format.
        grid_primary: The grid primary servers for this zone.
        grid_secondaries: The list with Grid members that are secondary
            servers for this zone.
        locked: If you enable this flag, other administrators cannot
            make conflicting changes. This is for administration
            purposes only. The zone will continue to serve DNS data even
            when it is locked.
        locked_by: The name of a superuser or the administrator who
            locked this zone.
        log_rpz: Determines whether RPZ logging enabled or not at zone
            level. When this is set to False, the logging is disabled.
        mask_prefix: IPv4 Netmask or IPv6 prefix for this zone.
        member_soa_mnames: The list of per-member SOA MNAME information.
        member_soa_serials: The list of per-member SOA serial
            information.
        network_view: The name of the network view in which this zone
            resides.
        ns_group: The name server group that serves DNS for this zone.
        parent: The parent zone of this zone.Note that when searching
            for reverse zones, the "in-addr.arpa" notation should be
            used.
        prefix: The RFC2317 prefix value of this DNS zone.Use this field
            only when the netmask is greater than 24 bits; that is, for
            a mask between 25 and 31 bits. Enter a prefix, such as the
            name of the allocated address block. The prefix can be
            alphanumeric characters, such as 128/26 , 128-189 , or
            sub-B.
        primary_type: The type of the primary server.
        record_name_policy: The hostname policy for records under this
            zone.
        rpz_drop_ip_rule_enabled: Enables the appliance to ignore RPZ-IP
            triggers with prefix lengths less than the specified minimum
            prefix length.
        rpz_drop_ip_rule_min_prefix_length_ipv4: The minimum prefix
            length for IPv4 RPZ-IP triggers. The appliance ignores RPZ-
            IP triggers with prefix lengths less than the specified
            minimum IPv4 prefix length.
        rpz_drop_ip_rule_min_prefix_length_ipv6: The minimum prefix
            length for IPv6 RPZ-IP triggers. The appliance ignores RPZ-
            IP triggers with prefix lengths less than the specified
            minimum IPv6 prefix length.
        rpz_last_updated_time: The timestamp of the last update for zone
            data.
        rpz_policy: The response policy zone override policy.
        rpz_priority: The priority of this response policy zone.
        rpz_priority_end: This number is for UI to identify the end of
            qualified zone list.
        rpz_severity: The severity of this response policy zone.
        rpz_type: The type of rpz zone.
        set_soa_serial_number: The serial number in the SOA record
            incrementally changes every time the record is modified. The
            Infoblox appliance allows you to change the serial number
            (in the SOA record) for the primary server so it is higher
            than the secondary server, thereby ensuring zone transfers
            come from the primary server (as they should). To change the
            serial number you need to set a new value at
            "soa_serial_number" and pass "set_soa_serial_number" as
            True.
        soa_default_ttl: The Time to Live (TTL) value of the SOA record
            of this zone. This value is the number of seconds that data
            is cached.
        soa_email: The SOA email value for this zone. This value can be
            in unicode format.
        soa_expire: This setting defines the amount of time, in seconds,
            after which the secondary server stops giving out answers
            about the zone because the zone data is too old to be
            useful. The default is one week.
        soa_negative_ttl: The negative Time to Live (TTL) value of the
            SOA of the zone indicates how long a secondary server can
            cache data for "Does Not Respond" responses.
        soa_refresh: This indicates the interval at which a secondary
            server sends a message to the primary server for a zone to
            check that its data is current, and retrieve fresh data if
            it is not.
        soa_retry: This indicates how long a secondary server must wait
            before attempting to recontact the primary server after a
            connection failure between the two servers occurs.
        soa_serial_number: The serial number in the SOA record
            incrementally changes every time the record is modified. The
            Infoblox appliance allows you to change the serial number
            (in the SOA record) for the primary server so it is higher
            than the secondary server, thereby ensuring zone transfers
            come from the primary server (as they should). To change the
            serial number you need to set a new value at
            "soa_serial_number" and pass "set_soa_serial_number" as
            True.
        substitute_name: The canonical name of redirect target in
            substitute policy of response policy zone.
        use_external_primary: This flag controls whether the zone is
            using an external primary.
        use_grid_zone_timer: Use flag for: soa_default_ttl , soa_expire,
            soa_negative_ttl, soa_refresh, soa_retry
        use_log_rpz: Use flag for: log_rpz
        use_record_name_policy: Use flag for: record_name_policy
        use_rpz_drop_ip_rule: Use flag for: rpz_drop_ip_rule_enabled ,
            rpz_drop_ip_rule_min_prefix_length_ipv4,
            rpz_drop_ip_rule_min_prefix_length_ipv6
        use_soa_email: Use flag for: soa_email
        view: The name of the DNS view in which the zone resides.
            Example "external".
    """
    _infoblox_type = 'zone_rp'
    _fields = ['address', 'comment', 'disable', 'display_domain',
               'dns_soa_email', 'extattrs', 'external_primaries',
               'external_secondaries', 'fireeye_rule_mapping', 'fqdn',
               'grid_primary', 'grid_secondaries', 'locked', 'locked_by',
               'log_rpz', 'mask_prefix', 'member_soa_mnames',
               'member_soa_serials', 'network_view', 'ns_group', 'parent',
               'prefix', 'primary_type', 'record_name_policy',
               'rpz_drop_ip_rule_enabled',
               'rpz_drop_ip_rule_min_prefix_length_ipv4',
               'rpz_drop_ip_rule_min_prefix_length_ipv6',
               'rpz_last_updated_time', 'rpz_policy', 'rpz_priority',
               'rpz_priority_end', 'rpz_severity', 'rpz_type',
               'set_soa_serial_number', 'soa_default_ttl', 'soa_email',
               'soa_expire', 'soa_negative_ttl', 'soa_refresh', 'soa_retry',
               'soa_serial_number', 'substitute_name', 'use_external_primary',
               'use_grid_zone_timer', 'use_log_rpz', 'use_record_name_policy',
               'use_rpz_drop_ip_rule', 'use_soa_email', 'view']
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
    """ ZoneStub: DNS Stub Zone object.
    Corresponds to WAPI object 'zone_stub'

    A stub zone contains records that identify the authoritative name
    servers in the zone. It does not contain resource records for
    resolving IP addresses to hosts in the zone. Instead, it contains
    the following records:

    SOA (Start of Authority) record of the zone

    NS (name server) records at the apex of the stub zone

    A (Address) records that map the name servers to their IP addresses

    Stub zones, like secondary zones, obtain their records from other
    name servers. Their records are read only; therefore, administrators
    do not manually add, remove, or modify the records.

    Stub zone records are also periodically refreshed, just like
    secondary zone records. However, secondary name servers contain a
    complete copy of the zone data on the primary server. Therefore,
    zone transfers from a primary server to a secondary server, or
    between secondary servers, can increase CPU usage and consume
    excessive bandwidth. A name server hosting a stub zone maintains a
    much smaller set of records; therefore, updates are less CPU
    intensive and consume less bandwidth. When a name server hosting a
    stub zone receives a query for a domain name that it determines is
    in the stub zone, the name server uses the records in the stub zone
    to locate the correct name server to query, eliminating the need to
    query the root server.

    Attributes:
        address: The IP address of the server that is serving this zone.
        comment: Comment for the zone; maximum 256 characters.
        disable: Determines whether a zone is disabled or not. When this
            is set to False, the zone is enabled.
        disable_forwarding: Determines if the name servers that host the
            zone should not forward queries that end with the domain
            name of the zone to any configured forwarders.
        display_domain: The displayed name of the DNS zone.
        dns_fqdn: The name of this DNS zone in punycode format. For a
            reverse zone, this is in "address/cidr" format. For other
            zones, this is in FQDN format in punycode format.
        extattrs: Extensible attributes associated with the object.For
            valid values for extensible attributes, see the following
            information.
        external_ns_group: A forward stub server name server group.
        fqdn: The name of this DNS zone. For a reverse zone, this is in
            "address/cidr" format. For other zones, this is in FQDN
            format. This value can be in unicode format.Note that for a
            reverse zone, the corresponding zone_format value should be
            set.
        locked: If you enable this flag, other administrators cannot
            make conflicting changes. This is for administration
            purposes only. The zone will continue to serve DNS data even
            when it is locked.
        locked_by: The name of a superuser or the administrator who
            locked this zone.
        mask_prefix: IPv4 Netmask or IPv6 prefix for this zone.
        ms_ad_integrated: The flag that determines whether Active
            Directory is integrated or not. This field is valid only
            when ms_managed is "STUB", "AUTH_PRIMARY", or "AUTH_BOTH".
        ms_ddns_mode: Determines whether an Active Directory-integrated
            zone with a Microsoft DNS server as primary allows dynamic
            updates. Valid values are:"SECURE" if the zone allows secure
            updates only."NONE" if the zone forbids dynamic
            updates."ANY" if the zone accepts both secure and nonsecure
            updates.This field is valid only if ms_managed is either
            "AUTH_PRIMARY" or "AUTH_BOTH". If the flag ms_ad_integrated
            is false, the value "SECURE" is not allowed.
        ms_managed: The flag that indicates whether the zone is assigned
            to a Microsoft DNS server. This flag returns the
            authoritative name server type of the Microsoft DNS server.
            Valid values are:"NONE" if the zone is not assigned to any
            Microsoft DNS server."STUB" if the zone is assigned to a
            Microsoft DNS server as a stub zone."AUTH_PRIMARY" if only
            the primary server of the zone is a Microsoft DNS
            server."AUTH_SECONDARY" if only the secondary server of the
            zone is a Microsoft DNS server."AUTH_BOTH" if both the
            primary and secondary servers of the zone are Microsoft DNS
            servers.
        ms_read_only: Determines if a Grid member manages the zone
            served by a Microsoft DNS server in read-only mode. This
            flag is true when a Grid member manages the zone in read-
            only mode, false otherwise.When the zone has the
            ms_read_only flag set to True, no changes can be made to
            this zone.
        ms_sync_master_name: The name of MS synchronization master for
            this zone.
        ns_group: A stub member name server group.
        parent: The parent zone of this zone.Note that when searching
            for reverse zones, the "in-addr.arpa" notation should be
            used.
        prefix: The RFC2317 prefix value of this DNS zone.Use this field
            only when the netmask is greater than 24 bits; that is, for
            a mask between 25 and 31 bits. Enter a prefix, such as the
            name of the allocated address block. The prefix can be
            alphanumeric characters, such as 128/26 , 128-189 , or
            sub-B.
        soa_email: The SOA email for the zone. This value can be in
            unicode format.
        soa_expire: This setting defines the amount of time, in seconds,
            after which the secondary server stops giving out answers
            about the zone because the zone data is too old to be
            useful.
        soa_mname: The SOA mname value for this zone. The Infoblox
            appliance allows you to change the name of the primary
            server on the SOA record that is automatically created when
            you initially configure a zone. Use this method to change
            the name of the primary server on the SOA record. For
            example, you may want to hide the primary server for a zone.
            If your device is named dns1.zone.tld, and for security
            reasons, you want to show a secondary server called
            dns2.zone.tld as the primary server. To do so, you would go
            to dns1.zone.tld zone (being the true primary) and change
            the primary server on the SOA to dns2.zone.tld to hide the
            true identity of the real primary server. This value can be
            in unicode format.
        soa_negative_ttl: The negative Time to Live (TTL) value of the
            SOA of the zone indicates how long a secondary server can
            cache data for "Does Not Respond" responses.
        soa_refresh: This indicates the interval at which a secondary
            server sends a message to the primary server for a zone to
            check that its data is current, and retrieve fresh data if
            it is not.
        soa_retry: This indicates how long a secondary server must wait
            before attempting to recontact the primary server after a
            connection failure between the two servers occurs.
        soa_serial_number: The serial number in the SOA record
            incrementally changes every time the record is modified. The
            Infoblox appliance allows you to change the serial number
            (in the SOA record) for the primary server so it is higher
            than the secondary server, thereby ensuring zone transfers
            come from the primary server.
        stub_from: The primary servers (masters) of this stub zone.
        stub_members: The Grid member servers of this stub zone.Note
            that the lead/stealth/grid_replicate/
            preferred_primaries/override_preferred_primaries fields of
            the struct will be ignored when set in this field.
        stub_msservers: The Microsoft DNS servers of this stub zone.Note
            that the stealth field of the struct will be ignored when
            set in this field.
        using_srg_associations: This is true if the zone is associated
            with a shared record group.
        view: The name of the DNS view in which the zone resides.
            Example "external".
        zone_format: Determines the format of this zone.
    """
    _infoblox_type = 'zone_stub'
    _fields = ['address', 'comment', 'disable', 'disable_forwarding',
               'display_domain', 'dns_fqdn', 'extattrs', 'external_ns_group',
               'fqdn', 'locked', 'locked_by', 'mask_prefix',
               'ms_ad_integrated', 'ms_ddns_mode', 'ms_managed',
               'ms_read_only', 'ms_sync_master_name', 'ns_group', 'parent',
               'prefix', 'soa_email', 'soa_expire', 'soa_mname',
               'soa_negative_ttl', 'soa_refresh', 'soa_retry',
               'soa_serial_number', 'stub_from', 'stub_members',
               'stub_msservers', 'using_srg_associations', 'view',
               'zone_format']
    _search_for_update_fields = ['fqdn', 'view']
    _updateable_search_fields = ['comment', 'view']
    _all_searchable_fields = ['comment', 'fqdn', 'parent', 'view',
                              'zone_format']
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
