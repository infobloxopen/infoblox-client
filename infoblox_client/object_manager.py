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

from oslo_log import log as logging

from infoblox_client import exceptions as ib_ex
from infoblox_client import objects as obj
from infoblox_client import utils as ib_utils

LOG = logging.getLogger(__name__)


class InfobloxObjectManager(object):

    def __init__(self, connector):
        self.connector = connector

    def create_network_view(self, network_view, extattrs):
        return obj.NetworkView.create(self.connector,
                                      name=network_view,
                                      extattrs=extattrs)

    def delete_network_view(self, network_view):
        # never delete default network view
        if network_view == 'default':
            return
        nview = obj.NetworkView.search(self.connector,
                                       name=network_view)
        if nview:
            nview.delete()

    def create_dns_view(self, network_view, dns_view):
        return obj.DNSView.create(self.connector,
                                  name=dns_view,
                                  network_view=network_view)

    def delete_dns_view(self, dns_view):
        dns_view = obj.DNSView.search(self.connector,
                                      name=dns_view)
        if dns_view:
            dns_view.delete()

    def create_network(self, net_view_name, cidr, nameservers=None,
                       members=None, gateway_ip=None, dhcp_trel_ip=None,
                       network_extattrs=None):
        """Create NIOS Network and prepare DHCP options.

        Some DHCP options are valid for IPv4 only, so just skip processing
        them for IPv6 case.

        :param net_view_name: network view name
        :param cidr: network to allocate, example '172.23.23.0/24'
        :param nameservers: list of name servers hosts/ip
        :param members: list of objects.AnyMember objects that are expected
            to serve dhcp for created network
        :param gateway_ip: gateway ip for the network (valid for IPv4 only)
        :param dhcp_trel_ip: ip address of dhcp relay (valid for IPv4 only)
        :param network_extattrs: extensible attributes for network (instance of
            objects.EA)
        :returns: created network (instance of objects.Network)
        """
        ipv4 = ib_utils.determine_ip_version(cidr) == 4

        options = []
        if nameservers:
            options.append(obj.DhcpOption(name='domain-name-servers',
                                          value=",".join(nameservers)))
        if ipv4 and gateway_ip:
            options.append(obj.DhcpOption(name='routers',
                                          value=gateway_ip))
        if ipv4 and dhcp_trel_ip:
            options.append(obj.DhcpOption(name='dhcp-server-identifier',
                                          num=54,
                                          value=dhcp_trel_ip))
        return obj.Network.create(self.connector,
                                  network_view=net_view_name,
                                  cidr=cidr,
                                  members=members,
                                  options=options,
                                  extattrs=network_extattrs,
                                  check_if_exists=False)

    def get_network(self, network_view, cidr):
        return obj.Network.search(self.connector,
                                  network_view=network_view,
                                  cidr=cidr)

    def create_ip_range(self, network_view, start_ip, end_ip, network,
                        disable, range_extattrs):
        """Creates IPRange or fails if already exists."""
        return obj.IPRange.create(self.connector,
                                  network_view=network_view,
                                  start_addr=start_ip,
                                  end_addr=end_ip,
                                  cidr=network,
                                  disable=disable,
                                  extattrs=range_extattrs,
                                  check_if_exists=False)

    def delete_ip_range(self, network_view, start_ip, end_ip):
        range = obj.IPRange.search(self.connector,
                                   network_view=network_view,
                                   start_addr=start_ip,
                                   end_addr=end_ip)
        if range:
            range.delete()

    def has_networks(self, network_view_name):
        networks = obj.Network.search_all(self.connector,
                                          network_view=network_view_name)
        return bool(networks)

    def network_exists(self, network_view, cidr):
        """Deprecated, use get_network() instead."""
        LOG.warning(
            "DEPRECATION WARNING! Using network_exists() is deprecated "
            "and to be removed in next releases. "
            "Use get_network() or objects.Network.search instead")
        network = obj.Network.search(self.connector,
                                     network_view=network_view,
                                     cidr=cidr)
        return network is not None

    def delete_network(self, network_view, cidr):
        network = obj.Network.search(self.connector,
                                     network_view=network_view,
                                     cidr=cidr)
        if network:
            network.delete()

    def create_network_from_template(self, network_view, cidr, template,
                                     extattrs):
        return obj.Network.create(self.connector,
                                  network_view=network_view,
                                  cidr=cidr,
                                  template=template,
                                  extattrs=extattrs,
                                  check_if_exists=False)

    def update_network_options(self, ib_network, extattrs=None):
        if extattrs:
            if ib_network.extattrs:
                # Merge EA values as dicts
                ea_dict = ib_network.extattrs.ea_dict
                ea_dict.update(extattrs.ea_dict)
                merged_ea = obj.EA(ea_dict)
                ib_network.extattrs = merged_ea
            else:
                ib_network.extattrs = extattrs
        return ib_network.update()

    def get_host_record(self, dns_view, ip, network_view=None):
        return obj.HostRecord.search(self.connector,
                                     view=dns_view,
                                     ip=ip,
                                     network_view=network_view)

    def find_hostname(self, dns_view, hostname, ip, network_view=None):
        return obj.HostRecord.search(self.connector,
                                     name=hostname,
                                     view=dns_view,
                                     ip=ip,
                                     network_view=network_view)

    def create_host_record_for_given_ip(self, dns_view, zone_auth,
                                        hostname, mac, ip, extattrs,
                                        use_dhcp, use_dns=True):
        name = '.'.join([hostname, zone_auth])
        ip_obj = obj.IP.create(ip=ip, mac=mac, configure_for_dhcp=use_dhcp)
        return obj.HostRecord.create(self.connector,
                                     view=dns_view,
                                     name=name,
                                     ip=ip_obj,
                                     configure_for_dns=use_dns,
                                     extattrs=extattrs,
                                     check_if_exists=False)

    def create_host_record_from_range(self, dns_view, network_view_name,
                                      zone_auth, hostname, mac, first_ip,
                                      last_ip, extattrs, use_dhcp,
                                      use_dns=True):
        name = '.'.join([hostname, zone_auth])
        ip_alloc = obj.IPAllocation.next_available_ip_from_range(
            network_view_name, first_ip, last_ip)
        ip_obj = obj.IP.create(ip=ip_alloc, mac=mac,
                               configure_for_dhcp=use_dhcp)
        return obj.HostRecord.create(self.connector,
                                     view=dns_view,
                                     name=name,
                                     ip=ip_obj,
                                     configure_for_dns=use_dns,
                                     extattrs=extattrs,
                                     check_if_exists=False)

    def delete_host_record(self, dns_view, ip_address, network_view=None):
        host_record = obj.HostRecord.search(self.connector,
                                            view=dns_view, ip=ip_address,
                                            network_view=network_view)
        if host_record:
            host_record.delete()

    def create_fixed_address_for_given_ip(self, network_view, mac, ip,
                                          extattrs):
        return obj.FixedAddress.create(self.connector,
                                       network_view=network_view,
                                       mac=mac,
                                       ip=ip,
                                       extattrs=extattrs,
                                       check_if_exists=False)

    def create_fixed_address_from_range(self, network_view, mac, first_ip,
                                        last_ip, extattrs):
        ip = obj.IPAllocation.next_available_ip_from_range(
            network_view, first_ip, last_ip)
        return obj.FixedAddress.create(self.connector,
                                       ip=ip,
                                       mac=mac,
                                       network_view=network_view,
                                       extattrs=extattrs,
                                       check_if_exists=False)

    def create_fixed_address_from_cidr(self, netview, mac, cidr, extattrs):
        ip = obj.IPAllocation.next_available_ip_from_cidr(netview, cidr)
        return obj.FixedAddress.create(self.connector,
                                       network_view=netview,
                                       ip=ip,
                                       mac=mac,
                                       extattrs=extattrs,
                                       check_if_exists=False)

    def delete_fixed_address(self, network_view, ip_address):
        fixed_address = obj.FixedAddress.search(self.connector,
                                                network_view=network_view,
                                                ip=ip_address)
        if fixed_address:
            fixed_address.delete()

    def add_ip_to_record(self, host_record, ip, mac, use_dhcp=True):
        ip_obj = obj.IP.create(ip=ip, mac=mac, configure_for_dhcp=use_dhcp)
        host_record.ip.append(ip_obj)
        return host_record.update()

    def add_ip_to_host_record_from_range(self, host_record, network_view,
                                         mac, first_ip, last_ip,
                                         use_dhcp=True):
        ip_alloc = obj.IPAllocation.next_available_ip_from_range(
            network_view, first_ip, last_ip)
        ip_obj = obj.IP.create(ip=ip_alloc, mac=mac,
                               configure_for_dhcp=use_dhcp)
        host_record.ip.append(ip_obj)
        return host_record.update()

    def delete_ip_from_host_record(self, host_record, ip):
        host_record.ip.remove(ip)
        return host_record.update()

    def has_dns_zones(self, dns_view):
        zones = obj.DNSZone.search_all(self.connector, view=dns_view)
        return bool(zones)

    def create_dns_zone(self, dns_view, dns_zone,
                        grid_primary=None, grid_secondaries=None,
                        zone_format=None, ns_group=None, prefix=None,
                        extattrs=None):
        return obj.DNSZone.create(self.connector,
                                  fqdn=dns_zone,
                                  view=dns_view,
                                  extattrs=extattrs,
                                  zone_format=zone_format,
                                  ns_group=ns_group,
                                  prefix=prefix,
                                  grid_primary=grid_primary,
                                  grid_secondaries=grid_secondaries)

    def delete_dns_zone(self, dns_view, dns_zone_fqdn):
        dns_zone = obj.DNSZone.search(self.connector,
                                      fqdn=dns_zone_fqdn,
                                      view=dns_view)
        if dns_zone:
            dns_zone.delete()

    def update_dns_zone_attrs(self, dns_view, dns_zone_fqdn, extattrs):
        if not extattrs:
            return
        dns_zone = obj.DNSZone.search(self.connector,
                                      fqdn=dns_zone_fqdn,
                                      view=dns_view)
        if dns_zone:
            dns_zone.extattrs = extattrs
            dns_zone.update()

    def update_host_record_eas(self, dns_view, ip, extattrs):
        host_record = obj.HostRecord.search(self.connector,
                                            view=dns_view,
                                            ip=ip)
        if host_record:
            host_record.extattrs = extattrs
            host_record.update()

    def update_fixed_address_eas(self, network_view, ip, extattrs):
        fixed_address = obj.FixedAddress.search(self.connector,
                                                network_view=network_view,
                                                ip=ip)
        if fixed_address:
            fixed_address.extattrs = extattrs
            fixed_address.update()

    def update_dns_record_eas(self, dns_view, ip, extattrs):
        a_record = obj.ARecordBase.search(self.connector,
                                          ip=ip,
                                          view=dns_view)
        if a_record:
            a_record.extattrs = extattrs
            a_record.update()

        ptr_record = obj.PtrRecord.search(self.connector,
                                          ip=ip,
                                          view=dns_view)
        if ptr_record:
            ptr_record.extattrs = extattrs
            ptr_record.update()

    def bind_name_with_host_record(self, dns_view, ip, name, extattrs,
                                   network_view=None):
        host_record = obj.HostRecord.search(self.connector,
                                            view=dns_view,
                                            ip=ip,
                                            network_view=network_view)
        if host_record:
            host_record.name = name
            host_record.extattrs = extattrs
            host_record.update()

    def bind_name_with_record_a(self, dns_view, ip, name, bind_list,
                                extattrs):
        is_ipv4 = ib_utils.determine_ip_version(ip) == 4
        if ((is_ipv4 and 'record:a' in bind_list) or
                (not is_ipv4 and 'record:aaaa' in bind_list)):
            obj.ARecordBase.create(self.connector,
                                   view=dns_view,
                                   ip=ip,
                                   name=name,
                                   extattrs=extattrs,
                                   update_if_exists=True)

        if 'record:ptr' in bind_list:
            obj.PtrRecord.create(self.connector,
                                 view=dns_view,
                                 ip=ip,
                                 ptrdname=name,
                                 extattrs=extattrs,
                                 update_if_exists=True)

    def unbind_name_from_record_a(self, dns_view, ip, name, unbind_list):
        is_ipv4 = ib_utils.determine_ip_version(ip) == 4
        if ((is_ipv4 and 'record:a' in unbind_list) or
                (not is_ipv4 and 'record:aaaa' in unbind_list)):
            a_record = obj.ARecordBase.search(self.connector,
                                              view=dns_view,
                                              ip=ip,
                                              name=name)
            if a_record:
                self.delete_objects_associated_with_a_record(a_record.name,
                                                             a_record.view,
                                                             unbind_list)
                a_record.delete()

        if 'record:ptr' in unbind_list:
            ptr_record = obj.PtrRecord.search(self.connector,
                                              view=dns_view,
                                              ip=ip,
                                              ptrdname=name)
            if ptr_record:
                ptr_record.delete()

    def get_member(self, member):
        member.fetch()
        return member

    def get_all_ea_definitions(self):
        return obj.EADefinition.search_all(self.connector)

    def create_ea_definition(self, ea_def, reraise=False):
        try:
            return obj.EADefinition.create(self.connector,
                                           check_if_exists=False,
                                           **ea_def)
        except ib_ex.InfobloxCannotCreateObject:
            LOG.error('Unable to create Extensible Attribute Definition '
                      '%s' % ea_def)
            if reraise:
                raise

    def create_required_ea_definitions(self, required_ea_defs, reraise=False):
        existing_ea_defs = self.get_all_ea_definitions()
        missing_ea_defs = []
        for req_def in required_ea_defs:
            if not [ea_def for ea_def in existing_ea_defs
                    if ea_def.name == req_def['name']]:
                missing_ea_defs.append(req_def)

        created_ea_defs = []
        for ea_def in missing_ea_defs:
            if self.create_ea_definition(ea_def, reraise=reraise):
                created_ea_defs.append(ea_def)
        return created_ea_defs

    def restart_all_services(self, member):
        if not member._ref:
            member.fetch(only_ref=True)
        self.connector.call_func('restartservices', member._ref,
                                 {'restart_option': 'RESTART_IF_NEEDED',
                                  'service_option': 'ALL'})

    def delete_objects_associated_with_a_record(self, name, view, delete_list):
        """Deletes records associated with record:a or record:aaaa."""
        search_objects = {}
        if 'record:cname' in delete_list:
            search_objects['record:cname'] = 'canonical'
        if 'record:txt' in delete_list:
            search_objects['record:txt'] = 'name'

        if not search_objects:
            return

        for obj_type, search_type in search_objects.items():
            payload = {'view': view,
                       search_type: name}
            ib_objs = self.connector.get_object(obj_type, payload)
            if ib_objs:
                for ib_obj in ib_objs:
                    self.delete_object_by_ref(ib_obj['_ref'])

    def delete_all_associated_objects(self, network_view, ip, delete_list):
        LOG.warning(
            "DEPRECATION WARNING! Using delete_all_associated_objects() "
            "is deprecated and to be removed in next releases. "
            "Use unbind_name_from_record_a() instead.")

    def delete_object_by_ref(self, ref):
        try:
            self.connector.delete_object(ref)
        except ib_ex.InfobloxCannotDeleteObject:
            pass
