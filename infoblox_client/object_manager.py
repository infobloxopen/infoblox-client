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
        """Create NIOS Network."""

        # NIOS does not allow to set Dhcp options for IPv6 over WAPI,
        # so limit options usage with IPv4 only
        ipv4 = ib_utils.determine_ip_version(cidr) == 4

        options = []
        if ipv4 and nameservers:
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
        try:
            networks = obj.Network.search_all(self.connector,
                                              network_view=network_view_name)
            return bool(networks)
        except ib_ex.InfobloxSearchError:
            return False

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
            ib_network.extattrs = extattrs
        return ib_network.update()

    def get_host_record(self, dns_view, ip):
        return obj.HostRecord.search(self.connector,
                                     view=dns_view,
                                     ip=ip)

    def find_hostname(self, dns_view, hostname, ip):
        return obj.HostRecord.search(self.connector,
                                     name=hostname,
                                     view=dns_view,
                                     ip=ip)

    def create_host_record_for_given_ip(self, dns_view, zone_auth,
                                        hostname, mac, ip, extattrs,
                                        use_dhcp):
        name = '.'.join([hostname, zone_auth])
        ip_obj = obj.IP.create(ip=ip, mac=mac, configure_for_dhcp=use_dhcp)
        return obj.HostRecord.create(self.connector,
                                     view=dns_view,
                                     name=name,
                                     ip=ip_obj,
                                     extattrs=extattrs,
                                     check_if_exists=False)

    def create_host_record_from_range(self, dns_view, network_view_name,
                                      zone_auth, hostname, mac, first_ip,
                                      last_ip, extattrs, use_dhcp):
        name = '.'.join([hostname, zone_auth])
        ip_alloc = obj.IPAllocation.next_available_ip_from_range(
            network_view_name, first_ip, last_ip)
        ip_obj = obj.IP.create(ip=ip_alloc, mac=mac,
                               configure_for_dhcp=use_dhcp)
        return obj.HostRecord.create(self.connector,
                                     view=dns_view,
                                     name=name,
                                     ip=ip_obj,
                                     extattrs=extattrs,
                                     check_if_exists=False)

    def delete_host_record(self, dns_view, ip_address):
        host_record = obj.HostRecord.search(self.connector,
                                            view=dns_view, ip=ip_address)
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
        try:
            zones = obj.DNSZone.search_all(self.connector, view=dns_view)
            return bool(zones)
        except ib_ex.InfobloxSearchError:
            return False

    def create_dns_zone(self, dns_view, dns_zone,
                        grid_primary=None, grid_secondaries=None,
                        zone_format=None, ns_group=None, prefix=None,
                        extattrs=None):
        try:
            return obj.DNSZone.create(self.connector,
                                      fqdn=dns_zone,
                                      view=dns_view,
                                      extattrs=extattrs,
                                      zone_format=zone_format,
                                      ns_group=ns_group,
                                      prefix=prefix,
                                      grid_primary=grid_primary,
                                      grid_secondaries=grid_secondaries)
        except ib_ex.InfobloxCannotCreateObject:
            LOG.warning('Unable to create DNS zone %(dns_zone_fqdn)s '
                        'for %(dns_view)s',
                        {'dns_zone_fqdn': dns_zone, 'dns_view': dns_view})

    def delete_dns_zone(self, dns_view, dns_zone_fqdn):
        dns_zone = obj.DNSZone.search(self.connector,
                                      fqdn=dns_zone_fqdn,
                                      view=dns_view)
        if dns_zone:
            dns_zone.delete()

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

    def bind_name_with_host_record(self, dns_view, ip, name, extattrs):
        host_record = obj.HostRecord.search(self.connector,
                                            view=dns_view,
                                            ip=ip)
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
        try:
            ea_defs = obj.EADefinition.search_all(self.connector)
            return ea_defs
        except ib_ex.InfobloxSearchError:
            return None

    def create_ea_definition(self, ea_def):
        try:
            return obj.EADefinition.create(self.connector,
                                           check_if_exists=False,
                                           **ea_def)
        except ib_ex.InfobloxCannotCreateObject:
            LOG.error('Unable to create Extensible Attribute Definition '
                      '%s' % ea_def)

    def create_required_ea_definitions(self, required_ea_defs):
        existing_ea_defs = self.get_all_ea_definitions()
        missing_ea_defs = filter(lambda x: not next(
            (y for y in existing_ea_defs if x['name'] == y.name), None),
            required_ea_defs)

        for ea_def in missing_ea_defs:
            self.create_ea_definition(ea_def)

    def restart_all_services(self, member):
        if not member._ref:
            member.fetch()
        self.connector.call_func('restartservices', member._ref,
                                 {'restart_option': 'RESTART_IF_NEEDED',
                                  'service_option': 'ALL'})

    def get_object_refs_associated_with_a_record(self, a_record_ref):
        # record should in the format: {object_type, search_field}
        associated_with_a_record = [
            {'type': 'record:cname', 'search': 'canonical'},
            {'type': 'record:txt', 'search': 'name'}
        ]

        ib_obj_refs = []
        a_record = self.connector.get_object(a_record_ref)

        for rec_inf in associated_with_a_record:
            obj_type = rec_inf['type']
            payload = {'view': a_record['view'],
                       rec_inf['search']: a_record['name']}
            ib_objs = self.connector.get_object(obj_type, payload)
            if ib_objs:
                for ib_obj in ib_objs:
                    ib_obj_refs.append(ib_obj['_ref'])
        return ib_obj_refs

    def get_all_associated_objects(self, network_view, ip):
        ip_objects = obj.IPAddress.search(self.connector,
                                          network_view=network_view,
                                          ip_address=ip)
        if ip_objects:
            return ip_objects.objects
        return []

    @staticmethod
    def _get_object_type_from_ref(ref):
        return ref.split('/', 1)[0]

    def delete_all_associated_objects(self, network_view, ip, delete_list):
        del_ib_objs = []
        ib_obj_refs = self.get_all_associated_objects(network_view, ip)

        for ib_obj_ref in ib_obj_refs:
            del_ib_objs.append(ib_obj_ref)
            obj_type = self._get_object_type_from_ref(ib_obj_ref)
            if obj_type in ['record:a', 'record:aaaa']:
                del_ib_objs.extend(
                    self.get_object_refs_associated_with_a_record(ib_obj_ref))

        for ib_obj_ref in del_ib_objs:
            obj_type = self._get_object_type_from_ref(ib_obj_ref)
            if obj_type in delete_list:
                self.connector.delete_object(ib_obj_ref)

    def delete_object_by_ref(self, ref):
        try:
            self.connector.delete_object(ref)
        except ib_ex.InfobloxCannotDeleteObject:
            pass
