# Copyright 2015 OpenStack LLC.
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

import datetime
import decimal
import netaddr
import random
import re
import six

from oslo_log import log as logging
from oslo_serialization import jsonutils


LOG = logging.getLogger(__name__)
EA_CLOUD_MGMT_PLATFORM_TYPE = 'CMP Type'


def json_to_obj(obj_type, json_data):
    """Converts json data to an object with a given object type

    :param obj_type: converted object's type that is determined dynamically
    :param json_data: json string or json object
    :return: object
    """
    def dic2obj(x):
        if isinstance(x, dict):
            return type(obj_type, (),
                        {k: dic2obj(v) for k, v in six.iteritems(x)})
        else:
            return x

    if isinstance(json_data, six.string_types):
        json_data = jsonutils.loads(json_data)
    return dic2obj(json_data)


def get_values_from_records(key, records):
    key_vals = []
    if records is None:
        return key_vals

    for record in records:
        key_val = record.get(key, None)
        if key_val:
            key_vals.append(key_val)
    return key_vals


def db_records_to_obj(obj_type, records):
    record_json = db_records_to_json(records)
    if not isinstance(record_json, list):
        return json_to_obj(obj_type, record_json)

    result_set = []
    for record in records:
        result_set.append(json_to_obj(obj_type, record))
    return result_set


def db_records_to_json(records):
    """Converts db records to json.

    alchemy_encoder is needed for date and numeric(x,y) fields since
    they will turn into datetime.date and decimal.Decimal types.
    """
    def alchemy_encoder(obj):
        if isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, decimal.Decimal):
            return float(obj)

    rows = []
    for record in records:
        if isinstance(record, tuple):
            merge = dict()
            for table in record:
                merge.update(dict(table))
            rows.append(merge)
        else:
            rows.append(dict(record))

    # return all rows as a JSON array of objects
    json_str = jsonutils.dumps(rows, alchemy_encoder)
    return jsonutils.loads(json_str)


def construct_ea(attributes):
    ea = {}
    for name, value in six.iteritems(attributes):
        str_val = get_string_or_none(value)
        if str_val:
            ea[name] = {'value': str_val}

    ea[EA_CLOUD_MGMT_PLATFORM_TYPE] = {'value': 'OpenStack'}
    return ea


def get_string_or_none(value):
    ret_val = None
    if isinstance(value, six.string_types):
        ret_val = value
    else:
        if value is not None:
            ret_val = str(value)
    return ret_val


def scalar_from_ea(name, extattrs):
    valid = (name and isinstance(name, six.string_types) and
             extattrs and isinstance(extattrs, dict))
    if not valid:
        ValueError("Invalid argument was passed")

    value = None
    if extattrs:
        root = extattrs.get("extattrs")
        name_attr = root.get(name)
        if name_attr:
            value = name_attr.get('value')
    return value


def get_ip_version(ip_address):
    valid = ip_address and isinstance(ip_address, six.string_types)
    if not valid:
        ValueError("Invalid argument was passed")

    if type(ip_address) is dict:
        ip = ip_address['ip_address']
    else:
        ip = ip_address

    try:
        ip = netaddr.IPAddress(ip)
    except ValueError:
        ip = netaddr.IPNetwork(ip)
    return ip.version


def is_valid_ip(ip):
    try:
        netaddr.IPAddress(ip)
    except netaddr.core.AddrFormatError:
        return False
    return True


def generate_duid(mac):
    """DUID is consisted of 10 hex numbers.

    0x00 + 3 random hex + mac with 6 hex
    """
    valid = mac and isinstance(mac, six.string_types)
    if not valid:
        ValueError("Invalid argument was passed")
    duid = [0x00,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, duid)) + ':' + mac


def get_prefix_for_dns_zone(subnet_name, cidr):
    valid = cidr and isinstance(cidr, six.string_types)
    if not valid:
        ValueError("Invalid argument was passed")

    subnet_name = subnet_name if subnet_name else ''
    try:
        ip_version = get_ip_version(cidr)
    except netaddr.core.AddrFormatError:
        return ValueError("Invalid cidr")

    # add prefix only for classless networks (ipv4) mask greater than
    # 24 needs prefix; use meaningful prefix if used
    prefix = None
    if ip_version == 4:
        m = re.search(r'/\d+', cidr)
        mask = m.group().replace("/", "")
        if int(mask) > 24:
            if len(subnet_name) > 0:
                prefix = subnet_name
            else:
                prefix = '-'.join(
                    filter(None,
                           re.split(r'[.:/]', cidr))
                )
    return prefix


def get_physical_network_meta(network):
    valid = network and isinstance(network, dict)
    if not valid:
        ValueError("Invalid argument was passed")

    network = network if network else {}
    provider_network_type = network.get('provider:network_type')
    provider_physical_network = network.get('provider:physical_network')
    provider_segmentation_id = network.get('provider:segmentation_id')
    network_meta = {'network_type': provider_network_type,
                    'physical_network': provider_physical_network,
                    'segmentation_id': provider_segmentation_id}
    return network_meta


def get_list_from_string(data_string, delimiter_list):
    valid = (data_string and
             isinstance(data_string, six.string_types) and
             delimiter_list and
             isinstance(delimiter_list, list))
    if not valid:
        ValueError("Invalid argument was passed")

    list_data = remove_any_space(data_string)
    if isinstance(delimiter_list, six.string_types):
        if len(delimiter_list) == 0:
            return data_string
        return list_data.split(delimiter_list)

    if isinstance(delimiter_list, list):
        delimiter_count = len(delimiter_list)
        if delimiter_count == 0:
            return data_string
        if delimiter_count == 1:
            return list_data.split(delimiter_list[0])
        if delimiter_count > 2:
            return ValueError("Delimiter list can contain up to 2 delimiters.")

        result_list = []
        for delimiter in delimiter_list:
            if isinstance(list_data, six.string_types):
                list_data = list_data.split(delimiter)
            else:
                for ld in list_data:
                    result_list.append(ld.split(delimiter))
        # clean up empty string element ['']
        result_list[0] = [m for m in result_list[0] if m]
        result_list[1] = [m for m in result_list[1] if m]
        return result_list

    return ValueError("Unsupported delimiter list type")


def exists_in_sequence(sub_sequence_to_find, full_list_in_sequence):
    valid = (sub_sequence_to_find and
             isinstance(sub_sequence_to_find, list) and
             full_list_in_sequence and
             isinstance(full_list_in_sequence, list))
    if not valid:
        ValueError("Invalid argument was passed")

    return any(full_list_in_sequence[pos:pos + len(sub_sequence_to_find)] ==
               sub_sequence_to_find for pos in
               range(0,
                     len(full_list_in_sequence) - len(sub_sequence_to_find)
                     + 1))


def exists_in_list(list_to_find, full_list):
    valid = (list_to_find and isinstance(list_to_find, list) and
             full_list and isinstance(full_list, list))
    if not valid:
        ValueError("Invalid argument was passed")

    found_list = [m for m in list_to_find if m in full_list]
    return len(found_list) == len(list_to_find)


def find_one_in_list(search_key, search_value, search_list):
    valid = (search_key and isinstance(search_key, six.string_types) and
             search_value and isinstance(search_value, six.string_types) and
             search_list and isinstance(search_list, list))
    if not valid:
        ValueError("Invalid argument was passed")

    found_list = [m for m in search_list
                  if m.get(search_key) == search_value]
    return found_list[0] if found_list else None


def find_in_list(search_key, search_values, search_list):
    valid = (search_key and isinstance(search_key, six.string_types) and
             search_values and isinstance(search_values, list) and
             search_list and isinstance(search_list, list))
    if not valid:
        ValueError("Invalid argument was passed")

    found_list = [m for m in search_list
                  if m.get(search_key) in search_values]
    return found_list


def merge_list(*list_args):
    merge_lsit = []
    for lst in list_args:
        merge_lsit += lst
    return list(set(merge_lsit))


def remove_any_space(text):
    return re.sub(r'\s+', '', text)


def determine_ip_version(ip_in):
    ip_ver = 4
    if isinstance(ip_in, (list, tuple)):
        ip_in = ip_in[0]
    if ip_in:
        if isinstance(ip_in, int):
            if ip_in == 6:
                ip_ver = 6
            else:
                ip_ver = 4
        elif hasattr(ip_in, 'ip_version'):
            return ip_in.ip_version
        else:
            if type(ip_in) is dict:
                addr = ip_in['ip_address']
            else:
                addr = ip_in
            try:
                ip = netaddr.IPAddress(addr)
            except ValueError:
                ip = netaddr.IPNetwork(addr)

            ip_ver = ip.version
    return ip_ver
