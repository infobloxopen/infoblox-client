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

import netaddr
import six

try:
    from oslo_log import log as logging
except ImportError:  # pragma: no cover
    import logging

try:
    from oslo_serialization import jsonutils
except ImportError:  # pragma: no cover
    import json as jsonutils

LOG = logging.getLogger(__name__)


def is_valid_ip(ip):
    try:
        netaddr.IPAddress(ip)
    except netaddr.core.AddrFormatError:
        return False
    return True


def generate_duid(mac):
    """DUID is consisted of 10 hex numbers.

    0x00 + mac with last 3 hex + mac with 6 hex
    """
    valid = mac and isinstance(mac, six.string_types)
    if not valid:
        raise ValueError("Invalid argument was passed")
    return "00:" + mac[9:] + ":" + mac


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


def safe_json_load(data):
    try:
        return jsonutils.loads(data)
    except ValueError:
        LOG.warning("Could not decode reply into json: %s", data)


def try_value_to_bool(value, strict_mode=True):
    """Tries to convert value into boolean.

    Args:
        value       (str): Value that should be converted into boolean.

        strict_mode (bool):
            - If strict_mode is True, Only string representation of str(True)
              and str(False) are converted into booleans;
            - If strict_mode is False, anything that looks like True or False
              is converted into booleans:

              - Values accepted as True are: 'true', 'on', 'yes' (case
                independent)
              - Values accepted as False are: 'false', 'off', 'no' (case
                independent)

    Returns:
        True, False, or original value in case of failed conversion.
    """
    if strict_mode:
        true_list = ('True',)
        false_list = ('False',)
        val = value
    else:
        true_list = ('true', 'on', 'yes')
        false_list = ('false', 'off', 'no')
        val = str(value).lower()

    if val in true_list:
        return True
    elif val in false_list:
        return False
    return value


def paging(response, max_results):
    """Returns WAPI response page by page

    Args:
        response (list): WAPI response.
        max_results (int): Maximum number of objects to be returned
                           in one page.
    Returns:
        Generator object with WAPI response split page by page.
    """
    i = 0
    while i < len(response):
        yield response[i:i + max_results]
        i = i + max_results
