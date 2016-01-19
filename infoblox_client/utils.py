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
import random
import six

from oslo_log import log as logging
from oslo_serialization import jsonutils


LOG = logging.getLogger(__name__)


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
        LOG.warn("Could not decode reply into json: %s", data)


def try_value_to_bool(value, strict_mode=True):
    """Tries to convert value into boolean.

    strict_mode is True:
    - Only string representation of str(True) and str(False)
      are converted into booleans;
    - Otherwise unchanged incoming value is returned;

    strict_mode is False:
    - Anything that looks like True or False is converted into booleans.
    Values accepted as True:
    - 'true', 'on', 'yes' (case independent)
    Values accepted as False:
    - 'false', 'off', 'no' (case independent)
    - all other values are returned unchanged
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
