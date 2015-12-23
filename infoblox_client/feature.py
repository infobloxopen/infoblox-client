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
import string

from infoblox_client import exceptions as ib_ex

FEATURE_VERSIONS = {
    'create_ea_def': '2.2',
    'cloud_api': '2.0',
    'member_ipv6_setting': '2.2',
    'member_licenses': '2.0',
    'enable_member_dns': '2.2.1',
    'enable_member_dhcp': '2.2.1'}


class Feature(object):
    """Class representing available NIOS features

    Based on the following:
      - Infoblox WAPI Version
      - Known features and corresponding WAPI version requirement
    the Feature class represents available NIOS features as attributes.
    """
    def __init__(self, version, feature_versions=None):
        self._wapi_version = None

        if feature_versions is None:
            feature_versions = FEATURE_VERSIONS

        if isinstance(version, six.string_types):
            wapi_version = version
        elif hasattr(version, 'wapi_version'):
            wapi_version = getattr(version, 'wapi_version')
        else:
            msg = "WAPI version cannot be determined from '%s'" % version
            raise ib_ex.InfobloxConfigException(msg=msg)

        wapi_util = WapiVersionUtil(wapi_version)
        for f, v in feature_versions.items():
            setattr(self,
                    f,
                    wapi_util.is_version_supported(v))


class WapiVersionUtil(object):
    """Provide utility functions for manipulating WAPI version

    Provide methods that manipulate and get information from
    WAPI version string.
    """
    def __init__(self, version):
        self._version_parts = self._get_wapi_version_parts(version)

    @property
    def version_parts(self):
        return self._version_parts

    @property
    def major_version(self):
        return self.version_parts[0]

    @property
    def minor_version(self):
        return self.version_parts[1]

    @property
    def patch_version(self):
        return self.version_parts[2]

    def is_version_supported(self, req_ver):
        req_parts = WapiVersionUtil(req_ver).version_parts

        for a, b in zip(self.version_parts, req_parts):
            if a is None:
                return True if b is None else False
            elif b is None:
                return True
            elif not a == b:
                return (a > b)
        return True

    @staticmethod
    def _get_wapi_version_parts(version):
        parts = version.split('.')
        if (not parts or len(parts) > 3 or len(parts) < 2):
            raise ValueError("Invalid argument was passed")
        for p in parts:
            if not len(p) or p not in string.digits:
                raise ValueError("Invalid argument was passed")
        parts = [int(x) for x in parts]
        if len(parts) == 2:
            parts.append(None)
        return parts
