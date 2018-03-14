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
import unittest

from infoblox_client import utils


class TestUtils(unittest.TestCase):

    def test_is_valid_ip(self):
        ips = ('192.168.0.1',
               '8.8.8.8',
               'fffe::1')
        for ip in ips:
            self.assertEqual(True, utils.is_valid_ip(ip))

    def test_is_invalid_ip(self):
        ips = ('192.data.0.1',
               'text',
               None,
               '192.168.159.658')
        for ip in ips:
            self.assertEqual(False, utils.is_valid_ip(ip))

    def test_safe_json_load_no_exception(self):
        data = 'Some regular not json text'
        self.assertEqual(None, utils.safe_json_load(data))

    def test_safe_json_load(self):
        data = '{"array":[1,2,3]}'
        expected_data = {'array': [1, 2, 3]}
        self.assertEqual(expected_data, utils.safe_json_load(data))

    def test_try_value_to_bool(self):
        test_data = ((True, True),
                     (False, False),
                     (str(True), True),
                     (str(False), False),
                     ('True', True),
                     ('False', False),
                     ('TRUE', 'TRUE'),
                     ('FALSE', 'FALSE'),
                     ('/path/to/file', '/path/to/file'))
        for value, result in test_data:
            self.assertEqual(result, utils.try_value_to_bool(value))

    def test_try_value_to_bool_not_strict(self):
        true_values = (True, 'True', 'true', 'TRUE', 'tRUE',
                       'On', 'ON', 'on', 'oN',
                       'Yes', 'YES', 'yes')
        for v in true_values:
            self.assertEqual(True,
                             utils.try_value_to_bool(v, strict_mode=False))

        false_values = (False, 'False', 'false', 'FALSE', 'fALSE',
                        'Off', 'OFF', 'off',
                        'No', 'NO', 'no')
        for v in false_values:
            self.assertEqual(False,
                             utils.try_value_to_bool(v, strict_mode=False))

        unchanged_values = ('/path/to/file', 'YES!', '/tmp/certificate')
        for v in unchanged_values:
            self.assertEqual(v, utils.try_value_to_bool(v, strict_mode=False))

    def test_generate_duid(self):
        # DUID mac address starts from position 12
        duid_mac_start_point = 12

        mac = 'fa:16:3e:bd:ce:14'
        duid = utils.generate_duid(mac)
        # 10 octets for duid
        self.assertEqual(10, len(duid.split(':')))
        self.assertEqual(True, (duid.find(mac) == duid_mac_start_point))
        self.assertEqual(False, (duid[3:11] == "00:00:00"))

    def test_generate_duid_with_invalid_mac(self):
        mac = 123
        with self.assertRaises(ValueError):
            utils.generate_duid(mac)
