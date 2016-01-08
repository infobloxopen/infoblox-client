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
import mock

from infoblox_client import feature


class TestFeature(unittest.TestCase):

    def test_wapi_version_util(self):
        wapi1 = feature.WapiVersionUtil('2.3')
        self.assertEqual(2, wapi1.major_version)
        self.assertEqual(3, wapi1.minor_version)
        self.assertEqual(None, wapi1.patch_version)

        wapi2 = feature.WapiVersionUtil('2.2.3')
        self.assertEqual(2, wapi2.major_version)
        self.assertEqual(2, wapi2.minor_version)
        self.assertEqual(3, wapi2.patch_version)

        wapi3 = feature.WapiVersionUtil('2.2')
        self.assertEqual(True, wapi3.is_version_supported('2.1'))
        self.assertEqual(True, wapi3.is_version_supported('1.3'))
        self.assertEqual(True, wapi3.is_version_supported('2.2'))
        self.assertEqual(False, wapi3.is_version_supported('2.3'))
        self.assertEqual(False, wapi3.is_version_supported('3.1'))
        self.assertEqual(False, wapi3.is_version_supported('2.2.1'))

        wapi3 = feature.WapiVersionUtil('2.3.4')
        self.assertEqual(True, wapi3.is_version_supported('2.1'))
        self.assertEqual(True, wapi3.is_version_supported('1.5'))
        self.assertEqual(True, wapi3.is_version_supported('2.3'))
        self.assertEqual(True, wapi3.is_version_supported('2.3.3'))
        self.assertEqual(True, wapi3.is_version_supported('2.3.4'))
        self.assertEqual(False, wapi3.is_version_supported('2.4'))
        self.assertEqual(False, wapi3.is_version_supported('3.1'))
        self.assertEqual(False, wapi3.is_version_supported('2.3.5'))

        self.assertRaises(ValueError, feature.WapiVersionUtil, ' ')
        self.assertRaises(ValueError, feature.WapiVersionUtil, '2.')
        self.assertRaises(ValueError, feature.WapiVersionUtil, '.')
        self.assertRaises(ValueError, feature.WapiVersionUtil, '.2')
        self.assertRaises(ValueError, feature.WapiVersionUtil, '1.2.3.4')

    def test_features(self):
        feature_versions = {
            'ea_def_creation': '2.2',
            'cloud_api': '2.0',
            'enable_member_dns': '2.2.1'}

        my_feature1 = feature.Feature('2.2', feature_versions)
        self.assertEqual(True, my_feature1.ea_def_creation)
        self.assertEqual(True, my_feature1.cloud_api)
        self.assertEqual(False, my_feature1.enable_member_dns)

        my_feature2 = feature.Feature('2.0', feature_versions)
        self.assertEqual(False, my_feature2.ea_def_creation)
        self.assertEqual(True, my_feature2.cloud_api)
        self.assertEqual(False, my_feature2.enable_member_dns)

        my_feature3 = feature.Feature('1.6', feature_versions)
        self.assertEqual(False, my_feature3.ea_def_creation)
        self.assertEqual(False, my_feature3.cloud_api)
        self.assertEqual(False, my_feature3.enable_member_dns)

        my_feature4 = feature.Feature('2.2.2', feature_versions)
        self.assertEqual(True, my_feature4.ea_def_creation)
        self.assertEqual(True, my_feature4.cloud_api)
        self.assertEqual(True, my_feature4.enable_member_dns)

        my_feature5 = feature.Feature('2.2.0', feature_versions)
        self.assertEqual(True, my_feature5.ea_def_creation)
        self.assertEqual(True, my_feature5.cloud_api)
        self.assertEqual(False, my_feature5.enable_member_dns)

        my_feature6 = feature.Feature('2.2.1', feature_versions)
        self.assertEqual(True, my_feature6.ea_def_creation)
        self.assertEqual(True, my_feature6.cloud_api)
        self.assertEqual(True, my_feature6.enable_member_dns)

    def _mock_connector(self, wapi_version):
        connector = mock.Mock(wapi_version=wapi_version)
        return connector

    def test_features_with_connector(self):
        feature_versions = {
            'ea_def_creation': '2.2',
            'cloud_api': '2.0',
            'enable_member_dns': '2.2.1'}

        connector1 = self._mock_connector('2.2')
        my_feature1 = feature.Feature(connector1, feature_versions)
        self.assertEqual(True, my_feature1.ea_def_creation)
        self.assertEqual(True, my_feature1.cloud_api)
        self.assertEqual(False, my_feature1.enable_member_dns)

        connector2 = self._mock_connector('2.0')
        my_feature2 = feature.Feature(connector2, feature_versions)
        self.assertEqual(False, my_feature2.ea_def_creation)
        self.assertEqual(True, my_feature2.cloud_api)
        self.assertEqual(False, my_feature2.enable_member_dns)

        connector3 = self._mock_connector('1.6')
        my_feature3 = feature.Feature(connector3, feature_versions)
        self.assertEqual(False, my_feature3.ea_def_creation)
        self.assertEqual(False, my_feature3.cloud_api)
        self.assertEqual(False, my_feature3.enable_member_dns)

        connector4 = self._mock_connector('2.2.2')
        my_feature4 = feature.Feature(connector4, feature_versions)
        self.assertEqual(True, my_feature4.ea_def_creation)
        self.assertEqual(True, my_feature4.cloud_api)
        self.assertEqual(True, my_feature4.enable_member_dns)

        connector5 = self._mock_connector('2.2.0')
        my_feature5 = feature.Feature(connector5, feature_versions)
        self.assertEqual(True, my_feature5.ea_def_creation)
        self.assertEqual(True, my_feature5.cloud_api)
        self.assertEqual(False, my_feature5.enable_member_dns)

        connector6 = self._mock_connector('2.2.1')
        my_feature6 = feature.Feature(connector6, feature_versions)
        self.assertEqual(True, my_feature6.ea_def_creation)
        self.assertEqual(True, my_feature6.cloud_api)
        self.assertEqual(True, my_feature6.enable_member_dns)
