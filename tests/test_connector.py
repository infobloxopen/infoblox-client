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
import requests
from mock import patch
from requests import exceptions as req_exc

from oslo_serialization import jsonutils

from infoblox_client import connector
from infoblox_client import exceptions


class TestInfobloxConnector(unittest.TestCase):
    def setUp(self):
        super(TestInfobloxConnector, self).setUp()

        self.default_opts = self._prepare_options()
        self.connector = connector.Connector(self.default_opts)

    @staticmethod
    def _prepare_options():
        opts = mock.Mock()
        opts.host = 'infoblox.example.org'
        opts.wapi_version = '1.1'
        opts.username = 'admin'
        opts.password = 'password'
        opts.ssl_verify = False
        opts.silent_ssl_warnings = True
        opts.http_pool_connections = 10
        opts.http_pool_maxsize = 10
        opts.http_request_timeout = 10
        opts.max_retries = 3
        opts.max_results = None
        return opts

    def test_create_object(self):
        objtype = 'network'
        payload = {'ip': '0.0.0.0'}

        with patch.object(requests.Session, 'post',
                          return_value=mock.Mock()) as patched_create:
            patched_create.return_value.status_code = 201
            patched_create.return_value.content = '{}'
            self.connector.create_object(objtype, payload)
            patched_create.assert_called_once_with(
                'https://infoblox.example.org/wapi/v1.1/network',
                data=jsonutils.dumps(payload),
                headers=self.connector.DEFAULT_HEADER,
                timeout=self.default_opts.http_request_timeout,
            )

    def test_create_object_with_extattrs(self):
        objtype = 'network'
        payload = {'extattrs': {'Subnet ID': {'value': 'fake_subnet_id'}},
                   'ip': '0.0.0.0'}
        with patch.object(requests.Session, 'post',
                          return_value=mock.Mock()) as patched_create:
            patched_create.return_value.status_code = 201
            patched_create.return_value.content = '{}'
            self.connector.create_object(objtype, payload)
            patched_create.assert_called_once_with(
                'https://infoblox.example.org/wapi/v1.1/network',
                data=jsonutils.dumps(payload),
                headers=self.connector.DEFAULT_HEADER,
                timeout=self.default_opts.http_request_timeout,
            )

    def test_create_object_raises_member_assigned(self):
        nios_error = (
            '{ "Error": "AdmConDataError: None (IBDataConflictError:'
            'IB.Data.Conflict:Member 10.39.12.91 is assigned to another '
            'network view \'test2\')",'
            '"code": "Client.Ibap.Data.Conflict",'
            '"text": "Member 10.39.12.91 is assigned to another '
            'network view \'test2\'"}')
        with patch.object(requests.Session, 'post',
                          return_value=mock.Mock()) as patched_create:
            patched_create.return_value.status_code = 400
            patched_create.return_value.content = nios_error
            self.assertRaises(exceptions.InfobloxMemberAlreadyAssigned,
                              self.connector.create_object,
                              'network', {'network': '192.178.1.0/24'})

    def test_get_object(self):
        objtype = 'network'
        payload = {'ip': '0.0.0.0'}

        with patch.object(requests.Session, 'get',
                          return_value=mock.Mock()) as patched_get:
            patched_get.return_value.status_code = 200
            patched_get.return_value.content = '{}'
            self.connector.get_object(objtype, payload)
            patched_get.assert_called_once_with(
                'https://infoblox.example.org/wapi/v1.1/network?ip=0.0.0.0',
                headers=self.connector.DEFAULT_HEADER,
                timeout=self.default_opts.http_request_timeout,
            )

    def test_get_objects_with_extattrs(self):
        objtype = 'network'
        payload = {'ip': '0.0.0.0'}
        extattrs = {
            'Subnet ID': {'value': 'fake_subnet_id'}
        }
        with patch.object(requests.Session, 'get',
                          return_value=mock.Mock()) as patched_get:
            patched_get.return_value.status_code = 200
            patched_get.return_value.content = '{}'
            self.connector.get_object(objtype, payload, extattrs=extattrs)
            patched_get.assert_called_once_with(
                'https://infoblox.example.org/wapi/'
                'v1.1/network?*Subnet ID=fake_subnet_id&ip=0.0.0.0',
                headers=self.connector.DEFAULT_HEADER,
                timeout=self.default_opts.http_request_timeout,
            )

    def test_get_objects_with_max_results(self):
        objtype = 'network'
        with patch.object(requests.Session, 'get',
                          return_value=mock.Mock()) as patched_get:
            patched_get.return_value.status_code = 200
            patched_get.return_value.content = '{}'
            self.connector.get_object(objtype, {}, max_results=20)
            patched_get.assert_called_once_with(
                'https://infoblox.example.org/wapi/'
                'v1.1/network?_max_results=20',
                headers=self.connector.DEFAULT_HEADER,
                timeout=self.default_opts.http_request_timeout,
            )

    def test_get_objects_with_max_results_as_connector_opt(self):
        objtype = 'network'
        with patch.object(requests.Session, 'get',
                          return_value=mock.Mock()) as patched_get:
            patched_get.return_value.status_code = 200
            patched_get.return_value.content = '{}'

            opts = self._prepare_options()
            opts.max_results = 10
            conn = connector.Connector(opts)
            conn.get_object(objtype, {})
            patched_get.assert_called_once_with(
                'https://infoblox.example.org/wapi/'
                'v1.1/network?_max_results=10',
                headers=self.connector.DEFAULT_HEADER,
                timeout=self.default_opts.http_request_timeout,
            )

    def test_max_results_priority(self):
        objtype = 'network'
        with patch.object(requests.Session, 'get',
                          return_value=mock.Mock()) as patched_get:
            patched_get.return_value.status_code = 200
            patched_get.return_value.content = '{}'

            opts = self._prepare_options()
            opts.max_results = 10
            conn = connector.Connector(opts)
            # max_results passed to get_object should have higher priority
            # over max_results connector option
            conn.get_object(objtype, {}, max_results=-20)
            patched_get.assert_called_once_with(
                'https://infoblox.example.org/wapi/'
                'v1.1/network?_max_results=-20',
                headers=self.connector.DEFAULT_HEADER,
                timeout=self.default_opts.http_request_timeout,
            )

    def test_update_object(self):
        ref = 'network'
        payload = {'ip': '0.0.0.0'}

        with patch.object(requests.Session, 'put',
                          return_value=mock.Mock()) as patched_update:
            patched_update.return_value.status_code = 200
            patched_update.return_value.content = '{}'
            self.connector.update_object(ref, payload)
            patched_update.assert_called_once_with(
                'https://infoblox.example.org/wapi/v1.1/network',
                data=jsonutils.dumps(payload),
                headers=self.connector.DEFAULT_HEADER,
                timeout=self.default_opts.http_request_timeout,
            )

    def test_delete_object(self):
        ref = 'network'
        with patch.object(requests.Session, 'delete',
                          return_value=mock.Mock()) as patched_delete:
            patched_delete.return_value.status_code = 200
            patched_delete.return_value.content = '{}'
            self.connector.delete_object(ref)
            patched_delete.assert_called_once_with(
                'https://infoblox.example.org/wapi/v1.1/network',
                headers=self.connector.DEFAULT_HEADER,
                timeout=self.default_opts.http_request_timeout,
            )

    def test_construct_url_absolute_path_fails(self):
        pathes = ('/starts_with_slash', '', None)
        for path in pathes:
            self.assertRaises(ValueError,
                              self.connector._construct_url, path)

    def test_construct_url_with_query_params_and_extattrs(self):
        query_params = {'some_option': 'some_value'}
        ext_attrs = {'Subnet ID': {'value': 'fake_subnet_id'}}
        url = self.connector._construct_url('network',
                                            query_params=query_params,
                                            extattrs=ext_attrs)
        self.assertEqual('https://infoblox.example.org/wapi/v1.1/network?'
                         '*Subnet ID=fake_subnet_id&some_option=some_value',
                         url)

    def test_construct_url_with_force_proxy(self):
        ext_attrs = {'Subnet ID': {'value': 'fake_subnet_id'}}
        url = self.connector._construct_url('network',
                                            extattrs=ext_attrs,
                                            force_proxy=True)
        self.assertEqual('https://infoblox.example.org/wapi/v1.1/network?'
                         '*Subnet ID=fake_subnet_id&_proxy_search=GM',
                         url)

    def test_get_object_with_proxy_flag(self):
        self.connector._get_object = mock.MagicMock(return_value=False)
        self.connector._construct_url = mock.MagicMock()
        self.connector.cloud_api_enabled = True

        result = self.connector.get_object('network', force_proxy=True)

        self.assertEqual(None, result)
        self.connector._construct_url.assert_called_with('network', {},
                                                         None, True)
        self.connector._get_object.called_with('network',
                                               self.connector._construct_url)

    def test_get_object_without_proxy_flag(self):
        self.connector._get_object = mock.MagicMock(return_value=False)
        self.connector._construct_url = mock.MagicMock()
        self.connector.cloud_api_enabled = True

        result = self.connector.get_object('network')

        self.assertEqual(None, result)
        construct_calls = [mock.call('network', {}, None, False),
                           mock.call('network', {}, None, force_proxy=True)]
        self.connector._construct_url.assert_has_calls(construct_calls)

    def test__get_object_search_error_return_none(self):
        response = mock.Mock()
        response.status_code = '404'
        response.content = 'Object not found'
        self.connector.session = mock.Mock()
        self.connector.session.get.return_value = response

        url = 'http://some-url/'
        self.assertEqual(None, self.connector._get_object('network', url))


class TestInfobloxConnectorStaticMethods(unittest.TestCase):
    def test_neutron_exception_is_raised_on_any_request_error(self):
        # timeout exception raises InfobloxTimeoutError
        f = mock.Mock()
        f.__name__ = 'mock'
        f.side_effect = req_exc.Timeout
        self.assertRaises(exceptions.InfobloxTimeoutError,
                          connector.reraise_neutron_exception(f))

        # all other request exception raises InfobloxConnectionError
        supported_exceptions = [req_exc.HTTPError,
                                req_exc.ConnectionError,
                                req_exc.ProxyError,
                                req_exc.SSLError,
                                req_exc.TooManyRedirects,
                                req_exc.InvalidURL]

        for ex in supported_exceptions:
            f.side_effect = ex
            self.assertRaises(exceptions.InfobloxConnectionError,
                              connector.reraise_neutron_exception(f))

    def test_exception_raised_for_non_authorized(self):
        response = mock.Mock()
        response.status_code = requests.codes.UNAUTHORIZED
        self.assertRaises(exceptions.InfobloxBadWAPICredential,
                          connector.Connector._validate_authorized,
                          response)

    def test_no_exceptions_for_ok_statuses(self):
        response = mock.Mock()
        ok_statuses = (requests.codes.OK,
                       requests.codes.CREATED,
                       requests.codes.ACCEPTED)
        for status_code in ok_statuses:
            response.status_code = status_code
            connector.Connector._validate_authorized(response)

    def test_non_cloud_api_detection(self):
        wapi_not_cloud = ('1.4.1', '1.9/', '1.99', 'asd', 'v1.4')
        for url in wapi_not_cloud:
            self.assertFalse(connector.Connector.is_cloud_wapi(url))

    def test_cloud_api_detection(self):
        wapi_cloud = ('2.1/', '/2.0/', '2.0.1',
                      '3.0/', '11.0.1/', 'v2.1', 'v2.0')
        for url in wapi_cloud:
            self.assertTrue(connector.Connector.is_cloud_wapi(url))

    def test_allow_options_as_dict(self):
        opts = dict(host='infoblox.example.org',
                    wapi_version='1.1',
                    username='admin',
                    password='password',
                    ssl_verify=False,
                    silent_ssl_warnings=True,
                    max_results=50,
                    http_pool_connections=10,
                    http_pool_maxsize=10,
                    http_request_timeout=10)
        conn = connector.Connector(opts)
        self.assertEqual(opts['host'], conn.host)
        self.assertEqual(opts['wapi_version'], conn.wapi_version)
        self.assertEqual(opts['username'], conn.username)
        self.assertEqual(opts['password'], conn.password)
        self.assertEqual(opts['ssl_verify'], conn.ssl_verify)
        self.assertEqual(opts['silent_ssl_warnings'],
                         conn.silent_ssl_warnings)
        self.assertEqual(opts['max_results'],
                         conn.max_results)
        self.assertEqual(opts['http_pool_connections'],
                         conn.http_pool_connections)
        self.assertEqual(opts['http_pool_maxsize'], conn.http_pool_maxsize)
        self.assertEqual(opts['http_request_timeout'],
                         conn.http_request_timeout)

    def test_incomplete_options_raises_exception(self):
        opts = dict(host='infoblox.example.org',
                    wapi_version='1.1')
        self.assertRaises(exceptions.InfobloxConfigException,
                          connector.Connector, opts)

    def test_default_options(self):
        opts = dict(host='infoblox.example.org',
                    username='admin',
                    password='password')
        conn = connector.Connector(opts)
        self.assertEqual(False, conn.ssl_verify)
        self.assertEqual(False, conn.silent_ssl_warnings)
        self.assertEqual(10, conn.http_request_timeout)
        self.assertEqual(10, conn.http_pool_connections)
        self.assertEqual(10, conn.http_pool_maxsize)
        self.assertEqual(3, conn.max_retries)
        self.assertEqual('1.4', conn.wapi_version)
        self.assertEqual(None, conn.max_results)

    def test_blank_values_not_allowed(self):
        base_dict = {'host': '192.168.1.15',
                     'username': 'admin',
                     'password': 'pass'}
        for field in base_dict:
            test_dict = base_dict.copy()
            test_dict[field] = None
            self.assertRaises(exceptions.InfobloxConfigException,
                              connector.Connector, test_dict)

    def test_is_cloud_wapi_raises_exception(self):
        for value in (None, '', 0, 1, self, 1.2):
            self.assertRaises(ValueError,
                              connector.Connector.is_cloud_wapi,
                              value)

    def test__parse_reply_raises_connection_error(self):
        request = mock.Mock()
        request.content = ('<HTML><BODY BGCOLOR="FFFFFF">'
                           'Some error reply</BODY></HTML>\n')
        self.assertRaises(exceptions.InfobloxConnectionError,
                          connector.Connector._parse_reply,
                          request)

    def test__parse_reply(self):
        request = mock.Mock()
        request.content = (
            '[{"_ref": "network/ZG5zLm5ldHdvcmskMTAuNDAuMjUuMC8yNC8w:'
            '10.40.25.0/24/default","network": "10.40.25.0/24",'
            '"network_view": "default"}]')
        expected_reply = [
            {'_ref': "network/ZG5zLm5ldHdvcmskMTAuNDAuMjUuMC8yNC8w"
                     ":10.40.25.0/24/default",
             'network': "10.40.25.0/24",
             'network_view': "default"}]

        parsed_reply = connector.Connector._parse_reply(request)
        self.assertEqual(expected_reply, parsed_reply)
