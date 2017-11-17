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


class BaseExc(Exception):
    """Base Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = "An unknown exception occurred."

    def __init__(self, **kwargs):
        super(BaseExc, self).__init__(self.message % kwargs)
        self.msg = self.message % kwargs


class InfobloxException(BaseExc):
    """Generic Infoblox Exception."""
    def __init__(self, response, **kwargs):
        self.response = response
        super(InfobloxException, self).__init__(**kwargs)


class InfobloxSearchError(InfobloxException):
    message = ("Cannot search '%(obj_type)s' object(s): "
               "%(content)s [code %(code)s]")


class InfobloxCannotCreateObject(InfobloxException):
    message = ("Cannot create '%(obj_type)s' object(s): "
               "%(content)s [code %(code)s]")


class InfobloxMemberAlreadyAssigned(InfobloxCannotCreateObject):
    pass


class InfobloxCannotDeleteObject(InfobloxException):
    message = ("Cannot delete object with ref %(ref)s: "
               "%(content)s [code %(code)s]")


class InfobloxCannotUpdateObject(InfobloxException):
    message = ("Cannot update object with ref %(ref)s: "
               "%(content)s [code %(code)s]")


class InfobloxFuncException(InfobloxException):
    message = ("Error occurred during function's '%(func_name)s' call: "
               "ref %(ref)s: %(content)s [code %(code)s]")


class InfobloxHostRecordIpAddrNotCreated(BaseExc):
    message = ("Infoblox host record ipv4addr/ipv6addr has not been "
               "created for IP %(ip)s, mac %(mac)s")


class InfobloxCannotAllocateIp(BaseExc):
    message = ("Cannot allocate IP %(ip_data)s")


class InfobloxDidNotReturnCreatedIPBack(BaseExc):
    message = ("Infoblox did not return created IP back")


class InfobloxNetworkNotAvailable(BaseExc):
    message = ("No network view %(network_view)s for %(cidr)s")


class InfobloxObjectParsingError(BaseExc):
    message = ("Infoblox object cannot be parsed from dict: %(data)s")


class HostRecordNotPresent(InfobloxObjectParsingError):
    message = ("Cannot parse Host Record object from dict because "
               "'ipv4addrs'/'ipv6addrs' is absent.")


class InfobloxInvalidIp(InfobloxObjectParsingError):
    message = ("Bad IP address: %(ip)s")


class InfobloxConnectionError(BaseExc):
    message = ("Infoblox HTTP request failed with: %(reason)s")


class InfobloxConfigException(BaseExc):
    """Generic Infoblox Config Exception."""
    message = ("Config error: %(msg)s")


class InfobloxBadWAPICredential(InfobloxException):
    message = ("Infoblox IPAM is misconfigured: "
               "infoblox_username and infoblox_password are incorrect.")


class InfobloxTimeoutError(InfobloxException):
    message = ("Connection to NIOS timed out")


class InfobloxGridTemporaryUnavailable(InfobloxException):
    message = ("Cannot perform operation %(operation)s with ref %(ref)s: "
               "%(content)s [code %(code)s]")
