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

LOG = logging.getLogger(__name__)


class EADefinitionManager(object):

    def __init__(self, connector):
        self._connector = connector

    def get_existing_ea_defs(self):
        # Sends request with Authentication Information
        self._existing_ea_defs = self._connector.get_object(
            "extensibleattributedef")

        if not self._existing_ea_defs:
            LOG.error("Cannot get EA Definitions from Grid")
        return self._existing_ea_defs

    def find_missing_ea_defs(self, target_ea_defs, existing_ea_defs=None):

        if not existing_ea_defs:
            existing_ea_defs = self._existing_ea_defs
        self._missing_ea_defs = filter(lambda x: not next(
            (y for y in existing_ea_defs if x['name'] == y['name']), None),
            target_ea_defs)
        return self._missing_ea_defs

    def create_ea_def(self, ea_def):
        obj = self._connector.create_object(
            "extensibleattributedef", ea_def)
        if not obj:
            LOG.error(
                "Cannot create EA Definition '%s'." % ea_def)
            return False
        LOG.info(
            "EA Definition '%s' successfully created." % ea_def)
        return True

    def create_missing_ea_defs(self, missing_ea_defs=None):
        if not missing_ea_defs:
            missing_ea_defs = self._missing_ea_defs

        ea_defs_created = []
        for ea_def in missing_ea_defs:
            if self.create_ea_def(ea_def):
                ea_defs_created.append(ea_def)
        return ea_defs_created
