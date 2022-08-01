from collections import deque

from infoblox_client.connector import Connector


class E2EConnectorFacade(Connector):
    """
    Connector class facade for end-to-end tests.

    This facade will remember all created objects, and then sweep those objects
    after the test is done.
    """

    def __init__(self, options):
        self.__delete_queue = deque()
        super(E2EConnectorFacade, self).__init__(options)

    def create_object(self, obj_type, payload, return_fields=None):
        resp = super(E2EConnectorFacade, self).create_object(obj_type,
                                                             payload,
                                                             return_fields)
        self.__delete_queue.append(resp['_ref'])
        return resp

    def update_object(self, ref, payload, return_fields=None):
        new_obj = super(E2EConnectorFacade, self).update_object(ref,
                                                                payload,
                                                                return_fields)
        self.__delete_queue.remove(ref)
        self.__delete_queue.append(new_obj["_ref"])
        return new_obj

    def delete_object(self, ref, delete_arguments=None):
        self.__delete_queue.remove(ref)
        return super(E2EConnectorFacade, self).delete_object(ref,
                                                             delete_arguments)

    def sweep_objects(self):
        """
        Sweep all objects created by the connector.
        """
        while self.__delete_queue:
            super(E2EConnectorFacade, self).delete_object(
                self.__delete_queue.pop()
            )
