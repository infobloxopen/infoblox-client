=========
Examples
=========

Retrieve list of all networks from NIOS page by page
-----------------------------------------------------

.. code:: python
  
    from infoblox_client import connector, objects, exceptions
    def main():
        try:
            def default_infoblox_connection():
                opts = {'host': '10.197.36.2', 'username': 'admin', 'password': 'admin'}
                conn = connector.Connector(opts)
                return conn
        
            def paging(conn, max_results):
                # search all networks in default view 
                response= objects.Network.search_all(conn, view='default', paging=True, return_fields=['members'])
                i=0
                while i<len(response):
                    yield (response[i:i+max_results])
                    i =i+max_results

            connection = default_infoblox_connection()
            op=paging(connection,max_results=2)
            print(next(op))
            print(next(op))
            print(next(op))
            print(next(op))
        except exceptions.InfobloxConnectionError as e:
            status_code = e.kwargs["reason"].response.status_code
            if status_code == 404:
                print("Not Found!", status_code)
            if status_code == 500:
                print("Internal Server Error", status_code)
        except StopIteration:
            print("No more records")


For above example request output will be displayed as:

.. code:: python
    
    [NetworkV4: members="[]", _ref="network/ZG5zLm5ldHdvcmskNDMuMC4wLjAvMjQvMA:43.0.0.0/24/default", NetworkV4: members="[]", _ref="network/ZG5zLm5ldHdvcmskMjcuMC4wLjAvMjQvMA:27.0.0.0/24/default"]
    
    [NetworkV4: members="[]", _ref="network/ZG5zLm5ldHdvcmskNjguMC4yLjAvMjQvMA:68.0.2.0/24/default", NetworkV4: members="[]", _ref="network/ZG5zLm5ldHdvcmskMTQuMi4wLjAvMjQvMA:14.2.0.0/24/default"]
    
    [NetworkV4: members="[]", _ref="network/ZG5zLm5ldHdvcmskMTkuMC4yMi4wLzI0LzA:19.0.22.0/24/default"]
    
    No more records
