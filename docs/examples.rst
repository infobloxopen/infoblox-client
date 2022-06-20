=========
Examples
=========

Print WAPI response page by page
--------------------------------

If you want to print WAPI response page by page, please use the :meth:`~infoblox_client.utils.paging` helper
function as described in the following example:

.. code:: python

    from infoblox_client import connector, objects, utils

    opts = {'host': '192.168.1.10', 'username': 'admin', 'password': 'admin'}
    conn = connector.Connector(opts)

    resp = objects.DNSZone.search_all(conn, view='default', paging=True)

    for page in utils.paging(resp, max_results=2):
        print(page)
        input("Press enter to read more...")


