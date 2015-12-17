.. :changelog:

History
-------

0.2.0 (2015-12-17)
------------------
* Deprecate network_exists method in object_manager
* Add _global_field_processing for objects
* Add parsing 'extattrs' into EA objects for all InfobloxObject childs
* Add docs badge to README.rst
* Reworked get_network in object_manager
* Move _eq_ to BaseObject
* Check if fixed address is found before delete


0.1.4 (2015-12-08)
__________________
* Field updates for Member object
* Log all api calls in connector on debug level

0.1.3 (2015-12-04)
__________________
* Add 'network' field to ip versioned fields
* Skip adding DHCP options for IPv6 network
* Do not search IPRange before creating

0.1.2 (2015-12-02)
__________________
* Do not fail if object is not found on delete
* Raise exception with details if reply is not json
* Add 'silent_ssl_warnings' option to connector

0.1.1 (2015-12-01)
__________________
* Fix unbind_name_from_record_a

0.1.0 (2015-12-01)
__________________
* Add new field type '_updateable_search_field' to objects and fix HostRecord search
* Fix 'make docs'
* Update README.rst (fixed formatting)

0.0.11 (2015-11-25)
___________________
* Fix adding second ip to HostRecord
* Fix failing in pdb
* Convert EA values into boolean if possible
* Added 'ips' allias for ip field in HostRecord

0.0.10 (2015-11-19)
___________________
* Add utility to determine supported feature
* Update README.rst with objects interface

0.0.9 (2015-11-13)
__________________
* Add allowed_object_types field for EA Definition
* Allow to return default fields for object
* Update README.rst with list of supported objects

0.0.8 (2015-11-12)
___________________
* Add Extensible Attributes Definition support
* Fixed options processing for create_network in object_manager
* Fixed missed DNSZone object in create_dns_zone

0.0.7 (2015-10-27)
____________________
* Added 'network' to IPRange search fields
* Modified `get` method of the EA class to allow return default values

0.0.6 (2015-10-26)
____________________
* Added initial support of Extensible Attributes as sub objects
* Added search by Extensible Attributes
* Improved validation in connector
* Added delete_object_by_ref to object manager

0.0.5 (2015-10-12)
____________________
* Fixed issues in working with objects
* Added missed _get_object_type_from_ref
* Added code coverage
* Updated links to point to infobloxopen repository

0.0.4 (2015-09-23)
____________________
* Added object abstraction for interacting with NIOS objects
* Added object_manager to simplify some operations on objects

0.0.3 (2015-09-15)
____________________
* Added dependencies to package.


0.0.2 (2015-09-11)
____________________
* Fixed using dashes in package directory names that prevented package import after install.


0.0.1 (2015-09-11)
---------------------
* Added connector to send wapi requests to NIOS, does not includes NIOS object model at this point.
* First release on PyPI.
