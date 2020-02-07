# sfm-custom-ldap-data-store
Built according to the [PingFederate SDK](https://www.pingidentity.com/content/dam/developer/documentation/pingfederate/server-sdk/9.2/doc/overview-summary.html), the `SFMCustomLDAPDataStore` class can be used to run arbitrary LDAP searches against any configured LDAP data store in [PingFederate](https://www.pingidentity.com/en/software/pingfederate.html). The class was written because the built-in support for nested groups can take a long time to run if the directory has a large number of groups, leading to LDAP timeouts. With this, the LDAP filter an be optimized for better performance.

Configuration consists solely of the system ID of the LDAP data store.

This data source uses 2 parameters at run time: base DN and LDAP filter.

The filter value can include values from adapters and/or policy contracts. For example:

    (&(objectClass=group)(member:1.2.840.113556.1.4.1941:=${DN})(cn=grp-aws-*))

The result is a list of DNs returned in the searchResult field.
