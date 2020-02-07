/*
 * ****************************************************
 *  Copyright (C) 2020 Scott L. Price
 *  All rights reserved.
 *
 *  2020-02-04  Initial release
 * ****************************************************
 */

package industries.sfm.customldapdatastore;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.SimpleFieldList;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;

import com.pingidentity.sources.CustomDataSourceDriver;
import com.pingidentity.sources.CustomDataSourceDriverDescriptor;
import com.pingidentity.sources.SourceDescriptor;
import com.pingidentity.sources.gui.FilterFieldsGuiDescriptor;

import com.pingidentity.access.DataSourceAccessor;
import org.sourceid.saml20.domain.datasource.info.LdapInfo;
import javax.naming.Context;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.directory.SearchControls;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * The SFMCustomLDAPDataStore class can be used to run arbitrary LDAP searches
 * against any configured LDAP data store.
 *
 * Configuration consists solely of the system ID of the LDAP data store.
 *
 * This data source uses 2 parameters at run time: base DN and LDAP filter.
 *
 * The results are a list of DNs returned in the searchResult field.
 */
public class SFMCustomLDAPDataStore implements CustomDataSourceDriver
{
    private static final String CONFIG_LDAPID = "LDAP ID";
    private static final String FILTER_BASEDN = "Base DN";
    private static final String FILTER_LDAPFILTER = "Filter";
    private static final String RESULT_FIELD = "searchResult";

    // A reference to the CustomDataSourceDriverDescriptor
    private final CustomDataSourceDriverDescriptor descriptor;

    // A list of fields that will be returned to the user, which can be selected
    // and mapped to an adapter contract.
    private static final List<String> listOfFields = new ArrayList<String>();

    static
    {
        listOfFields.add(RESULT_FIELD);
    }

    // The LDAP system ID of the data store to use
    private String ldapId;

    public SFMCustomLDAPDataStore()
    {
        // create a FilterFieldsGuiDescriptor in order to filter values from the
        // data store. The filter value can be a static string or can also
        // include values from adapters and/or policy contracts. For example:
        // (&(objectClass=group)(member:1.2.840.113556.1.4.1941:=${DN})(cn=grp-aws-*))
        FilterFieldsGuiDescriptor filterFieldsDescriptor = new FilterFieldsGuiDescriptor();
        filterFieldsDescriptor.addField(new TextFieldDescriptor(
            FILTER_BASEDN,
            "The base DN from which the search is based."));
        filterFieldsDescriptor.addField(new TextFieldDescriptor(
            FILTER_LDAPFILTER,
            "The LDAP filter to search with."));

        // create the configuration descriptor for the custom data store
        AdapterConfigurationGuiDescriptor dataStoreConfigGuiDesc = new AdapterConfigurationGuiDescriptor(
            "Configuration settings for the custom LDAP data store.");
        dataStoreConfigGuiDesc.addField(new TextFieldDescriptor(CONFIG_LDAPID,
             "The system ID of the LDAP data store to use."));

        descriptor = new CustomDataSourceDriverDescriptor(this,
            "Custom LDAP Data Store",
            dataStoreConfigGuiDesc, filterFieldsDescriptor);
    }

    /**
     * PingFederate will invoke this method on your driver to discover the
     * metadata necessary to correctly configure it. PingFederate will use this
     * information to dynamically draw a screen that will allow a user to
     * correctly configure your driver for use. <br/>
     * <br/>
     * The metadata returned by this method should be static. Allowing the same
     * driver to produce different configuration screens is not supported.
     * 
     * @return a SourceDescriptor that contains the UI information necessary to
     * display the configuration screen.
     */
    @Override
    public SourceDescriptor getSourceDescriptor()
    {
        return descriptor;
    }

    /**
     * This method is called by the PingFederate server to push configuration
     * values entered by the administrator via the dynamically rendered GUI
     * configuration screen in the PingFederate administration console. Your
     * implementation should use the {@link Configuration} parameter to
     * configure its own internal state as needed. <br/>
     * <br/>
     * Each time the PingFederate server creates a new instance of your plugin
     * implementation this method will be invoked with the proper configuration.
     * All concurrency issues are handled in the server so you don't need to
     * worry about them here. The server doesn't allow access to your plugin
     * implementation instance until after creation and configuration is
     * completed.
     * 
     * @param configuration
     *            the Configuration object constructed from the values entered
     *            by the user via the GUI.
     */
    @Override
    public void configure(Configuration configuration)
    {
        // load the data store configuration from the Configuration object
        ldapId = configuration.getFieldValue(CONFIG_LDAPID);
    }

    /**
     * This method is used to determine whether the connection managed by a
     * specific driver instance is available. This method is used by the
     * PingFederate UI prior to rendering to determine whether the driver
     * information should be editable.
     * 
     * @return true if the connection is available
     */
    @Override
    public boolean testConnection()
    {
        // Test that the LDAP data store exists
        try
        {
            DataSourceAccessor dataSourceAccessor = new DataSourceAccessor();
            LdapInfo ldapConnection = dataSourceAccessor.getLdapInfo(ldapId);
            return ldapConnection != null;
        }
        catch (Exception e)
        {
            // do nothing
        }

        return false;
    }

    /**
     * This method is called by PingFederate when a connection (either IdP or
     * SP) needs to retrieve information from the specified driver. This method
     * is expected to return a map containing the resulting values.
     * 
     * @param attributeNamesToFill
     *            An array of names to retrieve values for. In the JDBC
     *            paradigm, these would be column names.
     * @param filterConfiguration
     *            A {@link org.sourceid.saml20.adapter.conf.SimpleFieldList}
     *            list of filter criteria to use when retrieve values. May be
     *            null if no filter configuration is provided. These fields are
     *            described by the {@link CustomDataSourceDriverDescriptor}
     *            class.
     * @return A map, keyed by values from the attributeNamesToFill array, that
     *         contains values retrieved by the custom driver. If no data
     *         matches the filter criteria, then an empty Map should be
     *         returned. Null should not be returned.
     */
    @Override
    public Map<String, Object> retrieveValues(Collection<String> attributeNamesToFill,
            SimpleFieldList filterConfiguration)
    {
        String baseDn = filterConfiguration.getFieldValue(FILTER_BASEDN);
        String ldapFilter = filterConfiguration.getFieldValue(FILTER_LDAPFILTER);
        Map<String, Object> results = new HashMap<String, Object>();
        try
        {
            DataSourceAccessor dataSourceAccessor = new DataSourceAccessor();
            LdapInfo ldapConnection = dataSourceAccessor.getLdapInfo(ldapId);
            Hashtable ldapEnvironment = new Hashtable();
            ldapEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            ldapEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
            ldapEnvironment.put(Context.SECURITY_PRINCIPAL, ldapConnection.getPrincipal());
            ldapEnvironment.put(Context.SECURITY_CREDENTIALS, ldapConnection.getCredentials());
            ldapEnvironment.put(Context.PROVIDER_URL, ldapConnection.getServerUrl());
            LdapContext ldapContext = new InitialLdapContext(ldapEnvironment, null);
            SearchControls ldapSearchControls = new SearchControls();
            ldapSearchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            ldapSearchControls.setReturningAttributes(new String[0]);
            NamingEnumeration ldapSearch = ldapContext.search(baseDn, ldapFilter, ldapSearchControls);
            List<String> names = new ArrayList<String>();
            while (ldapSearch.hasMoreElements()) {
                SearchResult sr = (SearchResult) ldapSearch.next();
                if (sr != null) {
                    names.add(sr.getNameInNamespace());
                }
            }
            ldapContext.close();
            results.put(RESULT_FIELD, new AttributeValue(names));
        }
        catch (Exception e)
        {
            // Return an empty map instead of null as per the interface
            // documentation
            return new HashMap<String, Object>();
        }

        return results;
    }

    /**
     * PingFederate will take the list returned from this method, and display
     * the field names as individual checkbox items. The user can select those
     * fields for which they want values, and then map those selected fieldnames
     * against adapter contracts. During execution, the names that the user has
     * mapped will be sent to the
     * {@link #retrieveValues(Collection, SimpleFieldList)} method.
     * 
     * @return A list of available fields to display to the user.
     */
    @Override
    public List<String> getAvailableFields()
    {
        return listOfFields;
    }
}
