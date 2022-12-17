package com.mycompany.app;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.NoVerificationTrustManager;

import java.io.Console;
import java.util.*;

public class App
{
    public static final String windowsAdUserDoesNotExistErrorCode = "data 2030";

    @Getter
    @Setter
    @AllArgsConstructor
    public static class LdapConfiguration {
        String ldapUrl;
        Integer ldapPort;
        String ldapBaseDN;
        String ldapCustomerUUID;
        String ldapDnPrefix;
        boolean ldapUseSsl;
        boolean ldapUseTls;
        boolean useLdapSearchAndBind;
        String serviceAccountUserName;
        String serviceAccountPassword;
        String ldapSearchAttribute;
        boolean enableDetailedLogs;
    }

    public static String getPassword(Scanner sc) {

        String password;
        Console console = System.console();
        if (console == null) {
            System.out.print("Enter password: ");
            password = sc.nextLine();
        } else {
            password = String.valueOf(console.readPassword("Enter password: "));
        }
        return password;
    }

    public static void main( String[] args ) {
        System.out.println("Test LDAP Client Program");

        Scanner sc= new Scanner(System.in);
        System.out.print("Enter email: ");
        String email = sc.nextLine();
        String password = getPassword(sc);
        System.out.print("Enter LDAP host name: ");
        String ldapUrl = sc.nextLine();
        System.out.print("Enter LDAP port: ");
        String port = sc.nextLine();
        Integer ldapPort = Integer.parseInt(port);
        System.out.print("Use LDAPS: ");
        String ssl = sc.nextLine();
        boolean ldapUseSsl = ssl.equals("true");
        System.out.print("Use startTls: ");
        String tls = sc.nextLine();
        boolean ldapUseTls = tls.equals("true");
        System.out.print("Use search and bind: ");
        String searchBind = sc.nextLine();
        boolean useLdapSearchAndBind = searchBind.equals("true");
        System.out.print("Enter service account username: ");
        String serviceAccountUserName = sc.nextLine();
        System.out.println("Enter service account password: ");
        String serviceAccountPassword = getPassword(sc);
        System.out.print("Enter LDAP search attribute ");
        String ldapSearchAttribute = sc.nextLine();

        System.out.print("Enter LDAP Base DN: ");
        String ldapBaseDN = sc.nextLine();

        String ldapCustomerUUID = "";
        String ldapDnPrefix = "CN=";
        boolean enabledDetailedLogs = true;

        LdapConfiguration ldapConfiguration =
                new LdapConfiguration(
                        ldapUrl,
                        ldapPort,
                        ldapBaseDN,
                        ldapCustomerUUID,
                        ldapDnPrefix,
                        ldapUseSsl,
                        ldapUseTls,
                        useLdapSearchAndBind,
                        serviceAccountUserName,
                        serviceAccountPassword,
                        ldapSearchAttribute,
                        enabledDetailedLogs);
        try {
        authViaLDAP(email, password, ldapConfiguration); } catch (Exception e) {
            System.out.println("Failed authenticating via LDAP");
        }
    }

    private static void deleteUserAndThrowException(String email) {
        String errorMessage = "LDAP user " + email + " does not exist on the LDAP server";
        throw new RuntimeException(errorMessage);
    }

    public static void authViaLDAP(String email, String password, LdapConfiguration ldapConfiguration)
            throws LdapException {
        LdapNetworkConnection connection = null;
        try {
            LdapConnectionConfig config = new LdapConnectionConfig();
            config.setLdapHost(ldapConfiguration.getLdapUrl());
            config.setLdapPort(ldapConfiguration.getLdapPort());
            if (ldapConfiguration.isLdapUseSsl() || ldapConfiguration.isLdapUseTls()) {
                config.setTrustManagers(new NoVerificationTrustManager());
                if (ldapConfiguration.isLdapUseSsl()) {
                    config.setUseSsl(true);
                } else {
                    config.setUseTls(true);
                }
            }

            String distinguishedName =
                    ldapConfiguration.getLdapDnPrefix() + email + "," + ldapConfiguration.getLdapBaseDN();
            connection = createNewLdapConnection(config);

            String role = "";
            if (ldapConfiguration.isUseLdapSearchAndBind()) {
                if (ldapConfiguration.getServiceAccountUserName().isEmpty()
                        || ldapConfiguration.getServiceAccountPassword().isEmpty()
                        || ldapConfiguration.getLdapSearchAttribute().isEmpty()) {
                    throw new RuntimeException(
                            "Service account and LDAP Search Attribute must be configured"
                                    + " to use search and bind.");
                }
                Pair<String, String> dnAndRole =
                        searchAndBind(
                                email, ldapConfiguration, connection, ldapConfiguration.isEnableDetailedLogs());
                String fetchedDistinguishedName = dnAndRole.getKey();
                if (!fetchedDistinguishedName.isEmpty()) {
                    distinguishedName = fetchedDistinguishedName;
                }
                role = dnAndRole.getValue();
            }

            email = email.toLowerCase();
            try {
                connection.bind(distinguishedName, password);
            } catch (LdapNoSuchObjectException e) {
                System.out.println(e.getMessage());
                deleteUserAndThrowException(email);
            } catch (LdapAuthenticationException e) {
                if (e.getMessage().contains(windowsAdUserDoesNotExistErrorCode)) {
                    deleteUserAndThrowException(email);
                }
                String errorMessage = "Failed with " + e.getMessage();
                System.out.println(errorMessage);
                throw new RuntimeException(errorMessage);
            }

            if (role.isEmpty() && !ldapConfiguration.isUseLdapSearchAndBind()) {
                if (!ldapConfiguration.getServiceAccountUserName().isEmpty()
                        && !ldapConfiguration.getServiceAccountPassword().isEmpty()) {
                    connection.unBind();
                    String serviceAccountDistinguishedName =
                            ldapConfiguration.getLdapDnPrefix()
                                    + ldapConfiguration.getServiceAccountUserName()
                                    + ","
                                    + ldapConfiguration.getLdapBaseDN();
                    try {
                        connection.bind(
                                serviceAccountDistinguishedName, ldapConfiguration.getServiceAccountPassword());
                    } catch (LdapAuthenticationException e) {
                        String errorMessage =
                                "Service Account bind failed. "
                                        + "Defaulting to current user connection with LDAP Server."
                                        + e.getMessage();
                        System.out.println(errorMessage);
                        connection.bind(distinguishedName, password);
                    }
                }

                try {
                    EntryCursor cursor =
                            connection.search(distinguishedName, "(objectclass=*)", SearchScope.SUBTREE, "*");
                    while (cursor.next()) {
                        Entry entry = cursor.get();
                        Attribute parseRole = entry.get("yugabytePlatformRole");
                        role = parseRole.getString();
                    }
                } catch (Exception e) {
                    System.out.printf(
                            "LDAP query failed with {} Defaulting to ReadOnly role. %s%n", e.getMessage());
                }
            }

            System.out.println("Authentication successful");
            System.out.println("Successfully signed in as = " + distinguishedName);


        } catch (LdapException e) {
            System.out.printf("LDAP error while attempting to auth email %s", email);
            String errorMessage = "LDAP parameters are not configured correctly. " + e.getMessage();
            System.out.println("errorMessage = " + errorMessage);
            throw new RuntimeException(errorMessage);
        } catch (Exception e) {
            System.out.printf("LDAP error while attempting to auth email %s", email);
            System.out.println(e.getMessage());
            String errorMessage = "Invalid LDAP credentials. " + e.getMessage();
            throw new RuntimeException(errorMessage);
        } finally {
            if (connection != null) {
                connection.unBind();
                connection.close();
            }
        }
    }

    public static LdapNetworkConnection createNewLdapConnection(LdapConnectionConfig ldapConnectionConfig) {
        return new LdapNetworkConnection(ldapConnectionConfig);
    }

    private static Pair<String, String> searchAndBind(
            String email,
            LdapConfiguration ldapConfiguration,
            LdapNetworkConnection connection,
            boolean enableDetailedLogs)
            throws Exception {
        String distinguishedName = "", role = "";
        String serviceAccountDistinguishedName =
                ldapConfiguration.getLdapDnPrefix()
                        + ldapConfiguration.getServiceAccountUserName()
                        + ","
                        + ldapConfiguration.getLdapBaseDN();
        try {
            connection.bind(
                    serviceAccountDistinguishedName, ldapConfiguration.getServiceAccountPassword());
        } catch (LdapAuthenticationException e) {
            String errorMessage = "Service Account bind failed. " + e.getMessage();
            System.out.println(errorMessage);
            e.printStackTrace();
            throw e;
        }
        try {
            EntryCursor cursor =
                    connection.search(
                            ldapConfiguration.getLdapBaseDN(),
                            "(" + ldapConfiguration.getLdapSearchAttribute() + "=" + email + ")",
                            SearchScope.SUBTREE,
                            "*");
            System.out.println("cursor = " + cursor);
            while (cursor.next()) {
                Entry entry = cursor.get();
                if (enableDetailedLogs) {
                    System.out.println("LDAP server returned response: " + entry);
                }
                Attribute parseDn = entry.get("distinguishedName");
                System.out.println("parseDn = " + parseDn);
                if (parseDn == null) {
                    distinguishedName = entry.getDn().toString();
                    System.out.println("parsedDn = " + distinguishedName);
                } else {
                    distinguishedName = parseDn.getString();
                }
                System.out.println("Distinguished name parsed: " + distinguishedName);
                Attribute parseRole = entry.get("yugabytePlatformRole");
                if (parseRole != null) {
                    role = parseRole.getString();
                }

                // Cursor.next returns true in some environments
                if (!StringUtils.isEmpty(distinguishedName)) {
                    System.out.println("Successfully fetched DN");
                    break;
                }
            }

            try {
                cursor.close();
                connection.unBind();
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Failed closing connections");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("LDAP query failed: " + e);
            throw new RuntimeException("LDAP search failed.");
        }
        return new ImmutablePair<>(distinguishedName, role);
    }
}
