using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.AuthenticationEngines.LDAP;
using VaultAgent.Backends;
using VaultAgent.Backends.System;
using VaultAgent.Models;

namespace VaultClient
{
    class InitiateVault
    {
        private VaultAgentAPI _vault;
        private LdapAuthEngine _ldapAuthEngine;
        private string _ldapMountName;
        private VaultSystemBackend _vaultSystemBackend;

        public InitiateVault(VaultAgentAPI vaultAgent)
        {
            _vault = vaultAgent;
        }



        public async void SetupLDAP()
        {
            LdapConfig lc = new LdapConfig("dc=cin,dc=sheakley,dc=com");
            lc.BindPassword = "7PNsEe%N9#am";
            lc.BindDN = "cn=SVC_LDAP_Lookup";
            lc.InsecureTLS = true;
            lc.LDAPServers = "ldaps://cindsv10008.cin.sheakley.com:636";
            lc.UserDN = "ou=SheakleyGroup";
            lc.SetActiveDirectoryDefaults();

            _ldapMountName = "Cincinnati";

            // Define the engine.
            _ldapAuthEngine = (LdapAuthEngine) _vault.ConnectAuthenticationBackend(EnumBackendTypes.A_LDAP, "ldap_test", _ldapMountName);
            _vaultSystemBackend = _vault.System;

            // Delete mount point so create succeeds
            _vaultSystemBackend.AuthDisable(_ldapMountName);


            // Now create the Mount point.
            AuthMethod authMethod = new AuthMethod(_ldapMountName, EnumAuthMethods.LDAP);
            authMethod.Description = "Cincinnati Prod Domain";

            try
            {
                if (!(await _vaultSystemBackend.AuthEnable(authMethod)))
                {

                    Console.WriteLine("Error: unable to create the backend");
                    return;
                }

                Console.WriteLine("LDAP Backend Mount created.");

                if (!await _ldapAuthEngine.ConfigureLDAPBackend(lc))
                {
                    Console.WriteLine("Error setting the LDAP Configuration");
                    return;
                }
                Console.WriteLine("LDAP Config saved");

            }
            catch (VaultException e)
            {
                if (e.SpecificErrorCode != EnumVaultExceptionCodes.BackendMountAlreadyExists)
                {
                    Console.WriteLine("Error connecting to authentication backend - {0}", e.Message);
                }
            }

            bool exists = await _vaultSystemBackend.AuthExists(_ldapMountName);

            _vaultSystemBackend.AuthExists(_ldapMountName);

            // Now connect
            LoginResponse lr = await _ldapAuthEngine.Login("sherrmann", "1P@ssword12");
            Console.WriteLine("Success");
        }

    }
}
