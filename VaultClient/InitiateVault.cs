using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
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
            _ldapMountName = "Cincinnati";

            // Define the engine.
            _ldapAuthEngine = (LdapAuthEngine) _vault.ConnectAuthenticationBackend(EnumBackendTypes.A_LDAP, "ldap_test", _ldapMountName);
            _vaultSystemBackend = _vault.System;

            // Delete mount point so create succeeds
            _vaultSystemBackend.AuthDisable(_ldapMountName);


            // Now create the Mount point.
            AuthMethod authMethod = new AuthMethod(_ldapMountName, EnumAuthMethods.LDAP);
            authMethod.Description = "Cincinnati Prod Domain";


            // Create Config object - load defaults from file.
            LdapConfig ldapConfig = _ldapAuthEngine.GetLDAPConfigFromFile(@"C:\a_dev\Configs\AD_Cin_Connector.json");

            try
            {
                if (!(await _vaultSystemBackend.AuthEnable(authMethod)))
                {

                    Console.WriteLine("Error: unable to create the backend");
                    return;
                }

                Console.WriteLine("LDAP Backend Mount created.");

                if (!await _ldapAuthEngine.ConfigureLDAPBackend(ldapConfig))
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



            // Now read credentials from test file
            JsonSerializer jsonSerializer = new JsonSerializer();
            string json = File.ReadAllText(@"C:\A_Dev\Configs\ClientLoginCredentials.json");

            LDAPUserCredentials user = VaultSerializationHelper.FromJson<LDAPUserCredentials>(json);

            try
            {
                // Now connect
                LoginResponse lr = await _ldapAuthEngine.Login(user.UserId, user.Password);
                Console.WriteLine("Success");
            }
            catch (VaultException e)
            {
                if (e.SpecificErrorCode == EnumVaultExceptionCodes.LDAPLoginServerConnectionIssue)
                {
                    Console.WriteLine("Error - Problem with LDAP Connection");
                }
                else
                {
                    Console.WriteLine("Exceptyion: {0}", e.Message);
                }
            }
        }

    }
}
