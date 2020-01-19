using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.AuthenticationEngines.LDAP;
using VaultAgent.Backends;
using VaultAgent.Backends.System;
using VaultAgent.Models;
using VaultAgent.SecretEngines;

namespace VaultClient
{
    class InitiateVault
    {
        private const string VAULT_KEYCRYPT_NAME = "AppVault";
        private const string VAULT_KEYCRYPT_DESC = "KV2 AppData Vault";
        private const string VAULT_HASH_NAME = "AppHash";
        private const string VAULT_HASH_DESC = "Application Hash Vault";
        private const string LDAP_MOUNTNAME = "ldapcin";
        

        private VaultAgentAPI _vault;
        private LdapAuthEngine _ldapAuthEngine;
        private VaultSystemBackend _vaultSystemBackend;
        private AuthMethod _authMethod;

        public InitiateVault(VaultAgentAPI vaultAgent)
        {
            _vault = vaultAgent;
            _vaultSystemBackend = _vault.System;

            _ldapAuthEngine = (LdapAuthEngine)_vault.ConnectAuthenticationBackend(EnumBackendTypes.A_LDAP, LDAP_MOUNTNAME, LDAP_MOUNTNAME);

            _authMethod = new AuthMethod(LDAP_MOUNTNAME, EnumAuthMethods.LDAP);
            _authMethod.Description = LDAP_MOUNTNAME;
            

        }


        /// <summary>
        /// Performs the initial setup of a vault instance.
        /// </summary>
        /// <returns></returns>
        public async Task<bool> InitialSetup()
        {
            bool success;

            await SetupLDAP();

            

            // Build the Application Data Vault
            BuildBackends(VAULT_KEYCRYPT_NAME, VAULT_KEYCRYPT_DESC);
            BuildBackends(VAULT_HASH_NAME, VAULT_HASH_DESC);
            success = await BuildAdminPolicy();


            // Connect to the KeyValue2 Vault that we will use 
            KV2SecretEngine vaultAppCrypt;
            vaultAppCrypt = (KV2SecretEngine)_vault.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, VAULT_KEYCRYPT_NAME, VAULT_KEYCRYPT_NAME);

            return success;
        }


        /// <summary>
        /// Builds the required Key Value 2 backends
        /// </summary>
        /// <param name="name">Name of the backend.  This is also its path</param>
        /// <param name="desc">Brief description of the backend</param>
        public async void BuildBackends(string name, string desc)
        {
            // Create the KV2 App backend if it does not exist
            bool exists = await _vaultSystemBackend.SysMountExists(name);
            if (!exists)
            {
                await _vaultSystemBackend.SysMountCreate(name, desc, EnumSecretBackendTypes.KeyValueV2);
            }
        }


        /// <summary>
        /// Reads the configuration of the LDAP Backend
        /// </summary>
        /// <returns></returns>
        public async Task<string> GetConfig()
        {
            string json = await _ldapAuthEngine.ReadLDAPConfigAsJSON();
            return json;
        }


        public async Task<bool> WipeVault()
        {
            await _vaultSystemBackend.AuthDisable(_authMethod.Path);
            await _vaultSystemBackend.SysMountDelete(VAULT_KEYCRYPT_NAME);
            await _vaultSystemBackend.SysMountDelete(VAULT_HASH_NAME);
            return true;
        }



        /// <summary>
        /// Builds a policy for the full admins of the vault.
        /// </summary>
        /// <returns></returns>
        internal async Task<bool> BuildAdminPolicy()
        {
            // Create the Permission Paths

            // FullAdmins will have full control to the HashPath
            VaultPolicyPathItem hashPath = new VaultPolicyPathItem(true,VAULT_HASH_NAME, "/*");
            hashPath.CRUDAllowed = true;

            // FullAdmins will have full control to the AppKey Vault
            VaultPolicyPathItem appPath = new VaultPolicyPathItem(true,VAULT_KEYCRYPT_NAME,"/*");
            appPath.CRUDAllowed = true;



            // Now create the policy
            VaultPolicyContainer adminContainer = new VaultPolicyContainer("FullAdmin");
            adminContainer.AddPolicyPathObject(hashPath);
            adminContainer.AddPolicyPathObject(appPath);

            bool success = await _vaultSystemBackend.SysPoliciesACLCreate(adminContainer);


            List<string> adminPolicies = new List<string>();
            adminPolicies.Add(adminContainer.Name);

            // Associate the Admin Active Directory group to the policy.
            success = await _ldapAuthEngine.CreateGroupToPolicyMapping("_IT-SystemEngineers", adminPolicies);

            List<string> groups = await _ldapAuthEngine.ListGroups();


            return success;
        }




        /// <summary>
        /// Configures the LDAP Backend for a new vault.
        /// </summary>
        /// <returns></returns>
        public async Task SetupLDAP()
        {
            // Create Config object - load defaults from file.
            LdapConfig ldapConfig = _ldapAuthEngine.GetLDAPConfigFromFile(@"C:\a_dev\Configs\AD_Cin_Connector.json");

            try
            {
                if (!(await _vaultSystemBackend.AuthEnable(_authMethod)))
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

            bool exists = await _vaultSystemBackend.AuthExists(LDAP_MOUNTNAME);
        }



        /// <summary>
        /// Performs the login of a user to the vault
        /// </summary>
        /// <returns></returns>
        public async Task<bool> Login()
        {
            // Login
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
                    Console.WriteLine("Exception: {0}", e.Message);
                }
            }

            return true;

        }
    }
}
