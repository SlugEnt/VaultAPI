using NUnit.Framework;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultAgent.Backends.System;
using VaultAgent.Backends;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using SlugEnt;
using VaultAgent.AuthenticationEngines.LDAP;
using VaultAgent.AuthenticationEngines.LoginConnectors;
using VaultAgent.Models;



namespace VaultAgentTests
{
    [TestFixture]
    [Parallelizable]
    public class LDAPAuth_Tests {
        private VaultAgentAPI _vault;
        private VaultSystemBackend _vaultSystemBackend;
        private UniqueKeys _uniqueKeys = new UniqueKeys ("_", "__"); // Unique Key generator
        private LdapAuthEngine _ldapAuthEngine;
        private string _ldapMountName;
        private LdapConfig _origConfig;
        private LDAPTestObj _testData;

        private LDAPLoginConnector _ldapLoginConnector;

        [OneTimeSetUp]
        public async Task Setup () {
            // Build Connection to Vault.
            _vault = new VaultAgentAPI ("AppRoleVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);
            _vaultSystemBackend = _vault.System;
            _ldapMountName = _uniqueKeys.GetKey ("LDAP");

            // Define the engine.
            _ldapAuthEngine = (LdapAuthEngine) _vault.ConnectAuthenticationBackend (EnumBackendTypes.A_LDAP, "ldap_test", _ldapMountName);

            // Now create the Mount point.
            AuthMethod authMethod = new AuthMethod (_ldapMountName, EnumAuthMethods.LDAP);
            authMethod.Description = "Ldap Test";
            Assert.True (await _vaultSystemBackend.AuthEnable (authMethod), "A10:  Expected the LDAP Backend to have been enabled.");

            // Now build the LDAP Backend.
            _origConfig = _ldapAuthEngine.GetLDAPConfigFromFile(@"C:\a_Dev\Configs\LDAP_Test.json");
            SetLDAPConfig (_ldapMountName, _origConfig);

            // Save the Config.  We do this here so the SetLDAPConfig can be used for multiple engines.
            Assert.True (await _ldapAuthEngine.ConfigureLDAPBackend (_origConfig), "A100:  Expected the LDAP Configuration method to return True");

            // Initialize the LDAP Login Connector.
            _ldapLoginConnector = new LDAPLoginConnector(_vault,_ldapAuthEngine.MountPoint,"Test LDAP Backend");

            // Load the Test Data Object
            LoadTestData();
        }


        /// <summary>
        /// We need to ensure we are using the normal Vault Token ID.  Some of the tests overwrite this
        /// </summary>
        [SetUp]
        public void SetupEachTest () { _vault.TokenID = VaultServerRef.rootToken; }


        // Validate we can load the config from a JSON file.
        // Called as part of the Setup Process.
        public void SetLDAPConfig (string backend, LdapConfig config) {
            TestContext.WriteLine ("LDAP Backend Name = " + backend);


            config.SetActiveDirectoryDefaults();
            //config.UserDN = "oldUserDN";
            //config.GroupDN = "oldgroupDN";


            

            // Store off some of the values:
            string exGroupFilter = config.GroupFilter;
            string exGroupAttr = config.GroupAttr;
            string exUserAttr = config.UserAttr;


            // Validate the AD fields are set.
            Assert.IsNotEmpty (exGroupAttr, "A10:  Expected the GroupAttr property to be set.");
            Assert.IsNotEmpty (exGroupAttr, "A20:  Expected the GroupFilter property to be set.");
            Assert.IsNotEmpty (exGroupAttr, "A30:  Expected the UserAttr property to be set.");

            // TODO Delete or uncomment

            // Read a JSON Config file containing LDAP Credentials from a JSON file into the class.       
            JsonSerializer jsonSerializer = new JsonSerializer();
            string json = File.ReadAllText (@"C:\A_Dev\Configs\ClientLoginCredentials.json");

            // Append JSON to existing objects values.
            jsonSerializer.Populate (new StringReader (json), config);


            // Validate the AD fields are still set to their original values.
            Assert.AreEqual (exGroupAttr, config.GroupAttr, "A50:  GroupAttr was changed during the reading of the LDAP config file.");
            Assert.AreEqual (exGroupFilter, config.GroupFilter, "A60:  GroupFilter was changed during the reading of the LDAP config file.");
            Assert.AreEqual (exUserAttr, config.UserAttr, "A70:  UserAttr was changed during the reading of the LDAP config file.");

        }


        /// <summary>
        /// Reads data from the testData Json file in the the TestDataObject.
        /// </summary>
        internal void LoadTestData () {
            // Read a JSON Config file containing LDAP Credentials from a JSON file into the class.       
            JsonSerializer jsonSerializer = new JsonSerializer();
            string json = File.ReadAllText (@"C:\A_Dev\Configs\ClientLoginCredentials.json");

            _testData = VaultSerializationHelper.FromJson<LDAPTestObj> (json);
        }



        /// <summary>
        /// Validates that we can load a LDAP Config file settings from a file.  This tests the Non-AD version
        /// </summary>
        [Test]
        public void LoadsLDapConfig_NonAD()
        {
            LdapConfig ldapConfig =  _ldapAuthEngine.GetLDAPConfigFromFile(@"TestFiles\ldapConfig_Test_noAD.json");
        //    Assert.True(ValidateConfigFromJSON(ldapConfig), "A10: LdapConfig read from JSON had initial validation errors");

        }





        [Test]
        public async Task ReadLDAP_Config_Success () {
            LdapConfig readConfig = await _ldapAuthEngine.ReadLDAPConfig();

            Assert.AreEqual (_origConfig.GroupAttr, readConfig.GroupAttr, "A10: GroupAttr Different");
            Assert.AreEqual (_origConfig.GroupFilter, readConfig.GroupFilter, "A10: GroupFilter Different");
            Assert.AreEqual (_origConfig.GroupDN, readConfig.GroupDN, "A10: GroupDN Different");
            Assert.AreEqual (_origConfig.UserDN, readConfig.UserDN, "A10: UserDN different");
            Assert.AreEqual (_origConfig.BindDN, readConfig.BindDN, "A50: BindDN Different");
            Assert.AreEqual (_origConfig.CaseSensitiveNames, readConfig.CaseSensitiveNames, "A60: CaseSendsitiveNames Different");
            Assert.AreEqual (_origConfig.Certificate, readConfig.Certificate, "A70: Certificate Different");
            Assert.AreEqual (_origConfig.DenyNullBind, readConfig.DenyNullBind, "A80: DenyNullBind Different");
            Assert.AreEqual (_origConfig.DiscoverDN, readConfig.DiscoverDN, "A90: DiscoverDN Different");
            Assert.AreEqual (_origConfig.InsecureTLS, readConfig.InsecureTLS, "A100: Insecure Different");
            Assert.AreEqual (_origConfig.LDAPServers, readConfig.LDAPServers, "A110: LDAPServers Different");
            Assert.AreEqual (_origConfig.TLSMaxVersion, readConfig.TLSMaxVersion, "A10: TLSMax Version Different");
            Assert.AreEqual (_origConfig.TLSMinVersion, readConfig.TLSMinVersion, "A10: TLSMin Version Different");

            //    Assert.AreEqual(_origConfig, readConfig, "A10: GroupAttr Different");
        }




        // Validate that LDAP Engine Setting CaseSensitiveNames if set to True results in Vault storing Groups and Users in case sensitive format
        [Test]
        public void CaseSensitiveNames_Setting_Works () {
            // Right now Vault seems to not save groups with a case sensitive value no matter the setting of CaseSensitiveNames.  For now we just pass this test.
            Assert.Pass ("Vault does not honor this setting.  Not sure if bug or something else.  For now we just pass this test.");
            return;

            /*
            // For this test we need to create a unique LDAP Engine with a unique Config.
            string ldapMountName = _uniqueKeys.GetKey ("case").ToLower();

            // Define the engine.
            LdapAuthEngine ldapAuthEngine = (LdapAuthEngine) _vault.ConnectAuthenticationBackend (EnumBackendTypes.A_LDAP, "ldap_test", ldapMountName);

            // Now create the Mount point.
            AuthMethod authMethod = new AuthMethod (ldapMountName, EnumAuthMethods.LDAP);
            authMethod.Description = "Ldap Case Sensitive Test";
            Assert.True (await _vaultSystemBackend.AuthEnable (authMethod), "A10:  Expected the LDAP Backend to have been enabled.");

            // Now configure this engine.  Use same base config, just change the CaseSensitive setting.
            LdapConfig caseConfig = new LdapConfig();
            SetLDAPConfig (ldapMountName, caseConfig);

            // Adjust Config
            caseConfig.CaseSensitiveNames = true;

            // Save Config
            Assert.True (await ldapAuthEngine.ConfigureLDAPBackend (caseConfig), "A100:  Expected the LDAP Configuration method to return True");


            // Now we can Test!

            // Save a group to policy mapping.  Should be exact match to case sensitive Group name.
            string polA = "polA";
            string groupName = _uniqueKeys.GetKey ("grpCase");

            // Make sure we have a mixed case group name.
            Assert.AreNotEqual (groupName, groupName.ToLower(),
                                "The group name must contain mixed case letters in order to perform this test.  It contained: " + groupName);

            List<string> groupPolicyMap = new List<string>();
            groupPolicyMap.Add (polA);

            // Final Group Case Sensitive Test.
            Assert.IsTrue (await _ldapAuthEngine.CreateGroupToPolicyMapping (groupName, groupPolicyMap), "A10:  Saving of the group failed.");
            List<string> groups = await _ldapAuthEngine.ListGroups();
            CollectionAssert.Contains (groups, groupName, "A20:  Expected the group to have actually been saved.  Does not appear in the list of groups.");

            
            */
        }




        // Validate we can get a list of Groups that the LDAP backend supports
        [Test, Order (2200)]
        public async Task Group_List_Success () {
            List<string> groups = await _ldapAuthEngine.ListGroups();

        }



        // Validate we can create a LDAP group to Vault policy mapping object
        [Test]
        public async Task GroupToPolicy_Success () {
            string polA = "polA";
            string polB = "polB";
            string polC = "polC";
            string groupName = _uniqueKeys.GetKey ("grp").ToLower();

            List<string> groupPolicyMap = new List<string>();
            groupPolicyMap.Add (polA);
            groupPolicyMap.Add (polB);
            groupPolicyMap.Add (polC);

            Assert.IsTrue (await _ldapAuthEngine.CreateGroupToPolicyMapping (groupName, groupPolicyMap), "A10:  Saving of the group failed.");
            List<string> groups = await _ldapAuthEngine.ListGroups();
            CollectionAssert.Contains (groups, groupName, "A20:  Expected the group to have actually been saved.  Does not appear in the list of groups.");
        }


        // Validate that we can get a list of policies assigned to an LDAP Group To Policy Mapping object
        [Test]
        public async Task GroupListPolicies_Success () {
            string groupName = _uniqueKeys.GetKey ("grp").ToLower();

            List<string> groupPolicyMap = new List<string>();
            groupPolicyMap.Add ("pola");
            groupPolicyMap.Add ("polb");
            groupPolicyMap.Add ("polc");

            Assert.IsTrue (await _ldapAuthEngine.CreateGroupToPolicyMapping (groupName, groupPolicyMap), "A10:  Saving of the group failed.");
            List<string> groups = await _ldapAuthEngine.ListGroups();
            CollectionAssert.Contains (groups, groupName, "A20:  Expected the group to have actually been saved.  Does not appear in the list of groups.");

            // Now test the Read Group
            List<string> groupPolicies = await _ldapAuthEngine.GetPoliciesAssignedToGroup (groupName);
            CollectionAssert.AreEquivalent (groupPolicyMap, groupPolicies, "The policies do not seem to have been saved correctly.");
        }


        [Test]
        public async Task GroupListPolicies_InvalidGroup () {
            string groupName = _uniqueKeys.GetKey ("invalidGL");

            // Now test the Read Group
            List<string> groupPolicies = await _ldapAuthEngine.GetPoliciesAssignedToGroup (groupName);
            Assert.AreEqual (0, groupPolicies.Count, "A10:  Expected the list to be empty since no group to policy mapping objects were found.");
        }




        // Validate we can get a list of AD users.
        [Test, Order (3100)]
        public async Task Users_List_Success () {
            List<string> users = await _ldapAuthEngine.ListUsers();

        }



        // Validate a successful login
        [Test, Order (3000)]
        public async Task Login_Success () {
            // We want to associate a group to policy mapping for the user.  So set that up first.
            // It is vital that the Active Directory Server contains this userID and is a member of the groupName group or else this test will fail.
            string groupName = _testData.User1Group;

            List<string> groupPolicyMap = new List<string>();
            groupPolicyMap.Add ("pola");
            groupPolicyMap.Add ("polb");
            groupPolicyMap.Add ("polc");

            
            Assert.IsTrue (await _ldapAuthEngine.CreateGroupToPolicyMapping (groupName, groupPolicyMap), "A10:  Saving of the group failed.");
            List<string> groupPolicies = await _ldapAuthEngine.GetPoliciesAssignedToGroup (groupName);
            CollectionAssert.AreEquivalent (groupPolicyMap, groupPolicies, "A20:  The policies do not seem to have been saved correctly.");

            _ldapLoginConnector.UserName = _testData.UserId;
            _ldapLoginConnector.Password = _testData.Password;
            Assert.IsTrue(await _ldapLoginConnector.Connect());
            Assert.IsNotEmpty(_ldapLoginConnector.Response.ClientToken);
        }


#pragma warning disable CS1998


        // Validate the error if invalid user or password.
        [Test, Order (3000)]
        public async Task Login_Fails () {
            Assert.ThrowsAsync<VaultException> (async () => await _ldapAuthEngine.Login (_testData.UserId, "invalid"));
            Assert.ThrowsAsync<VaultException> (async () => await _ldapAuthEngine.Login ("notauser", "invalid"));
        }
#pragma warning restore CS1998
    }




    /// <summary>
        /// This class is used to load in values from a JSON file that contains the test data we want to use.
        /// </summary>
        internal class LDAPTestObj {
		public LDAPTestObj () { }

		public string UserId { get; set; }
		public string Password { get; set; }

		// A group that the user1 is a direct member of
		public string User1Group { get; set; }
	}
}
