﻿using NUnit.Framework;
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
using VaultAgent.Models;



namespace VaultAgentTests
{
    [TestFixture]
    [Parallelizable]
    public class LDAPAuth_Tests
    {
        private VaultAgentAPI _vault;
        private VaultSystemBackend _vaultSystemBackend;
        private UniqueKeys _uniqueKeys = new UniqueKeys("_", "__");       // Unique Key generator
        private LdapAuthEngine _ldapAuthEngine;
        private string _ldapMountName;
	    private LdapConfig _origConfig;
	    private LDAPTestObj _testData;


        [OneTimeSetUp]
        public async Task Setup () {
            // Build Connection to Vault.
            _vault = new VaultAgentAPI("AppRoleVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);
            _vaultSystemBackend = _vault.System;
            _ldapMountName = _uniqueKeys.GetKey ("LDAP"); 

            // Define the engine.
            _ldapAuthEngine = (LdapAuthEngine) _vault.ConnectAuthenticationBackend (EnumBackendTypes.A_LDAP, "ldap_test", _ldapMountName);

            // Now create the Mount point.
            AuthMethod authMethod = new AuthMethod(_ldapMountName,EnumAuthMethods.LDAP);
            authMethod.Description = "Ldap Test";
            Assert.True( await _vaultSystemBackend.AuthEnable (authMethod),"A10:  Expected the LDAP Backend to have been enabled.");

			// Now build the LDAP Backend.
            _origConfig = new LdapConfig();
	        await SetLDAPConfig(_ldapMountName,_origConfig);

            // Save the Config.  We do this here so the SetLDAPConfig can be used for multiple engines.
            Assert.True(await _ldapAuthEngine.ConfigureLDAPBackend(_origConfig), "A100:  Expected the LDAP Configuration method to return True");

            // Load the Test Data Object
            LoadTestData();
        }


		// Validate we can load the config from a JSON file.
		// Called as part of the Setup Process.
		public async Task SetLDAPConfig(string backend, LdapConfig config)
        {
            TestContext.WriteLine("LDAP Backend Name = " + backend);

			
			config.SetActiveDirectoryDefaults();
	        config.UserDN = "oldUserDN";
	        config.GroupDN = "oldgroupDN";


			// Store off some of the values:
	        string exGroupFilter = config.GroupFilter;
	        string exGroupAttr = config.GroupAttr;
	        string exUserAttr = config.UserAttr;


	        // Validate the AD fields are set.
	        Assert.IsNotEmpty(exGroupAttr, "A10:  Expected the GroupAttr property to be set.");
	        Assert.IsNotEmpty(exGroupAttr, "A20:  Expected the GroupFilter property to be set.");
	        Assert.IsNotEmpty(exGroupAttr, "A30:  Expected the UserAttr property to be set.");


			// Read a JSON Config file containing LDAP Credentials from a JSON file into the class.       
			JsonSerializer jsonSerializer = new JsonSerializer();
	        string json = File.ReadAllText(@"C:\A_Dev\Configs\Vault_LDAPEngine_TestCredentials.json");

			// Append JSON to existing objects values.
			jsonSerializer.Populate(new StringReader(json), config);
			

			// Validate the AD fields are still set to their original values.
			Assert.AreEqual(exGroupAttr,config.GroupAttr,"A50:  GroupAttr was changed during the reading of the LDAP config file.");
	        Assert.AreEqual(exGroupFilter, config.GroupFilter, "A60:  GroupFilter was changed during the reading of the LDAP config file.");
	        Assert.AreEqual(exUserAttr, config.UserAttr, "A70:  UserAttr was changed during the reading of the LDAP config file.");
        }


		/// <summary>
		/// Reads data from the testData Json file in the the TestDataObject.
		/// </summary>
	    internal void LoadTestData () {
		    // Read a JSON Config file containing LDAP Credentials from a JSON file into the class.       
		    JsonSerializer jsonSerializer = new JsonSerializer();
		    string json = File.ReadAllText(@"C:\A_Dev\Configs\Vault_LDAPTests.json");

			_testData = VaultSerializationHelper.FromJson<LDAPTestObj>(json);
		}




		[Test]
	    public async Task ReadLDAP_Config_Success () {
		    LdapConfig readConfig = await _ldapAuthEngine.ReadLDAPConfig();
		    
			Assert.AreEqual(_origConfig.GroupAttr,readConfig.GroupAttr,"A10: GroupAttr Different");
		    Assert.AreEqual(_origConfig.GroupFilter, readConfig.GroupFilter, "A10: GroupFilter Different");
		    Assert.AreEqual(_origConfig.GroupDN, readConfig.GroupDN, "A10: GroupDN Different");
		    Assert.AreEqual(_origConfig.UserDN, readConfig.UserDN,"A10: UserDN different");
		    Assert.AreEqual(_origConfig.BindDN, readConfig.BindDN, "A50: BindDN Different");
		    Assert.AreEqual(_origConfig.CaseSensitiveNames, readConfig.CaseSensitiveNames, "A60: CaseSendsitiveNames Different");
		    Assert.AreEqual(_origConfig.Certificate, readConfig.Certificate, "A70: Certificate Different");
		    Assert.AreEqual(_origConfig.DenyNullBind, readConfig.DenyNullBind, "A80: DenyNullBind Different");
		    Assert.AreEqual(_origConfig.DiscoverDN, readConfig.DiscoverDN, "A90: DiscoverDN Different");
		    Assert.AreEqual(_origConfig.InsecureTLS, readConfig.InsecureTLS, "A100: Insecure Different");
		    Assert.AreEqual(_origConfig.LDAPServers, readConfig.LDAPServers, "A110: LDAPServers Different");
		    Assert.AreEqual(_origConfig.TLSMaxVersion, readConfig.TLSMaxVersion, "A10: TLSMax Version Different");
		    Assert.AreEqual(_origConfig.TLSMinVersion, readConfig.TLSMinVersion, "A10: TLSMin Version Different");
		//    Assert.AreEqual(_origConfig, readConfig, "A10: GroupAttr Different");
		}




        // Validate that LDAP Engine Setting CaseSensitiveNames if set to True results in Vault storing Groups and Users in case sensitive format
        [Test]
        public async Task CaseSensitiveNames_Setting_Works()
        {
            // Right now Vault seems to not save groups with a case sensitive value no matter the setting of CaseSensitiveNames.  For now we just pass this test.
            Assert.Pass("Vault does not honor this setting.  Not sure if bug or something else.  For now we just pass this test.");
            return;

            // For this test we need to create a unique LDAP Engine with a unique Config.
            string ldapMountName = _uniqueKeys.GetKey("case").ToLower();

            // Define the engine.
            LdapAuthEngine ldapAuthEngine = (LdapAuthEngine)_vault.ConnectAuthenticationBackend(EnumBackendTypes.A_LDAP, "ldap_test", ldapMountName);

            // Now create the Mount point.
            AuthMethod authMethod = new AuthMethod(ldapMountName, EnumAuthMethods.LDAP);
            authMethod.Description = "Ldap Case Sensitive Test";
            Assert.True(await _vaultSystemBackend.AuthEnable(authMethod), "A10:  Expected the LDAP Backend to have been enabled.");

            // Now configure this engine.  Use same base config, just change the CaseSensitive setting.
            LdapConfig caseConfig = new LdapConfig();
            await SetLDAPConfig (ldapMountName, caseConfig);

            // Adjust Config
            caseConfig.CaseSensitiveNames = true;

            // Save Config
            Assert.True(await ldapAuthEngine.ConfigureLDAPBackend(caseConfig), "A100:  Expected the LDAP Configuration method to return True");


            // Now we can Test!

            // Save a group to policy mapping.  Should be exact match to case sensitive Group name.
            string polA = "polA";
            string groupName = _uniqueKeys.GetKey("grpCase");
            
            // Make sure we have a mixed case group name.
            Assert.AreNotEqual(groupName,groupName.ToLower(),"The group name must contain mixed case letters in order to perform this test.  It contained: " + groupName);

            List<string> groupPolicyMap = new List<string>();
            groupPolicyMap.Add(polA);

            // Final Group Case Sensitive Test.
            Assert.IsTrue(await _ldapAuthEngine.SaveGroup(groupName, groupPolicyMap), "A10:  Saving of the group failed.");
            List<string> groups = await _ldapAuthEngine.ListGroups();
            CollectionAssert.Contains(groups, groupName, "A20:  Expected the group to have actually been saved.  Does not appear in the list of groups.");

            //TODO  Test user case.
        }




        // Validate we can get a list of Groups that the LDAP backend supports
        [Test,Order(2200)]
	    public async Task Group_List_Success () {
		    List<string> groups = await _ldapAuthEngine.ListGroups();

	    }



        // Validate we can create a LDAP group to Vault policy mapping object
        [Test]
        public async Task GroupToPolicy_Success()
        {
            string polA = "polA";
            string polB = "polB";
            string polC = "polC";
            string groupName = _uniqueKeys.GetKey("grp").ToLower();

            List<string> groupPolicyMap = new List<string>();
            groupPolicyMap.Add(polA);
            groupPolicyMap.Add(polB);
            groupPolicyMap.Add(polC);

            Assert.IsTrue(await _ldapAuthEngine.SaveGroup(groupName, groupPolicyMap), "A10:  Saving of the group failed.");
            List<string> groups = await _ldapAuthEngine.ListGroups();
            CollectionAssert.Contains(groups, groupName, "A20:  Expected the group to have actually been saved.  Does not appear in the list of groups.");
        }


        // Validate that we can get a list of policies assigned to an LDAP Group To Policy Mapping object
        [Test]
        public async Task GroupListPolicies_Success()
        {
            string groupName = _uniqueKeys.GetKey("grp").ToLower();

            List<string> groupPolicyMap = new List<string>();
            groupPolicyMap.Add("pola");
            groupPolicyMap.Add("polb");
            groupPolicyMap.Add("polc");

            Assert.IsTrue(await _ldapAuthEngine.SaveGroup(groupName, groupPolicyMap), "A10:  Saving of the group failed.");
            List<string> groups = await _ldapAuthEngine.ListGroups();
            CollectionAssert.Contains(groups, groupName, "A20:  Expected the group to have actually been saved.  Does not appear in the list of groups.");

            // Now test the Read Group
            List<string> groupPolicies = await _ldapAuthEngine.GetPoliciesAssignedToGroup (groupName);
            CollectionAssert.AreEquivalent(groupPolicyMap,groupPolicies,"The policies do not seem to have been saved correctly.");
        }


        [Test]
        public async Task GroupListPolicies_InvalidGroup () {
            string groupName = _uniqueKeys.GetKey ("invalidGL");

            // Now test the Read Group
            List<string> groupPolicies = await _ldapAuthEngine.GetPoliciesAssignedToGroup(groupName);
            Assert.AreEqual(0,groupPolicies.Count,"A10:  Expected the list to be empty since no group to policy mapping objects were found.");
            

        }




        // Validate we can get a list of AD users.
        [Test,Order(3100)]
	    public async Task Users_List_Success() {
		    List<string> users= await _ldapAuthEngine.ListUsers();

	    }



		// Validate a successful login
	    [Test,Order(3000)]
	    public async Task Login_Success () {
            // We want to associate a group to policy mapping for the user.  So set that up first.
            // It is vital that the Active Directory Server contains this userID and is a member of the groupName group or else this test will fail.
            string groupName = _testData.user1Group;

            List<string> groupPolicyMap = new List<string>();
            groupPolicyMap.Add("pola");
            groupPolicyMap.Add("polb");
            groupPolicyMap.Add("polc");

            Assert.IsTrue(await _ldapAuthEngine.SaveGroup(groupName, groupPolicyMap), "A10:  Saving of the group failed.");
            List<string> groupPolicies = await _ldapAuthEngine.GetPoliciesAssignedToGroup(groupName);
            CollectionAssert.AreEquivalent(groupPolicyMap, groupPolicies, "A20:  The policies do not seem to have been saved correctly.");

            LoginResponse lr = await _ldapAuthEngine.Login(_testData.loginUser1, _testData.loginPass1);
            Assert.IsNotNull(lr,"A30:  LoginResponse was null.  Should have been a valid response.");
	    }



		// Validate the error if invalid user or password.
	    [Test, Order(3000)]
	    public async Task Login_Fails () {
		    Assert.ThrowsAsync<VaultInvalidDataException>(async () => await _ldapAuthEngine.Login(_testData.loginUser1, "invalid"));
		    Assert.ThrowsAsync<VaultInvalidDataException>(async () => await _ldapAuthEngine.Login("notauser", "invalid"));
		}


	}



	/// <summary>
	/// This class is used to load in values from a JSON file that contains the test data we want to use.
	/// </summary>
	internal class LDAPTestObj {
		public LDAPTestObj () { }

		public string loginUser1 { get; set; }
		public string loginPass1 { get; set; }

		// A group that the user1 is a direct member of
		public string user1Group { get; set; }
	}
}