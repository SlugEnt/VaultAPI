using System.IO;
using Newtonsoft.Json;
using NUnit.Framework;
using VaultAgent.AuthenticationEngines.LDAP;
using VaultAgentTests;

namespace VaultAgent.Test.ModelTests
{
	[Parallelizable]
	[TestFixture]
	class LDAPConfig_Tests
	{

		#region "LDAPConfig Tests"


		// Validates that if we have specified a DN Suffix and then set the UserDN that it appends the suffix.
		[Test]
		public void UserDN_DNsuffixSpecified_SetCorrectly() {
			string dnSuffix = "dc=test,dc=tst,dc=org";
			string user = "tstUSEROU";

			LdapConfig lc = new LdapConfig(dnSuffix);
			lc.UserDN = user;
			Assert.AreEqual(user + "," + dnSuffix, lc.UserDN, "A10: Unexpected userDN");
		}


		// Validates that if we do not specify a DN suffix that it uses just the value passed in.
		[Test]
		public void UserDN_No_DNsuffix_SetCorrectly() {
			string user = "tstUSEROU,DC=practice,DC=org";

			LdapConfig lc = new LdapConfig();
			lc.UserDN = user;
			Assert.AreEqual(user, lc.UserDN, "A10: Unexpected userDN");
		}


		// Validates that if we have specified a DN Suffix and then set the GroupDN that it appends the suffix.
		[Test]
		public void GroupDN_DNsuffixSpecified_SetCorrectly() {
			string dnSuffix = "dc=test,dc=tst,dc=org";
			string group = "tstUSEROU";

			LdapConfig lc = new LdapConfig(dnSuffix);
			lc.GroupDN = group;
			Assert.AreEqual(group + "," + dnSuffix, lc.GroupDN, "A10: Unexpected groupDN");
		}


		// Validates that if we do not specify a DN suffix that it uses just the value passed in.
		[Test]
		public void GroupDN_No_DNsuffix_SetCorrectly() {
			string group = "tstUSEROU,DC=practice,DC=org";

			LdapConfig lc = new LdapConfig();
			lc.GroupDN = group;
			Assert.AreEqual(group, lc.GroupDN, "A10: Unexpected groupDN");
		}



		// Validates that if we have specified a DN Suffix and then set the BindDN that it appends the suffix.
		[Test]
		public void BindDN_DNsuffixSpecified_SetCorrectly() {
			string dnSuffix = "dc=test,dc=tst,dc=org";
			string bind = "tstUSEROU";

			LdapConfig lc = new LdapConfig(dnSuffix);
			lc.BindDN = bind;
			Assert.AreEqual(bind + "," + dnSuffix, lc.BindDN, "A10: Unexpected bindDN");
		}


		// Validates that if we do not specify a DN suffix that it uses just the value passed in.
		[Test]
		public void BindDN_No_DNsuffix_SetCorrectly() {
			string bind = "tstUSEROU,DC=practice,DC=org";

			LdapConfig lc = new LdapConfig();
			lc.BindDN = bind;
			Assert.AreEqual(bind, lc.BindDN, "A10: Unexpected bindDN");
		}


		// Validates that SetActiveDirectoryDefaults does set the required fields.
		[Test]
		public void SetADDefaults_Works() {
			LdapConfig a = new LdapConfig();
			a.SetActiveDirectoryDefaults();

			// Store off some of the values:
			string exGroupFilter = a.GroupFilter;
			string exGroupAttr = a.GroupAttr;
			string exUserAttr = a.UserAttr;

			// Validate the AD fields are set.
			Assert.IsNotEmpty(exGroupAttr, "A10:  Expected the GroupAttr property to be set.");
			Assert.IsNotEmpty(exGroupFilter, "A20:  Expected the GroupFilter property to be set.");
			Assert.IsNotEmpty(exUserAttr, "A30:  Expected the UserAttr property to be set.");
		}



        [Test]
        public void IsActiveDirectory_SetsADValues()
        {
            LdapConfig a = new LdapConfig("",true);

            // Store off some of the values:
            string exGroupFilter = a.GroupFilter;
            string exGroupAttr = a.GroupAttr;
            string exUserAttr = a.UserAttr;

            // Validate the AD fields are set.
            Assert.IsNotEmpty(exGroupAttr, "A10:  Expected the GroupAttr property to be set.");
            Assert.IsNotEmpty(exGroupFilter, "A20:  Expected the GroupFilter property to be set.");
            Assert.IsNotEmpty(exUserAttr, "A30:  Expected the UserAttr property to be set.");

            Assert.True(exGroupAttr.Contains("cn"), "A10: Group Attr does not contain the expected value");
            Assert.True(exUserAttr.Contains("samaccountname"), "A20:  User attribute does not contain correct value");
            Assert.True(exGroupFilter.Contains("objectClass=group"), "A30:  Group Filter does not contain correct value");
        }


        #endregion



        /// <summary>
        /// Tests that loading a config from JSON results in all default values.
        /// </summary>
        [Test]
        public void LoadConfigFromFile_TestDefaults()
        {
            LdapConfig ldapConfig = GetLDAPConfigFromFile(@"TestFiles\ldapConfig_Test_Simple.json");

            Assert.IsFalse(ldapConfig.CaseSensitiveNames);
            Assert.AreEqual(ldapConfig.Certificate, "");

            Assert.IsTrue(ldapConfig.DenyNullBind);
            Assert.IsFalse(ldapConfig.DiscoverDN);
            Assert.AreEqual(ldapConfig.GroupAttr, "");

            Assert.AreEqual(ldapConfig.GroupFilter, "");
            Assert.IsTrue(ldapConfig.InsecureTLS);
            Assert.IsFalse(ldapConfig.IsActiveDirectoryConnection);
            Assert.AreEqual(ldapConfig.LDAPServers, "");
            Assert.IsFalse(ldapConfig.StartTLS);
            Assert.AreEqual(ldapConfig.TLSMaxVersion, "tls12");
            Assert.AreEqual(ldapConfig.TLSMinVersion, "tls12");
            Assert.AreEqual(ldapConfig.BindDN, "");
            Assert.AreEqual(ldapConfig.BindPassword, "");
            Assert.AreEqual(ldapConfig.GroupDN, "");
            Assert.AreEqual(ldapConfig.DN_Suffix, "");
        }



        /// <summary>
        /// Load a sample Non-ActiveDirectory config file
        /// </summary>
        [Test]
        public void LoadConfigFromFile_NonAD()
        {
            LdapConfig ldapConfig = GetLDAPConfigFromFile(@"TestFiles\ldapConfig_Test_noAD.json");
            Assert.IsTrue(ValidateConfigFromJSON(ldapConfig,true));
        }



        /// <summary>
        /// Load a sample ActiveDirectory config file
        /// </summary>
        [Test]
        public void LoadConfigFromFile_ActiveDirectory()
        {
            LdapConfig ldapConfig = GetLDAPConfigFromFile(@"TestFiles\ldapConfig_Test_AD.json");
            Assert.IsTrue(ValidateConfigFromJSON(ldapConfig, true, true));
        }


        /// <summary>
        ///  Base Validation of Config file loaded from JSON
        /// </summary>
        /// <param name="ldapConfig"></param>
        /// <param name="withDNSSuffix"></param>
        /// <param name="withAD"></param>
        /// <returns></returns>
        private bool ValidateConfigFromJSON(LdapConfig ldapConfig, bool withDNSSuffix = false, bool withAD = false)
        {
            // TODO all tests are backwards, actual, expected. fix
            Assert.AreEqual(ldapConfig.BindPassword, "password");

            Assert.IsFalse(ldapConfig.CaseSensitiveNames);
            Assert.AreEqual(ldapConfig.Certificate, "");

            Assert.IsTrue(ldapConfig.DenyNullBind);
            Assert.IsFalse(ldapConfig.DiscoverDN);

            Assert.IsTrue(ldapConfig.InsecureTLS);
            
            Assert.AreEqual(ldapConfig.LDAPServers, "ldaps://testserver:686");
            Assert.IsFalse(ldapConfig.StartTLS);
            Assert.AreEqual(ldapConfig.TLSMaxVersion, "tls12");
            Assert.AreEqual(ldapConfig.TLSMinVersion, "tls12");


            if (withDNSSuffix)
            {
                Assert.AreEqual(ldapConfig.DN_Suffix, "DC=test,dc=org");
                Assert.AreEqual(ldapConfig.BindDN, FullDNValue("CN=SearchUser", ldapConfig.DN_Suffix));
                Assert.AreEqual(ldapConfig.GroupDN, FullDNValue("OU=Groups",ldapConfig.DN_Suffix));
            }
            else
            {
                Assert.AreEqual(ldapConfig.BindDN, "");
                Assert.AreEqual(ldapConfig.BindPassword, "");
                Assert.AreEqual(ldapConfig.GroupDN, "");
                Assert.AreEqual(ldapConfig.DN_Suffix, "");
            }


            if (withAD)
            {
                Assert.IsTrue(ldapConfig.IsActiveDirectoryConnection);
                Assert.AreEqual("cn",ldapConfig.GroupAttr );
                Assert.AreEqual("samaccountname",ldapConfig.UserAttr);
                Assert.AreEqual("(\u0026(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))",ldapConfig.GroupFilter);
            }
            else
            {
                Assert.IsFalse(ldapConfig.IsActiveDirectoryConnection);
                Assert.AreEqual("",ldapConfig.GroupAttr);
                Assert.AreEqual("", ldapConfig.UserAttr);
                Assert.AreEqual("", ldapConfig.GroupFilter);
            }

            return true;

            
        }


        /// <summary>
        /// Returns an LDAPConfig object that was initialized from values in a config file.
        /// </summary>
        /// <param name="filename"></param>
        /// <returns></returns>
        internal LdapConfig GetLDAPConfigFromFile(string filename)
        {
            // Read a JSON Config file containing LDAP Credentials from a JSON file into the class.       
            JsonSerializer jsonSerializer = new JsonSerializer();
            string json = File.ReadAllText(filename);

            // Append JSON to existing objects values.
            LdapConfig ldapConfig = new LdapConfig();
            jsonSerializer.Populate(new StringReader(json), ldapConfig);
            return ldapConfig;
        }

        internal string FullDNValue(string dn, string suffix = "")
        {
            if (suffix == "") { return dn; }

            return dn + "," + suffix;
        }
    }
}
