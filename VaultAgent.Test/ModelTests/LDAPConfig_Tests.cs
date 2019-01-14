using NUnit.Framework;
using VaultAgent.AuthenticationEngines.LDAP;

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


		#endregion

	}
}
