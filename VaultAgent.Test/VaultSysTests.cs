using NUnit.Framework;
using System.Net.Http;
using System.Collections.Generic;
using VaultAgent;
using VaultAgent.Models;
using System;
using System.Threading.Tasks;
using VaultAgent.Backends;
using VaultAgent.Backends.System;
using System.Diagnostics;

namespace VaultAgentTests
{
    [TestFixture]
	[Parallelizable]
    public class VaultSysTests
    {
        private VaultAgentAPI _vaultAgentAPI;

        private VaultSystemBackend _vaultSystemBackend;
        private UniqueKeys _uniqueKeys = new UniqueKeys();       // Unique Key generator



        [OneTimeSetUp]
        public async Task Backend_Init()
        {
            if (_vaultSystemBackend != null)
            {
                return;
            }

            // Build Connection to Vault.
            _vaultAgentAPI = new VaultAgentAPI("transitVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);

            // Create a new system Backend Mount for this series of tests.
            _vaultSystemBackend = _vaultAgentAPI.System;
        }



		//TODO Replace this test function.  VaultAPI_Http is not accessible any longer outside the VaultAgent project.
/*		[Test, Order(1)]
		public async Task TokenInfoTest () {
			// This is temporary until we have the ability to send input parameters
			string path = "v1/auth/token/lookup";

			// JSON the input variables
			Dictionary<string, string> content = new Dictionary<string, string>();
			content.Add("token", VaultServerRef.rootToken);

			try {
				VaultAPI_Http VH = new VaultAPI_Http(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

				VaultDataResponseObject vdr = await VH.PostAsync(path, "TokenInfoTest" ,content);

				string sJSON = vdr.GetResponsePackageAsJSON();

				Assert.IsNotEmpty(sJSON);
			}
			catch (Exception e) { }
		}
*/


        [Test]
		public async Task Transit_CanEnableTransitBackend () {
			// Generate a hopefully small unique name.
		    string beName = _uniqueKeys.GetKey("TranBEN"); 
			string oldName = _uniqueKeys.GetKey("TranBEO"); 
            Assert.True(await _vaultSystemBackend.SysMountCreate(beName, "transit test backend", EnumSecretBackendTypes.Transit));
			Assert.True(await _vaultSystemBackend.SysMountCreate(oldName, "transit test backend", EnumSecretBackendTypes.Transit));
		}


        #region Auth_Tests

        [Test]
		// Make sure that the JSON constructor will set the path and name value correctly.
		public void AuthMethod_JSONConstructor_SetsNameAndPathCorrectly () {
			string path = "test2/";
			string name = path.Substring(0, path.Length - 1);
			AuthMethod am = new AuthMethod(path, EnumAuthMethods.Kubernetes);

			Assert.AreEqual(path, am.Path);
			Assert.AreEqual(name, am.Name);
		}



		[Test]
		// Make sure that the non-JSON constructor will set the path and name value correctly.
		public void AuthMethod_Constructor_SetsNameAndPathCorrectly() {
			string path = "test2/";
			string name = path.Substring(0, path.Length - 1);
			AuthMethod am = new AuthMethod(path, EnumAuthMethods.Kubernetes);

			Assert.AreEqual(path, am.Path);
			Assert.AreEqual(name, am.Name);
		}



		[Test]
		// Make sure that specifying a name value will build the appropriate path value.
		public void AuthMethod_Constructor_SetsNameAndPathCorrectly_WhenProvidedName() {
			string name = "test2";
			string path = name + "/";
			AuthMethod am = new AuthMethod(name, EnumAuthMethods.Kubernetes);

			Assert.AreEqual(path, am.Path);
			Assert.AreEqual(name, am.Name);
		}


		[Test]
		// Make sure we can set path and name properties and they will update the other property.
		public void AuthMethod_PathAndNameProperties_SetCorrectly () {
			string name = "test2";
			string path = name + "/";
			AuthMethod am = new AuthMethod(name, EnumAuthMethods.Kubernetes);

			string newName = "ABC";
			am.Name = newName;
			Assert.AreEqual(newName, am.Name);
			Assert.AreEqual(newName + "/", am.Path);

			string newPath = "ZXY/";
			am.Path = newPath;
			Assert.AreEqual(newPath, am.Path);
			Assert.AreEqual(newPath.Substring(0, newPath.Length - 1), am.Name);
		}



		[Test]
		// we do not allow an empty path/name value when calling the non JSON constructor.
		public void AuthMethod_NormlConstructor_ThrowsOnInvalidPathArgument () {
			string path = "";
			Assert.Throws<ArgumentException>(() => new AuthMethod(path, EnumAuthMethods.GitHub));

			Assert.Throws<ArgumentException>(() => new AuthMethod(null, EnumAuthMethods.GitHub));
		}



		[Test]
		// The JSON constructor must accept a null value for path as the Vault API does not return the path value inside the objects JSON value, but rather
		// outside it as the dictionary key...
		public void AuthMethod_JSONConstructor_AcceptsNullPath() {
			Assert.DoesNotThrow(() => new AuthMethod(null, AuthMethodEnumConverters.EnumAuthMethodsToString(EnumAuthMethods.AppRole)));
		}



		[Test]
		// Make sure the enum to string converters are working correctly.
		[TestCase(EnumAuthMethods.AppRole,"approle")]
		[TestCase(EnumAuthMethods.AWS, "aws")]
		[TestCase(EnumAuthMethods.GoogleCloud, "gcp")]
		[TestCase(EnumAuthMethods.GitHub, "github")]
		[TestCase(EnumAuthMethods.Kubernetes, "kubernetes")]
		[TestCase(EnumAuthMethods.LDAP, "ldap")]
		[TestCase(EnumAuthMethods.Okta, "okta")]
		[TestCase(EnumAuthMethods.TLSCertificates, "cert")]
		[TestCase(EnumAuthMethods.UsernamePassword, "userpass")]
		public void AuthMethod_ConstructViaString (EnumAuthMethods i,string val) {
			AuthMethod am = new AuthMethod(_uniqueKeys.GetKey("TST") ,val);
			Assert.AreEqual(i, am.Type);
		}



		[Test]
		[TestCase(EnumAuthMethods.AppRole, "approle")]
		[TestCase(EnumAuthMethods.AWS, "aws")]
		[TestCase(EnumAuthMethods.GoogleCloud, "gcp")]
		[TestCase(EnumAuthMethods.GitHub, "github")]
		[TestCase(EnumAuthMethods.Kubernetes, "kubernetes")]
		[TestCase(EnumAuthMethods.LDAP, "ldap")]
		[TestCase(EnumAuthMethods.Okta, "okta")]
		[TestCase(EnumAuthMethods.TLSCertificates, "cert")]
		[TestCase(EnumAuthMethods.UsernamePassword, "userpass")]
		public void AuthMethod_ConstructViaEnum_Success (EnumAuthMethods i, string val) {
			string sPath = "GHI" + i.ToString();
			AuthMethod am = new AuthMethod(sPath,i);
			Assert.AreEqual(am.TypeAsString,val);
		}



		[Test]
		[TestCase(EnumAuthMethods.LDAP)]
		[TestCase(EnumAuthMethods.Okta)]
		[TestCase(EnumAuthMethods.TLSCertificates)]
		[TestCase(EnumAuthMethods.UsernamePassword)]
		[TestCase(EnumAuthMethods.AppRole)]
		[TestCase(EnumAuthMethods.AWS)]
		[TestCase(EnumAuthMethods.GoogleCloud)]
		[TestCase(EnumAuthMethods.GitHub)]
		[TestCase(EnumAuthMethods.Kubernetes)]
		// Test that we can enable an authentication method with the provided name and no config options.  We test all possible authentication methods.
		//public async Task SystemBE_Auth_Enable_NoConfigOptions_Works([Range((int)EnumAuthMethods.AppRole, (int)EnumAuthMethods.Token)] EnumAuthMethods auth) {
		public async Task Auth_Enable_NoConfigOptions_Works (EnumAuthMethods auth) {
			string a = Guid.NewGuid().ToString();
			string c = a.Substring(0, 5);
			string sPath = c + (int)auth;

			Debug.WriteLine("NBoConfig:  Path = " + sPath);
			AuthMethod am = new AuthMethod(sPath, auth);
			Assert.True(await _vaultSystemBackend.AuthEnable(am));

		}



		[Test]
		public async Task Auth_Enable_ConfigOptions ()
		{
		    string key = _uniqueKeys.GetKey("TST");
			AuthMethod am = new AuthMethod(key,EnumAuthMethods.AppRole);
			am.Config.DefaultLeaseTTL = "120";
			am.Config.MaxLeaseTTL = "240";
			Assert.True(await _vaultSystemBackend.AuthEnable(am));
		}



		[Test]
		public async Task Auth_Disable_Works () {
			string key = _uniqueKeys.GetKey("TST");
            AuthMethod am = new AuthMethod(key, EnumAuthMethods.AppRole);
			Assert.True(await _vaultSystemBackend.AuthEnable(am));
			Assert.True(await _vaultSystemBackend.AuthDisable(am));	
		}



		[Test]
		public async Task Auth_EnableDisableValidated () {
			string name = _uniqueKeys.GetKey("TST");
            AuthMethod am = new AuthMethod(name,EnumAuthMethods.AppRole);
			string path = am.Path;
			Debug.WriteLine("EnDisValid: Enabling first");
			Assert.True(await _vaultSystemBackend.AuthEnable(am));

			// Now get listing of methods and search for our test one.
			Debug.WriteLine("EnDisValid: Getting List.");
			Dictionary<string, AuthMethod> authMethods = await _vaultSystemBackend.AuthListAll();
			Assert.NotNull(authMethods);
			Assert.That(authMethods, Contains.Key(path));

			
			// Now disable and verify it is not in list.
			Debug.WriteLine("EnDisValid:  Disabling...");
			Assert.True(await _vaultSystemBackend.AuthDisable(am));
			Debug.WriteLine("EnDisValid:  Get new list LatestMethods...");
			Dictionary<string, AuthMethod> latestMethods = await _vaultSystemBackend.AuthListAll();
			Debug.WriteLine("EnDisValid:  Final Asserts");
			Assert.NotNull(latestMethods);
			Assert.That(latestMethods, !Contains.Key(path));
		}
		#endregion


		#region "AuditTests"
		[Test]
		public async Task CanEnableAndDisableAuditing () {
			string name = _uniqueKeys.GetKey("audit");
			string path = @"C:\temp\" + DateTime.Now.ToString("yyyy_MM_dd_HH_mm_ss_audit.log");

			Assert.True(await _vaultSystemBackend.AuditEnableFileDevice(name, path),"M1: Unable to enable audit device");

			Assert.True(await _vaultSystemBackend.AuditDisable(name), "M2: Unable to delete the audit device");
		}

		#endregion
	}

}