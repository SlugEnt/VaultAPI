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
	[Parallelizable]
    public class VaultSysTests
    {
		// Used for testing so we do not need to create the backend everytime.
		SysBackend vsb;
		Object vsbLocker = new Object();


		[OneTimeSetUp]
		public void SystemTestInit() {
			if (vsb == null) {
				lock(vsbLocker) {
					vsb = new SysBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);
				}
			}
		}


        [Test, Order(1)]
        public void VaultSetupTest()
        {
			// Make sure we have a root token and an ip address.
			Assert.AreNotEqual(VaultServerRef.rootToken, "");
			Assert.AreNotEqual(VaultServerRef.ipAddress, "");
        }



		[Test, Order(1)]
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



		//[Test, Order(50)]
		public async Task SystemBE_CanEnableTransitBackend () {
			// Utilize System Backend to mount a new Transit Engine at transit_B
			SysBackend newBE = new SysBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);
			SysBackend oldBE = new SysBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

			// Generate a hopefully small unique name.
			string beName = "transit" + Guid.NewGuid().ToString().Substring(0, 6);
			string oldName = "tr455" + Guid.NewGuid().ToString().Substring(0, 6);
			Assert.True(await newBE.SysMountEnable(beName, "transit test backend", EnumBackendTypes.Transit));
			Assert.True(await oldBE.SysMountEnable(oldName, "transit test backend", EnumBackendTypes.Transit));
		}


		#region Policy_Tests
		[Test, Order(1)]
		public void SystemBE_VaultPolicyPath_InitialFields_AreCorrect () {
			VaultPolicyPath vpp = new VaultPolicyPath("ABC");

			Assert.False(vpp.CreateAllowed,"Create Not False");
			Assert.False(vpp.DeleteAllowed, "Delete Not False");
			Assert.False(vpp.ListAllowed, "List Not False");
			Assert.False(vpp.ReadAllowed, "Read Not False");
			Assert.False(vpp.RootAllowed, "Root Not False");
			Assert.False(vpp.SudoAllowed, "Sudo Not False");
			Assert.False(vpp.UpdateAllowed, "Update Not False");

			// Denied is true initially.
			Assert.True(vpp.Denied, "Denied Not True");
		}



		[Test, Order(1)]
		// Test that setting capabilities to true works.
		public void SystemBE_VaultPolicyPath_SettingTrueToFieldsWorks () {
			VaultPolicyPath vpp = new VaultPolicyPath("ABC");
			vpp.CreateAllowed = true;
			Assert.True(vpp.CreateAllowed, "Create Allowed was not True");
			Assert.False(vpp.Denied, "Denied should have been set to false on Create true");

			VaultPolicyPath vpp2 = new VaultPolicyPath("ABC");
			vpp2.DeleteAllowed = true;
			Assert.True(vpp2.DeleteAllowed, "Delete Allowed was not True");
			Assert.False(vpp.Denied, "Denied should have been set to false on Delete true");

			VaultPolicyPath vpp3 = new VaultPolicyPath("ABC");
			vpp3.Denied = true;
			Assert.True(vpp3.Denied, "Denied was not True after explicitly setting it");

			VaultPolicyPath vpp4 = new VaultPolicyPath("ABC");
			vpp4.ListAllowed = true;
			Assert.True(vpp4.ListAllowed, "List Allowed was not True");
			Assert.False(vpp.Denied, "Denied should have been set to false on list true");

			VaultPolicyPath vpp5 = new VaultPolicyPath("ABC");
			vpp5.ReadAllowed = true;
			Assert.True(vpp5.ReadAllowed, "Read Allowed was not True");
			Assert.False(vpp.Denied, "Denied should have been set to false on read true");

			VaultPolicyPath vpp6 = new VaultPolicyPath("ABC");
			vpp6.RootAllowed = true;
			Assert.True(vpp6.RootAllowed, "Root Allowed was not True");
			Assert.False(vpp.Denied, "Denied should have been set to false on root true");

			VaultPolicyPath vpp7 = new VaultPolicyPath("ABC");
			vpp7.SudoAllowed = true;
			Assert.True(vpp7.SudoAllowed, "SUDO Allowed was not True");
			Assert.False(vpp.Denied, "Denied should have been set to false on sudo true");

			VaultPolicyPath vpp8 = new VaultPolicyPath("ABC");
			vpp8.UpdateAllowed = true;
			Assert.True(vpp8.UpdateAllowed, "Update Allowed was not True");
			Assert.False(vpp.Denied, "Denied should have been set to false on update true");
		}



		[Test, Order(1)]
		public void SystemBE_VaultPolicyPath_SetDenied_SetsEverythingElseToFalse () {
			VaultPolicyPath vpp = new VaultPolicyPath("ABC");
			vpp.CreateAllowed = true;
			vpp.ReadAllowed = true;
			vpp.UpdateAllowed = true;
			

			Assert.True(vpp.CreateAllowed, "Create Allowed was not True");
			Assert.True(vpp.ReadAllowed, "Read Allowed was not True");
			Assert.True(vpp.UpdateAllowed, "Update Allowed was not True");

			// Now set Denied.  Make sure the above are false.
			vpp.Denied = true;
			Assert.False(vpp.CreateAllowed, "Create Allowed was not set to False");
			Assert.False(vpp.ReadAllowed, "Read Allowed was not set to False");
			Assert.False(vpp.UpdateAllowed, "Update Allowed was not set to False");
		}



		[Test, Order(1)]
		public void SystemBE_VaultPolicyPath_ConstructorSetsPath () {
			VaultPolicyPath vpp = new VaultPolicyPath("ABC");
			Assert.AreEqual("ABC", vpp.Path);
		}



		[Test, Order(2001)]
		public async Task SystemBE_CanCreateAPolicy_WithSingleVaultPolicyItem () {
			// Create a Vault Policy Path Item
			VaultPolicyPath vpi = new VaultPolicyPath("secret/TestA");
			vpi.DeleteAllowed = true;

			// Create a Vault Policy Item
			VaultPolicy VP = new VaultPolicy("TestingABC");
			VP.PolicyPaths.Add(vpi);
			bool rc = await vsb.SysPoliciesACLCreate(VP);
		}



		[Test, Order(2001)]
		public async Task SystemBE_CanCreateAPolicy_WithMultipleVaultPolicyItems() {
			// Create multiple Vault Policy Path Items
			VaultPolicyPath vpi1 = new VaultPolicyPath("secret/TestA");
			vpi1.DeleteAllowed = true;
			vpi1.ReadAllowed = true;
			vpi1.CreateAllowed = true;

			VaultPolicyPath vpi2 = new VaultPolicyPath("secret/TestB");
			vpi2.ListAllowed = true;

			VaultPolicyPath vpi3 = new VaultPolicyPath("secret/TestC");
			vpi3.ListAllowed = true;
			vpi3.DeleteAllowed = true;
			vpi3.ReadAllowed = true;
			vpi3.SudoAllowed = true;

			VaultPolicyPath vpi4 = new VaultPolicyPath("secret/TestD");
			vpi4.DeleteAllowed = true;


			// Create a Vault Policy Item and add the policy paths.
			VaultPolicy VP = new VaultPolicy("TestingABCD");
			VP.PolicyPaths.Add(vpi1);
			VP.PolicyPaths.Add(vpi2);
			VP.PolicyPaths.Add(vpi3);
			VP.PolicyPaths.Add(vpi4);

			Assert.True(await vsb.SysPoliciesACLCreate(VP));
		}



		[Test, Order(15)]
		public async Task SystemBE_Policy_CanReadSinglePathPolicy () {
			VaultPolicy VP = new VaultPolicy("Test2000A");

			VaultPolicyPath vpi3 = new VaultPolicyPath("secret/Test2000A");
			vpi3.ListAllowed = true;
			vpi3.DeleteAllowed = true;
			vpi3.ReadAllowed = true;
			vpi3.SudoAllowed = true;
			VP.PolicyPaths.Add(vpi3);

			Assert.True(await vsb.SysPoliciesACLCreate(VP));


			// Now lets read it back. 
			VaultPolicy vpNew = await vsb.SysPoliciesACLRead("Test2000A");

			Assert.AreEqual(1, vpNew.PolicyPaths.Count);
			Assert.AreEqual(vpi3.ListAllowed, vpNew.PolicyPaths[0].ListAllowed);
			Assert.AreEqual(vpi3.DeleteAllowed, vpNew.PolicyPaths[0].DeleteAllowed);
			Assert.AreEqual(vpi3.ReadAllowed, vpNew.PolicyPaths[0].ReadAllowed);
			Assert.AreEqual(vpi3.SudoAllowed, vpNew.PolicyPaths[0].SudoAllowed);
		}




		[Test, Order(15)]
		// Can read a policy that has multiple paths attached to it.
		public async Task SystemBE_Policy_CanReadMultiplePathPolicy() {
			// Create a Vault Policy Item and add the policy paths.
			VaultPolicy VP = new VaultPolicy("Test2000B");


			string path1 = "secret/Test2000B1";
			VaultPolicyPath vpi1 = new VaultPolicyPath(path1);
			vpi1.ListAllowed = true;
			vpi1.DeleteAllowed = true;
			vpi1.ReadAllowed = true;
			vpi1.SudoAllowed = true;
			VP.PolicyPaths.Add(vpi1);

			// 2nd policy path
			string path2 = "secret/Test2000B2";
			VaultPolicyPath vpi2 = new VaultPolicyPath(path2);
			vpi2.Denied = true;
			VP.PolicyPaths.Add(vpi2);


			// 3rd policy path
			string path3 = "secret/Test2000B3";
			VaultPolicyPath vpi3 = new VaultPolicyPath(path3);
			vpi3.ListAllowed = true;
			vpi3.ReadAllowed = true;
			vpi3.UpdateAllowed = true;
			VP.PolicyPaths.Add(vpi3);

			Assert.True(await vsb.SysPoliciesACLCreate(VP));


			// Now lets read it back. 
			VaultPolicy vpNew = await vsb.SysPoliciesACLRead("Test2000B");

			Assert.AreEqual(3, vpNew.PolicyPaths.Count);
			foreach (VaultPolicyPath item in vpNew.PolicyPaths) {
				if (item.Path == path1) {
					Assert.AreEqual(vpi1.ListAllowed, item.ListAllowed);
					Assert.AreEqual(vpi1.DeleteAllowed, item.DeleteAllowed);
					Assert.AreEqual(vpi1.ReadAllowed, item.ReadAllowed);
					Assert.AreEqual(vpi1.SudoAllowed, item.SudoAllowed);
				}
				else if (item.Path == path2) {
					Assert.AreEqual(vpi2.Denied, item.Denied);
				}
				else if (item.Path == path3) {
					Assert.AreEqual(vpi3.ListAllowed, item.ListAllowed);
					Assert.AreEqual(vpi3.ReadAllowed, item.ReadAllowed);
					Assert.AreEqual(vpi3.UpdateAllowed, item.UpdateAllowed);
					Assert.AreEqual(vpi3.CreateAllowed, false);
					Assert.AreEqual(vpi3.DeleteAllowed, false);
					Assert.AreEqual(vpi3.SudoAllowed, false);
					Assert.AreEqual(vpi3.Denied, false);
				}
				// If here, something is wrong.
				else { Assert.True(false, "invalid path returned of {0}",item.Path); }
			}
		}




		[Test, Order(15)]
		public async Task SystemBE_Policy_ListReturnsPolicies () {
			// Ensure there is at least one policy saved.
			VaultPolicy VP = new VaultPolicy("listPolicyA");
			VaultPolicyPath vpi = new VaultPolicyPath("secret/listpol2000A");
			vpi.ListAllowed = true;
			VP.PolicyPaths.Add(vpi);

			Assert.True(await vsb.SysPoliciesACLCreate(VP));

			// Now get a list of policies.
			List<string> polList = await vsb.SysPoliciesACLList();
			Assert.True(polList.Count > 0);
		}




		[Test, Order(15)]
		// Providing a valid policy name results in returning true.
		public async Task SystemBE_Policy_CanDelete_ValidPolicyName () {
			// Create a policy to delete
			VaultPolicy VP = new VaultPolicy("deletePolicyA");
			VaultPolicyPath vpi = new VaultPolicyPath("secret/Test2000A");
			vpi.ListAllowed = true;
			VP.PolicyPaths.Add(vpi);

			Assert.True(await vsb.SysPoliciesACLCreate(VP));

			// Now delete it.
			Assert.True(await vsb.SysPoliciesACLDelete(VP.Name));
		}



		
		[Test, Order(15)]
		// Providing an invalid policy name returns false.
		public async Task SystemBE_Policy_Delete_InvalidPolicyName_ReturnsTrue () {
			Assert.True(await vsb.SysPoliciesACLDelete("invalidName"));
		}
		#endregion


		#region Auth_Tests

		[Test, Order(0)]
		// Make sure that the JSON constructor will set the path and name value correctly.
		public void SystemBE_AuthMethod_JSONConstructor_SetsNameAndPathCorrectly () {
			string path = "test2/";
			string name = path.Substring(0, path.Length - 1);
			AuthMethod am = new AuthMethod(path, EnumAuthMethods.Kubernetes);

			Assert.AreEqual(path, am.Path);
			Assert.AreEqual(name, am.Name);
		}



		[Test, Order(0)]
		// Make sure that the non-JSON constructor will set the path and name value correctly.
		public void SystemBE_AuthMethod_Constructor_SetsNameAndPathCorrectly() {
			string path = "test2/";
			string name = path.Substring(0, path.Length - 1);
			AuthMethod am = new AuthMethod(path, EnumAuthMethods.Kubernetes);

			Assert.AreEqual(path, am.Path);
			Assert.AreEqual(name, am.Name);
		}



		[Test, Order(0)]
		// Make sure that specifying a name value will build the appropriate path value.
		public void SystemBE_AuthMethod_Constructor_SetsNameAndPathCorrectly_WhenProvidedName() {
			string name = "test2";
			string path = name + "/";
			AuthMethod am = new AuthMethod(name, EnumAuthMethods.Kubernetes);

			Assert.AreEqual(path, am.Path);
			Assert.AreEqual(name, am.Name);
		}


		[Test, Order(0)]
		// Make sure we can set path and name properties and they will update the other property.
		public void SystemBE_AuthMethod_PathAndNameProperties_SetCorrectly () {
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



		[Test, Order(0)]
		// we do not allow an empty path/name value when calling the non JSON constructor.
		public void SystemBE_AuthMethod_NormlConstructor_ThrowsOnInvalidPathArgument () {
			string path = "";
			Assert.Throws<ArgumentException>(() => new AuthMethod(path, EnumAuthMethods.GitHub));

			Assert.Throws<ArgumentException>(() => new AuthMethod(null, EnumAuthMethods.GitHub));
		}



		[Test, Order(0)]
		// The JSON constructor must accept a null value for path as the Vault API does not return the path value inside the objects JSON value, but rather
		// outside it as the dictionary key...
		public void SystemBE_AuthMethod_JSONConstructor_AcceptsNullPath() {
			Assert.DoesNotThrow(() => new AuthMethod(null, AuthMethodEnumConverters.EnumAuthMethodsToString(EnumAuthMethods.AppRole)));
		}



		[Test,Order(1)]
		// Make sure the enum to string converters are working correctly.
		[TestCase(EnumAuthMethods.AppRole,"approle")]
		[TestCase(EnumAuthMethods.AWS, "aws")]
		[TestCase(EnumAuthMethods.GoogleCloud, "gcp")]
		[TestCase(EnumAuthMethods.GitHub, "github")]
		[TestCase(EnumAuthMethods.Kubernetes, "kubernetes")]
		[TestCase(EnumAuthMethods.LDAP, "ldap")]
		[TestCase(EnumAuthMethods.Okta, "okta")]
		//[TestCase(EnumAuthMethods.Radius, "radius")]
		[TestCase(EnumAuthMethods.TLSCertificates, "cert")]
		[TestCase(EnumAuthMethods.UsernamePassword, "userpass")]
		public void SystemBE_AuthMethod_ConstructViaString (EnumAuthMethods i,string val) {
			AuthMethod am = new AuthMethod("test",val);
			Assert.AreEqual(i, am.Type);
		}



		[Test,Order(1)]
		[TestCase(EnumAuthMethods.AppRole, "approle")]
		[TestCase(EnumAuthMethods.AWS, "aws")]
		[TestCase(EnumAuthMethods.GoogleCloud, "gcp")]
		[TestCase(EnumAuthMethods.GitHub, "github")]
		[TestCase(EnumAuthMethods.Kubernetes, "kubernetes")]
		[TestCase(EnumAuthMethods.LDAP, "ldap")]
		[TestCase(EnumAuthMethods.Okta, "okta")]
		//[TestCase(EnumAuthMethods.Radius, "radius")]
		[TestCase(EnumAuthMethods.TLSCertificates, "cert")]
		[TestCase(EnumAuthMethods.UsernamePassword, "userpass")]
		public void SystemBE_AuthMethod_ConstructViaEnum (EnumAuthMethods i, string val) {
			string sPath = "GHI" + i.ToString();
			AuthMethod am = new AuthMethod(sPath,i);
			Assert.AreEqual(am.TypeAsString,val);
		}



		[Test, Order(0)]
		[TestCase(EnumAuthMethods.LDAP)]
		[TestCase(EnumAuthMethods.Okta)]
		//[TestCase(EnumAuthMethods.Radius)]
		[TestCase(EnumAuthMethods.TLSCertificates)]
		[TestCase(EnumAuthMethods.UsernamePassword)]
		[TestCase(EnumAuthMethods.AppRole)]
		// Token can no longer be instantiated.  It is an automatic entry.
		//[TestCase(EnumAuthMethods.Token)]
		[TestCase(EnumAuthMethods.AWS)]
		[TestCase(EnumAuthMethods.GoogleCloud)]
		[TestCase(EnumAuthMethods.GitHub)]
		[TestCase(EnumAuthMethods.Kubernetes)]
		// Test that we can enable an authentication method with the provided name and no config options.  We test all possible authentication methods.
		//public async Task SystemBE_Auth_Enable_NoConfigOptions_Works([Range((int)EnumAuthMethods.AppRole, (int)EnumAuthMethods.Token)] EnumAuthMethods auth) {
		public async Task SystemBE_Auth_Enable_NoConfigOptions_Works (EnumAuthMethods auth) {
			string a = Guid.NewGuid().ToString();
			string c = a.Substring(0, 5);
			string sPath = c + (int)auth;

			Debug.WriteLine("NBoConfig:  Path = " + sPath);
			AuthMethod am = new AuthMethod(sPath, auth);
			Assert.True(await vsb.AuthEnable(am));

		}



		[Test,Order(110)]
		public async Task SystemBE_Auth_Enable_ConfigOptions () {
			AuthMethod am = new AuthMethod("TST2110A",EnumAuthMethods.AppRole);
			am.Config.DefaultLeaseTTL = "120";
			am.Config.MaxLeaseTTL = "240";
			Assert.True(await vsb.AuthEnable(am));
		}



		[Test,Order(9)]
		public async Task SystemBE_Auth_Disable_Works () {
			SystemTestInit();
			try {
				AuthMethod am = new AuthMethod("TST2110B2", EnumAuthMethods.AppRole);
				Assert.True(await vsb.AuthEnable(am));
				Assert.True(await vsb.AuthDisable(am));
			}
			catch (Exception e) { }
		}



		[Test,Order(9)]
		public async Task SystemBE_Auth_EnableDisableValidated () {
			string name = "TST2BZZ3";
			AuthMethod am = new AuthMethod(name,EnumAuthMethods.AppRole);
			string path = am.Path;
			Debug.WriteLine("EnDisValid: Enabling first");
			Assert.True(await vsb.AuthEnable(am));

			// Now get listing of methods and search for our test one.
			Debug.WriteLine("EnDisValid: Getting List.");
			Dictionary<string, AuthMethod> authMethods = await vsb.AuthListAll();
			Assert.NotNull(authMethods);
			Assert.That(authMethods, Contains.Key(path));

			
			// Now disable and verify it is not in list.
			Debug.WriteLine("EnDisValid:  Disableing...");
			Assert.True(await vsb.AuthDisable(am));
			Debug.WriteLine("EnDisValid:  Get new list LatestMethods...");
			Dictionary<string, AuthMethod> latestMethods = await vsb.AuthListAll();
			Debug.WriteLine("EnDisValid:  Final Asserts");
			Assert.NotNull(latestMethods);
			Assert.That(latestMethods, !Contains.Key(path));
		}
		#endregion
	}

}