using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Backends;
using VaultAgent.Backends.System;
using VaultAgent.Models;
using VaultAgent.SecretEngines;
using VaultAgent.SecretEngines.KV2;
using VaultAgentTests;
using SlugEnt;

namespace VaultAgentTests
{
    /// <summary>
    /// This test suite fully exercises the KeyValue Version 2 secret store as well as security policies against that secret store. 
    /// </summary>
	[TestFixture]
	[Parallelizable]
	public class PolicyKV2_Tests {
		
		private VaultAgentAPI _vaultAgentAPI;
		private VaultSystemBackend _vaultSystemBackend;
		private UniqueKeys _uniqueKeys = new UniqueKeys("_","__"); // Unique Key generator
		private string _beName;
		private KV2SecretEngine _rootEng;
		private VaultAgentAPI _vaultRootAgentAPI;

		private List<VaultAgentAPI> _vaultAgents;


      
        /// <summary>
        /// Reusable method that updates the provided secret and then returns the updated version.
        /// </summary>
        /// <param name="secret"></param>
        /// <returns></returns>
        private async Task<KV2Secret> UpdateSecretRandom(KV2Secret secret)
	    {
	        secret.Attributes.Add(_uniqueKeys.GetKey("attr"), "val");
	        Assert.True(await _rootEng.SaveSecret(secret, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, secret.Version), "UpdateSecretRandom:  Failed to save correctly.");
	        return await _rootEng.ReadSecret(secret);
	    }



        [OneTimeSetUp]
		public async Task Backend_Init() {
			if (_vaultSystemBackend != null) {
				return;
			}

			// Build Connection to Vault.
			_vaultAgentAPI = new VaultAgentAPI("PolicyBE", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);

			// Create a new system Backend Mount for this series of tests.
			_vaultSystemBackend = _vaultAgentAPI.System;


			// Create the backend.
			_beName = _uniqueKeys.GetKey("beP");
			VaultSysMountConfig testBE = new VaultSysMountConfig();
			Assert.True(await _vaultSystemBackend.SysMountCreate(_beName, "KeyValue2 Policy Testing Backend", EnumSecretBackendTypes.KeyValueV2),
				"A10:  Enabling backend " + _beName + " failed.");

			// Create the Root Engine that we will use 
			_vaultRootAgentAPI = new VaultAgentAPI("Root", _vaultAgentAPI.IP, _vaultAgentAPI.Port, _vaultAgentAPI.Token.ID);
			_rootEng = (KV2SecretEngine)_vaultRootAgentAPI.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, _beName, _beName);

			_vaultAgents = new List<VaultAgentAPI>();
		}




		/// <summary>
		/// Routine to be used prior to each test to setup the test.
		/// </summary>
		/// <returns></returns>
		private async Task<(string policyPath, KV2Secret secret)> SetupIndividualTestAsync() {
			string pathAppFolder = _uniqueKeys.GetKey("appA");
			string policyAppPath = "data/apps/" + pathAppFolder + "/*";
			string secretRoot = "apps/";
			string secretBaseFolder = secretRoot + pathAppFolder;

			// Create our base secret path.

			// Save Secret for base path.
			KV2Secret secretA = new KV2Secret("secretA", secretBaseFolder);
			secretA.Attributes.Add("attrA", "valueA");
			secretA.Attributes.Add("attrB", "valueB");
			Assert.True(await _rootEng.SaveSecret(secretA, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A30:  Unable to save the Initial Base Secret Path.");


			// BA - Validate that the secret actually was written and can be read by the root token.
			KV2Secret secret;
			secret = await _rootEng.ReadSecret(secretA);
			Assert.AreEqual(secretA.Attributes.Count, secret.Attributes.Count, "A100:  Secret Attributes are not equal.  This is not the secret we saved.");


			return (policyAppPath, secret);
		}




		// Create the token engines for a successful test and then the control test.
		private async Task<(KV2SecretEngine engKV2OK, KV2SecretEngine engKV2FAIL)> SetupTokenEngines(string policyWithPermission) {
			// Get connection to Token Engine so we can create tokens.
			TokenAuthEngine tokenEng = (TokenAuthEngine)_vaultAgentAPI.ConnectAuthenticationBackend(EnumBackendTypes.A_Token);

			// AA - The token that will have the policy.
			TokenNewSettings tokenASettings = new TokenNewSettings();
			tokenASettings.Policies.Add(policyWithPermission);
			Token tokenOK = await tokenEng.CreateToken(tokenASettings);

			// AB - The token that will not have the policy.
			TokenNewSettings tokenBSettings = new TokenNewSettings();
			tokenBSettings.Policies.Add("default");
			Token tokenFAIL = await tokenEng.CreateToken(tokenBSettings);


			// AC - Create 2 Vault Instances that will use each Token.
			VaultAgentAPI vaultOK = new VaultAgentAPI("OKToken", _vaultAgentAPI.IP, _vaultAgentAPI.Port, tokenOK.ID);
			VaultAgentAPI vaultFail = new VaultAgentAPI("FAILToken", _vaultAgentAPI.IP, _vaultAgentAPI.Port, tokenFAIL.ID);
			_vaultAgents.Add(vaultOK);
			_vaultAgents.Add(vaultFail);


			// AD - Create the KeyValue Engines for each Token
			KV2SecretEngine engKV2OK = (KV2SecretEngine)vaultOK.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, _beName, _beName);
			KV2SecretEngine engKV2FAIL = (KV2SecretEngine)vaultFail.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, _beName, _beName);

			return (engKV2OK, engKV2FAIL);
		}



		private async Task<(VaultPolicyContainer polContainer, VaultPolicyPathItem vppi)> SetupPolicy(string policyAppPath) {
			// B.  Lets create a policy for root path.
			VaultPolicyPathItem vppi = new VaultPolicyPathItem(_beName, policyAppPath);
			vppi.Denied = true;

			// C.  Create the Actual Policy container
			string polName = _uniqueKeys.GetKey("polCon");
			VaultPolicyContainer polCon1 = new VaultPolicyContainer(polName);
			polCon1.AddPolicyPathObject(vppi);

			// D.  Save Policy to Vault Instance.
			Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(polCon1), "SetupPolicy: A10:  Saving the initial policy to Vault Instance failed.");

			return (polCon1, vppi);
		}



		// Validates that the initial test scenario is correct.  Both tokens should have no access.
		[Test]
		public async Task InitialTokenAccess_IsDeniedForBothTokens() {
			// Setup basics.
			(string policyPath, KV2Secret origSecret) = await SetupIndividualTestAsync();

			// Setup Policy
			(VaultPolicyContainer polContainer, VaultPolicyPathItem vppi) = await SetupPolicy(policyPath);

			// Setup the Test Engines, One has a good token and one has a control token.
			(KV2SecretEngine engOK, KV2SecretEngine engFail) = await SetupTokenEngines(polContainer.Name);


			//**************************************
			// Actual Test
			// Neither token should have access to the Secret's base path as we did not provide permission. Lets Test.
			KV2Secret secret = null;
			try { secret = await engOK.ReadSecret(origSecret); }
			catch (VaultForbiddenException e) {
				Assert.AreEqual(EnumVaultExceptionCodes.PermissionDenied, e.SpecificErrorCode, "A105:  Expected permission denied error, received something else.");
			}
			Assert.IsNull(secret, "A110:  Expected the Secret to not be found.  But it seems we found one.  Something is wrong with permissions.");
			try { secret = await engFail.ReadSecret(origSecret); }
			catch (VaultForbiddenException e) {
				Assert.AreEqual(EnumVaultExceptionCodes.PermissionDenied, e.SpecificErrorCode, "A115:  Expected permission denied error, received something else.");
			}
			Assert.IsNull(secret, "A120:  Expected the Secret to not be found.  But it seems we found one.  Something is wrong with permissions.");
		}




		// Validates that the initial test scenario is correct.  Both tokens should have no access.
		[Test]
		public async Task SettingReadAllowed_ProvidesAccessToSecret() {
			// Setup basics.
			(string policyPath, KV2Secret origSecret) = await SetupIndividualTestAsync();

			// Setup Policy
			(VaultPolicyContainer polContainer, VaultPolicyPathItem vppi) = await SetupPolicy(policyPath);

			// Setup the Test Engines, One has a good token and one has a control token.
			(KV2SecretEngine engOK, KV2SecretEngine engFail) = await SetupTokenEngines(polContainer.Name);


			//**************************************
			// Actual Test
			// Provide access to Read for the OK Token.
			vppi.Denied = true;
			vppi.ReadAllowed = true;
			Assert.True(await _vaultSystemBackend.SysPoliciesACLUpdate(polContainer), "A125:  Updating the policy to Vault Instance failed.");


			// BD - Now the OK token should have access.
			KV2Secret secret = null;
			try { secret = await engOK.ReadSecret(origSecret); }
			catch (VaultForbiddenException) {
				Assert.Fail("A130:  Received a Vault forbidden exception.  Was not expected it to fail.");
			}
			Assert.IsNotNull(secret, "A132:  Expected the Secret to be found and successfully read.  We did not find a secret object.  Something is wrong with permissions.");


			// Validate the control is still in place - Should fail.
			secret = null;
			try { secret = await engFail.ReadSecret(origSecret); }
			catch (VaultForbiddenException e) {
				Assert.AreEqual(EnumVaultExceptionCodes.PermissionDenied, e.SpecificErrorCode, "A134:  Expected permission denied error, received something else.");
			}
			Assert.IsNull(secret, "A136:  Expected the Secret to not be found.  But it seems we found one.  Something is wrong with permissions.");
		}



		// Validates that the initial test scenario is correct.  Both tokens should have no access.
		[Test]
		public async Task SettingUpdatellowed_ProvidesAbilityToUpdateSecret() {
			// Setup basics.
			(string policyPath, KV2Secret origSecret) = await SetupIndividualTestAsync();

			// Setup Policy
			(VaultPolicyContainer polContainer, VaultPolicyPathItem vppi) = await SetupPolicy(policyPath);

			// Setup the Test Engines, One has a good token and one has a control token.
			(KV2SecretEngine engOK, KV2SecretEngine engFail) = await SetupTokenEngines(polContainer.Name);


			//**************************************
			// Actual Test
			// Provide access to Read for the OK Token.
			vppi.Denied = true;
			vppi.UpdateAllowed = true;
			string attC = "attC";
			string valueC = "valueC";

			int versionNumber = origSecret.Version;


			origSecret.Attributes.Add(attC, valueC);
			VaultForbiddenException e1 = Assert.ThrowsAsync<VaultForbiddenException>(async () => await engOK.SaveSecret(origSecret, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, versionNumber), "A200:  Expected VaultForbidden Error to be thrown.");
			Assert.AreEqual(EnumVaultExceptionCodes.PermissionDenied, e1.SpecificErrorCode, "A202:  Expected PermissionDenied to be set on SpecificErrorCode Field.");


			// CB - Try with the Fail Token - should fail.
			VaultForbiddenException eCB1 = Assert.ThrowsAsync<VaultForbiddenException>(async () => await engFail.SaveSecret(origSecret, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, versionNumber), "A204:  Expected VaultForbidden Error to be thrown.");
			Assert.AreEqual(EnumVaultExceptionCodes.PermissionDenied, eCB1.SpecificErrorCode, "A206:  Expected PermissionDenied to be set on SpecificErrorCode Field.");


			// CC - Update the policy to allow.
			vppi.UpdateAllowed = true;
			Assert.True(await _vaultSystemBackend.SysPoliciesACLUpdate(polContainer), "A208:  Updating the policy object failed.");

			// CD - Retry the save.
			Assert.True(await engOK.SaveSecret(origSecret, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, versionNumber),
				"A209:  Updating of the secret was not successful.  This should have succeeded.");
		}




		// Validates that the initial test scenario is correct.  Both tokens should have no access.
		[Test]
		public async Task SettingDeleteAllowed_ProvidesAbilityToDeleteSecret() {
			// Setup basics.
			(string policyPath, KV2Secret origSecret) = await SetupIndividualTestAsync();

			// Setup Policy
			(VaultPolicyContainer polContainer, VaultPolicyPathItem vppi) = await SetupPolicy(policyPath);

			// Setup the Test Engines, One has a good token and one has a control token.
			(KV2SecretEngine engOK, KV2SecretEngine engFail) = await SetupTokenEngines(polContainer.Name);



			//**************************************
			// Test Setup.  Lets save several versions of the secret.
			KV2Secret secret2 = await UpdateSecretRandom(origSecret);
			secret2 = await UpdateSecretRandom(secret2);
			secret2 = await UpdateSecretRandom(secret2);


			// Failure Test
			VaultForbiddenException eDA1 = Assert.ThrowsAsync<VaultForbiddenException>(async () => await engOK.DeleteSecretVersion(secret2), "A300:  Expected VaultForbidden Error to be thrown.");
			Assert.AreEqual(EnumVaultExceptionCodes.PermissionDenied, eDA1.SpecificErrorCode, "A10:  Expected PermissionDenied to be set on SpecificErrorCode Field.");


			// Change policy
			vppi.Denied = true;
			vppi.DeleteAllowed = true;
			Assert.True(await _vaultSystemBackend.SysPoliciesACLUpdate(polContainer), "A20:  Updating the policy object failed.");


			// Success Test
			Assert.True(await engOK.DeleteSecretVersion(secret2), "A30:  Expected deletion of specific secret version to succeed..");

			// Validate Test.
			Thread.Sleep(200);
			KV2Secret delSecret = await _rootEng.ReadSecret(secret2);
			Assert.IsNull(delSecret, "A40:  Deletion of secret does not appear to have worked.");

		}



		// Validates that the initial test scenario is correct.  Both tokens should have no access.
		[Test]
		public async Task SettingUndeleteAllowed_ProvidesAbilityToUndeleteSecret() {
			// Setup basics.
			(string policyPath, KV2Secret origSecret) = await SetupIndividualTestAsync();

			// Setup Policy
			(VaultPolicyContainer polContainer, VaultPolicyPathItem vppi) = await SetupPolicy(policyPath);

			// Setup the Test Engines, One has a good token and one has a control token.
			(KV2SecretEngine engOK, KV2SecretEngine engFail) = await SetupTokenEngines(polContainer.Name);



			//**************************************
			// Test Setup.  Lets save several versions of the secret.
			KV2Secret secret2 = await UpdateSecretRandom(origSecret);
			secret2 = await UpdateSecretRandom(secret2);
			secret2 = await UpdateSecretRandom(secret2);

			// Delete the latest version.
			int versionNum = secret2.Version;
			Assert.True(await _rootEng.DeleteSecretVersion(secret2,secret2.Version), "A10:  Expected deletion of specific secret version to succeed..");


			// Read it back with the root engine.	
			Thread.Sleep(200);
			KV2Secret delSecret = await _rootEng.ReadSecret(secret2);
			Assert.IsNull(delSecret,"A20:  Deletion of secret does not appear to have worked.");


			// Failure Test
			// Lets try to undelete the secret.
			VaultForbiddenException eDL1 = Assert.ThrowsAsync<VaultForbiddenException>(async () => await engOK.UndeleteSecretVersion(secret2, secret2.Version), "DL10:  Expected VaultForbidden Error to be thrown.");


			// Provide Access
			vppi.Denied = true;
			vppi.ExtKV2_UndeleteSecret = true;
			Assert.True(await _vaultSystemBackend.SysPoliciesACLUpdate(polContainer), "A30:  Updating the policy object failed.");


			// Success Test.
			Assert.True(await engOK.UndeleteSecretVersion(secret2, secret2.Version), "A40:  Expected Undelete to succeed.");


			// Validate - We use the root accessor, since our base token does not have Read Access.
			KV2Secret secret3 = null;
			secret3 = await _rootEng.ReadSecret(secret2);
			Assert.IsNotNull(secret3, "A50:  Expected the Secret to be found and successfully read.  We did not find a secret object.  Something is wrong with permissions.");
			Assert.AreEqual(secret2.Attributes.Count,secret3.Attributes.Count, "A60:  Undeleted version of secret is not same as deleted version.");
		}




		[Test]
		public async Task SettingDestroyAllowed_ProvidesAbilityToDestroySecret() {
			// Setup basics.
			(string policyPath, KV2Secret origSecret) = await SetupIndividualTestAsync();

			// Setup Policy
			(VaultPolicyContainer polContainer, VaultPolicyPathItem vppi) = await SetupPolicy(policyPath);

			// Setup the Test Engines, One has a good token and one has a control token.
			(KV2SecretEngine engOK, KV2SecretEngine engFail) = await SetupTokenEngines(polContainer.Name);



			//**************************************
			// Test Setup.  Lets save several versions of the secret.
			KV2Secret secret2 = await UpdateSecretRandom(origSecret);
			secret2 = await UpdateSecretRandom(secret2);
			secret2 = await UpdateSecretRandom(secret2);


			// Failure Test
			VaultForbiddenException eDT1 = Assert.ThrowsAsync<VaultForbiddenException>(async () => await engOK.DestroySecretVersion(secret2, secret2.Version), "A10:  Expected VaultForbidden Error to be thrown.");
			Assert.AreEqual(EnumVaultExceptionCodes.PermissionDenied, eDT1.SpecificErrorCode, "A20:  Expected Permission Denied to be set on SpecificErrorCode Field.");


			// Provide Access
			vppi.Denied = true;
			vppi.ExtKV2_DestroySecret = true;
			Assert.True(await _vaultSystemBackend.SysPoliciesACLUpdate(polContainer), "A30:  Updating the policy object failed.");

			// Success Test
			Assert.True(await engOK.DestroySecretVersion(secret2, secret2.Version), "A40:  Destroy Secret Specific Version Failed.");

			// Validate - We use the root engine token accessor since our token does not have access.
			KV2Secret desSecret = await _rootEng.ReadSecret(secret2);
			Assert.IsNull(desSecret, "A50:  Expected the Secret to not be found.");
		}


		[Test]
		public async Task DeletionOfSpecificVersions_Success() {
			// Setup basics.
			(string policyPath, KV2Secret origSecret) = await SetupIndividualTestAsync();

			// Setup Policy
			(VaultPolicyContainer polContainer, VaultPolicyPathItem vppi) = await SetupPolicy(policyPath);

			// Setup the Test Engines, One has a good token and one has a control token.
			(KV2SecretEngine engOK, KV2SecretEngine engFail) = await SetupTokenEngines(polContainer.Name);


			// Setup
			// Lets save several versions of the secret.
			KV2Secret secret2 = await UpdateSecretRandom(origSecret);
			KV2Secret secret3 = await UpdateSecretRandom(secret2);
			KV2Secret secret4 = await UpdateSecretRandom(secret3);
			KV2Secret secret5 = await UpdateSecretRandom(secret4);
			KV2Secret secret6 = await UpdateSecretRandom(secret5);


			// Failure Test
			VaultForbiddenException eEC1 = Assert.ThrowsAsync<VaultForbiddenException>(async () => await engOK.DeleteSecretVersion(secret4, secret4.Version), "A10:  Expected VaultForbidden Error to be thrown.");
			Assert.AreEqual(EnumVaultExceptionCodes.PermissionDenied, eEC1.SpecificErrorCode, "A20:  Expected PermissionDenied to be set on SpecificErrorCode Field.");



			// Provide Access
			vppi.Denied = true;
			vppi.ReadAllowed= true;
			vppi.ExtKV2_DeleteAnyKeyVersion = true;
			Assert.True(await _vaultSystemBackend.SysPoliciesACLUpdate(polContainer), "A30:  Updating the policy object failed.");


			// Success Test
			Assert.True(await engOK.DeleteSecretVersion(secret4, secret4.Version), "A40:  Expected deletion of specific secret version to succeed..");


			// Validate
			Thread.Sleep(200);
			KV2Secret secGone = await engOK.ReadSecret(secret4, secret4.Version);
			Assert.IsNull(secGone, "A50:  Expected to not find the given secret.  But found it.  This means it did not get deleted.");
		}



		/// <summary>
		/// This test validates the SysCapabilities method.  In order to do this it must setup a complex scenario:
		/// There are 2 main parts to this scenario.
		///  A: Normal fully specified paths.
		///  B: Templated paths for use with entities.
		/// 
		///   - Create an AppRole backend
		///   - Create a KeyValue V2 backend
		///   - Create a set of policies to secure paths in the backends
		///   - Create an AppRole
		///   - Assign the policies to the approle
		///   - Create a secretID for the AppRole
		///   - Login with that AppRole and secretID to acquire a token.
		///   - Call the method to get the capabilities of the token in regards to each path.
		///
		///  For scenario B.  We create an additional AppRole and a set of templated policies.
		///   - Then acquire a new token tied to an entity and test it's capabilities against the paths.
		/// </summary>
		/// <returns></returns>
		[Test]
	    public async Task TestCapabilitiesFunctionality() {
		    string appBE = _uniqueKeys.GetKey("appBE");
		    string kv2BE = _uniqueKeys.GetKey("kv2BE");


			// 1 - Setup backends needed for testing.
		    // We need to setup a KV2 Secrets engine and also an AppRole Backend.
			// Create an Authentication method of App Role.	- This only needs to be done when the Auth method is created.  
			AuthMethod am = new AuthMethod(appBE, EnumAuthMethods.AppRole);
		    await _vaultAgentAPI.System.AuthEnable(am);

		    // Create a KV2 Secret Mount if it does not exist.           
		    await _vaultAgentAPI.System.SysMountCreate(kv2BE, "ClientTest KeyValue 2 Secrets", EnumSecretBackendTypes.KeyValueV2);

			
			// Now we 
			VaultAgentAPI vault = new VaultAgentAPI("capability", _vaultAgentAPI.IP, _vaultAgentAPI.Port,_vaultAgentAPI.TokenID);
		    AppRoleAuthEngine authEngine = (AppRoleAuthEngine) vault.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, appBE, appBE);
		    KV2SecretEngine secretEngine =
			    (KV2SecretEngine) vault.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, "KV2 Secrets", kv2BE);


			// 2. Setup the policy to provide the permissions to test against.
			VaultPolicyContainer policyContainer = new VaultPolicyContainer("capa");

			VaultPolicyPathItem vppi1 = new VaultPolicyPathItem(kv2BE, "data/app/appA/*");
		    VaultPolicyPathItem vppi2 = new VaultPolicyPathItem( kv2BE + "data/app/appA/subItem/*");
		    VaultPolicyPathItem vppi3 = new VaultPolicyPathItem( kv2BE + "metadata/app/appA/*");
		    VaultPolicyPathItem vppi4 = new VaultPolicyPathItem( kv2BE + "data/shared/*");

			vppi1.FullControl = true;
			vppi2.FullControl = true;
			vppi3.ReadAllowed = true;
			vppi4.ReadAllowed = true;

		    policyContainer.AddPolicyPathObject(vppi1);
		    policyContainer.AddPolicyPathObject(vppi2);
		    policyContainer.AddPolicyPathObject(vppi3);
		    policyContainer.AddPolicyPathObject(vppi4);

		    await _vaultAgentAPI.System.SysPoliciesACLCreate(policyContainer);


			// 3. Now create an App Role & Secret ID
		    string roleName = _uniqueKeys.GetKey("role");
			AppRole appRole = new AppRole(roleName);
			appRole.Policies.Add(policyContainer.Name);
		    appRole = await authEngine.SaveRoleAndReturnRoleObject(appRole);

		    AppRoleSecret secretID = await authEngine.CreateSecretID(appRole.Name);


			// 4.  Now we can create a token against that 
		    Token token = await authEngine.Login(appRole.RoleID, secretID.ID);


			// 5.  Now we can finally test the capabilities of that token.
			List<string> paths = new List<string>();
			string path1 = kv2BE + "/data/app/appA/subItem";
			string path2 = kv2BE + "/data/app/appB/subItem";
			string path3 = kv2BE + "/noaccess/app/appA";
			string path4 = kv2BE + "/data/noaccess/app/appA/subItem";

			paths.Add(path1);
			paths.Add(path2);
			paths.Add(path3);
		    paths.Add(path4);



			Dictionary<string, List<string>> permissions;
		    permissions = await _vaultAgentAPI.System.GetTokenCapabilityOnPaths(token.ID, paths);

			// 6. Validate the results.
			Assert.AreEqual(4,permissions.Count, "A10:  Expected to receive 4 permission objects back.");
			Assert.AreEqual(5,permissions[path1].Count,"A20:  Expected the item: " + path1 + " to contain 5 permissions.");
			Assert.AreEqual(1, permissions[path2].Count, "A30:  Expected the item: " + path2 + " to contain 1 deny permission.");
			CollectionAssert.Contains(permissions[path2],"deny","A35:  Expected the permission to be deny for path: " + path2);
			Assert.AreEqual(1, permissions[path3].Count, "A40:  Expected the item: " + path3 + " to contain 1 deny permission.");
			CollectionAssert.Contains(permissions[path3], "deny", "A35:  Expected the permission to be deny for path: " + path3);
			Assert.AreEqual(1, permissions[path4].Count, "A40:  Expected the item: " + path4 + " to contain 1 deny permission.");
			CollectionAssert.Contains(permissions[path4], "deny", "A35:  Expected the permission to be deny for path: " + path4);
		}



		[Test]
		public async Task TestTemplatedPolicies() {
			string appBE = _uniqueKeys.GetKey("appTE");
			string kv2BE = _uniqueKeys.GetKey("kv2TE");


			// 1A - Setup backends needed for testing.
			// We need to setup a KV2 Secrets engine and also an AppRole Backend.
			// Create an Authentication method of App Role.	- This only needs to be done when the Auth method is created.  
			AuthMethod am = new AuthMethod(appBE, EnumAuthMethods.AppRole);
			await _vaultAgentAPI.System.AuthEnable(am);

			// Create a KV2 Secret Mount if it does not exist.           
			await _vaultAgentAPI.System.SysMountCreate(kv2BE, "ClientTest KeyValue 2 Secrets", EnumSecretBackendTypes.KeyValueV2);




			// 1B. Now we can connect to the backends.
			VaultAgentAPI vault = new VaultAgentAPI("capability", _vaultAgentAPI.IP, _vaultAgentAPI.Port, _vaultAgentAPI.TokenID);
			AppRoleAuthEngine authEngine = (AppRoleAuthEngine)vault.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, appBE, appBE);
			KV2SecretEngine secretEngine =
				(KV2SecretEngine)vault.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, "KV2 Secrets", kv2BE);
			IdentitySecretEngine idEngine = (IdentitySecretEngine)_vaultAgentAPI.ConnectToSecretBackend(EnumSecretBackendTypes.Identity);

			// 1C - Write out some values.
			TestContext.WriteLine("App Role Auth Backend:   {0}", authEngine.Name);
			TestContext.WriteLine("KV2 Secret Backend:      {0}", secretEngine.Name);


			// 2. Setup the policy to provide the permissions to test against.
			VaultPolicyContainer policyContainer = new VaultPolicyContainer("capa");


			// 3. Now create an App Role & Secret ID.  The app role in this case has no policies - it will get them from the Entity.
			string roleName = _uniqueKeys.GetKey("role");
			AppRole appRole = new AppRole(roleName);
			appRole = await authEngine.SaveRoleAndReturnRoleObject(appRole);
			AppRoleSecret secretID = await authEngine.CreateSecretID(appRole.Name);




			// 4.  Create an Entity and Entity Alias.
			// 4A.  Get Authentication backend accessor.
			Dictionary<string, AuthMethod> authMethods = await _vaultAgentAPI.System.AuthListAll();
			AuthMethod authMethod = authMethods[authEngine.Name + "/"];
			Assert.IsNotNull(authMethod,"B10:  Expected to find the authentication backend.  But did not.");
			string mountAccessor = authMethod.Accessor;

			// 4B.  Create an entity for the app role.
			string name = _uniqueKeys.GetKey("EAR");
			Entity entity = new Entity(roleName);
			entity.Policies.Add(policyContainer.Name);

			// 4C.  Now save entity
			entity = await idEngine.SaveEntity(entity);
			Assert.IsNotNull(entity, "B20:  Expected to receive an Entity object");


			// 4D. Write out some values 
			TestContext.WriteLine("Entity Name:      {0}", entity.Name);
			TestContext.WriteLine("Entity ID:        {0}", entity.Id);


			// 5. Create an alias that ties the Entity we just created to the AppRole in the authentication backend.
			Guid roleID = new Guid(appRole.RoleID);
			Guid aliasGuid = await idEngine.SaveAlias(entity.Id, mountAccessor, appRole.RoleID);
			Assert.AreNotEqual(aliasGuid.ToString(), Guid.Empty.ToString());
			
			// 5B.  Re-read the entity - it should now contain the alias.
			Entity fullEntity = await idEngine.ReadEntity(entity.Id);
			Assert.AreEqual(1,fullEntity.Aliases.Count, "B30:  Expected the full entity to now contain the alias ID.");


			// 6.  Now define the policy and save to Vault.
			policyContainer.PolicyPaths.Clear();
			string appPath1 = "app/{{identity.entity.aliases." + mountAccessor + ".name}}/*";
			VaultPolicyPathItem vppi1 = new VaultPolicyPathItem(kv2BE, "data/" + appPath1);
			VaultPolicyPathItem vppi2 = new VaultPolicyPathItem(kv2BE, "data/app/appA/subItem/*");
			VaultPolicyPathItem vppi3 = new VaultPolicyPathItem(kv2BE, "data/shared/common/*");
			VaultPolicyPathItem vppi4 = new VaultPolicyPathItem(kv2BE, "data/shared/info/*");

			vppi1.FullControl = true;
			vppi2.FullControl = true;
			vppi3.CRUDAllowed = true;
			vppi4.ReadAllowed = true;


			policyContainer.AddPolicyPathObject(vppi1);
			policyContainer.AddPolicyPathObject(vppi2);
			policyContainer.AddPolicyPathObject(vppi3);
			policyContainer.AddPolicyPathObject(vppi4);

			await _vaultAgentAPI.System.SysPoliciesACLCreate(policyContainer);


			// 7.  Now we can login to get a token..  Validate the entity policy has been set on token.
			Token token = await authEngine.Login(appRole.RoleID, secretID.ID);
			Assert.IsNotNull("B40:  A valid token was not received.");

			CollectionAssert.Contains(token.IdentityPolicies,policyContainer.Name,"B100:  Did not find the policy that should have been applied from the entity.");


			// 8.  Now we can finally test the capabilities of that token.
			List<string> paths = new List<string>();
			string pathBase = kv2BE + "/data/app/" + fullEntity.Aliases[0].Name + "/config";
			string metaBase = kv2BE + "/metadata/app" + fullEntity.Aliases[0].Name + "/config";
			string path1 = pathBase;
			string path2 = pathBase + "/subItem";
			string path3 = kv2BE + "/data/shared/common/testEntry";
			paths.Add(path1);
			paths.Add(path2);
			paths.Add(path3);


			Dictionary<string, List<string>> permissions;
			permissions = await _vaultAgentAPI.System.GetTokenCapabilityOnPaths(token.ID, paths);


			// 9. Validate the permission results.
			Assert.AreEqual(3, permissions.Count, "B130:  Expected to receive 3 permission objects back.");
			Assert.AreEqual(5, permissions[path1].Count, "B140:  Expected the item: " + path1 + " to contain 5 permissions.");
			Assert.AreEqual(5, permissions[path2].Count, "B150:  Expected the item: " + path2 + " to contain 5 permissions.");
			Assert.AreEqual(4, permissions[path3].Count, "B160:  Expected the item: " + path3 + " to contain 3 permissions.");

			CollectionAssert.Contains(permissions[path3], "create", "B170:  Expected the permission to be create for path: " + path3);
			CollectionAssert.Contains(permissions[path3], "read", "B171:  Expected the permission to be read for path: " + path3);
			CollectionAssert.Contains(permissions[path3], "update", "B172:  Expected the permission to be update for path: " + path3);
			CollectionAssert.Contains(permissions[path3], "delete", "B173:  Expected the permission to be read for path: " + path3);


			// 10. Try to create a secret at path 1
			string secName1 = _uniqueKeys.GetKey("sec1");
			KV2Secret secret1 = new KV2Secret("config", "app/" + fullEntity.Aliases[0].Name);
			secret1.Attributes.Add("version", "v12.2");
			Assert.True(await secretEngine.SaveSecret(secret1, KV2EnumSecretSaveOptions.AlwaysAllow), "B200:  Save of secret did not work.  Check permissions.");


			// 11. Create and delete a secret at path3.
			KV2Secret secret2 = new KV2Secret("options","shared/common/testEntry");
			secret2.Attributes.Add("color","blue");
			secret2.Attributes.Add("size","Large");
			Assert.True(await secretEngine.SaveSecret(secret2,KV2EnumSecretSaveOptions.AlwaysAllow),"B210:  Save of secret2 failed.");

			// Now delete it.
			Assert.True(await secretEngine.DeleteSecretVersion(secret2));


		}

	}
}
