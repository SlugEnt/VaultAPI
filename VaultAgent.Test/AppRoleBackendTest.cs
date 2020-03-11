using System;
using System.Collections.Generic;
using System.Diagnostics;
using NUnit.Framework;
using System.Threading.Tasks;
using VaultAgent.Backends.System;
using VaultAgent.Backends;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Models;
using SlugEnt;


namespace VaultAgentTests
{
	/// <summary>
	/// Tests the AppRole authentication backend.
	/// </summary>
	[TestFixture]
	[Parallelizable]
    public class AppRoleAuthEngineTest
    {
		private VaultAgentAPI _vault;
		private VaultSystemBackend _vaultSystemBackend;
		private UniqueKeys _uniqueKeys = new UniqueKeys("_","__");       // Unique Key generator

		private AppRoleAuthEngine _appRoleAuthEngine;


		[OneTimeSetUp]
		public async Task AppRoleAuthEngineSetup () {
			// Build Connection to Vault.
            _vault = await VaultServerRef.ConnectVault("AppRoleVault");
			//_vault = new VaultAgentAPI("AppRoleVault", VaultServerRef.ipAddress, VaultServerRef.ipPort);  //, VaultServerRef.rootToken,true);
            _vaultSystemBackend = new VaultSystemBackend(_vault.TokenID, _vault);
            

			string approleMountName = _uniqueKeys.GetKey("AppAuth");


			// Create an AppRole authentication connection.
			_appRoleAuthEngine = (AppRoleAuthEngine) _vault.ConnectAuthenticationBackend (EnumBackendTypes.A_AppRole,"AppRole",approleMountName);
			

			// Create an Authentication method of App Role.	- This only needs to be done when the Auth method is created.  
			AuthMethod am = new AuthMethod(approleMountName, EnumAuthMethods.AppRole);		    
			bool rc = await _vaultSystemBackend.AuthEnable(am);
		}



		// Validate we can talk to the Vault Default AppRole backend at the default mount location.
	    [Test]
	    public async Task MountDefaultAppRoleMount_Success() {
			AppRoleAuthEngine defaultBE = (AppRoleAuthEngine) _vault.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole);
			AuthMethod defaultAM = new AuthMethod(defaultBE.MountPoint,EnumAuthMethods.AppRole);
		    try {
			    Assert.True(await _vaultSystemBackend.AuthEnable(defaultAM));
		    }
		    catch (VaultException e) {
				if (e.SpecificErrorCode == EnumVaultExceptionCodes.BackendMountAlreadyExists) { 
					// Disable and re-enable to confirm we can do this.
				    Assert.True(await _vaultSystemBackend.AuthDisable(defaultAM));
				    Assert.True(await _vaultSystemBackend.AuthEnable(defaultAM));
				}
			    else {
				    Assert.Fail("Unexpected Vault Error - " + e.Message);
			    }
		    }
		    catch (Exception e) {
			    Assert.Fail("Unexpected error from Vault: " + e.Message);

		    }
			

		    string name = _uniqueKeys.GetKey("RoleDef");
		    AppRole ar = new AppRole(name);
		    Assert.True(await _appRoleAuthEngine.SaveRole(ar));
		}



		// Validates that enabling an authentication engine twice at the same mount point produces the desired error.
	    [Test]
	    public async Task EnablingABackendTwice_ProducesExpectedError() {
		    string engineName = _uniqueKeys.GetKey("engA");
		    AppRoleAuthEngine engA = (AppRoleAuthEngine) _vault.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, engineName, engineName);
		    AuthMethod authMethodA = new AuthMethod(engA.MountPoint, EnumAuthMethods.AppRole);

			// First time should succed.  Second should fail.
		    for (int i = 0; i < 2; i++) {
			    try {
				    Assert.True((await _vaultSystemBackend.AuthEnable(authMethodA)));
			    }
			    catch (VaultException e) {
					Assert.AreEqual(e.SpecificErrorCode, EnumVaultExceptionCodes.BackendMountAlreadyExists);
			    }
		    }
	    }



	    [Test]
		public void AppRoleName_IsConvertedToLowerCase() {
			string name = _uniqueKeys.GetKey("Role");
			AppRole ar = new AppRole(name);
			Assert.AreEqual(name.ToLower(), ar.Name);
		}



		[Test]
		public void AppRolePropertyName_IsConvertedToLowerCase() {
			string name = _uniqueKeys.GetKey("Role");
			AppRole ar = new AppRole("abc");
			ar.Name = name;
			Assert.AreEqual(name.ToLower(), ar.Name);
		}



		// Validate we can create an application role.
		[Test]
		public async Task CreateARole_Success () {
			string name = _uniqueKeys.GetKey("Role");
			
			AppRole ar = new AppRole(name); 
			Assert.True(await _appRoleAuthEngine.SaveRole(ar));
		}



		// Validate we can read a role back and its name is lowercase and set.
		[Test]
		public async Task CreateAndReadBack_Success () {
			string rName = _uniqueKeys.GetKey("Role");
			AppRole ar = new AppRole(rName);
			Assert.True(await _appRoleAuthEngine.SaveRole(ar));

			AppRole arReturn = await (_appRoleAuthEngine.ReadRole(rName));
			Assert.NotNull(arReturn);
			Assert.AreEqual(ar.Name, arReturn.Name);
		}




		[Test]
		public async Task DeleteRoleThatExists_Success () {
			string rName = _uniqueKeys.GetKey("Role");

			AppRole ar = new AppRole(rName);
			Assert.True(await _appRoleAuthEngine.SaveRole(ar));

			// Delete it.
			Assert.True(await _appRoleAuthEngine.DeleteRole(ar));
		}


		// Validate that deleting a nonexistent role still returns True
		[Test]
		public async Task AppRoleBE_DeleteRoleThatDoesNotExist_ReturnsTrue () {
			string rName = _uniqueKeys.GetKey("Role");
			Assert.True(await _appRoleAuthEngine.DeleteRole(rName));
		}



		[Test]
		public async Task CreateRoleThatAlreadyExists () {
			string rName = _uniqueKeys.GetKey("Role");
			AppRole ar = new AppRole(rName) {
				NumberOfUses = 100
			};
			Assert.True(await _appRoleAuthEngine.SaveRole(ar));

			// Read the role back
			AppRole ar2 = await (_appRoleAuthEngine.ReadRole(rName));
			Assert.AreEqual(100, ar2.NumberOfUses);

			// Change value - and recreate
			ar2.NumberOfUses = 200;
			Assert.True(await _appRoleAuthEngine.SaveRole(ar2));

			// Read the role back
			AppRole ar3 = await (_appRoleAuthEngine.ReadRole(rName));
			Assert.AreEqual(ar.Name, ar3.Name);
			Assert.AreEqual(200, ar3.NumberOfUses);
			Assert.AreEqual((ar.NumberOfUses + 100), ar3.NumberOfUses);
		}



		// Runs thru an entire AppRole Sequence:  Create, List - Confirm its there
		// Delete, List - Confirm its gone.
		[Test]
		public async Task CreateListDeleteList_CycleValidated () {
			string rName = "roleCycle";
			AppRole ar = new AppRole(rName);
			Assert.True(await _appRoleAuthEngine.SaveRole(ar));

			List<string> appRoles = await _appRoleAuthEngine.ListRoles();
			int startCount = appRoles.Count;
			Assert.True(appRoles.Count > 0);
			Assert.That(appRoles, Contains.Item(rName.ToLower()));

			Assert.True(await _appRoleAuthEngine.DeleteRole(ar));

			List<string> appRoles2 = await _appRoleAuthEngine.ListRoles();
			int endCount = appRoles2.Count;
			Assert.AreEqual((startCount -1),endCount);
			Assert.That(appRoles2, !Contains.Item(rName.ToLower()));
		}



		// Validates we can read a role ID that exists.
		[Test]
		public async Task ReadValidRoleID_Returns_RoleID () {
			string rName = _uniqueKeys.GetKey("Role");

			AppRole ar = new AppRole(rName);
			Assert.True(await _appRoleAuthEngine.SaveRole(ar));

			string Id = await _appRoleAuthEngine.ReadRoleID(rName);
			Assert.NotNull(Id);
		}

/* VDRO-B conversion tests - not needed anymore
	    // Validates we can read a role ID that exists.
	    [Test]
	    public async Task ReadValidRoleID_Returns_RoleID_B() {
		    string rName = _uniqueKeys.GetKey("Role");

		    AppRole ar = new AppRole(rName);
		    Assert.True(await _appRoleAuthEngine.SaveRole(ar));

		    string Id = await _appRoleAuthEngine.ReadRoleID_B(rName);
		    Assert.NotNull(Id);
	    }
*/


		// Validates that asking for an invalid roleID returns an empty string if it does not exist.
		[Test]
	    public async Task ReadNonExistantRoleID_ReturnsEmptyString () {
		    string rName = _uniqueKeys.GetKey("Role");
		    string Id = await _appRoleAuthEngine.ReadRoleID(rName);
		    Assert.NotNull(Id, "A1:  Expected an empty string, but was null instead");
		    Assert.IsEmpty(Id, "A2:  Expected an empty string, but the ID returned was: " + Id);
		}



		// Validates that we can set a new RoleID for a given application.
		[Test]
		public async Task AppRoleBE_UpdateRoleID() {
			string rName = _uniqueKeys.GetKey("Role");
			AppRole ar = new AppRole(rName);
			Assert.True(await _appRoleAuthEngine.SaveRole(ar));

			// Now read a Role ID for it.
			string roleID = await _appRoleAuthEngine.ReadRoleID(ar.Name);

			// Update the role ID
			Assert.True(await _appRoleAuthEngine.UpdateAppRoleID(ar.Name, "newDomain"));
			string roleIDNew = await _appRoleAuthEngine.ReadRoleID(ar.Name);
			Assert.AreEqual("newDomain", roleIDNew);
		}



		// Validate that All the parameters of an App Role can be stored in the Vault instance and read back.
		[Test]
		public async Task CreateReadAppRoleAllParams () {
			string rName = _uniqueKeys.GetKey("Role");

			//TODO - Add All of the List objects - BoundCIDRList, TokenBoundCIDRList...
			AppRole ar = new AppRole {
				Name = rName,
				IsSecretIDRequiredOnLogin = true,
				SecretNumberOfUses = 3,
				SecretTTL = "60",
				NumberOfUses = 9,
				TokenTTL = "900",
				TokenMaxTTL = "1240",
				Period = "3600"
			};

			// Create
			Assert.True(await _appRoleAuthEngine.SaveRole(ar));

			// Read
			AppRole rr = await _appRoleAuthEngine.ReadRole(rName);

			// Validate
			Assert.AreEqual(ar.Name, rr.Name, "App Role Name stored in Vault is not same as we sent it!");
			Assert.AreEqual(ar.IsSecretIDRequiredOnLogin,rr.IsSecretIDRequiredOnLogin, "IsSecretIDRequiredOnLogin value stored in Vault is not same as we sent it!");
			Assert.AreEqual(ar.SecretNumberOfUses, rr.SecretNumberOfUses, "SecretNumberOfUses stored in Vault is not same as we sent it!");
			Assert.AreEqual(ar.SecretTTL, rr.SecretTTL, "SecretTTL stored in Vault is not same as we sent it!");
			Assert.AreEqual(ar.NumberOfUses, rr.NumberOfUses, "NumberOfUses stored in Vault is not same as we sent it!");
			Assert.AreEqual(ar.TokenTTL, rr.TokenTTL, "TokenTTL stored in Vault is not same as we sent it!");
			Assert.AreEqual(ar.TokenMaxTTL, rr.TokenMaxTTL, "TokenMaxTTL stored in Vault is not same as we sent it!");
			Assert.AreEqual(ar.Period, rr.Period, "Period stored in Vault is not same as we sent it!");
		}



		/// <summary>
		/// At present Vault does not allow the EnableLocalSecretIDs value to be true.  Testing to make sure if we set this to true it generates an error.
		/// </summary>
		[Test]
		public void SettingEnableLocalSecretIDS_ThrowsError() {
			string name = Guid.NewGuid().ToString();

			Assert.Throws<NotImplementedException>(() =>
				new AppRole {
					Name = name,
					EnableLocalSecretIDs = true
				});
		}


		// Validates we can set MetaData on a secret.
	    [Test]
	    public async Task GenerateSecret_WithMetaData_Success() {
		    string rName = _uniqueKeys.GetKey("Role");
		    AppRole roleA = new AppRole(rName);
		    Assert.True(await _appRoleAuthEngine.SaveRole(roleA));


			// Build a Meta Data object
			Dictionary<string,string> metadata = new Dictionary<string, string>() 
		    {
			    { "testKey","dev"},
			    { "Name","Bob Jones"}
		    };


		    // Get a secret for it
		    AppRoleSecret appRoleSecret = await _appRoleAuthEngine.GenerateSecretID(roleA.Name,true,metadata);
		    Assert.NotNull(appRoleSecret);
		    Assert.IsNotEmpty(appRoleSecret.ID);
		    Assert.IsNotEmpty(appRoleSecret.Accessor);
			CollectionAssert.AreEquivalent(metadata,appRoleSecret.Metadata,"A10:  Expected the 2 metadata collections to be the same.");

	        TestContext.WriteLine("Auth Engine Mount Point:  {0}  |  Mount Point Path:  {1}", _appRoleAuthEngine.MountPoint, _appRoleAuthEngine.MountPointPath);
	        TestContext.WriteLine("Role A:     {0}", roleA.Name);
	        TestContext.WriteLine("Secret ID:  {0}", appRoleSecret.ID);
            foreach (KeyValuePair<string,string> a in appRoleSecret.Metadata)
	        {
	            TestContext.WriteLine("MetaData:   {0} - {1}", a.Key,a.Value);
            }        
        }



        // Validates the ReadSecretID routine returns all of a secret's properties
        [Test]
        public async Task ReadSecretID_Success()
        {
            string rName = _uniqueKeys.GetKey("Role");
            AppRole roleA = new AppRole(rName);
            Assert.True(await _appRoleAuthEngine.SaveRole(roleA));


	        // Build a Meta Data object
	        Dictionary<string, string> metadata = new Dictionary<string, string>()
	        {
		        { "testKey","dev"},
		        { "Name","Bob Jones"}
	        };

			// Get a secret for it - GenerateSecretID with True setting performs the ReadSecret
			AppRoleSecret appRoleSecret = await _appRoleAuthEngine.GenerateSecretID(roleA.Name, false, metadata);
            Assert.NotNull(appRoleSecret,"A10:  appRoleSecret was null.");
            Assert.IsNotEmpty(appRoleSecret.ID,"A20:  Secret ID was empty.");
            Assert.IsNotEmpty(appRoleSecret.Accessor, "A30:  Secret Accessor was not set to a valid value");

            // Now read the secret back.
            AppRoleSecret secretFull = await _appRoleAuthEngine.ReadSecretID(roleA.Name, appRoleSecret.ID);

            Assert.AreEqual(appRoleSecret.ID,secretFull.ID,"A40:  Secret ID's were not the same");
	        CollectionAssert.AreEquivalent(metadata, secretFull.Metadata, "A50:  Expected the 2 metadata collections to be the same.");

			TestContext.WriteLine("Auth Engine Mount Point:  {0}  |  Mount Point Path:  {1}", _appRoleAuthEngine.MountPoint, _appRoleAuthEngine.MountPointPath);
            TestContext.WriteLine("Role A:     {0}", roleA.Name);
            TestContext.WriteLine("Secret ID:  {0}", appRoleSecret.ID);
            foreach (KeyValuePair<string, string> a in appRoleSecret.Metadata)
            {
                TestContext.WriteLine("MetaData:   {0} - {1}", a.Key, a.Value);
            }
        }



        // Validate that the routine will return the secret ID accessors attached to a given role.
        // We will create 2 app roles.  Then we will create 3 secrets against 1 role and 1 secret against the other role
        //Then we will confirm that the routine will list the correct 3 secrets for the one role and one secret for the other.
        [Test]
        public async Task ListSecretIDAccessors_Success()
        {
            string roleName_A = _uniqueKeys.GetKey("RoleAC");
            string roleName_B = _uniqueKeys.GetKey("RoleAC");

            AppRole roleA = new AppRole(roleName_A);
            AppRole roleB = new AppRole(roleName_B);

            Assert.True(await _appRoleAuthEngine.SaveRole(roleA));
            Assert.True(await _appRoleAuthEngine.SaveRole(roleB));


            // Now create the 4 secrets
            AppRoleSecret secret_A1 = await _appRoleAuthEngine.GenerateSecretID(roleA.Name);
            AppRoleSecret secret_A2 = await _appRoleAuthEngine.GenerateSecretID(roleA.Name);
            AppRoleSecret secret_A3 = await _appRoleAuthEngine.GenerateSecretID(roleA.Name);
            AppRoleSecret secret_B1 = await _appRoleAuthEngine.GenerateSecretID(roleB.Name);


            // Acquire the list of secrets.
            List<string> secrets_A = await _appRoleAuthEngine.ListSecretIDAccessors(roleA.Name);
            List<string> secrets_B = await _appRoleAuthEngine.ListSecretIDAccessors(roleB.Name);

            // Make sure the counts and the correct secrets are in each list.
            Assert.AreEqual(3,secrets_A.Count);
            Assert.AreEqual(1,secrets_B.Count);

            Assert.Contains(secret_A1.Accessor,secrets_A);
            Assert.Contains(secret_A2.Accessor, secrets_A);
            Assert.Contains(secret_A3.Accessor, secrets_A);

            Assert.Contains(secret_B1.Accessor, secrets_B);

            TestContext.WriteLine("Auth Engine Mount Point:  {0}  |  Mount Point Path:  {1}", _appRoleAuthEngine.MountPoint,_appRoleAuthEngine.MountPointPath);
            TestContext.WriteLine("Role A:     {0}",roleA.Name);
            TestContext.WriteLine("Role A:     {0}", roleB.Name);
            TestContext.WriteLine("Secret A1:  ID: {0}  |  Accessor: {1}",secret_A1.ID,  secret_A1.Accessor);
            TestContext.WriteLine("Secret A2:  ID: {0}  |  Accessor: {1}", secret_A2.ID, secret_A2.Accessor);
            TestContext.WriteLine("Secret A3:  ID: {0}  |  Accessor: {1}", secret_A3.ID, secret_A3.Accessor);
            TestContext.WriteLine("Secret B1:  ID: {0}  |  Accessor: {1}", secret_B1.ID, secret_B1.Accessor);
        }



		// Validate that attempting to delete a secret that does exist will actually delete the secret.
	    [Test]
	    public async Task DeleteSecret_ThatExists_Success() {
		    string roleName_A = _uniqueKeys.GetKey("RDel");
		    AppRole roleA = new AppRole(roleName_A);
		    Assert.True(await _appRoleAuthEngine.SaveRole(roleA), "A1: Saving the role failed.");

		    // Now create the a secret
		    AppRoleSecret secret_A = await _appRoleAuthEngine.GenerateSecretID(roleA.Name);

			Assert.True(await _appRoleAuthEngine.DeleteSecretID(roleA.Name,secret_A.ID),"A2: Deleting the secret failed");
			Assert.IsNull(await _appRoleAuthEngine.ReadSecretID(roleA.Name, secret_A.ID),"A3: Expected to not find the given secret.  But instead was returned a secret.  Delete did not work?");
	    }



		// Validate that attempting to delete a secret that does not exist returns True.
	    [Test]
	    public async Task DeleteSecret_ThatDoesNotExist_ReturnsTrue() {
		    string roleName_A = _uniqueKeys.GetKey("RDel");
		    AppRole roleA = new AppRole(roleName_A);

		    Assert.True(await _appRoleAuthEngine.SaveRole(roleA), "A1: Saving the role failed.");
			Assert.True(await _appRoleAuthEngine.DeleteSecretID(roleA.Name, "invalid_secretAFF"), "A1: Deleting the secret failed");
	    }



		// Validate we can login.
	    [Test]
	    public async Task LoginWithValidCredentials_Success() {
		    string roleName_A = _uniqueKeys.GetKey("RLogin");
		    AppRole roleA = new AppRole(roleName_A);

		    Assert.True(await _appRoleAuthEngine.SaveRole(roleA), "A1: Saving the role failed.");

			// Read the role ID back.
		    string roleID = await _appRoleAuthEngine.ReadRoleID(roleA.Name);
			
		    // Now create the a secret
		    AppRoleSecret secret_A = await _appRoleAuthEngine.GenerateSecretID(roleA.Name);


			// Now attempt to login - We need to create a new vault object or else we will screw with the other tests, since a successful login changes the token.
            VaultAgentAPI v = new VaultAgentAPI("logintest",VaultServerRef.ipAddress,VaultServerRef.ipPort);
	        AppRoleAuthEngine eng1 =  (AppRoleAuthEngine) v.ConnectAuthenticationBackend (EnumBackendTypes.A_AppRole, "Test", _appRoleAuthEngine.MountPoint);

	        Token token = await eng1.Login (roleID, secret_A.ID);

/*		    bool rc;
		    rc = await _appRoleAuthEngine.Login(roleID, secret_A.ID);

		    Assert.True(rc);
*/
            Assert.IsNotNull(token,"A1:  A token was not returned.  The login failed.");
            Assert.IsNotEmpty(token.ID,"A2:  A token was returned, but it did not have an ID value.");
	    }



        // Validate that logging in with an invalid Secret ID and RoleID generate correct errors
        [Test]
        public async Task LoginWithInvalidCredentials_GeneratesExpectedError()
        {
            string roleName_A = _uniqueKeys.GetKey("FailLogin");
            AppRole roleA = new AppRole(roleName_A);

            Assert.True(await _appRoleAuthEngine.SaveRole(roleA), "A1: Saving the role failed.");

            // Read the role ID back.
            string roleID = await _appRoleAuthEngine.ReadRoleID(roleA.Name);

            // Now create the a secret
            AppRoleSecret secret_A = await _appRoleAuthEngine.GenerateSecretID(roleA.Name);


            // Now attempt to login
            VaultInvalidDataException e = Assert.ThrowsAsync<VaultInvalidDataException> (async () => await _appRoleAuthEngine.Login (roleID, ""),
                "A1: Expected Login with bad Secret to throw the [VaultInvalidDataException] but it did not.");
            Assert.AreEqual(EnumVaultExceptionCodes.LoginSecretID_NotFound,e.SpecificErrorCode,"A2: Expected to see the specificErrorCode field set to [LoginSecretID_NotFound] but it was set to "+ e.SpecificErrorCode);

            // Now try with invalid Role ID.
            VaultInvalidDataException e2 = Assert.ThrowsAsync<VaultInvalidDataException>(async () => await _appRoleAuthEngine.Login("", secret_A.ID),
                "A1: Expected Login with bad RoleID to throw the [VaultInvalidDataException] but it did not.");
            Assert.AreEqual(EnumVaultExceptionCodes.LoginRoleID_NotFound, e2.SpecificErrorCode, "A2: Expected to see the specificErrorCode field set to [LoginRoleID_NotFound] but it was set to " + e2.SpecificErrorCode);
        }



        // Validate that the RoleExists method returns true if a role exists and false if it does not.
        [Test]
	    public async Task RoleExists_ReturnsCorrectValues() {
		    string rName = _uniqueKeys.GetKey("Role");

			AppRole appRole = new AppRole(rName);
		    Assert.True(await _appRoleAuthEngine.SaveRole(appRole));

			// Check existence
		    Assert.True(await _appRoleAuthEngine.RoleExists(rName));

			// Now check for a role that does not exist.
		    string badName = _uniqueKeys.GetKey("badRole");
			Assert.False(await _appRoleAuthEngine.RoleExists(badName));
	    }



		[Test]
		// Validate that the SaveRole
	    public async Task SaveRoleAndReturnNewAppRoleObject_Success() {
		    string roleName_A = _uniqueKeys.GetKey("RLogin");
		    AppRole roleA = new AppRole(roleName_A);


		    AppRole newRole = (await _appRoleAuthEngine.SaveRoleAndReturnRoleObject(roleA));  //   .SaveRole(roleA), "A1: Saving the role failed.");

			Assert.AreEqual(roleA.Name,newRole.Name,"A1:  Expected the role names to be equal.");
			Assert.IsNotEmpty(newRole.RoleID);
		}



		// Validate that RoleID is empty string upon creation of an AppRole object.
		[Test]
	    public void AppRole_RoleID_Empty_OnConstruction() {
		    AppRole approle = new AppRole();
			Assert.AreEqual("",approle.RoleID);
	    }



		//Validates that the ListRoles Command works
	    [Test, Order(100)]
	    public async Task ListRoles_Works () {
		    short i;
		    string [] roleNames = new string[10];

		    for ( i = 0; i < 10; i++ ) {
			    string name = _uniqueKeys.GetKey("LR").ToLower();
			    roleNames [i] = name;
				AppRole appRole = new AppRole(name);
			    Assert.True(await _appRoleAuthEngine.SaveRole(appRole),"A10:  Failed to save the appRole");
			}

		    List<string> appRoles = await _appRoleAuthEngine.ListRoles();
			Assert.AreEqual(i,appRoles.Count,"A20:  Expected the listed roles to be equal to the number created.");
			CollectionAssert.AreEquivalent(roleNames,appRoles,"A30:  Collections were not the same.");
		}
		/*
	    //Validates that the ListRoles Command works
	    [Test]
	    public async Task ListRolesB_Works() {
		    short i;
		    string[] roleNames = new string[10];

		    for (i = 0; i < 10; i++) {
			    string name = _uniqueKeys.GetKey("LR").ToLower();
			    roleNames[i] = name;
			    AppRole appRole = new AppRole(name);
			    Assert.True(await _appRoleAuthEngine.SaveRole(appRole), "A10:  Failed to save the appRole");
		    }

		    List<string> appRoles = await _appRoleAuthEngine.ListRoles_B();
		    Assert.AreEqual(i, appRoles.Count, "A20:  Expected the listed roles to be equal to the number created.");
		    CollectionAssert.AreEquivalent(roleNames, appRoles, "A30:  Collections were not the same.");
	    }
		*/

	}
}
