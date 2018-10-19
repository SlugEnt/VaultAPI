using System;
using System.Collections.Generic;
using NUnit.Framework;
using System.Threading.Tasks;
using VaultAgent.Backends.System;
using VaultAgent.Backends;
using VaultAgent;
using VaultAgent.AuthenticationEngines;

namespace VaultAgentTests
{
	[TestFixture]
	[Parallelizable]
    public class AppRoleAuthEngineTest
    {
		private VaultAgentAPI vault;
		private VaultSystemBackend VSB;
		private UniqueKeys UK = new UniqueKeys();       // Unique Key generator

		private AppRoleAuthEngine _ARB;


		[OneTimeSetUp]
		public async Task AppRoleAuthEngineSetup () {
			// Build Connection to Vault.
			vault = new VaultAgentAPI("AppRoleVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);


			string _AppRoleName = UK.GetKey("AppR");
			string approleMountName = UK.GetKey("AppAuth");

			// Create the AppRole Mount Point
			_ARB = (AppRoleAuthEngine) vault.ConnectAuthenticationBackend (EnumBackendTypes.A_AppRole,"AppRole",approleMountName);

			

			// Create an Authentication method of App Role.
			
			AuthMethod am = new AuthMethod(approleMountName, EnumAuthMethods.AppRole);

			// Ensure we have an authentication method of AppRole enabled on the Vault.
			//VaultSystemBackend VSB = new VaultSystemBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);
		    VaultSystemBackend VSB = vault.System;

			bool rc = await VSB.AuthEnable(am);
		}



		[Test]
		public void AppRoleBE_AppRole_NameIsLowerCase() {
			string name = UK.GetKey("Role");
			AppRole ar = new AppRole(name);
			Assert.AreEqual(name.ToLower(), ar.Name);
		}



		[Test]
		public void AppRoleBE_AppRole_PropertyNameIsLowerCase() {
			string name = UK.GetKey("Role");
			AppRole ar = new AppRole("abc");
			ar.Name = name;
			Assert.AreEqual(name.ToLower(), ar.Name);
		}



		[Test]
		public async Task AppRoleBE_CreateRole () {
			string name = UK.GetKey("Role");
			
			AppRole ar = new AppRole(name); 
			Assert.True(await _ARB.CreateRole(ar));
		}



		// Validate we can read a role back and its name is lowercase and set.
		[Test]
		public async Task AppRoleBE_ReadRole () {
			string rName = UK.GetKey("Role");
			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			AppRole arReturn = await (_ARB.ReadAppRole(rName));
			Assert.NotNull(arReturn);
			Assert.AreEqual(ar.Name, arReturn.Name);
		}




		[Test]
		public async Task AppRoleBE_DeleteRoleThatExists () {
			string rName = UK.GetKey("Role");

			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			// Delete it.
			Assert.True(await _ARB.DeleteAppRole(ar));
		}



		public async Task AppRoleBE_DeleteRoleThatDoesNotExist_ReturnsTrue () {
			string rName = UK.GetKey("Role");
			Assert.True(await _ARB.DeleteAppRole(rName));
		}



		[Test, Order(1000)]
		public async Task AppRoleBE_CreateRoleThatAlreadyExists () {
			string rName = UK.GetKey("Role");
			AppRole ar = new AppRole(rName) {
				NumberOfUses = 100
			};
			Assert.True(await _ARB.CreateRole(ar));

			// Read the role back
			AppRole ar2 = await (_ARB.ReadAppRole(rName));
			Assert.AreEqual(100, ar2.NumberOfUses);

			// Change value - and recreate
			ar2.NumberOfUses = 200;
			Assert.True(await _ARB.CreateRole(ar2));

			// Read the role back
			AppRole ar3 = await (_ARB.ReadAppRole(rName));
			Assert.AreEqual(ar.Name, ar3.Name);
			Assert.AreEqual(200, ar3.NumberOfUses);
			Assert.AreEqual((ar.NumberOfUses + 100), ar3.NumberOfUses);
		}



		// Runs thru an entire AppRole Sequence:  Create, List - Confirm its there
		// Delete, List - Confirm its gone.
		[Test]
		public async Task AppRoleBE_CreateListDeleteList_CycleValidated () {
			string rName = "roleCycle";
			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			List<string> appRoles = await _ARB.ListRoles();
			int startCount = appRoles.Count;
			Assert.True(appRoles.Count > 0);
			Assert.That(appRoles, Contains.Item(rName.ToLower()));

			Assert.True(await _ARB.DeleteAppRole(ar));

			List<string> appRoles2 = await _ARB.ListRoles();
			int endCount = appRoles2.Count;
			Assert.AreEqual((startCount -1),endCount);
			Assert.That(appRoles2, !Contains.Item(rName.ToLower()));
		}




		[Test]
		public async Task AppRoleBE_GetRoleID () {
			string rName = UK.GetKey("Role");

			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			string Id = await _ARB.GetRoleID(rName);
			Assert.NotNull(Id);
		}



		[Test]
		public async Task AppRoleBE_UpdateRoleID() {
			string rName = UK.GetKey("Role");
			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			// Now read a Role ID for it.
			string roleID = await _ARB.GetRoleID(ar.Name);

			// Update the role ID
			Assert.True(await _ARB.UpdateAppRoleID(ar.Name, "newDomain"));
			string roleIDNew = await _ARB.GetRoleID(ar.Name);
			Assert.AreEqual("newDomain", roleIDNew);
		}


		[Test]
		public async Task AppRoleBE_CreateSecret () {
			string rName = UK.GetKey("Role");
			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			// Get a secret for it
			AppRoleSecret ars = await _ARB.CreateSecretID(ar.Name);
			Assert.NotNull(ars);
			Assert.IsNotEmpty(ars.ID);
			Assert.IsNotEmpty(ars.Accessor);
		}


		[Test]
		public async Task AppRoleBE_CreateReadAppRoleAllParams () {
			string rName = UK.GetKey("Role");

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
			Assert.True(await _ARB.CreateRole(ar));

			// Read
			AppRole rr = await _ARB.ReadAppRole(rName);

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
		public void AppRoleBE_SettingEnableLocalSecretIDS_ThrowsError() {
			string name = Guid.NewGuid().ToString();

			Assert.Throws<NotImplementedException>(() =>
				new AppRole {
					Name = name,
					EnableLocalSecretIDs = true
				});
		}
	}
}
