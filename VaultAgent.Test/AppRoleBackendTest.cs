using System;
using System.Collections.Generic;
using VaultAgent.Backends.AppRole;
using NUnit.Framework;
using System.Threading;
using System.Threading.Tasks;
using VaultAgent.Backends.System;
using VaultAgent.Models;

namespace VaultAgentTests
{
	[Parallelizable]
    public class AppRoleBackendTest
    {
		private AppRoleBackEnd _ARB;
		private object _arLocker = new object();
		private string roleName;
		private string _authBEName = "auth2";



		[OneTimeSetUp]
		public async Task AppRoleBackendSetup () {
			// Ensure we have an authentication method of AppRole enabled on the Vault.
			SysBackend VSB = new SysBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);
			AuthMethod am = new AuthMethod(_authBEName, EnumAuthMethods.AppRole);
			bool rc = await VSB.AuthEnable(am);
			AppBackendTestInit();
		}


		[SetUp]
		// Ensure Backend is initialized during each test.
		protected void AppBackendTestInit() {
			lock (_arLocker) {
				if (_ARB == null) {
					roleName = "roleABC";
					_ARB = new AppRoleBackEnd(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, _authBEName);
				}
			}
		}

		[Test,Order(100)]
		public void AppRoleBE_AppRole_NameIsLowerCase() {
			string name = "GGGttRR";
			AppRole ar = new AppRole(name);
			Assert.AreEqual(name.ToLower(), ar.Name);
		}



		[Test, Order(100)]
		public void AppRoleBE_AppRole_PropertyNameIsLowerCase() {
			string name = "GGGttRR";
			AppRole ar = new AppRole("abc");
			ar.Name = name;
			Assert.AreEqual(name.ToLower(), ar.Name);
		}



		[Test,Order(1000)]
		public async Task AppRoleBE_CreateRole () {
			string rName = "hhFFG";
			AppRole ar = new AppRole(rName); 
			Assert.True(await _ARB.CreateRole(ar));
		}



		// Validate we can read a role back and its name is lowercase and set.
		[Test,Order(1000)]
		public async Task AppRoleBE_ReadRole () {
			string rName = "uutts5";
			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			AppRole arReturn = await (_ARB.ReadAppRole(rName));
			Assert.NotNull(arReturn);
			Assert.AreEqual(rName, arReturn.Name);
		}




		[Test,Order(1000)]
		public async Task AppRoleBE_DeleteRoleThatExists () {
			string rName = "roleZYX";
			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			// Delete it.
			Assert.True(await _ARB.DeleteAppRole(ar));
		}



		[Test, Order(1000)]
		public async Task AppRoleBE_DeleteRoleThatDoesNotExist_ReturnsTrue () {
			string rName = "rolezzzzz";
			Assert.True(await _ARB.DeleteAppRole(rName));
		}



		[Test, Order(1000)]
		public async Task AppRoleBE_CreateRoleThatAlreadyExists () {
			string rName = "gg443";
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
		[Test,Order(1100)]
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




		[Test, Order(1000)]
		public async Task AppRoleBE_GetRoleID () {
			string rName = "jk45";

			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			string Id = await _ARB.GetRoleID(rName);
			Assert.NotNull(Id);
		}



		[Test,Order(1000)]
		public async Task AppRoleBE_UpdateRoleID() {
			string rName = "krte3";

			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			// Now read a Role ID for it.
			string roleID = await _ARB.GetRoleID(ar.Name);

			// Update the role ID
			Assert.True(await _ARB.UpdateAppRoleID(ar.Name, "newDomain"));
			string roleIDNew = await _ARB.GetRoleID(ar.Name);
			Assert.AreEqual("newDomain", roleIDNew);
		}


		[Test,Order(1000)]
		public async Task AppRoleBE_CreateSecret () {
			string rName = "jladd5";

			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			// Get a secret for it
			AppRoleSecret ars = await _ARB.CreateSecretID(ar.Name);
			Assert.NotNull(ars);
			Assert.IsNotEmpty(ars.ID);
			Assert.IsNotEmpty(ars.Accessor);
		}


		[Test,Order(1000)]
		public async Task AppRoleBE_CreateReadAppRoleAllParams () {

			string name = "hggfde95"; // Guid.NewGuid().ToString();

			//TODO - Add All of the List objects - BoundCIDRList, TokenBoundCIDRList...
			AppRole ar = new AppRole {
				Name = name,
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
			AppRole rr = await _ARB.ReadAppRole(name);

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
