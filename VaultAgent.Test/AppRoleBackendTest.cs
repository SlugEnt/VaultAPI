using System;
using System.Collections.Generic;
using VaultAgent.Backends.AppRole;
using NUnit.Framework;
using System.Threading;
using System.Threading.Tasks;
using VaultAgent.Backends.System;


namespace VaultAgentTests
{
    public class AppRoleBackendTest
    {
		private AppRoleBackEnd _ARB;
		private object _arLocker = new object();
		private string roleName;
		private string _authBEName = "auth2";



		[SetUp]
		public async Task AppRoleBackendSetup () {
			// Ensure we have an authentication method of AppRole enabled on the Vault.
			SysBackend VSB = new SysBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);
			AuthMethod am = new AuthMethod(_authBEName, EnumAuthMethods.AppRole);
			bool rc = await VSB.AuthEnable(am);
			AppBackendTestInit();
		}



		// Ensure Backend is initialized during each test.
		protected void AppBackendTestInit() {
			if (_ARB == null) {
				roleName = "roleABC";
				lock (_arLocker) {
					_ARB = new AppRoleBackEnd(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken,_authBEName);
				}
			}
		}


		[Test,Order(1000)]
		public async Task AppRoleBE_CreateRole () {
			AppBackendTestInit();
			AppRole ar = new AppRole(roleName); 
			Assert.True(await _ARB.CreateRole(ar));
		}



		[Test,Order(1000)]
		public async Task AppRoleBE_DeleteRoleThatExists () {
			AppBackendTestInit();
			string rName = "roleZYX";
			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));


			// Delete it.
			Assert.True(await _ARB.DeleteAppRole(ar));
		}



		[Test, Order(1000)]
		public async Task AppRoleBE_DeleteRoleThatDoesNotExist_ReturnsTrue () {
			AppBackendTestInit();
			string rName = "rolezzzzz";
			Assert.True(await _ARB.DeleteAppRole(rName));
		}




		// Runs thru an entire AppRole Sequence:  Create, List - Confirm its there
		// Delete, List - Confirm its gone.
		[Test,Order(1100)]
		public async Task AppRoleBE_CreateListDeleteList_CycleValidated () {
			AppBackendTestInit();
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
			AppBackendTestInit();
			AppRole ar = new AppRole(rName);
			Assert.True(await _ARB.CreateRole(ar));

			string Id = await _ARB.GetRoleID(rName);
			Assert.NotNull(Id);


		}
	}
}
