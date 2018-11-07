using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultAgent.AuthenticationEngines;


namespace VaultClient
{
    public class VaultClient_AppRoleAuthEngine
    {
		AppRoleAuthEngine ARB;
		private string _AppRoleName;

		public VaultClient_AppRoleAuthEngine(AppRoleAuthEngine arb) {
			ARB = arb;
			//ARB = new AppRoleAuthEngine(ip, port, token);
			_AppRoleName = "test_appRoleA";
		}



		public async Task Run() {
			// List current roles.  Create role if does not exist.  Read the role.  List the roles again.
			List<string> appRoles = await AppRole_ListRoles();
			if (!appRoles.Contains(_AppRoleName)) {
				await AppRole_Create();
			}
			await ReadRole();

			appRoles = await AppRole_ListRoles();

			// Now get a role ID
			string roleID = await ARB.GetRoleID(_AppRoleName);

			// Now delete the app role.
			bool rc = await ARB.DeleteAppRole(_AppRoleName);
		}



		private async Task ReadRole() {
			AppRole art = await ARB.ReadAppRole(_AppRoleName);
			Console.WriteLine("Read token: {0}", art);
		}



		private async Task<List<string>> AppRole_ListRoles() {
			List<string> appRoles = await ARB.ListRoles();

			foreach (string role in appRoles) {
				Console.WriteLine("App Role: {0}", role);
			}
			return appRoles;
		}


		private async Task AppRole_Create() {
			AppRole art = new AppRole(_AppRoleName);

			await ARB.CreateRole(art);

		}

	}
}
