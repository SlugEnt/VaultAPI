using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent.Backends.AppRole;
using System.Threading.Tasks;

namespace VaultClient
{
    public class VaultClient_AppRoleBackend
    {
		AppRoleBackEnd ARB;
		private string _AppRoleName;

		public VaultClient_AppRoleBackend(string token, string ip, int port) {
			ARB = new AppRoleBackEnd(ip, port, token);
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
