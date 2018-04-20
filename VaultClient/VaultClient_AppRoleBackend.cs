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


		public VaultClient_AppRoleBackend(string token, string ip, int port) {
			ARB = new AppRoleBackEnd(ip, port, token);
		}



		public async Task Run() {
			//		await PolicyCreateExamples();
			await AppRole_ListRoles();
			await AppRole_Create();
		}




		private async Task AppRole_ListRoles() {
			List<string> appRoles = await ARB.ListRoles();

			foreach (string role in appRoles) {
				Console.WriteLine("App Role: {0}", role);
			}

		}

		private async Task AppRole_Create() {
			AppRoleToken art = new AppRoleToken("testABC");

			await ARB.Create(art);

		}

	}
}
