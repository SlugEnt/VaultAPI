using System.Threading.Tasks;
using VaultAgent.Backends.System;
using System.Collections.Generic;
using System;

namespace VaultClient
{
    public class VaultClient_SystemBackend
    {
		SysBackend VSB;

		private string _token;
		private string _ip;
		private int _port;

		public VaultClient_SystemBackend(string token, string ip, int port) {
			VSB = new SysBackend(ip, port, token);
			_token = token;
			_ip = ip;
			_port = port;

		}



		public async Task Run() {
			// Not Working - bool rc = await VSB.SysAuditEnable("testABC");
			//await AuthEnableExample();
			return;
	//		await PolicyCreateExamples();
			await PolicyReadExamples();
			await PolicyListExamples();
			await PolicyDeleteExamples();
		}


		




		private async Task PolicyReadExamples () {
			VaultPolicy vp;
			vp = await VSB.SysPoliciesACLRead("TestingABC");
		}




		private async Task PolicyCreateExamples () {

			// Create a policy with multiple sub path objects.
			VaultPolicy VP = new VaultPolicy("TestingABC");


			VaultPolicyPath vpi = new VaultPolicyPath("secret/TestA") {
				DeleteAllowed = true,
				ReadAllowed = true,
				CreateAllowed = true
			};
			VP.PolicyPaths.Add(vpi);


			VaultPolicyPath vpi2 = new VaultPolicyPath("secret/TestB");
			vpi2.ListAllowed = true;
			VP.PolicyPaths.Add(vpi2);


			VaultPolicyPath vpi3 = new VaultPolicyPath("secret/TestC");
			vpi3.ListAllowed = true;
			vpi3.DeleteAllowed = true;
			vpi3.ReadAllowed = true;
			vpi3.SudoAllowed = true;
//			VP.PolicyPaths.Add(vpi3);


			var rc = await VSB.SysPoliciesACLCreate(VP);




		}


		private async Task PolicyListExamples () {
			List<string> policies = await VSB.SysPoliciesACLList();

			foreach (string policy in policies) {
				Console.WriteLine("Policy: {0}",policy);
			}
		}


		private async Task PolicyDeleteExamples () {
			bool rc = await VSB.SysPoliciesACLDelete("n");
		}
	}
}
