using System.Threading.Tasks;
using VaultAgent.Backends.System;
using System.Collections.Generic;
using System;
using VaultAgent;

namespace VaultClient
{
    public class VaultClient_SystemBackend
    {
        private VaultAgentAPI _vault;
        private readonly VaultSystemBackend _vaultSystemBackend;

		private string _token;

		public VaultClient_SystemBackend(string token, string ip, int port) {
            _vault = new VaultAgentAPI("VaultSys",ip,port,token);
			_token = token;
		    _vaultSystemBackend = _vault.System;

        }



        public async Task Run() {
			// Not Working - bool rc = await _vaultSystemBackend.SysAuditEnable("testABC");
			//await AuthEnableExample();
			return;
	//		await PolicyCreateExamples();
			await PolicyReadExamples();
			await PolicyListExamples();
			await PolicyDeleteExamples();
		}


		




		private async Task PolicyReadExamples () {
			VaultPolicy vp;
			vp = await _vaultSystemBackend.SysPoliciesACLRead("TestingABC");
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


			var rc = await _vaultSystemBackend.SysPoliciesACLCreate(VP);




		}


		private async Task PolicyListExamples () {
			List<string> policies = await _vaultSystemBackend.SysPoliciesACLList();

			foreach (string policy in policies) {
				Console.WriteLine("Policy: {0}",policy);
			}
		}


		private async Task PolicyDeleteExamples () {
			bool rc = await _vaultSystemBackend.SysPoliciesACLDelete("n");
		}
	}
}
