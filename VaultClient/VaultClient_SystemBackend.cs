using System.Threading.Tasks;
using VaultAgent.Backends.System;
using System.Collections.Generic;
using System;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.AuthenticationEngines.LoginConnectors;

namespace VaultClient
{
    public class VaultClient_SystemBackend
    {
        private VaultAgentAPI _vault;
        private VaultSystemBackend _vaultSystemBackend;

		private string _token;

		public VaultClient_SystemBackend(string token, string ip, int port) {
            _vault  = new VaultAgentAPI("VaultClient", ip, port);

            //_vault = new VaultAgentAPI("VaultSys",ip,port,token);
			_token = token;
		    //_vaultSystemBackend = _vault.System;

        }



        public async Task Run() {
            TokenLoginConnector loginConnector = new TokenLoginConnector(_vault, "ClientSysBE", _token, TokenAuthEngine.TOKEN_DEFAULT_MOUNT_NAME);
            bool success = await loginConnector.Connect();

            _vaultSystemBackend = new VaultSystemBackend(_vault.TokenID, _vault);

            await PolicyCreateExamples();
			await PolicyReadExamples();
			await PolicyListExamples();
			await PolicyDeleteExamples();
		}



		private async Task PolicyReadExamples () {
			VaultPolicyContainer vp;
			vp = await _vaultSystemBackend.SysPoliciesACLRead("TestingABC");
		}




		private async Task PolicyCreateExamples () {

			// Create a policy with multiple sub path objects.
			VaultPolicyContainer VP = new VaultPolicyContainer("TestingABC");


			VaultPolicyPathItem vpi = new VaultPolicyPathItem("secret/TestA") {
				DeleteAllowed = true,
				ReadAllowed = true,
				CreateAllowed = true
			};
			VP.AddPolicyPathObject(vpi);


			VaultPolicyPathItem vpi2 = new VaultPolicyPathItem("secret/TestB");
			vpi2.ListAllowed = true;
			VP.AddPolicyPathObject(vpi2);


			VaultPolicyPathItem vpi3 = new VaultPolicyPathItem("secret/TestC");
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
