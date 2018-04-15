using System.Threading.Tasks;
using VaultAgent.Backends.System;

namespace VaultClient
{
    public class VaultClient_SystemBackend
    {
		VaultSystemBackend VSB;

		public VaultClient_SystemBackend(string token, string ip, int port) {
			VSB = new VaultSystemBackend(ip, port, token);
		}



		public async Task Run() {
			await PolicyCreateExamples();
			await PolicyReadExamples();
			

		}


		private async Task PolicyReadExamples () {
			bool rc;
			rc = await VSB.SysPoliciesACLRead("TestingABC");
		}


		private async Task PolicyCreateExamples () {

			// Create a policy with multiple sub path objects.
			VaultPolicy VP = new VaultPolicy("TestingABC");


			VaultPolicyPath vpi = new VaultPolicyPath("secret/TestA");
			vpi.DeleteAllowed = true;
			vpi.ReadAllowed = true;
			vpi.CreateAllowed = true;
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
	}
}
