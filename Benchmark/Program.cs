using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Backends;
using VaultAgent.Backends.System;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultAgent.SecretEngines;


namespace MyBenchmarks
{

	public class Program
	{
		public static void Main(string[] args) {
			var summary = BenchmarkRunner.Run<APICall_A>();
		}
	}



	[CoreJob(baseline: true)]
	[RPlotExporter, RankColumn]
	public class APICall_A {
		private AppRoleAuthEngine _appRoleAuthEngine;
		private KV2SecretEngine _secretEngine;
		private VaultAgentAPI _vaultAgent;
		private static string _beAuthName = "BM_AppRole";
		private static string _beKV2Name = "BM_KV2";
		private string [] roles;

		//[Params(1000, 10000)]
		//public int N;


		[GlobalSetup]
		public async Task Setup() {
			string rootToken = "tokenA";
			string ip = "127.0.0.1";
			int port = 47002;

			// Connect to Vault, add an authentication backend of AppRole.
			_vaultAgent = new VaultAgentAPI("Vault", ip, port, rootToken, true);

			await CreateBackendMounts();
			_appRoleAuthEngine = (AppRoleAuthEngine)_vaultAgent.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _beAuthName, _beAuthName);
			_secretEngine = (KV2SecretEngine)_vaultAgent.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, "Benchmarking KV2 Secrets", _beKV2Name);

			await SetupRoles();
		}


		// Sets up a fixed number of Application Roles, that should be consistent between runs.
		private async Task SetupRoles () {
			roles = new string[10];
			roles [0] = "abcxyz123";
			roles [1] = "zyxabc986";
			roles [2] = "master";
			roles [3] = "secondary";
			roles [4] = "tertiary";
			roles [5] = "usa";
			roles [6] = "wildcats";
			roles [7] = "somerandomrolename";
			roles [8] = "borg";
			roles [9] = "terminator";

			// Now create / update these roles.
			foreach ( string role in roles ) {
				AppRole a = new AppRole(role);
				await _appRoleAuthEngine.SaveRole(a);
			}

			
		}

		/// <summary>
		/// Creates the backend Authorization and KeyValue Version 2 Secret Backends
		///  - Note the routine checks to see if the backends already exist.  If they do (which they might if you leave the Vault Instance up and running across runs
		///    of this program) then it ignores the errors and continues on.
		/// </summary>
		/// <returns></returns>
		private async Task CreateBackendMounts() {
			// 1.  Create an App Role Authentication backend. 
			try {
				// Create an Authentication method of App Role.	- This only needs to be done when the Auth method is created.  
				AuthMethod am = new AuthMethod(_beAuthName, EnumAuthMethods.AppRole);
				await _vaultAgent.System.AuthEnable(am);
			}
			// Ignore mount at same location errors.  This can happen if we are not restarting Vault Instance each time we run.  Nothing to worry about.
			catch (VaultException e) {
				if (e.SpecificErrorCode != EnumVaultExceptionCodes.BackendMountAlreadyExists) { Console.WriteLine("Unexpected error in BenchMark:CreateBackendMounts method: {0}", e.Message); }
			}
			catch (Exception e) { Console.WriteLine("Unexpected error in BenchMark:CreateBackendMounts method: {0}", e.Message); }


			// Create a KV2 Secret Mount if it does not exist.           
			try {
				await _vaultAgent.System.SysMountCreate(_beKV2Name, "BenchMark KeyValue 2 Secrets", EnumSecretBackendTypes.KeyValueV2);
			}
			catch (VaultInvalidDataException e) {
				if (e.SpecificErrorCode == EnumVaultExceptionCodes.BackendMountAlreadyExists) {
					Console.WriteLine("KV2 Secret Backend already exists.  No need to create it.");
				}
				else {
					string msg = "Exception trying to mount the KV2 secrets engine. Aborting the rest of the AppRoleBackend Scenario.   Mount Name: " + _beKV2Name + "- Error: " + e.Message;
					Console.WriteLine(msg);
					throw new ApplicationException(msg);
				}
			}
		}


		// BaseLine:        447 - 468 us.  
		// Optimization 1:  Use StringBuilder for Params and some minor string opts.  
		//                  450us   +7us improvement.
		// Optimization 2:  New VaultDataResponseObjectB, moved HTTPResponse into VDRB.
		//                  460us.  -10us disimprovement.
		// Optimization 3:  VaultDataResponse updates
		//                  370us   +90us improvement
		// Optimization 4:  VaultDataResponse B_ListData - Don't convert to json to string, manipulate directly from JObject
		//                  352us   +18us improvement
		// Optimization 5:  VDR GetDotNetObject - using generics instead of hard coded value.
		//                  366us   -14 disimprovement


		[Benchmark]
		public void DictionarySerializer_A () {
			Dictionary<string,string> a = new Dictionary<string, string>();
			a.Add("a", "1");
			a.Add("b", "2000");
			a.Add("c", "33333");
			a.Add("d", "4000044444");
			a.Add("e", "555555555555555555");


			string inputJSON = JsonConvert.SerializeObject(a, Formatting.None);
		}



		[Benchmark]
		public void DictionarySerializer_B () {
			Dictionary<string, object> a = new Dictionary<string, object>();
			a.Add("a", "1");
			a.Add("b", "2000");
			a.Add("c", "33333");
			a.Add("d", "4000044444");
			a.Add("e", "555555555555555555");
		


		string inputJSON = JsonConvert.SerializeObject(a, Formatting.None);
		}
	}





		/*
		[Benchmark]
		public async Task ListRoles_A () { List<string> roles = await _appRoleAuthEngine.ListRoles(); }


		[Benchmark]
		public async Task ListRoles_B () { List<string> roles = await _appRoleAuthEngine.ListRoles_B();}

	*/
/*
		[Benchmark]
		public async Task ReadRoles_A () {
			foreach ( string role in roles ) {
				AppRole a = await _appRoleAuthEngine.ReadRole(role);
			}
		}
*/
		/*
		[Benchmark]
		public async Task ReadRoles_B() {
			foreach (string role in roles) {
				AppRole a = await _appRoleAuthEngine.ReadRoleB(role);
			}
		}
		*/
}


