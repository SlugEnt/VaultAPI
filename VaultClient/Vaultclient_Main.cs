using System;
using System.Threading.Tasks;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Backends;


namespace VaultClient
{
	class Program
	{
		public static async Task Main(string[] args) {

			string rootToken;
			
			string ip;
			int port;

			// Use local dev server.
			rootToken = "tokenA";
			
			ip = "127.0.0.1";
			port = 47002;

			// Connect to Vault, add an authentication backend of AppRole.
			VaultAgentAPI vaultAgent = new VaultAgentAPI("Vault", ip, port, rootToken, true);
			

			// Perform optimize tests
			OptimizeTests optimize = new OptimizeTests(vaultAgent);
			await optimize.Run();
			return;

            
			VC_AppRoleAuthEngine roleBE = new VC_AppRoleAuthEngine(vaultAgent);
			await roleBE.Run();


			// System Backend Examples:
			VaultClient_SystemBackend sysBE = new VaultClient_SystemBackend(rootToken, ip, port);
			await sysBE.Run();





			// Transit Backend
			// Enable a new transit Backend.
			//bool rc = await VSB.SysMountEnable(transitDB, ("transit test DB -" + transitDB), EnumSecretBackendTypes.Transit);

			string transitDB = "transit";
			VaultClient_TransitBackend transit = new VaultClient_TransitBackend(rootToken, ip, port,transitDB);
			await transit.Run();
			Console.WriteLine("Finished with all sample runs.");
			Console.WriteLine("  -- Press any key to exit program.");
			Console.ReadKey();

			Console.ReadKey();
			return;

			//string path = "v1/auth/token/lookup";
//TODO This should be able to be replaced with a native VaultAgent implementation.  VaultAPI_HTTP is no longer public.
/*
			// JSON the input variables
			Dictionary<string, string> content = new Dictionary<string, string>();
			content.Add("token", lookupToken);

			VaultAPI_Http VH = new VaultAPI_Http(ip, port, rootToken);
			VaultDataResponseObject vdro  = await VH.PostAsync(path, "VaultClient_Main", content);

			Console.WriteLine(vdro.GetDataPackageAsJSON());

			VaultDataResponseObject vdr = await VH.PostAsync(path, "VaultClient_Main", content);
			Console.WriteLine("Response Return:");
			Console.WriteLine("JSON = {0}", vdr.GetResponsePackageAsJSON());


			Console.WriteLine("Response Data:");
			Console.WriteLine("JSON = {0}", vdr.GetDataPackageAsJSON());

			

			try {



				//VaultDataResponseObject vdr2 = await VH.PostAsyncReturnDictionary(path, content);
				Console.WriteLine("Response Return Dictionary:");
				foreach (KeyValuePair<string, object> item in vdr.GetResponsePackageAsDictionary()) {
					try {
						Console.WriteLine("KEy = {0}       Value = {1}", item.Key, item.Value.ToString());
					}
					catch (Exception e) { }
				}

				Console.WriteLine("Response Data:");
				foreach (KeyValuePair<string, object> item in vdr.GetDataPackageAsDictionary()) {
					try {
						Console.WriteLine("KEy = {0}       Value = {1}", item.Key, item.Value.ToString());
					}
					catch (Exception e) { }
				}

				// Test vault Exists methods
				if (vdr.DoesDataFieldExist("xyz")) {
					Console.WriteLine("Field Exists");
				}
				else { Console.WriteLine("xyz Field Not Found");  }
				
			//	Console.WriteLine(" Looking for Lease field: {0}", vdr.GetResponsePackageFieldAsJSON("lease"));



				// Now see if we can build an object.
				string JsonA = vdr.GetDataPackageAsJSON();
				Token t = JsonConvert.DeserializeObject<Token>(JsonA);
				Console.WriteLine("Token is orphan? {0}", t.IsOrphan);
				Console.WriteLine("Token has parent? {0}", t.HasParent);
				Console.WriteLine("Token is renewable? {0}", t.IsRenewable);

				Console.WriteLine("Token Creation Date: {0}", t.CreationTime_AsDateTime);
			}
			catch (Exception e) {
				Console.WriteLine("Error detected - {0}", e.Message);
			}

*/				


		}
	}
}
