using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using VaultAgent;
using VaultAgent.Models;
using Newtonsoft.Json;

namespace VaultClient
{
	class Program
	{
		public static async Task Main(string[] args) {

			string rootToken;
			string lookupToken;
			string ip;
			int port;

			// USe remote Vault server
			if (2 == 2) {
				rootToken = "956ac20d-3516-cdd3-61fc-b50bc5763453";
				lookupToken = "7d13922b-7844-85d9-fbb8-6cc8bed270f2";
				ip = "192.168.1.86";
				port = 8200;
			}
			// Use local dev server.
			else {
				rootToken = "hi";
				lookupToken = "hi";
				ip = "127.0.0.1";
				port = 8200;
			}


			string path = "v1/auth/token/lookup";

			// JSON the input variables
			Dictionary<string, string> content = new Dictionary<string, string>();
			content.Add("token", lookupToken);

			VaultAPI_Http VH = new VaultAPI_Http(ip, port, rootToken);
			string ans = await VH.PostAsync(path, content);

			Console.WriteLine(ans);

			VaultDataReturn vdr = await VH.PostAsyncReturnDictionary(path, content);
			Console.WriteLine("Response Return:");
			Console.WriteLine("JSON = {0}", vdr.GetResponsePackageAsJSON());


			Console.WriteLine("Response Data:");
			Console.WriteLine("JSON = {0}", vdr.GetDataPackageAsJSON());

			
	
			Dictionary<string, object> RespDict;
			Dictionary<string, object> DataDict;

			try {



				//VaultDataReturn vdr2 = await VH.PostAsyncReturnDictionary(path, content);
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
				TokenInfo t = JsonConvert.DeserializeObject<TokenInfo>(JsonA);
				Console.WriteLine("Token is orphan? {0}", t.IsOrphan);
				Console.WriteLine("Token has parent? {0}", t.HasParent);
				Console.WriteLine("Token is renewable? {0}", t.IsRenewable);

				Console.WriteLine("Token Creation Date: {0}", t.CreationTime_AsDateTime);
			}
			catch (Exception e) {
				Console.WriteLine("Error detected - {0}", e.Message);
			}

				
				Console.ReadKey();

		}
	}
}
