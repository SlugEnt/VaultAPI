using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultAgent;

namespace VaultClient
{
	class Program
	{
		public static async Task Main(string[] args) {

			string rootToken = "956ac20d-3516-cdd3-61fc-b50bc5763453";
			string lookupToken = "7d13922b-7844-85d9-fbb8-6cc8bed270f2";


			string path = "v1/auth/token/lookup";

			// JSON the input variables
			Dictionary<string, string> content = new Dictionary<string, string>();
			content.Add("token", lookupToken);

			VaultAPI_Http VH = new VaultAPI_Http("192.168.1.86", 8200, rootToken);
			string ans = await VH.PostAsync(path, content);

			Console.WriteLine(ans);

			Dictionary<string, object> answers;
			answers = await VH.PostAsyncReturnDictionary(path, content);
			Console.ReadKey();

		}
	}
}
