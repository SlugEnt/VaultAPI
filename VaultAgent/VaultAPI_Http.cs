using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Collections;
using Newtonsoft.Json;


namespace VaultAgent
{

	public class VaultAPI_Http
	{
		private Uri vaultIPAddress;
		private string accessToken;
		private HttpClient httpClt;
		

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="vaultIP">IP Address of the Vault server</param>
		/// <param name="port">The network Port the Vault server is listening on</param>
		public VaultAPI_Http(string vaultIP, int port, string Token) {
			vaultIPAddress = new Uri("http://" + vaultIP + ":" + port);

			httpClt = new HttpClient();
			httpClt.BaseAddress = vaultIPAddress;
			accessToken = Token;

			// Set token into HTTP headers.
			httpClt.DefaultRequestHeaders.Add("X-Vault-Token", accessToken);
		}




		public async Task<VaultDataResponseObject> PostAsync(string APIPath, Dictionary<string, string> inputVars) {
			string inputVarsJSON = JsonConvert.SerializeObject(inputVars, Formatting.None);

			HttpContent contentBody = new StringContent(inputVarsJSON);
			contentBody.Headers.ContentType = new MediaTypeHeaderValue("application/json");

			string jsonResponse = "";

			var response = await httpClt.PostAsync(APIPath, contentBody);
			if (response.IsSuccessStatusCode) {
				jsonResponse = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
			}
			else { HandleVaultErrors(response.StatusCode);  }

			VaultDataResponseObject vdr = new VaultDataResponseObject(jsonResponse, response.StatusCode);
			return vdr;
		}





		/*
		public async Task<VaultDataResponseObject> PostAsyncReturnDictionary(string APIPath, Dictionary<string, string> inputVars) {
			string jsonResponse = await PostAsync(APIPath, inputVars);
			try {
				//VaultDataResponseObject vdr = new VaultDataResponseObject(answers);
				VaultDataResponseObject vdr = new VaultDataResponseObject(jsonResponse);
				return vdr;
			}
			catch (Exception e) {

				return null;
			}
		}
		*/



		protected void HandleVaultErrors (System.Net.HttpStatusCode responseCode) {
			switch ((int) responseCode) {
				case 400:
					throw new VaultInvalidDataException();
				case 403:
					throw new VaultForbiddenException();
				case 404:
					throw new VaultInvalidPathException();
				case 429:
					throw new VaultStandbyNodesErrorException();
				case 500:
					throw new VaultInternalErrorException();
				case 503:
					throw new VaultSealedException ();
			
			}
		}


		//public async Task<Dictionary<string, object>> PostAsyncReturnDictionary(string APIPath, Dictionary<string, string> inputVars) {
		//	string jsonResponse = await PostAsync(APIPath, inputVars);
		//	try {
		//		Dictionary<string, object> answers = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonResponse);
		//		return answers;
		//	}
		//	catch (Exception e) {

		//		return null;
		//	}
		//}
	}
}
