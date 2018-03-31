using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Collections;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using VaultAgent;


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




		public async Task<VaultDataResponseObject> PostAsync(string APIPath, string callingRoutineName, Dictionary<string, string> inputVars) {
			string inputVarsJSON = JsonConvert.SerializeObject(inputVars, Formatting.None);

			HttpContent contentBody = new StringContent(inputVarsJSON);
			contentBody.Headers.ContentType = new MediaTypeHeaderValue("application/json");

			string jsonResponse = "";

			var response = await httpClt.PostAsync(APIPath, contentBody);
			if (response.IsSuccessStatusCode) {
				jsonResponse = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
			}
			else { await HandleVaultErrors(response, APIPath, callingRoutineName); }


			VaultDataResponseObject vdr = new VaultDataResponseObject(jsonResponse, response.StatusCode);
			return vdr;
		}


		public async Task<VaultDataResponseObject> GetAsync(string APIPath, string callingRoutineName, Dictionary<string, string> sendParameters = null) {
			string jsonResponse="";
			string httpParameters = "";


			// Determine if we need to send parameters
			if (sendParameters != null) {
				foreach (KeyValuePair<string,string> item in sendParameters) {
					httpParameters += item.Key + "=" + item.Value + "&";
				}
				// Remove trailing &
				httpParameters = httpParameters.TrimEnd('&');

				// Add initial "?"
				httpParameters = "?" + httpParameters;
			}

			string fullURI = APIPath + httpParameters;
			

			var response = await httpClt.GetAsync(fullURI);
			if (response.IsSuccessStatusCode) {
				jsonResponse = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
			}
			else {  await HandleVaultErrors(response, fullURI, callingRoutineName); }

			VaultDataResponseObject vdr = new VaultDataResponseObject(jsonResponse, response.StatusCode);
			return vdr;

		}



		protected async Task HandleVaultErrors (HttpResponseMessage response, string vaultHttpPath, string callingRoutineName) {
			// See if Response Body Contains an Errors object.
			string jsonResponse = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
			List<string> Errors = ConvertJSONArrayToList(jsonResponse, "errors");


			string exceptionMsg;
			int status = (int)response.StatusCode;


			// Build out exception message:  Include any error text returned by Vault.
			exceptionMsg = "[" + callingRoutineName + "] (" +  vaultHttpPath + ") HttpStatusCode: " + status;
			if (Errors.Count > 0) { exceptionMsg += Environment.NewLine + "Vault returned the following error(s):"; }
			else { exceptionMsg += Environment.NewLine + "Vault did not return any additional error text."; }
			foreach (string error in Errors) {
				exceptionMsg += Environment.NewLine + error;
			}


			switch (status) {
				case 400:
					throw new VaultInvalidDataException(exceptionMsg);
				case 403:
					throw new VaultForbiddenException(exceptionMsg);
				case 404:
					throw new VaultInvalidPathException(exceptionMsg);
				case 429:
					throw new VaultStandbyNodesErrorException(exceptionMsg);
				case 500:
					throw new VaultInternalErrorException(exceptionMsg);
				case 503:
					throw new VaultSealedException(exceptionMsg);
				default:
					throw new System.Exception(exceptionMsg);
			}
		}

/*
		protected void HandleVaultErrors (System.Net.HttpStatusCode responseCode, string HttpMsg, string vaultHttpPath) {
			string exceptionMsg;
			int status = (int)responseCode;

			exceptionMsg = "[" + vaultHttpPath + "] HttpStatusCode: " + status;
			
			switch ((int) responseCode) {
				case 400:
					throw new VaultInvalidDataException(exceptionMsg);
				case 403:
					throw new VaultForbiddenException(exceptionMsg);
				case 404:
					throw new VaultInvalidPathException(exceptionMsg);
				case 429:
					throw new VaultStandbyNodesErrorException(exceptionMsg);
				case 500:
					throw new VaultInternalErrorException(exceptionMsg);
				case 503:
					throw new VaultSealedException (exceptionMsg);
				default:
					string customMsg = exceptionMsg + HttpMsg;
					throw new System.Exception(customMsg);
			}
		}
		*/


		// =========================================================================================================================
		/// <summary>
		/// Returns a specific field of the given JSON object.
		/// To return a given field of a sub key use the . format.  
		///   Example 
		///   - Return the data field:   data
		///   - Return the id field of the data element:   data.id
		/// </summary>
		/// <param name="json">The JSON string to parse</param>
		/// <param name="fieldName">The specific field or subfield you want JSON for in dot notation.  field.subfield.subsubfield....</param>
		/// <returns>JSON representation of the specified field.</returns>
		public List<string> ConvertJSONArrayToList(string json, string fieldName) {
			JToken token = JObject.Parse(json);

			try {
				foreach (string queryComponent in fieldName.Split('.')) {
					token = token[queryComponent];
				}

				if (token == null) {
					string msg = "Field " + fieldName + " not found.";
					throw new VaultFieldNotFoundException(msg);
				}
				string js = token.ToString();
				List<string> data = VaultUtilityFX.ConvertJSON<List<string>>(js);
				return data;
			}

			
			catch (Exception e) {
				throw new MissingFieldException("GetJSONPropertyValue method unable to find the field: " + fieldName);
			}
			
		}
	}
}
