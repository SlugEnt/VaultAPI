﻿using System;
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

	internal class VaultAPI_Http
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

			httpClt = new HttpClient(new HttpClientHandler { MaxConnectionsPerServer = 500 }) {	BaseAddress = vaultIPAddress	};
			//httpClt.BaseAddress = vaultIPAddress;
			accessToken = Token;

			// Set token into HTTP headers.
			httpClt.DefaultRequestHeaders.Add("X-Vault-Token", accessToken);
		}




		/// <summary>
		/// Calls the HTTP Post method, to send data to the Vault API server.  
		/// </summary>
		/// <param name="APIPath">The path to call on the Vault server.</param>
		/// <param name="callingRoutineName">String name of the routine that called this method.  Used for debugging and logging purposes only.</param>
		/// <param name="inputParams">A Dictionary of key value pairs of parameters that should be sent in the body of the HTTP Call.  Should set to null if overriding 
		/// with your own JSON string of parameters by setting the inputParamsJSON</param>
		/// <param name="inputParamsJSON">JSON string of the parameters you want to put in the body of the HTTP call.  This is used to override the inputParams Dictionary.</param>
		/// <returns>VaultDataResponseObject with the results of the call.</returns>
		public async Task<VaultDataResponseObject> PostAsync(string APIPath, string callingRoutineName, Dictionary<string, string> inputParams = null, string inputParamsJSON = "") {
			
			if (inputParams != null) {
				inputParamsJSON = JsonConvert.SerializeObject(inputParams, Formatting.None);
			}


			HttpContent contentBody = new StringContent(inputParamsJSON);
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



		/// <summary>
		/// Calls the HTTP Post method, to send data to the Vault API server.  
		/// </summary>
		/// <param name="APIPath">The path to call on the Vault server.</param>
		/// <param name="callingRoutineName">String name of the routine that called this method.  Used for debugging and logging purposes only.</param>
		/// <param name="inputParams">A Dictionary of key value pairs of parameters that should be sent in the body of the HTTP Call.  Should set to null if overriding 
		/// with your own JSON string of parameters by setting the inputParamsJSON</param>
		/// <param name="inputParamsJSON">JSON string of the parameters you want to put in the body of the HTTP call.  This is used to override the inputParams Dictionary.</param>
		/// <returns>VaultDataResponseObject with the results of the call.</returns>
		public async Task<VaultDataResponseObject> PostAsync2(string APIPath, string callingRoutineName, Dictionary<string, object> inputParams = null, string inputParamsJSON = "") {

			if (inputParams != null) {
				inputParamsJSON = JsonConvert.SerializeObject(inputParams, Formatting.None);
			}


			HttpContent contentBody = new StringContent(inputParamsJSON);
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




		/// <summary>
		/// Calls the HTTP PUT method, to send data to the Vault API server.  
		/// </summary>
		/// <param name="APIPath">The path to call on the Vault server.</param>
		/// <param name="callingRoutineName">String name of the routine that called this method.  Used for debugging and logging purposes only.</param>
		/// <param name="inputParams">A Dictionary of key value pairs of parameters that should be sent in the body of the HTTP Call.  Should set to null if overriding 
		/// with your own JSON string of parameters by setting the inputParamsJSON</param>
		/// <param name="inputParamsJSON">JSON string of the parameters you want to put in the body of the HTTP call.  This is used to override the inputParams Dictionary.</param>
		/// <returns>VaultDataResponseObject with the results of the call.</returns>
		public async Task<VaultDataResponseObject> PutAsync(string APIPath, string callingRoutineName, Dictionary<string, string> inputParams = null, string inputParamsJSON = "") {

			if (inputParams != null) {
				inputParamsJSON = JsonConvert.SerializeObject(inputParams, Formatting.None);
			}


			HttpContent contentBody = new StringContent(inputParamsJSON);
			contentBody.Headers.ContentType = new MediaTypeHeaderValue("application/json");

			string jsonResponse = "";

			var response = await httpClt.PutAsync(APIPath, contentBody);
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




		/// <summary>
		/// Performs an HTTP Delete operation.
		/// </summary>
		/// <param name="APIPath">The Vault path to call to perform a deletion on.</param>
		/// <param name="callingRoutineName">Routine that called this function</param>
		/// <returns>VaultDateResponseObject of the results of the operation.</returns>
		public async Task<VaultDataResponseObject> DeleteAsync(string APIPath, string callingRoutineName) {
			string jsonResponse = "";
			string httpParameters = "";

			string fullURI = APIPath + httpParameters;
			var response = await httpClt.DeleteAsync(fullURI);


			if (response.IsSuccessStatusCode) {			
				jsonResponse = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
			}
			else { await HandleVaultErrors(response, fullURI, callingRoutineName); }

			VaultDataResponseObject vdr = new VaultDataResponseObject(jsonResponse, response.StatusCode);
			return vdr;
		}



		/// <summary>
		/// Processes errors returned by calls to the Vault API.
		/// </summary>
		/// <param name="response">The actual HttpResponseMessage returned by the HTTP call.</param>
		/// <param name="vaultHttpPath">The path that we tried to run on the Vault API.</param>
		/// <param name="callingRoutineName">The name of the routine that was making the Vault API Call.</param>
		/// <returns>A thrown exception with a custom message detailing the errors returned by the vault API.  </returns>
		protected async Task HandleVaultErrors (HttpResponseMessage response, string vaultHttpPath, string callingRoutineName) {
			// See if Response Body Contains an Errors object.
			string jsonResponse = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
			List<string> Errors = new List<string>();

			try {
				Errors = ConvertJSONArrayToList(jsonResponse, "errors");
			}
			catch (MissingFieldException e) {
				// Swallow the error.  Latest updates to Vault V1.2.2 in KV2 do not necessarily populate the error object if object not foundf.
			}


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
