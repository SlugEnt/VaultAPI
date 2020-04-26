using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Collections;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using VaultAgent;


namespace VaultAgent {
    /// <summary>
    /// This class represents the HTTP connection object for the Vault Agent Interface.  It handles all the connections to Vault Instance as well as all error handling.
    /// </summary>
    public class VaultAPI_Http {
        private readonly Uri _vaultIPAddress;
        private readonly HttpClient _httpClt;



        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="vaultIP">IP Address of the Vault server</param>
        /// <param name="port">The network Port the Vault server is listening on</param>
        public VaultAPI_Http (string vaultIP, int port) {
            _vaultIPAddress = new Uri ("http://" + vaultIP + ":" + port);
            _httpClt = new HttpClient (new HttpClientHandler {MaxConnectionsPerServer = 500}) {BaseAddress = _vaultIPAddress};
        }


        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="vaultConnectionUri">Full URI Connection string (http(s)://url:port)</param>
        public VaultAPI_Http (Uri vaultConnectionUri) {
            _vaultIPAddress = vaultConnectionUri;
            _httpClt = new HttpClient(new HttpClientHandler {MaxConnectionsPerServer = 500}) {BaseAddress = _vaultIPAddress};
        }


        /// <summary>
        /// Sets the Vault Access token used to access Vault with.  This should be called by the VaultAgent any time the token changes.
        /// </summary>
        /// <param name="tokenID"></param>
        internal void SetTokenHeader (string tokenID) {
            // Set token into HTTP headers.
            _httpClt.DefaultRequestHeaders.Remove ("X-Vault-Token");
            _httpClt.DefaultRequestHeaders.Add ("X-Vault-Token", tokenID);
        }




        /// <summary>
        /// Post Method
        /// </summary>
        /// <param name="APIPath">The path in Vault</param>
        /// <param name="callingRoutineName">Name of the calling routine</param>
        /// <param name="inputParams">Dictionary of string, string input parameters</param>
        /// <param name="expectReturnToHaveBody">Set to True if you expect the return object to have a body</param>
        /// <returns></returns>
	    public async Task<VaultDataResponseObjectB> PostAsync_B (string APIPath, string callingRoutineName, Dictionary<string, string> inputParams, bool expectReturnToHaveBody = true) {
		    string paramJSON = JsonConvert.SerializeObject(inputParams, Formatting.None);
		    return await PostAsync_B(APIPath, callingRoutineName, paramJSON);
		}


        /// <summary>
        /// Post Method
        /// </summary>
        /// <param name="APIPath">The path in Vault</param>
        /// <param name="callingRoutineName">Name of the calling routine</param>
        /// <param name="inputParams">Dictionary of string,object input parameters</param>
        /// <param name="expectReturnToHaveBody">Set to True if you expect the return object to have a body</param>
        /// <returns></returns>
	    public async Task<VaultDataResponseObjectB> PostAsync_B(string APIPath, string callingRoutineName, Dictionary<string, object> inputParams, bool expectReturnToHaveBody = true) {
		    string paramJSON = JsonConvert.SerializeObject(inputParams, Formatting.None);
		    return await PostAsync_B(APIPath, callingRoutineName, paramJSON);
	    }



		/// <summary>
		/// Calls the HTTP Post method, to send data to the Vault API server.
		/// This is the updated version.
		/// </summary>
		/// <param name="APIPath">The path to call on the Vault server.</param>
		/// <param name="callingRoutineName">String name of the routine that called this method.  Used for debugging and logging purposes only.</param>
		/// <param name="inputParamsJSON">JSON string of the parameters you want to put in the body of the HTTP call.  This is used to override the inputParams Dictionary.</param>
		/// <param name="expectReturnToHaveBody">Set to true to optimize the call by not retrieving the body from the response because it is not needed or expected to be empty.</param>
		/// <returns>VaultDataResponseObject with the results of the call.</returns>
		public async Task<VaultDataResponseObjectB> PostAsync_B(string APIPath,
																string callingRoutineName,
																string inputParamsJSON = "",
																 bool expectReturnToHaveBody = true) {
		    HttpContent contentBody = new StringContent(inputParamsJSON);
		    contentBody.Headers.ContentType = new MediaTypeHeaderValue("application/json");


		    HttpResponseMessage response = await _httpClt.PostAsync(APIPath, contentBody);
		    if ( response.IsSuccessStatusCode ) {
			    VaultDataResponseObjectB vdr;
				if (!expectReturnToHaveBody) { vdr = new VaultDataResponseObjectB(response.StatusCode);}
			    else { vdr = new VaultDataResponseObjectB(response); }
			    return vdr;
		    }
		    else {
			    // Process errors.  This method will always throw an error.
			    await HandleVaultErrors(response, APIPath, callingRoutineName);
			    return null;
		    }
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
        public async Task<VaultDataResponseObjectB> PutAsync (string APIPath,
                                                             string callingRoutineName,
                                                             Dictionary<string, string> inputParams = null,
                                                             string inputParamsJSON = "") {
            if ( inputParams != null ) { inputParamsJSON = JsonConvert.SerializeObject (inputParams, Formatting.None); }


            HttpContent contentBody = new StringContent (inputParamsJSON);
            contentBody.Headers.ContentType = new MediaTypeHeaderValue ("application/json");

            string jsonResponse = "";

            HttpResponseMessage response = await _httpClt.PutAsync (APIPath, contentBody);
            if ( response.IsSuccessStatusCode ) { jsonResponse = await response.Content.ReadAsStringAsync().ConfigureAwait (false); }
            else { await HandleVaultErrors (response, APIPath, callingRoutineName); }


            VaultDataResponseObjectB vdr = new VaultDataResponseObjectB (response);
            return vdr;
        }



	    /// <summary>
	    /// Retrieves data from the Vault.
	    /// </summary>
	    /// <param name="APIPath">Path to the vault method you wish to execute.</param>
	    /// <param name="callingRoutineName">Name of routine that is calling us - used during error reporting.</param>
	    /// <param name="sendParameters">The parameters to send to the API method.</param>
	    /// <returns>A VaultDataResponseObject containing the return data or error codes.</returns>
	    public async Task<VaultDataResponseObjectB> GetAsync_B (string APIPath, string callingRoutineName, Dictionary<string, string> sendParameters = null) {
		    string fullURI;


		    // Build the fullURI string.  If it has parameters those are a part of it, otherwise it's just the APIPath
		    if (sendParameters != null) {
				// Assume 30 characters per parameter item.
				StringBuilder sendParams = new StringBuilder("?",sendParameters.Count * 30);
			    foreach (KeyValuePair<string, string> item in sendParameters) { sendParams.Append(item.Key + "=" + item.Value + "&"); }

			    // Remove trailing &
			    sendParams.Length--;

			    fullURI = APIPath + sendParams.ToString();
		    }
			else { fullURI = APIPath; }


		    HttpResponseMessage response = await _httpClt.GetAsync(fullURI);
		    if ( response.IsSuccessStatusCode ) {
				VaultDataResponseObjectB vdr = new VaultDataResponseObjectB(response);
			    return vdr;
		    }
		    else {
			    // Process errors.  This method will always throw an error.
			    await HandleVaultErrors(response, fullURI, callingRoutineName);
			    return null;
		    }
	    }





		/// <summary>
		/// Performs an HTTP Delete operation.
		/// </summary>
		/// <param name="APIPath">The Vault path to call to perform a deletion on.</param>
		/// <param name="callingRoutineName">Routine that called this function</param>
		/// <returns>VaultDateResponseObject of the results of the operation.</returns>
		public async Task<VaultDataResponseObjectB> DeleteAsync (string APIPath, string callingRoutineName) {
            string fullURI = APIPath;
            HttpResponseMessage response = await _httpClt.DeleteAsync (fullURI);


            if ( response.IsSuccessStatusCode ) {
                VaultDataResponseObjectB vdr = new VaultDataResponseObjectB(response);
                return vdr;
            }

            
            await HandleVaultErrors (response, fullURI, callingRoutineName);
            return null;
        }



        /// <summary>
        /// Processes errors returned by calls to the Vault API.  This will throw a new Error in all cases.
        /// </summary>
        /// <param name="response">The actual HttpResponseMessage returned by the HTTP call.</param>
        /// <param name="vaultHttpPath">The path that we tried to run on the Vault API.</param>
        /// <param name="callingRoutineName">The name of the routine that was making the Vault API Call.</param>
        /// <returns>A thrown exception with a custom message detailing the errors returned by the vault API.  </returns>
        protected async Task HandleVaultErrors (HttpResponseMessage response, string vaultHttpPath, string callingRoutineName) {
            // See if Response Body Contains an Errors object.
            string jsonResponse = await response.Content.ReadAsStringAsync().ConfigureAwait (false);
            List<string> errors = new List<string>();

            try { errors = ConvertJSONArrayToList (jsonResponse, "errors"); }
            catch ( MissingFieldException e) {
                // A few Vault Methods do not return the Errors Object, we swallow the error and move on.
                // Swallow the error.  Latest updates to Vault V1.2.2 in KV2 do not necessarily populate the error object if object not found.
            }


            int status = (int) response.StatusCode;


            // Build out exception message:  Include any error text returned by Vault.
            string exceptionMsg = "[" + callingRoutineName + "] (" + vaultHttpPath + ") HttpStatusCode: " + status;
            if ( errors.Count > 0 ) { exceptionMsg += Environment.NewLine + "Vault returned the following error(s):"; }
            else { exceptionMsg += Environment.NewLine + "Vault did not return any additional error text."; }

            foreach ( string error in errors ) { exceptionMsg += Environment.NewLine + error; }


            switch ( status ) {
                case 400: throw new VaultInvalidDataException (exceptionMsg);
                case 403: throw new VaultForbiddenException (exceptionMsg);
                case 404: throw new VaultInvalidPathException (exceptionMsg);
                case 429: throw new VaultStandbyNodesErrorException (exceptionMsg);
                case 500: throw new VaultInternalErrorException (exceptionMsg);
                case 503: throw new VaultSealedException (exceptionMsg);
                default: throw new System.Exception (exceptionMsg);
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
        public List<string> ConvertJSONArrayToList (string json, string fieldName) {
            JToken token = JObject.Parse (json);

            try {
                foreach ( string queryComponent in fieldName.Split ('.') ) { token = token [queryComponent]; }

                if ( token == null ) {
                    string msg = "Field " + fieldName + " not found.";
                    throw new VaultFieldNotFoundException (msg);
                }

                string js = token.ToString();
                List<string> data = VaultUtilityFX.ConvertJSON<List<string>> (js);
                return data;
            }


            catch ( Exception ) { throw new MissingFieldException ("GetJSONPropertyValue method unable to find the field: " + fieldName); }
        }
    }
}