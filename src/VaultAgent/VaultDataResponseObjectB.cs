using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

using System.Net;

namespace VaultAgent {
	/// <summary>
	/// The VaultDataResponseObject serves as the intermediary between an HTTP response and methods that need to make HTTP calls.
	/// </summary>
	public class VaultDataResponseObjectB {
		private HttpResponseMessage _httpResponseMessage;

		// The Response data / json as a base Newtonsoft JObject
		private JObject _respData;


		/// <summary>
		/// The Status code returned from the Vault API Call.
		/// </summary>
		public int HttpStatusCode { get; } 


		/// <summary>
		/// Whether the API Call was successful or not.
		/// </summary>
		public bool Success { get; }




		/// <summary>
		/// Creates a Vault Data Response Object that expects to return some data in the body of the HTTP message.  
		/// </summary>
		/// <param name="httpResponseMessage">The Http response message that will allow us to retrieve the body of the
		/// HTTP call.</param>
		public VaultDataResponseObjectB (HttpResponseMessage httpResponseMessage) {
			_httpResponseMessage = httpResponseMessage;
			HttpStatusCode = (int) _httpResponseMessage.StatusCode;

			// Vault at this time only returns 2 successful codes:
			//  200 - Success with data returned.
			//  204 - Success with no data returned.
			if ( HttpStatusCode <= 204 ) { Success = true; }
			else { Success = false; }
		}



		/// <summary>
		/// Constructor that should be used when there is expected to be no contents in the Body of the HTTP call.  Basically we
		/// just need to know whether the call worked or not.
		/// </summary>
		/// <param name="statusCode"></param>
		public VaultDataResponseObjectB(HttpStatusCode statusCode) {
			_httpResponseMessage = null;

			HttpStatusCode = (int) statusCode;

			// Vault at this time only returns 2 successful codes:
			//  200 - Success with data returned.
			//  204 - Success with no data returned.
			if (HttpStatusCode <= 204) { Success = true; }
			else { Success = false; }

		}



		/// <summary>
		/// Reads the response from the HTTP call as a stream asynchronously and places into a JObject. 
		/// </summary>
		/// <returns></returns>
		public async Task AsyncReadResponse () {
			if ( _httpResponseMessage != null ) {
				using ( var stream = await _httpResponseMessage.Content.ReadAsStreamAsync() )
					using ( var reader = new StreamReader(stream) )
						using ( var jsonReader = new JsonTextReader(reader) ) {
							_respData = await JObject.LoadAsync(jsonReader);

							// Clear the response message so we know we are finished with it.
							_httpResponseMessage = null;
						}
			}
		}



		/// <summary>
		/// Retrieves the specified object from the response.    If the response was empty it will throw an ArgumentNullException
		/// </summary>
		/// <typeparam name="T">Type of object that you are retrieving</typeparam>
		/// <param name="key">Allows you to pick a specific subpart of the JSON to retrieve an object from.  To specify multiple levels
		/// you separate with a period.  So data.keys will create an object from whatever the keys json field contains.
		/// <para>should be specified as all lower case.</para></param>
		/// <returns></returns>
		public async Task<T> GetDotNetObject<T> (string key = "data") {
			await AsyncReadResponse();

			if ( _respData == null ) {
				throw new ArgumentNullException(
					"The response data from the HTTP call was empty.  Confirm the HTTP call was expected to return data in its body.");
			}

			JToken json;

			if ( key == "" ) { json = _respData; }
			else { json = _respData.SelectToken(key); }

			return json.ToObject<T>();
		}


        /// <summary>
        /// Returns the Response from Vault as a JSON string.
        /// </summary>
        /// <param name="key">Allows you to pick a specific subpart of the JSON to retrieve an object from.  To specify multiple levels
        /// you separate with a period.  So data.keys will create an object from whatever the keys json field contains.
        /// <para>should be specified as all lower case.</para></param>
        /// <returns></returns>
        public async Task<string> GetJSON(string key = "data")
        {
            await AsyncReadResponse();

            if (_respData == null)
            {
                throw new ArgumentNullException(
                    "The response data from the HTTP call was empty.  Confirm the HTTP call was expected to return data in its body.");
            }

            JToken json;

            if (key == "") { json = _respData; }
            else { json = _respData.SelectToken(key); }

            return json.ToString();
        }
    }
}