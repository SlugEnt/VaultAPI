using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Buffers;

namespace VaultAgent
{
	/// <summary>
	/// The VaultDataResponseObject serves as the intermediary between an HTTP response and methods that need to make HTTP calls.
	/// </summary>
	public class VaultDataResponseObjectB {
		private HttpResponseMessage _httpResponseMessage;

		// The Response data / json as a base Newtonsoft JObject
		private JObject _respData;

		public int HttpStatusCode { get; } // The status code returned from the Vault API.
		public bool Success { get; }



		public VaultDataResponseObjectB (HttpResponseMessage httpResponseMessage) {
			_httpResponseMessage = httpResponseMessage;
			HttpStatusCode = (int) _httpResponseMessage.StatusCode;

			// Vault at this time only returns 2 successful codes:
			//  200 - Success with data returned.
			//  204 - Success with no data returned.
			if (HttpStatusCode <= 204) { Success = true; }
			else { Success = false; }
		}



		/// <summary>
		/// Reads the response from the HTTP call as a stream asynchronously and places into a JObject
		/// </summary>
		/// <returns></returns>
		public async Task AsyncReadResponse () {
			using (var stream = await _httpResponseMessage.Content.ReadAsStreamAsync())
			using (var reader = new StreamReader(stream))
				using ( var jsonReader = new JsonTextReader(reader) ) {
					_respData = await JObject.LoadAsync(jsonReader);
				}				
		}




		/// <summary>
		/// Retrieves the specified object from the response.  
		/// </summary>
		/// <typeparam name="T">Type of object that you are retrieving</typeparam>
		/// <param name="key">Allows you to pick a specific subpart of the JSON to retrieve an object from.  To specify multiple levels
		/// you separate with a period.  So data.keys will create an object from whatever the keys json field contains.
		/// <para>should be specified as all lower case.</para></param>
		/// <returns></returns>
		public  async Task<T> GetDotNetObject<T>(string key) {
			await AsyncReadResponse();

			JToken keyList = _respData.SelectToken(key);
			return keyList.ToObject<T>();
		}

	}
}