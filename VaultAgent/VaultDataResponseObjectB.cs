using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;


namespace VaultAgent
{
	public class VaultDataResponseObjectB {
		private HttpResponseMessage _httpResponseMessage;

		private JObject _respData;

		//private Task _taskRead;
		private string _responseJSON; // Raw JSON data that was provided by called API.
		private string _responseData; // This is populated the first time we are asked for this data from the Raw JSON.
		private Dictionary<string, object> _responseJSONDict;
		private Dictionary<string, object> _responseDataDict;

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
			//GetResponse();
		}


		private async Task GetResponse () {
			//TODO Move this out of this object 
		//	_taskRead = _getResponse();

			_responseJSON = await _httpResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
		}


		private async Task _getResponse () {
			_responseJSON = await _httpResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
		}


		public async Task AsyncReadResponse () {
			using (var stream = await _httpResponseMessage.Content.ReadAsStreamAsync())
			using (var reader = new StreamReader(stream))
				using ( var jsonReader = new JsonTextReader(reader) ) {
					_respData = await JObject.LoadAsync(jsonReader);
				}				
		}


		public async Task<List<string>> B_ListData () {
			await AsyncReadResponse();
			IList<JToken> jResults = _respData ["data"] ["keys"].Children().ToList();
			List<string> results = new List<string>();
			foreach ( JToken token in jResults ) {
				string str = token.ToObject<string>();
				results.Add(str);
			}

			return results;
		}


		public async Task<string> AccessResponse () {
			//if ( !_taskRead.IsCompleted ) { _taskRead.Wait();}
			await _getResponse();

			// Convert the Data out of the JSON if we have not done this before.  IE.  do this once - the first time it's requested.
			if (_responseData == null) { _responseData = GetJSONPropertyValue(_responseJSON, "data"); }

			return _responseData;
		}


		// =========================================================================================================================
		/// <summary>
		/// Constructor.  Accepts a single JSON string, which should be the entire JSON body returned by the Vault API.
		/// </summary>
		/// <param name="JSONresponse">The JSON string returned by the called Vault API.</param>
		public VaultDataResponseObjectB(string JSONresponse, System.Net.HttpStatusCode statusCode) {
			_responseJSON = JSONresponse;
			HttpStatusCode = (int)statusCode;


			// Vault at this time only returns 2 successful codes:
			//  200 - Success with data returned.
			//  204 - Success with no data returned.
			if (HttpStatusCode <= 204) { Success = true; }
			else { Success = false; }
		}



		// =========================================================================================================================
		/// <summary>
		/// Returns the actual JSON response returned from Vault.  This will contain everything returned.  Usually you will be 
		/// interested in the GetDataAsJSON method as that just returns the relevant data that pertains to the request.
		/// </summary>
		/// <returns></returns>
		public string GetResponsePackageAsJSON() { return _responseJSON; }



		// =========================================================================================================================
		/// <summary>
		/// Returns the data item from the response JSON.  Many Vault API's return a package that contains the Data field which is the actual data
		/// the caller is interested in.
		/// </summary>
		/// <returns>string represenation in JSON of the data element.</returns>
		public string GetDataPackageAsJSON() {
			// Convert the Data out of the JSON if we have not done this before.  IE.  do this once - the first time it's requested.
			if (_responseData == null) { _responseData = GetJSONPropertyValue(_responseJSON, "data"); }

			return _responseData;
		}



		// =========================================================================================================================
		/// <summary>
		/// Returns the response Package as a Dictionary.
		/// </summary>
		/// <returns>Dictionary [string, object]</returns>
		public Dictionary<string, object> GetResponsePackageAsDictionary() {
			if (_responseJSONDict == null) { _responseJSONDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(_responseJSON); }

			return _responseJSONDict;
		}



		// =========================================================================================================================
		/// <summary>
		/// Returns the data package of the response object as a dictionary.  This is usually what callers want.
		/// </summary>
		/// <returns>Dictionary [string, object]</returns>
		public Dictionary<string, object> GetDataPackageAsDictionary() {
			if (_responseDataDict == null) {
				Dictionary<string, object> respDict = GetResponsePackageAsDictionary();

				if (_responseJSONDict.ContainsKey("data")) {
					string val = _responseJSONDict["data"].ToString();
					_responseDataDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(val);
				}
			}

			return _responseDataDict;
		}



		// =========================================================================================================================
		/// <summary>
		/// Returns the Response Package's original JSON for a given field.
		/// </summary>
		/// <param name="fieldName">Field you wish to retrieve.</param>
		/// <returns>The field as JSON, both the field name and data.</returns>
		public string GetResponsePackageFieldAsJSON(string fieldName) { return GetJSONPropertyValue(this._responseJSON, fieldName); }



		// =========================================================================================================================
		/// <summary>
		/// Returns the Data Package's original JSON for a given field.
		/// </summary>
		/// <param name="fieldName">Field you wish to retrieve.</param>
		/// <returns>The field as JSON, both the field name and data.</returns>
		public string GetDataPackageFieldAsJSON(string fieldName) { return GetJSONPropertyValue(GetDataPackageAsJSON(), fieldName); }



		// =========================================================================================================================
		/// <summary>
		/// Checks if a given field exists in the Response Package
		/// </summary>
		/// <param name="fieldName">The field you are checking for.</param>
		/// <returns>True if the field was found.  False otherwise.</returns>
		public bool DoesResponseFieldExist(string fieldName) {
			try {
				string value = GetJSONPropertyValue(this._responseJSON, fieldName);
				return true;
			}
			catch (Exception e) { return false; }
		}



		// =========================================================================================================================
		/// <summary>
		/// Checks if a given field exists in the Data Package
		/// </summary>
		/// <param name="fieldName">The field you are checking for.</param>
		/// <returns>True if the field was found.  False otherwise.</returns>
		public bool DoesDataFieldExist(string fieldName) {
			try {
				string value = GetJSONPropertyValue(this._responseData, fieldName);
				return true;
			}
			catch (Exception e) { return false; }
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
		public string GetJSONPropertyValue(string json, string fieldName) {
			JToken token = JObject.Parse(json);

			try {
				foreach (string queryComponent in fieldName.Split('.')) { token = token[queryComponent]; }

				if (token == null) {
					string msg = "Field " + fieldName + " not found.";
					throw new VaultFieldNotFoundException(msg);
				}
			}

			catch (Exception e) { throw new MissingFieldException("GetJSONPropertyValue method unable to find the field: " + fieldName); }

			return token.ToString();
		}



		/// <summary>
		/// Populates a T object with the corresponding values from the JSON Response object Vault gave us.
		/// </summary>
		/// <typeparam name="T">The object type to fill from the JSON.</typeparam>
		/// <returns>T - Object filled with values from JSON.</returns>
		[Obsolete]
		public T GetVaultTypedObjectFromResponse<T>() { return JsonConvert.DeserializeObject<T>(GetResponsePackageAsJSON()); }


		/// <summary>
		/// This should be retired.  In order to do so, you need to remove the 3 Serialization functions added to custom classes by the QuickType Json App.
		/// Returns a T object with the corresponding values from the JSON Data Object that is a subset of the JSON Response object returned from Vault.
		/// </summary>
		/// <typeparam name="T">The object class to convert the JSON into.</typeparam>
		/// <returns>An instance of the object class requested, with the values from the JSON Data object.</returns>
		[Obsolete]
		public T GetVaultTypedObject<T>() { return JsonConvert.DeserializeObject<T>(GetDataPackageAsJSON()); }



		/// <summary>
		/// Returns a T object with the corresponding values from the JSON Data Object from the Response object returned from Vault.
		/// </summary>
		/// <typeparam name="T">The object class to convert the JSON into.</typeparam>
		/// <returns>An instance of the object class requested, with the values from the JSON Data object.</returns>
		public T GetVaultTypedObjectV2<T>() { return VaultSerializationHelper.FromJson<T>(GetDataPackageAsJSON()); }



		/// <summary>
		/// Populates a T object with the corresponding values from the JSON Response object Vault gave us.
		/// </summary>
		/// <typeparam name="T">The object type to fill from the JSON.</typeparam>
		/// <returns>T - Object filled with values from JSON.</returns>
		public T GetVaultTypedObjectFromResponseV2<T>() { return VaultSerializationHelper.FromJson<T>(GetResponsePackageAsJSON()); }


		public T GetVaultTypedObjectFromResponseField<T>(string fieldName) {
			string json = GetResponsePackageFieldAsJSON(fieldName);
			return VaultSerializationHelper.FromJson<T>(json);
		}
	}
}