using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace VaultAgent
{
	public class VaultDataResponseObject {
		private string responseJSON;		// Raw JSON data that was provided by called API.
		private string responseData;		// This is populated the first time we are asked for this data from the Raw JSON.
		private Dictionary<string, object> responseJSONDict;
		private Dictionary<string, object> responseDataDict;

		public int httpStatusCode { get; }			// The status code returned from the Vault API.



		// =========================================================================================================================
		/// <summary>
		/// Constructor.  Accepts a single JSON string, which should be the entire JSON body returned by the Vault API.
		/// </summary>
		/// <param name="JSONresponse">The JSON string returned by the called Vault API.</param>
		public VaultDataResponseObject (string JSONresponse, System.Net.HttpStatusCode statusCode) {
			responseJSON = JSONresponse;
			httpStatusCode = (int) statusCode;
		}




		// =========================================================================================================================
		/// <summary>
		/// Returns the actual JSON response returned from Vault.  This will contain everything returned.  Usually you will be 
		/// interested in the GetDataAsJSON method as that just returns the relevant data that pertains to the request.
		/// </summary>
		/// <returns></returns>
		public string GetResponsePackageAsJSON () {
			return responseJSON;
		}




		// =========================================================================================================================
		/// <summary>
		/// Returns the data item from the response JSON.  Many Vault API's return a package that contains the Data field which is the actual data
		/// the caller is interested in.
		/// </summary>
		/// <returns>string represenation in JSON of the data element.</returns>
		public string GetDataPackageAsJSON () {
			// Convert the Data out of the JSON if we have not done this before.  IE.  do this once - the first time it's requested.
			if (responseData == null) {
				responseData =  GetJSONPropertyValue(responseJSON, "data");
			}
			return responseData;
		}




		// =========================================================================================================================
		/// <summary>
		/// Returns the response Package as a Dictionary.
		/// </summary>
		/// <returns>Dictionary [string, object]</returns>
		public Dictionary<string, object> GetResponsePackageAsDictionary () {
			if (responseJSONDict == null) {
				responseJSONDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(responseJSON);
			}

			return responseJSONDict;
		}




		// =========================================================================================================================
		/// <summary>
		/// Returns the data package of the response object as a dictionary.  This is usually what callers want.
		/// </summary>
		/// <returns>Dictionary [string, object]</returns>
		public Dictionary<string, object> GetDataPackageAsDictionary () {
			if (responseDataDict == null) {
				Dictionary<string, object> respDict = GetResponsePackageAsDictionary();

				if (responseJSONDict.ContainsKey("data")) {
					string val = responseJSONDict["data"].ToString();
					responseDataDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(val);
				}
			}

			return responseDataDict;
		}




		// =========================================================================================================================
		/// <summary>
		/// Returns the Response Package's original JSON for a given field.
		/// </summary>
		/// <param name="fieldName">Field you wish to retrieve.</param>
		/// <returns>The field as JSON, both the field name and data.</returns>
		public string GetResponsePackageFieldAsJSON (string fieldName)
		{
			return GetJSONPropertyValue(this.responseJSON, fieldName);
		}




		// =========================================================================================================================
		/// <summary>
		/// Returns the Data Package's original JSON for a given field.
		/// </summary>
		/// <param name="fieldName">Field you wish to retrieve.</param>
		/// <returns>The field as JSON, both the field name and data.</returns>
		public string GetDataPackageFieldAsJSON (string fieldName) {
			return GetJSONPropertyValue(this.responseData, fieldName);
		}




		// =========================================================================================================================
		/// <summary>
		/// Checks if a given field exists in the Response Package
		/// </summary>
		/// <param name="fieldName">The field you are checking for.</param>
		/// <returns>True if the field was found.  False otherwise.</returns>
		public bool DoesResponseFieldExist(string fieldName) {
			try {
				string value = GetJSONPropertyValue(this.responseJSON, fieldName);
				return true;
			}
			catch (Exception e) {
				return false;
			}
		}




		// =========================================================================================================================
		/// <summary>
		/// Checks if a given field exists in the Data Package
		/// </summary>
		/// <param name="fieldName">The field you are checking for.</param>
		/// <returns>True if the field was found.  False otherwise.</returns>
		public bool DoesDataFieldExist (string fieldName) {
			try {
				string value = GetJSONPropertyValue(this.responseData, fieldName);
				return true;
			}
			catch (Exception e) {
				return false;
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
		private string GetJSONPropertyValue (string json, string fieldName) {
			JToken token = JObject.Parse(json);

			foreach (string queryComponent in fieldName.Split('.')) {
				token = token[queryComponent];
			}

			if (token == null) {
				string msg = "Field " + fieldName + " not found.";
				throw new VaultFieldNotFoundException (msg);  }
			return token.ToString();
		}




	}
}
