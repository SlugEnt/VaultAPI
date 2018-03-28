using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent
{
	public class VaultDataReturn {
		private string responseJSON;
		private string responseData;
		private Dictionary<string, object> responseJSONDict;
		private Dictionary<string, object> responseDataDict;


		//private Dictionary<string, object> data;
		public Dictionary<string, object> Data { get; }

		public VaultDataReturn (string JSONresponse) {
			responseJSON = JSONresponse;
			//responseData = JSONData;
		}
		//public VaultDataReturn (Dictionary<string,object> responseCode, Dictionary<string,object> DataValue) {
		//	responseJSON = responseCode;
		//	responseData = DataValue;

		//	//responseData = responseCode;
		//	//Data = DataValue;
		//}



		/// <summary>
		/// Returns the actual JSON response returned from Vault.  This will contain everything returned.  Usually you will be 
		/// interested in the GetDataAsJSON method as that just returns the relevant data that pertains to the request.
		/// </summary>
		/// <returns></returns>
		public string GetResponseAsJSON () {
			return responseJSON;
		}



		/// <summary>
		/// Returns the data item from the response JSON.  Many Vault return data contains the Data field which is the actual data
		/// the caller is interested in.
		/// </summary>
		/// <returns>string represenation in JSON of the data element.</returns>
		public string GetDataAsJSON () {
			// Convert the Data out of the JSON if we have not done this before.  IE.  do this once - the first time it's requested.
			if (responseData == null) {
				responseData =  GetJSONPropertyValue(responseJSON, "data");
			}
			return responseData;
		}
		

		public Dictionary<string, object> GetResponseAsDictionary () {
			if (responseJSONDict == null) {
				responseJSONDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(responseJSON);
			}

			return responseJSONDict;
		}


		public Dictionary<string, object> GetDataAsDictionary () {
			if (responseDataDict == null) {
				Dictionary<string, object> respDict = GetResponseAsDictionary();
				if (respDict != null) {

				}

				Dictionary<string, object> data;
				if (responseJSONDict.ContainsKey("data")) {

					string val = responseJSONDict["data"].ToString();
					responseDataDict = JsonConvert.DeserializeObject<Dictionary<string, object>>(val);
				}

			}

			return responseDataDict;
		}


	

		/// <summary>
		/// Returns a specific field of the given JSON object.
		/// To return a given field of a sub key use the . format.  
		///   Example 
		///   - Return the data field:   data
		///   - Return the id field of the data element:   data.id
		/// </summary>
		/// <param name="json">The JSON string to parse</param>
		/// <param name="property">The specific field or subfield you want JSON for in dot notation.  field.subfield.subsubfield....</param>
		/// <returns></returns>
		private string GetJSONPropertyValue (string json, string property) {
			JToken token = JObject.Parse(json);

			foreach (string queryComponent in property.Split('.')) {
				token = token[queryComponent];
			}
			return token.ToString();
		}
	}
}
