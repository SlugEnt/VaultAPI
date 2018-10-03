/*
 * Copyright 2018 Scott Herrmann

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VaultAgent.Backends.System
{
	/// <summary>
	/// Represents the configuration settings for a given Vault Mount.  
	/// </summary>
	public class VaultSysMountConfig {
		/// <summary>
		/// The default lease duration, specified as a string duration like "5s" or "30m".
		/// </summary>
		[JsonProperty("default_lease_ttl")]		
		public string DefaultLeaseTTL {get; set;}


		/// <summary>
		/// The maximum lease duration, specified as a string duration like "5s" or "30m"
		/// </summary>
		[JsonProperty("max_lease_ttl")]
		public string MaxLeaseTTL { get; set; }


		/// <summary>
		/// Disable caching.  Defaults to False
		/// </summary>
		[JsonProperty("force_no_cache")]
		public bool ForceNoCache { get; set; } = false;



		/// <summary>
		/// The name of the plugin in the plugin catalog to use
		/// </summary>
		[JsonProperty("plugin_name")]
		public string PluginName { get; set; }



		/// <summary>
		/// Comma-separated list of keys that will not be HMAC'd by audit devices in the request data object
		/// </summary>
		[JsonProperty("audit_non_hmac_request_keys")]
		public string RequestKeysToNotAuditViaHMAC { get; set; }



		/// <summary>
		/// Comma-separated list of keys that will not be HMAC'd by audit devices in the response data object
		/// </summary>
		[JsonProperty("audit_non_hmac_response_keys")]
		public string ResponseKeysToNotAuditViaHMAC { get; set; }



		/// <summary>
		/// Speficies whether to show this mount in the UI-specific listing endpoint. Valid values are "unauth" or "hidden". If not set, behaves like "hidden"
		/// </summary>
		[JsonProperty("listing_visibility")]
		public string VisibilitySetting { get; set; } = "hidden";

		/// <summary>
		/// Sets the VisibilitySetting to hidden.  Best to use this method to set the value.
		/// </summary>
		public bool SetVisibilityHidden { set { VisibilitySetting = "hidden"; } }

		/// <summary>
		/// Sets the visibility to viewable.  Best to use this method to set the value to viewable.
		/// </summary>
		public bool SetVisibilityViewable { set { VisibilitySetting = ""; } }



		/// <summary>
		/// Comma-separated list of headers to whitelist and pass from the request to the backend.
		/// </summary>
		[JsonProperty("passthrough_request_headers")]
		public string PassThruRequestHeaders { get; set; }
	}
}
