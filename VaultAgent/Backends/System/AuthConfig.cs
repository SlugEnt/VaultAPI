using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;


namespace VaultAgent.Backends.System
{
	/// <summary>
	/// Used to set configuration options for a particular Auth Method.
	/// </summary>
	public class AuthConfig
	{
		/// <summary>
		/// Number of seconds for token lease if numeric value, or Vault Time Element if number/string combo, ie, 12m is 12 minutes.
		/// </summary>
		[JsonProperty("default_lease_ttl")]
		public string DefaultLeaseTTL { get; set; } = "3600";

		/// <summary>
		/// Maximum amount of time that the token can be leased for before requiring a renewal.  
		/// </summary>
		[JsonProperty("max_lease_ttl")]
		public string MaxLeaseTTL { get; set; } = "0";

		[JsonProperty("plugin_name")]
		public string PluginName { get; set; } = "";

		[JsonProperty("audit_non_hmac_request_keys")]
		public List<string> Audit_NonHMAC_RequestKeys { get; set; } = new List<string>();

		[JsonProperty("audit_non_hmac_response_keys")]
		public List<string> Audit_NonHMAC_ResponseKeys { get; set; } = new List<string>();


		/// <summary>
		/// Determines if this authentication method is listed in the GUI.
		/// </summary>
		[JsonProperty("listing_visibility")]
		public string ListingVisibility { get; set; } = "";

		[JsonProperty("passthrough_request_headers")]
		public List<string> PassThroughRequestHeaders { get; set; } = new List<string>();
	}
}
