﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace VaultAgent.Backends.System
{
	/// <summary>
	/// Used to set configuration options for a particular Auth Method.
	/// </summary>
	public class AuthConfig
	{
		[JsonProperty("default_lease_ttl")]
		public string DefaultLeaseTTL { get; set; } = "3600";

		[JsonProperty("max_lease_ttl")]
		public string MaxLeaseTTL { get; set; } = "0";

		[JsonProperty("plugin_name")]
		public string PluginName { get; set; } = "";

		[JsonProperty("audit_non_hmac_request_keys")]
		public List<string> Audit_NonHMAC_RequestKeys { get; set; } = new List<string>();

		[JsonProperty("audit_non_hmac_response_keys")]
		public List<string> Audit_NonHMAC_ResponseKeys { get; set; } = new List<string>();

		[JsonProperty("listing_visibility")]
		public string ListingVisibility { get; set; } = "";

		[JsonProperty("passthrough_request_headers")]
		public List<string> PassThroughRequestHeaders { get; set; } = new List<string>();
	}
}