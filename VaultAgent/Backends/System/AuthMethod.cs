using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VaultAgent.Backends.System
{
	public class AuthMethod
	{
		[JsonProperty("path")]
		public string Path { get; set; }

		//[JsonProperty("description")]
		public string Description { get; set; }

		[JsonProperty("type")]
		public string Type { get; set; }

		[JsonProperty("plugin_name")]
		public string PluginName { get; set; }

		[JsonProperty("config", NullValueHandling = NullValueHandling.Ignore)]
		public AuthConfig Config { get; set; }
	}
}
