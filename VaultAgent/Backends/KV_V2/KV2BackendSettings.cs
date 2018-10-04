using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;


namespace VaultAgent.Backends.SecretEngines.KVV2
{
	/// <summary>
	/// Represents a Vault Key Value Backend Version 2 settings object.
	/// </summary>
	public class KV2BackendSettings
	{
		[JsonProperty("cas_required")]
		public bool CASRequired;

		[JsonProperty("max_versions")]
		public int MaxVersions;
	}
}
