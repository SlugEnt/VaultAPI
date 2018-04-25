using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;



namespace VaultAgent.Backends.AppRole
{
	public class AppRoleToken
	{
		public AppRoleToken (string name) {
			Name = name;
			IsSecretIDRequiredOnLogin = true;
			NumberOfUses = 0;
			SecretNumberOfUses = 0;
		}

		[JsonProperty("role_name")]
		public string Name { get; set; }

		[JsonProperty("bind_secret_id")]
		public bool IsSecretIDRequiredOnLogin { get; set; }

		[JsonProperty("bound_cidr_list")]
		public List<string> BoundCIDRList { get; set; }

		[JsonProperty("policies")]
		public List<string> Policies { get; set; }

		[JsonProperty("secret_id_num_uses")]
		public int SecretNumberOfUses { get; set; }

		[JsonProperty("secret_id_ttl")]
		public string SecretTTL { get; set; }

		[JsonProperty("token_num_uses")]
		public int NumberOfUses { get; set; }

		[JsonProperty("token_ttl")]
		public string TokenTTL { get; set; }

		[JsonProperty("token_max_ttl")]
		public string TokenMaxTTL { get; set; }

		[JsonProperty("period")]
		public string Period { get; set; }
	}
}
