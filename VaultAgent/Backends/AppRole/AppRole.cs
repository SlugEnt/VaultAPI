using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;



namespace VaultAgent.Backends.AppRole
{
	public class AppRole
	{
		private string _name;


		/// <summary>
		/// Creates an AppRole object with the specified name.  Number of uses is set to unlimited.
		/// </summary>
		/// <param name="name">Name to be given to the App Role.  It will be converted to Lower Case, since Vault only deals with lower case.</param>
		public AppRole (string name) {
			_name = name.ToLower();
			IsSecretIDRequiredOnLogin = true;
			NumberOfUses = 0;
			SecretNumberOfUses = 0;
		}


		[JsonConstructor]
		private AppRole () { }


		[JsonProperty("role_name")]
		public string Name {
			get { return _name; }
			set { _name = value.ToLower(); }
		}

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
