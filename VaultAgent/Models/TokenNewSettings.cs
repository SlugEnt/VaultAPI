using Newtonsoft.Json;
using System.Collections.Generic;

namespace VaultAgent.Models
{
    public class TokenNewSettings
    {
		[JsonProperty("id")]
		public string ID { get; set; }

		[JsonProperty("role_name")]
		public string RoleName { get; set; }

		[JsonProperty("policies")]
		public List<string> Policies { get; set; }

		[JsonProperty("meta")]
		public Dictionary<string,string> MetaData { get; set; }

		[JsonProperty("no_parent")]
		public bool NoParentToken { get; set; }

		[JsonProperty("no_default_policy")]
		public bool NoDefaultPolicy { get; set; }

		[JsonProperty("renewable")]
		public bool Renewable { get; set; }

		[JsonProperty("ttl")]
		public string TTL { get; set; }

		[JsonProperty("explicit_max_ttl")]
		public string MaxTTL { get; set; }

		[JsonProperty("display_name")]
		public string Name { get; set; }

		[JsonProperty("num_uses")]
		public long NumberOfUses { get; set; }

		[JsonProperty("period")]
		public string RenewalPeriod { get; set; }



        // Constructors 

        [JsonConstructor]
        public TokenNewSettings (string id) { ID = id; }

        /// <summary>
        /// Creates a new TokenSettings object with an empty initialized Policies List.
        /// </summary>
        public TokenNewSettings() {
            Policies = new List<string>();
        }
    }
}
