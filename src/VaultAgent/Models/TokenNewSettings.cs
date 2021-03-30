using Newtonsoft.Json;
using System.Collections.Generic;

namespace VaultAgent.Models {
    /// <summary>
    /// Class that captures the attributes that Vault Returns when requesting Token Information.  Some of the properties are also used when saving a Token.
    /// </summary>
    public class TokenNewSettings {
        /// <summary>
        /// The Token's ID.  Typically this is set by Vault.
        /// </summary>
        [JsonProperty ("id")]
        public string ID { get; set; }

        /// <summary>
        /// Name of the Role to create token against.  If speficied the Role may override other manually set Token Options
        /// </summary>
        [JsonProperty ("role_name")]
        public string RoleName { get; set; }

        /// <summary>
        /// The policies that are associated with the Token
        /// </summary>
        [JsonProperty ("policies")]
        public List<string> Policies { get; set; }


        /// <summary>
        /// Arbirtray data that is associated with the token
        /// </summary>
        [JsonProperty ("meta")]
        public Dictionary<string, string> MetaData { get; set; }


        /// <summary>
        /// True if the token has no parent.  
        /// </summary>
        [JsonProperty ("no_parent")]
        public bool NoParentToken { get; set; }


        /// <summary>
        /// Detach the default policy from the policy set for this token.  See Vault for what this means...
        /// </summary>
        [JsonProperty ("no_default_policy")]
        public bool NoDefaultPolicy { get; set; }


        /// <summary>
        /// If the Token can be renewed
        /// </summary>
        [JsonProperty ("renewable")]
        public bool IsRenewable { get; set; }


        //TODO change to TimeUnit type
        /// <summary>
        /// Initial TTL to associate with the Token.  
        /// </summary>
        [JsonProperty ("ttl")]
        public string TTL { get; set; }


        /// <summary>
        /// The Maximum amout of time that the TTL for this token can be set to
        /// </summary>
        [JsonProperty ("explicit_max_ttl")]
        public string MaxTTL { get; set; }


        /// <summary>
        /// Name of this Token
        /// </summary>
        [JsonProperty ("display_name")]
        public string Name { get; set; }


        /// <summary>
        /// How many times this token can be used
        /// </summary>
        [JsonProperty ("num_uses")]
        public long NumberOfUses { get; set; }


        //TODO Use TimeUnit Type
        /// <summary>
        /// How much time to extend the Token, when it is renewed.
        /// </summary>
        [JsonProperty ("period")]
        public string RenewalPeriod { get; set; }



        // Constructors 


        /// <summary>
        /// Constructor for use when reading the Settings from Vault.  Sets the ID.
        /// </summary>
        /// <param name="id">The token ID that Vault assigned</param>
        [JsonConstructor]
        public TokenNewSettings (string id) { ID = id; }


        /// <summary>
        /// Creates a new TokenSettings object with an empty initialized Policies list and empty Metadata Dictionary.
        /// </summary>
        public TokenNewSettings () {
            Policies = new List<string>();
            MetaData = new Dictionary<string, string>();
        }
    }
}