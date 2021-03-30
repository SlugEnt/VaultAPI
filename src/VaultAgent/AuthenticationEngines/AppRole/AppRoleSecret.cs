using Newtonsoft.Json;
using System;
using VaultAgent.Models;
using System.Collections.Generic;
using System.Globalization;
using Newtonsoft.Json.Converters;

namespace VaultAgent.AuthenticationEngines {
    /// <summary>
    /// An AppRoleSercret is the Secret ID which is associated with a particular Application Role.  This class represents the information that is 
    /// returned from the Vault Engine when requesting the SecretID.
    /// </summary>
    public class AppRoleSecret {
        /// <summary>
        /// Constructor
        /// </summary>
        [JsonConstructor]
        public AppRoleSecret () {
            // Initialize the Metadata object.
            Metadata = new Dictionary<string, string>();
        }

        /// <summary>
        /// The Secret ID value
        /// </summary>
        [JsonProperty ("secret_id")]
        public string ID { get; set; }


        /// <summary>
        /// An accessor that can be used to access this secret ID, without the need to know the SecretID.
        /// </summary>
        [JsonProperty ("secret_id_accessor")]
        public string Accessor { get; set; }


        /// <summary>
        /// List of IP's that are allowed to access
        /// </summary>
        [JsonProperty ("cidr_list")]
        public object [] CIDR_List { get; set; }

        /// <summary>
        /// When this Secret ID was created
        /// </summary>
        [JsonProperty ("creation_time")]
        public DateTimeOffset CreationTime { get; set; }


        /// <summary>
        /// When this secret ID expires
        /// </summary>
        [JsonProperty ("expiration_time")]
        public DateTimeOffset ExpirationTime { get; set; }


        /// <summary>
        /// The last time this secret ID was updated
        /// </summary>
        [JsonProperty ("last_updated_time")]
        public DateTimeOffset LastUpdatedTime { get; set; }


        /// <summary>
        /// The number of uses remaining for this SecretID.  If 0, it is unlimited
        /// </summary>
        [JsonProperty ("secret_id_num_uses")]
        public long NumberOfUses { get; set; }


        /// <summary>
        /// How long in seconds until this SecretId expires
        /// </summary>
        [JsonProperty ("secret_id_ttl")]
        public long SecretID_TTl { get; set; }


        /// <summary>
        /// List of IP address blocks that can authenticate with this role ID.
        /// </summary>
        [JsonProperty ("token_bound_cidrs")]
        public object [] TokenBoundCidrs { get; set; }


        /// <summary>
        /// Additional information about this SecretID
        /// </summary>
        [JsonProperty ("metadata")]
        public Dictionary<string, string> Metadata { get; internal set; }
    }
}