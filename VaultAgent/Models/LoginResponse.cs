using System;
using System.Collections.Generic;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;


namespace VaultAgent.Models {
    /// <summary>
    /// This class is used to get the response from a Login attempt.  It provides much of the information you will need in this object
    /// directly.  But best is still to go read the token object that corresponds to the ClientToken property.
    /// </summary>
    internal class LoginResponse {
        /// <summary>
        /// The ID of the token that was generated from the Login.
        /// </summary>
        [JsonProperty ("client_token")]
        public string ClientToken { get; set; }

        [JsonProperty ("accessor")]
        public string Accessor { get; set; }


        /// <summary>
        /// All policies that apply to this token.  This is the combined TokenPolicies + IdentityPolices.
        /// </summary>
        [JsonProperty ("policies")]
        public List<string> Policies { get; internal set; }


        /// <summary>
        /// The policies assigned to the token that came from the normal policy process. 
        /// </summary>
        [JsonProperty ("token_policies")]
        public List<string> TokenPolicies { get; internal set; }


        /// <summary>
        /// Policies that were provided due to the entity the login object was tied to.
        /// </summary>
        [JsonProperty ("identity_policies")]
        public List<string> IdentityPolicies { get; internal set; }


        /// <summary>
        /// Additional informational items that are associated with the token.
        /// </summary>
        [JsonProperty ("metadata")]
        public Dictionary<string, string> Metadata { get; internal set; }

        [JsonProperty ("lease_duration")]
        public long LeaseDuration { get; set; }

        [JsonProperty ("renewable")]
        public bool Renewable { get; set; }

        [JsonProperty ("entity_id")]
        public string EntityId { get; set; }
    }
}