using System.Collections.Generic;
using Newtonsoft.Json;



namespace VaultAgent.Models {
    /// <summary>
    /// This class is used to get the response from a Login attempt.  It provides much of the information you will need in this object
    /// directly.  But best is still to go read the token object that corresponds to the ClientToken property.
    /// <remarks>Note: TokenType added from LDAP login.  Is not found on EntityLogin.</remarks>
    /// </summary>
    public class LoginResponse {
        /// <summary>
        /// The ID of the token that was generated from the Login.
        /// </summary>
        [JsonProperty ("client_token")]
        public string ClientToken { get; internal set; }


        /// <summary>
        /// The accessor value for the Client Token
        /// </summary>
        [JsonProperty ("accessor")]
        public string Accessor { get; internal set; }


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


        /// <summary>
        /// How long this is valid for
        /// </summary>
        [JsonProperty ("lease_duration")]
        public long LeaseDuration { get; internal set; }


        /// <summary>
        /// Whether the token is renewable or not.
        /// </summary>
        [JsonProperty ("renewable")]
        public bool Renewable { get; internal set; }


        /// <summary>
        /// The Entity this login is associated with.
        /// </summary>
        [JsonProperty ("entity_id")]
        public string EntityId { get; internal set; }


        /// <summary>
        /// The type of token this is:  Service or Batch are the only valid values.
        /// </summary>
        [JsonProperty("token_type")]
        public string TokenType { get; internal set; }
    }
}