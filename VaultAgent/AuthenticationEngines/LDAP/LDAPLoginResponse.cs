using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using VaultAgent.SecretEngines.KV2;


namespace VaultAgent.AuthenticationEngines.LDAP {
    class LDAPLoginResponse {
        [JsonProperty ("client_token")]
        public string ClientToken { get; set; }

        [JsonProperty ("entity_id")]
        public Guid EntityId { get; set; }

        [JsonProperty ("accessor")]
        public string Accessor { get; set; }

        [JsonProperty ("policies")]
        public List<string> Policies { get; set; }

        [JsonProperty ("token_policies")]
        public List<string> TokenPolicies { get; set; }

        [JsonProperty ("metadata")]
        public Dictionary<string, string> Metadata { get; internal set; }

        [JsonProperty ("lease_duration")]
        public long LeaseDuration { get; set; }

        [JsonProperty ("renewable")]
        public bool Renewable { get; set; }


        [JsonProperty ("token_type")]
        public string TokenType { get; set; }
    }
}