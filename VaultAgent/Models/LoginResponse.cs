using System;
using System.Collections.Generic;

using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;


namespace VaultAgent.Models
{
    public class LoginResponse
    {
            [JsonProperty("client_token")]
            public string ClientToken { get; set; }

            [JsonProperty("accessor")]
            public string Accessor { get; set; }

            [JsonProperty("policies")]
            public List<string> Policies { get; set; }

            [JsonProperty("token_policies")]
            public List<string> TokenPolicies { get; set; }

            //TODO - Need to build a universal MetaData object that converts from KeyValue strings into a Dictionary.
          //  [JsonProperty("metadata")]
            //public string Metadata { get; set; }

            [JsonProperty("lease_duration")]
            public long LeaseDuration { get; set; }

            [JsonProperty("renewable")]
            public bool Renewable { get; set; }

            [JsonProperty("entity_id")]
            public string EntityId { get; set; }
    }
}
