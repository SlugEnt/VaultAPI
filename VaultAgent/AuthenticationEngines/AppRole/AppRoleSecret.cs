using Newtonsoft.Json;
using System;
using VaultAgent.Models;
using System.Collections.Generic;

using System.Globalization;

using Newtonsoft.Json.Converters;

namespace VaultAgent.AuthenticationEngines
{
	public class AppRoleSecret
	{
        [JsonConstructor]
	    public AppRoleSecret()
	    {
            MetaData = new VaultMetadata();
	    }


		[JsonProperty("secret_id")]
		public string ID { get; set; }


		[JsonProperty("secret_id_accessor")]
		public string Accessor { get; set; }


	    [JsonProperty("cidr_list")]
	    public object[] CIDR_List { get; set; }


	    [JsonProperty("creation_time")]
	    public DateTimeOffset CreationTime { get; set; }


	    [JsonProperty("expiration_time")]
	    public DateTimeOffset ExpirationTime { get; set; }


	    [JsonProperty("last_updated_time")]
	    public DateTimeOffset LastUpdatedTime { get; set; }


	    [JsonProperty("secret_id_num_uses")]
	    public long NumberOfUses { get; set; }


	    [JsonProperty("secret_id_ttl")]
	    public long SecretID_TTl { get; set; }


	    [JsonProperty("token_bound_cidrs")]
	    public object[] TokenBoundCidrs { get; set; }


	    [JsonProperty("metadata")]
	    public VaultMetadata MetaData { get; set; }

	}


    /*
    public static class Serialize
    {
        public static string ToJson(this Welcome self) => JsonConvert.SerializeObject(self, QuickType.Converter.Settings);
    }

    internal static class Converter
    {
        public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
        {
            MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
            DateParseHandling = DateParseHandling.None,
            Converters =
            {
                new IsoDateTimeConverter { DateTimeStyles = DateTimeStyles.AssumeUniversal }
            },
        };
    
    }*/
}
