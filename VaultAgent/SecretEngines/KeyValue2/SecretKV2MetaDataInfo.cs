using System;
using System.Collections.Generic;

using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

// To parse this JSON data, add NuGet 'Newtonsoft.Json' then do:
//
//    using VaultAgent.Backends.KV_V2;
//
//    var secretReadReturnObj = SecretReadReturnObj.FromJson(jsonString);

namespace VaultAgent.Backends.KV_V2.KV2SecretMetaData
{
	public partial class KV2SecretMetaDataInfo 
	{
		[JsonProperty("cas_required")]
		public bool CasRequired { get; set; }

		[JsonProperty("created_time")]
		public DateTimeOffset CreatedTime { get; set; }

		[JsonProperty("current_version")]
		public long CurrentVersion { get; set; }

		[JsonProperty("max_versions")]
		public long MaxVersions { get; set; }

		[JsonProperty("oldest_version")]
		public long OldestVersion { get; set; }

		[JsonProperty("updated_time")]
		public DateTimeOffset UpdatedTime { get; set; }

		[JsonProperty("versions")]
		public Dictionary<string, MetaDataVersion> Versions { get; set; }
	}

	public partial class MetaDataVersion
	{
		[JsonProperty("created_time")]
		public DateTimeOffset CreatedTime { get; set; }

		[JsonProperty("deletion_time")]
		public string DeletionTime { get; set; }

		[JsonProperty("destroyed")]
		public bool Destroyed { get; set; }
	}

	public partial class SecretReadReturnObj
	{
		public static SecretReadReturnObj FromJson(string json) => JsonConvert.DeserializeObject<SecretReadReturnObj>(json, VaultAgent.Backends.KV_V2.Converter.Settings);
	}

	public static class Serialize
	{
		public static string ToJson(this SecretReadReturnObj self) => JsonConvert.SerializeObject(self, VaultAgent.Backends.KV_V2.Converter.Settings);
	}

	internal static class Converter
	{
		public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings {
			MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
			DateParseHandling = DateParseHandling.None,
			Converters = {
				new IsoDateTimeConverter { DateTimeStyles = DateTimeStyles.AssumeUniversal }
			},
		};
	}
}
