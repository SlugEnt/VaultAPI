using System;
using System.Collections.Generic;


using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace VaultAgent.Backends.KV_V2
{

	public partial class SecretReadReturnObj
	{
		[JsonProperty("request_id")]
		public Guid RequestId { get; internal set; }

		[JsonProperty("lease_id")]
		public string LeaseId { get; internal set; }

		[JsonProperty("renewable")]
		public bool Renewable { get; internal set; }

		[JsonProperty("lease_duration")]
		public long LeaseDuration { get; internal set; }

		[JsonProperty("data")]
		public SecretReadReturnObjData Data { get; internal set; }

		[JsonProperty("wrap_info")]
		public object WrapInfo { get; internal set; }

		[JsonProperty("warnings")]
		public object Warnings { get; internal set; }

		[JsonProperty("auth")]
		public object Auth { get; internal set; }
	}

	public partial class SecretReadReturnObjData
	{
		[JsonProperty("data")]
		public SecretV2 SecretObj { get; set; }

		[JsonProperty("metadata")]
		public Metadata Metadata { get; internal set; }
	}

	public partial class Metadata
	{
		[JsonProperty("created_time")]
		public DateTimeOffset CreatedTime { get; internal set; }

		[JsonProperty("deletion_time")]
		public string DeletionTime { get; internal set; }

		[JsonProperty("destroyed")]
		public bool Destroyed { get; internal set; }

		[JsonProperty("version")]
		public long Version { get; internal set; }
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

	internal class ParseStringConverter : JsonConverter
	{
		public override bool CanConvert(Type t) => t == typeof(long) || t == typeof(long?);

		public override object ReadJson(JsonReader reader, Type t, object existingValue, JsonSerializer serializer) {
			if (reader.TokenType == JsonToken.Null) return null;
			var value = serializer.Deserialize<string>(reader);
			long l;
			if (Int64.TryParse(value, out l)) {
				return l;
			}
			throw new Exception("Cannot unmarshal type long");
		}

		public override void WriteJson(JsonWriter writer, object untypedValue, JsonSerializer serializer) {
			if (untypedValue == null) {
				serializer.Serialize(writer, null);
				return;
			}
			var value = (long)untypedValue;
			serializer.Serialize(writer, value.ToString());
			return;
		}

		public static readonly ParseStringConverter Singleton = new ParseStringConverter();
	}
}
