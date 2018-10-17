using System;
using System.Collections.Generic;


using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace VaultAgent.Backends.KV_V2
{

	/// <summary>
	/// The KV2SecretWrapper represents a Secret Container object that presents all the information Vault returns in regards to a secret.  
	/// Much of the info is just Informational, but some such as the version saved, etc is of critical nature.
	/// The main secret data is stored in the KV2Secret object.
	/// </summary>
	public partial class KV2SecretWrapper
	{
		// Default constructor used when created outside of vault.
		public KV2SecretWrapper () {
			WasReadFromVault = false;
			Data = new SecretReadReturnObjData(true);
		}



		/// <summary>
		/// This constructor should never be used by any outside caller.  Only used by the JSON Converter logic.
		/// It's sole purpose is to set the WasReadFromVault flag.
		/// </summary>
		/// <param name="value"></param>
		[JsonConstructor]
		public KV2SecretWrapper	(bool value) { WasReadFromVault = true; }



		/// <summary>
		/// Tells you if this Secret was read from the Vault storage engine or if it was created outside of Vault.  
		/// </summary>
		public bool WasReadFromVault { get; private set; }



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



		// The following are shortcuts to some of the properties above:

		/// <summary>
		/// Gets or sets the actual secret object.  This is a shortcut for going to obj.data.secretobj.
		/// </summary>
		public KV2Secret Secret
		{
			get { return this.Data.SecretObj; }
			set { this.Data.SecretObj = value; }
		}



		/// <summary>
		/// Accesses the attributes of the Secret.
		/// </summary>
		public Dictionary<string,string> SecretAttributes
		{
			get { return this.Data.SecretObj.Attributes; }
			
		}



		/// <summary>
		/// The version of the current key.  Versions are numerically increasing
		/// </summary>
		public int Version
		{
			get { return this.Data.Metadata.Version; }
			set { this.Data.Metadata.Version = value; }
		}
	}




	public partial class SecretReadReturnObjData
	{
		/// <summary>
		/// Default Constructor used by JSONConverter.
		/// </summary>
		[JsonConstructor]
		public SecretReadReturnObjData () { }


		/// <summary>
		/// Constructor used when this object is being created manually, vs populated thru JSON Converter.
		/// </summary>
		/// <param name="manualCreation"></param>
		public SecretReadReturnObjData (bool manualCreation = true) {
			SecretObj = new KV2Secret();
			Metadata = new Metadata();
		}


		/// <summary>
		/// The actual secret object - this is what most callers want.
		/// </summary>
		[JsonProperty("data")]
		public KV2Secret SecretObj { get; set; }


		/// <summary>
		/// The metadata - such as creation times, etc for this particular secret object.
		/// </summary>
		[JsonProperty("metadata")]
		public Metadata Metadata { get; internal set; }
	}



	/// <summary>
	/// This class is Vault Secret MetaData that tracks some values related to a given secret.
	/// Items tracked include when it was created and/or deleted, as well as if it is currently marked soft deleted and what the version # is.
	/// </summary>
	public partial class Metadata
	{
		/// <summary>
		/// When this particular secret version was created.
		/// </summary>
		[JsonProperty("created_time")]
		public DateTimeOffset CreatedTime { get; internal set; }


		/// <summary>
		/// When this particular secret version was deleted.
		/// </summary>
		[JsonProperty("deletion_time")]
		public string DeletionTime { get; internal set; }


		/// <summary>
		/// Boolean - Whether this particular secret version is soft deleted.
		/// </summary>
		[JsonProperty("destroyed")]
		public bool Destroyed { get; internal set; }


		/// <summary>
		/// The version number of this particular secret version.
		/// </summary>
		[JsonProperty("version")]
		public int Version { get; internal set; }
	}




	// All of the following code is for the JSON conversion.
	#region JSONConverterLogic


	public partial class KV2SecretWrapper
	{
		public static KV2SecretWrapper FromJson(string json) => JsonConvert.DeserializeObject<KV2SecretWrapper>(json, VaultAgent.Backends.KV_V2.Converter.Settings);
	}

	public static class Serialize
	{
		public static string ToJson(this KV2SecretWrapper self) => JsonConvert.SerializeObject(self, VaultAgent.Backends.KV_V2.Converter.Settings);
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
	#endregion
}
