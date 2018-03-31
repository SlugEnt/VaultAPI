using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultAgent.Backends;
using VaultAgent.Models;

namespace VaultAgent.Models
{
	/// <summary>
	/// This class represents a Vault Transit key object. 
	/// </summary>
	public class TransitKeyInfo {

		[JsonProperty("name")]
		public string Name { get; set; }

		[JsonProperty("type")]
		public string EncryptionMethod { get; set; }

		[JsonProperty("latest_version")]
		public string  LatestVersionNum {get;set;} 

		[JsonProperty("min_decryption_version")]
		public string MinDecryptionVersion  {get;set;}

		[JsonProperty("min_encryption_version")]
		public string  MinEncryptionVersion {get;set;}

		[JsonProperty("supports_decryption")]
		public bool SupportsDecryption  {get;set;}

		[JsonProperty("supports_derivation")]
		public bool  SupportsDerivation {get;set;}

		[JsonProperty("supports_encryption")]
		public bool SupportsEncryption  {get;set;}

		[JsonProperty("supports_signing")]
		public bool SupportsSigning  {get;set;}

		[JsonProperty("allow_plaintext_backup")]
		public bool AllowsPlainTextBackup  {get;set;}

		[JsonProperty("convergent_encryption")]
		public bool EnableConvergentEncryption { get; set; }

		[JsonProperty("deletion_allowed")]
		public bool CanDelete { get; set; }

		[JsonProperty("derived")]
		public bool IsDerivable { get; set; }

		[JsonProperty("exportable")]
		public bool IsExportable { get; set; }

		[JsonProperty("kdf")]
		public string KDF { get; set; }

		[JsonProperty("keys")]
		public Dictionary<int,object> Keys { get; set; }

	}


}