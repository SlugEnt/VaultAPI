using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultAgent.Backends;
using VaultAgent.Models;

namespace VaultAgent.Models {
    /// <summary>
    /// This class represents a Vault Transit key object. 
    /// </summary>
    public class TransitKeyInfo {
        /// <summary>
        /// Name of the Transit Key
        /// </summary>
        [JsonProperty ("name")]
        public string Name { get; set; }

        /// <summary>
        /// The Type
        /// </summary>
        [JsonProperty ("type")]
        public string Type { get; set; }

        /// <summary>
        /// Latest Version Number of this key
        /// </summary>
        [JsonProperty ("latest_version")]
        public int LatestVersionNum { get; set; }

        /// <summary>
        /// The minimum version decrypted
        /// </summary>
        [JsonProperty ("min_decryption_version")]
        public int MinDecryptionVersion { get; set; }

        /// <summary>
        /// The minimum encrypted Version
        /// </summary>
        [JsonProperty ("min_encryption_version")]
        public int MinEncryptionVersion { get; set; }

        /// <summary>
        /// If Decryption is allowed
        /// </summary>
        [JsonProperty ("supports_decryption")]
        public bool SupportsDecryption { get; set; }

        /// <summary>
        /// If Key Derivation is allowed
        /// </summary>
        [JsonProperty ("supports_derivation")]
        public bool SupportsDerivation { get; set; }

        /// <summary>
        /// If Encryption is supported
        /// </summary>
        [JsonProperty ("supports_encryption")]
        public bool SupportsEncryption { get; set; }

        /// <summary>
        ///  If the key supports signing
        /// </summary>
        [JsonProperty ("supports_signing")]
        public bool SupportsSigning { get; set; }


        /// <summary>
        /// If plaintext backup is allowed
        /// </summary>
        [JsonProperty ("allow_plaintext_backup")]
        public bool AllowsPlainTextBackup { get; set; }

        /// <summary>
        /// True if it supports Convergent Encryption
        /// </summary>
        [JsonProperty ("convergent_encryption")]
        public bool SupportsConvergentEncryption { get; set; }

        /// <summary>
        /// If deletion is allowed
        /// </summary>
        [JsonProperty ("deletion_allowed")]
        public bool CanDelete { get; set; }

        /// <summary>
        /// If Key is derivable
        /// </summary>
        [JsonProperty ("derived")]
        public bool IsDerivable { get; set; }

        /// <summary>
        /// If Key is exportable
        /// </summary>
        [JsonProperty ("exportable")]
        public bool IsExportable { get; set; }

        /// <summary>
        /// Unknown
        /// </summary>
        [JsonProperty ("kdf")]
        public string KDF { get; set; }

        /// <summary>
        /// List of Keys
        /// </summary>
        [JsonProperty ("keys")]
        public Dictionary<int, object> Keys { get; set; }


        /// <summary>
        /// The Encryption Method this key uses
        /// </summary>
        public string EncryptionMethod {
            get { return Type; }
        }

        /// <summary>
        /// Returns basic information about the key
        /// </summary>
        /// <returns></returns>
        public override string ToString () {
            return $"Key Name: {Name} | Version: {LatestVersionNum} | Type: {Type} | Supports Derivation: {SupportsDerivation} | Number of Keys: {Keys.Count}";
        }
    }
}