using Newtonsoft.Json;

namespace VaultAgent.Backends.Transit.Models {
    /// <summary>
    /// A single Vault Decrypted value.  
    /// </summary>
    public class TransitDecryptedItem {
        private string decrypted;


        /// <summary>
        /// The decrypted Value
        /// </summary>
        [JsonProperty ("plaintext")]
        public string DecryptedValue {
            get { return decrypted; }
            set { decrypted = VaultUtilityFX.Base64DecodeAscii (value); }
        }
    }
}