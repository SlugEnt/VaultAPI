using Newtonsoft.Json;

namespace VaultAgent.Backends.Transit.Models {
    /// <summary>
    /// Represents a Vault Encrypted value.
    /// </summary>
    public class TransitEncryptedItem {
        /// <summary>
        /// The Encrypted Item
        /// </summary>
        [JsonProperty ("ciphertext")]
        public string EncryptedValue { get; set; }
    }
}