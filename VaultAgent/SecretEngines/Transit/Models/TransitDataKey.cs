using Newtonsoft.Json;

namespace VaultAgent.Backends.Transit.Models {
    /// <summary>
    /// Represents the response object from the GenerateDataKey method.  Provides the encrypting and decrypting key values.
    /// </summary>
    public class TransitDataKey {
        /// <summary>
        /// Plain Text version of the Key
        /// </summary>
        [JsonProperty ("plaintext")]
        public string PlainText { get; set; }

        /// <summary>
        /// The cipher text
        /// </summary>
        [JsonProperty ("ciphertext")]
        public string CipherText { get; set; }
    }
}