using Newtonsoft.Json;

namespace VaultAgent.Backends {
    /// <summary>
    /// Represents a single item to be encrypted as part of a Bulk Encryption call.  
    /// </summary>
    public class TransitBulkItemToEncrypt {
        /// <summary>
        /// Constructor for a single item to be encrypted.
        /// </summary>
        /// <param name="itemToEncrypt">The string value of the item to encrypt</param>
        /// <param name="context">The Base64 Context for key derivation if desired</param>
        public TransitBulkItemToEncrypt (string itemToEncrypt, string context = null) {
            base64ItemToEncrypt = VaultUtilityFX.Base64EncodeAscii (itemToEncrypt);

            if ( context != null ) { base64Context = VaultUtilityFX.Base64EncodeAscii (context); }
        }


        /// <summary>
        /// Constructor
        /// </summary>
        public TransitBulkItemToEncrypt () { }


        /// <summary>
        /// The Base64 Context for Key Derivation if desired
        /// </summary>
        [JsonProperty ("context", NullValueHandling = NullValueHandling.Ignore)]
        public string base64Context { get; private set; }


        /// <summary>
        /// The Item to be encrypted
        /// </summary>
        [JsonProperty ("plaintext")]
        public string base64ItemToEncrypt { get; private set; }
    }
}