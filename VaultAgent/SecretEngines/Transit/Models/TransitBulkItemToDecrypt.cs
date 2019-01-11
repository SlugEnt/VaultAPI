using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VaultAgent.Backends.Transit.Models {
    /// <summary>
    /// Represents a single item within a list of items that need to be decrypted.  
    /// </summary>
    public class TransitBulkItemToDecrypt {
        public TransitBulkItemToDecrypt (string encryptedValue, string context = null) {
            encryptedItem = encryptedValue;
            if ( context != null ) { base64Context = VaultUtilityFX.Base64EncodeAscii (context); }
        }


        // Do not put context in JSON if it is null 
        [JsonProperty ("context", NullValueHandling = NullValueHandling.Ignore)]
        public string base64Context { get; private set; }


        [JsonProperty ("ciphertext")]
        public string encryptedItem { get; private set; }
    }
}