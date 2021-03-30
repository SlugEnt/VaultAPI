using Newtonsoft.Json;
using System.Collections.Generic;

namespace VaultAgent.Backends.Transit.Models {
    /// <summary>
    /// Contains the results of a bulk decryption operation.  The items are ordered in the list in the same order as the original encrypted values.
    /// </summary>
    public class TransitDecryptionResultsBulk {
        /// <summary>
        /// A List Of TransitDecryptedItems
        /// </summary>
        [JsonProperty ("batch_results")]
        public List<TransitDecryptedItem> DecryptedValues { get; set; }
    }
}