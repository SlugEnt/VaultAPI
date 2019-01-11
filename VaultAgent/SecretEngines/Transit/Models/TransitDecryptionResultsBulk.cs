using Newtonsoft.Json;
using System.Collections.Generic;

namespace VaultAgent.Backends.Transit.Models {
    /// <summary>
    /// Contains the results of a bulk decryption operation.  The items are ordered in the list in the same arder as the original encrypted values.
    /// </summary>
    public class TransitDecryptionResultsBulk {
        [JsonProperty ("batch_results")]
        public List<TransitDecryptedItem> DecryptedValues { get; set; }
    }
}