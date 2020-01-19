using Newtonsoft.Json;

namespace VaultAgent.Backends.Transit.Models {
    /// <summary>
    /// A Vault Response Object For a BackupRestore Item
    /// </summary>
    public class TransitBackupRestoreItem {
        /// <summary>
        /// The backup contains all the configuration data and keys of all the versions along with the HMAC key
        /// </summary>
        [JsonProperty ("backup")]
        public string KeyBackup { get; set; }

        /// <summary>
        /// True if successful
        /// </summary>
        [JsonIgnore]
        public bool Success { get; set; }

        /// <summary>
        /// If Errors encountered then this contains the error message
        /// </summary>
        [JsonIgnore]
        public string ErrorMsg { get; set; }
    }
}