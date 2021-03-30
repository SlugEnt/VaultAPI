using System;
using System.Collections.Generic;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;



namespace VaultAgent.SecretEngines.KV2.SecretMetaDataInfo {

    /// <summary>
    /// Class used to hold a Key Value 2 Secret's metadata or information about the secret that Vault Stores.  Mostly Timestamps and Version Info
    /// </summary>
    public partial class KV2SecretMetaDataInfo {
        /// <summary>
        /// Whether Check and Set is required during Secret Updates.  Check And Set determines if a secret can be overwritten always, never, or only if the current version matches the version number passed in.
        /// </summary>
        [JsonProperty ("cas_required")]
        public bool CasRequired { get; set; }

        /// <summary>
        /// Date and time that this version was created at.
        /// </summary>
        [JsonProperty ("created_time")]
        public DateTimeOffset CreatedTime { get; set; }

        /// <summary>
        /// The Current version of this secret
        /// </summary>
        [JsonProperty ("current_version")]
        public long CurrentVersion { get; set; }

        /// <summary>
        /// Maximum number of versions to keep of this particular secret
        /// </summary>
        [JsonProperty ("max_versions")]
        public long MaxVersions { get; set; }

        /// <summary>
        /// What the oldest version number of this secret is
        /// </summary>
        [JsonProperty ("oldest_version")]
        public long OldestVersion { get; set; }

        /// <summary>
        /// The data and time this secret was last updated
        /// </summary>
        [JsonProperty ("updated_time")]
        public DateTimeOffset UpdatedTime { get; set; }

        /// <summary>
        /// All of the MetaData for the current versions.
        /// </summary>
        [JsonProperty ("versions")]
        public Dictionary<string, MetaDataVersion> Versions { get; set; }
    }


    /// <summary>
    /// The MetaData Related Information in regards to the particular version of the secret
    /// </summary>
    public partial class MetaDataVersion {

        /// <summary>
        /// The time this version was created
        /// </summary>
        [JsonProperty ("created_time")]
        public DateTimeOffset CreatedTime { get; set; }

        /// <summary>
        /// The time this was Deleted
        /// </summary>
        [JsonProperty ("deletion_time")]
        public string DeletionTime { get; set; }

        /// <summary>
        /// Whether this version has been permanently deleted or not.
        /// </summary>
        [JsonProperty ("destroyed")]
        public bool Destroyed { get; set; }
    }
}