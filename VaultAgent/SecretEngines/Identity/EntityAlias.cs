using System;
using System.Collections.Generic;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;


namespace VaultAgent.SecretEngines {
    public partial class EntityAlias {
        /// <summary>
        /// The Entity ID this Alias belongs to.  
        /// </summary>
        [JsonProperty ("canonical_id")]
        public Guid CanonicalId { get; internal set; }


        /// <summary>
        /// The Entity ID this Alias belongs to.
        /// </summary>
        public Guid RelatedEntityID {
            get => CanonicalId;
            set { CanonicalId = value; }
        }


        /// <summary>
        /// When this alias was created
        /// </summary>
        [JsonProperty ("creation_time")]
        public DateTimeOffset CreationTime { get; internal set; }


        /// <summary>
        /// The Guid ID of this alias.
        /// </summary>
        [JsonProperty ("id")]
        public Guid Id { get; internal set; }


        /// <summary>
        /// When this Alias was last changed.
        /// </summary>
        [JsonProperty ("last_update_time")]
        public DateTimeOffset LastUpdateTime { get; internal set; }


        /// <summary>
        /// A list of Entity ID's that were merged into this Alias.
        /// </summary>
        [JsonProperty ("merged_from_canonical_ids")]
        public List<string> MergedFromCanonicalIds { get; internal set; }

        [JsonProperty ("metadata")]
        public Dictionary<string, string> Metadata { get; internal set; }

        [JsonProperty ("mount_accessor")]
        public string MountAccessor { get; internal set; }

        [JsonProperty ("mount_path")]
        public string MountPath { get; internal set; }

        [JsonProperty ("mount_type")]
        public string MountType { get; internal set; }

        [JsonProperty ("name")]
        public string Name { get; internal set; }
    }
}