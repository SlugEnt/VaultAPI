using System;
using System.Collections.Generic;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;


namespace VaultAgent.SecretEngines {
    /// <summary>
    /// Represents a Vault identity entity object.  Entities are used to provide a single identifier for a group of ID's across different
    /// authentication backends that are all really the same thing.  For instance a user has an LDAP, GitHub and AWS credentials.  The ID allows
    /// us to combine all of those into a single object.
    /// </summary>
    public partial class Entity {
        /// <summary>
        /// Constructor for a Vault Entity.
        /// </summary>
        /// <param name="entityName">Name of the Entity</param>
        public Entity (string entityName) {
            Name = entityName;
            Policies = new List<string>();
            Metadata = new Dictionary<string, string>();
        }


        /// <summary>
        /// This constructor should only be used by the JSON Backend.  Use the parameter constructor for creation of new entities
        /// </summary>
        [JsonConstructor]
        internal Entity () { }


        /// <summary>
        /// Other Names for this Entity.  See Vault Documentation for Details
        /// </summary>
        [JsonProperty ("aliases")]
        public List<EntityAlias> Aliases { get; internal set; }


        /// <summary>
        /// When this entity was created.
        /// </summary>
        [JsonProperty ("creation_time")]
        public DateTimeOffset CreationTime { get; internal set; }


        /// <summary>
        /// See Vault Documentation for Details
        /// </summary>
        [JsonProperty ("direct_group_ids")]
        public List<string> DirectGroupIds { get; internal set; }


        /// <summary>
        /// If this Entity is disabled. Disabled Entities tokens cannot be used.
        /// </summary>
        [JsonProperty ("disabled")]
        public bool IsDisabled { get; set; }


        /// <summary>
        /// See Vault Documentation for Details
        /// </summary>
        [JsonProperty ("group_ids")]
        public List<string> GroupIds { get; internal set; }


        /// <summary>
        /// The ID of this Entity
        /// </summary>
        [JsonProperty ("id")]
        public Guid Id { get; internal set; }


        /// <summary>
        /// See Vault Documentation for Details
        /// </summary>
        [JsonProperty ("inherited_group_ids")]
        public List<string> InheritedGroupIds { get; internal set; }


        /// <summary>
        /// Last time this Entity was updated
        /// </summary>
        [JsonProperty ("last_update_time")]
        public DateTimeOffset LastUpdateTime { get; internal set; }


        /// <summary>
        /// See Vault Documentation for Details
        /// </summary>
        //TODO - this probably needs to be changed to a List<string>  Need to verify the output type.
        [JsonProperty ("merged_entity_ids")]
        public object MergedEntityIds { get; internal set; }


        /// <summary>
        /// Additional information to associate with this Entity
        /// </summary>
        [JsonProperty ("metadata")]
        public Dictionary<string, string> Metadata { get; set; }


        /// <summary>
        /// Name of this Entity
        /// </summary>
        [JsonProperty ("name")]
        public string Name { get; internal set; }


        /// <summary>
        /// Policies to be assigned to this Entity
        /// </summary>
        [JsonProperty ("policies")]
        public List<string> Policies { get; set; }


        /// <summary>
        /// We Serialize the ID if it contains a valid value.
        /// <remarks>This prevents us from sending the ID if it was initialized to empty in the C# class constructor (ie. this is a new entity not yet saved to Vault.</remarks>
        /// </summary>
        /// <returns></returns>
        public bool ShouldSerializeId () {
            if ( Id == Guid.Empty ) { return false; }

            return true;
        }


        // Most of these properties are only valid on deserializing from Vault.  They are not needed when saving an Entity.  These 
        // methods tell Newtonsoft not to serialize.
#pragma warning disable CS1591
        public bool ShouldSerializeMergedEntityIds () { return false; }
        public bool ShouldSerializeLastUpdateTime () { return false; }
        public bool ShouldSerializeInheritedGroupIds () { return false; }
        public bool ShouldSerializeCreationTime () { return false; }
        public bool ShouldSerializeGroupIds () { return false; }
        public bool ShouldSerializeDirectGroupIds () { return false; }
        public bool ShouldSerializeAliases () { return false; }
    }
}