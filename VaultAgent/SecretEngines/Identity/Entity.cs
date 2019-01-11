using System;
using System.Collections.Generic;
using System.Globalization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;


namespace VaultAgent.SecretEngines {
    /// <summary>
    /// Represents a Vault identity entity object.  Entities are used to provide a single identified for a group of ID's across different
    /// authentication backends that are all really the same thing.  For instance a user has an LDAP, GitHub and AWS credentials.  The ID allows
    /// us to combine all of those into a single object.
    /// </summary>
    public partial class Entity {
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


        [JsonProperty ("aliases")]
        public List<EntityAlias> Aliases { get; internal set; }

        [JsonProperty ("creation_time")]
        public DateTimeOffset CreationTime { get; internal set; }

        [JsonProperty ("direct_group_ids")]
        public List<string> DirectGroupIds { get; internal set; }

        [JsonProperty ("disabled")]
        public bool IsDisabled { get; set; }

        [JsonProperty ("group_ids")]
        public List<string> GroupIds { get; internal set; }

        [JsonProperty ("id")]
        public Guid Id { get; internal set; }

        [JsonProperty ("inherited_group_ids")]
        public List<string> InheritedGroupIds { get; internal set; }

        [JsonProperty ("last_update_time")]
        public DateTimeOffset LastUpdateTime { get; internal set; }

        //TODO - this probably needs to be changed to a List<string>  Need to verify the output type.
        [JsonProperty ("merged_entity_ids")]
        public object MergedEntityIds { get; internal set; }

        [JsonProperty ("metadata")]
        public Dictionary<string, string> Metadata { get; set; }

        [JsonProperty ("name")]
        public string Name { get; internal set; }

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
        public bool ShouldSerializeMergedEntityIds () { return false; }
        public bool ShouldSerializeLastUpdateTime () { return false; }
        public bool ShouldSerializeInheritedGroupIds () { return false; }
        public bool ShouldSerializeCreationTime () { return false; }
        public bool ShouldSerializeGroupIds () { return false; }
        public bool ShouldSerializeDirectGroupIds () { return false; }
        public bool ShouldSerializeAliases () { return false; }
    }


    /*
    public partial class Entity
    {
        public static Entity FromJson(string json) => JsonConvert.DeserializeObject<Entity>(json, Converter.Settings);
    }

    public static class Serialize
    {
        public static string ToJson(this Entity self) => JsonConvert.SerializeObject(self, Converter.Settings);
    }

    internal static class Converter
    {
        public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings {
            MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
            DateParseHandling = DateParseHandling.None,
            Converters =
            {
                new IsoDateTimeConverter { DateTimeStyles = DateTimeStyles.AssumeUniversal }
            },
        };
    }
    */
}