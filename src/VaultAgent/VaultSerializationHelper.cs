using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent {
    /// <summary>
    /// NewtonSoft JSON Serialization settings for all of Vault
    /// </summary>
    public static class VaultSerializationHelper {
        /// <summary>
        /// Serialization Settings
        /// </summary>
        private static readonly JsonSerializerSettings serializationSettings = new JsonSerializerSettings
        {
            MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
            DateParseHandling = DateParseHandling.None,
        };


        /// <summary>
        /// Deserializes a JSON string into a C# object
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="json"></param>
        /// <returns></returns>
        public static T FromJson<T> (string json) { return JsonConvert.DeserializeObject<T> (json, serializationSettings); }


        /// <summary>
        /// Universal Serializer for JSON
        /// universal method for serialization to json
        /// this "this" keyword means, its "extension method"
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="self"></param>
        /// <returns></returns>
        public static string ToJson<T> (this T self) { return JsonConvert.SerializeObject (self, serializationSettings); }
    }
}