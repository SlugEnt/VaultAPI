﻿using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent {
	public static class VaultSerializationHelper {
		private static readonly JsonSerializerSettings serializationSettings = new JsonSerializerSettings
		{
			MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
			DateParseHandling = DateParseHandling.None,
		};

		// universal method for deserialization from json
		// the generic type "T" represents the result type of deserialization
		public static T FromJson<T>(string json) { return JsonConvert.DeserializeObject<T>(json, serializationSettings); }

		// universal method for serialization to json
		// this "this" keyword means, its "extension method"
		public static string ToJson<T>(this T self) { return JsonConvert.SerializeObject(self, serializationSettings); }
	}
}
