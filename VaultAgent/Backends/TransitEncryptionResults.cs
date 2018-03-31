using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VaultAgent.Backends
{
	public class TransitEncryptionResults
	{
		
		[JsonProperty("ciphertext")]
		[JsonConverter(typeof(JSONSingleOrArrayConverter<string>))]
		public List<string> Ciphers { get; set; }

		/*
		[JsonProperty("")]
		public string x { get; set; }

		[JsonProperty("")]
		public string x { get; set; }

	*/


	}
}
