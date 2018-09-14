using Newtonsoft.Json;
using System.Collections.Generic;


namespace VaultAgent.Backends.KV_V2
{
	/// <summary>
	/// Represents a secret read from the Vault.  Secrets can have many attributes which are just Key Value Pairs of a name and some data value.
	/// Important is that when saving a secret, you must save it with all it's attributes or else any that are missing on the save will be removed from 
	/// the vault.  So, if upon reading a secret it has attributes of canDelete:True and connection:db1 and you save it, but the only attribute in the 
	/// list upon save is connection:db1 then canDelete will no longer exist after the save.  
	/// </summary>
	public class KV2Secret {
		public KV2Secret() {
			Attributes = new Dictionary<string, string>();
		}

		public KV2Secret(string nameAndPath) {
			Path = nameAndPath;
			Attributes = new Dictionary<string, string>();
		}



		/// <summary>
		/// The full path including the secret name, of the secret to retrieve.
		/// </summary>
		public string Path { get; set; }


		/// <summary>
		/// The actual values that should be saved in the secret. 
		/// </summary>
		[JsonProperty("data")]
		public Dictionary<string, string> Attributes { get; set; }

		
		[JsonProperty("metadata")]
		public Dictionary<string,string> Metadata { get; set; }
	
	}
}
