using Newtonsoft.Json;
using System.Collections.Generic;

namespace VaultAgent.Backends.Transit.Models
{
	/// <summary>
	/// Contains the encrypted values from the bulk encrypt operation.  Values are ordered in same order as they were provided on the input side.
	/// </summary>
	public class TransitEncryptionResultsBulk
	{
		[JsonProperty("batch_results")]
		public List<TransitEncryptedItem> EncryptedValues { get; set; }
	}
}
