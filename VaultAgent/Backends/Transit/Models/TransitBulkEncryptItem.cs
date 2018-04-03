using Newtonsoft.Json;

namespace VaultAgent.Backends
{

	/// <summary>
	/// Represents a single item to be encrypted as part of a Bulk Encryption call.  
	/// </summary>
	public class TransitBulkEncryptItem
	{
		public TransitBulkEncryptItem(string itemToEncrypt, string context = null) {
			base64ItemToEncrypt = VaultUtilityFX.Base64EncodeAscii(itemToEncrypt);

			if (context != null) { base64Context = VaultUtilityFX.Base64EncodeAscii(context); }
		}


		public TransitBulkEncryptItem() { }


		// Do not put context in JSON if it is null 
		[JsonProperty("context", NullValueHandling = NullValueHandling.Ignore)]
		public string base64Context { get; private set; }


		[JsonProperty("plaintext")]
		public string base64ItemToEncrypt { get; private set; }
	}
}

