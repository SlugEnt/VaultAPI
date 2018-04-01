using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VaultAgent.Backends
{
	/// <summary>
	/// Represents a Vault Encrypted value.
	/// </summary>
	public class TransitEncryptedItem { 
		[JsonProperty("ciphertext")]
		public string EncryptedValue { get; set; }
	}



	/// <summary>
	/// Contains the encrypted values from the bulk encrypt operation.  Values are ordered in same order as they were provided on the input side.
	/// </summary>
	public class TransitEncryptionResultsBulk
	{
		[JsonProperty("batch_results")]
		public List<TransitEncryptedItem> EncryptedValues { get; set; }
	}



	/// <summary>
	/// A single Vault Decrypted value.  
	/// </summary>
	public class TransitDecryptedItem
	{
		private string decrypted;

		[JsonProperty("plaintext")]
		public string DecryptedValue { 
			get { return decrypted; }
			set { decrypted = VaultUtilityFX.Base64DecodeAscii(value); }
		}
	}



	/// <summary>
	/// Contains the results of a bulk decryption operation.  The items are ordered in the list in the same arder as the original encrypted values.
	/// </summary>
	public class TransitDecryptionResultsBulk
	{
		[JsonProperty("batch_results")]
		public List<TransitDecryptedItem> DecryptedValues { get; set; }
	}




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

