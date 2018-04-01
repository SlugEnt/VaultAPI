using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VaultAgent.Backends
{
	public class TransitEncryptionResultsSingle { 
		[JsonProperty("ciphertext")]
		public string Ciphertext { get; set; }
	}



	public class TransitEncryptionResultsBulk
	{
		[JsonProperty("batch_results")]
		public List<TransitEncryptionResultsSingle> Ciphers { get; set; }
	}


	public class TransitDecryptionResultSingle
	{
		private string decrypted;

		[JsonProperty("plaintext")]
		public string DecryptedValue { 
			get { return decrypted; }
			set { decrypted = VaultUtilityFX.Base64DecodeAscii(value); }
		}
	}


	public class TransitDecryptionResultsBulk
	{
		[JsonProperty("batch_results")]
		public List<TransitDecryptionResultSingle> DecryptedValues { get; set; }
	}
}

