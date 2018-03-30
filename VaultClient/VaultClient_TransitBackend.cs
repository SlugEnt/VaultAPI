using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent.Backends;
using System.Threading.Tasks;


namespace VaultClient
{
    public class VaultClient_TransitBackend
    {
		TransitBackend TB;
		

		public VaultClient_TransitBackend (string token, string ip, int port) {
			TB = new TransitBackend(ip, port, token);

		}

		public async Task Run() {
			try {
				Console.WriteLine("Running thru Vault TransitBackend exercises.");

				// Load parameters to Create an Encryption Key.
				Dictionary<string, string> vaultParams = new Dictionary<string, string>();
				vaultParams.Add("type", "aes256-gcm96");
				vaultParams.Add("derived", "true");
				vaultParams.Add("exportable", "true");
				vaultParams.Add("allow_plaintext_backup", "true");

				bool rc = await TB.CreateEncryptionKey("KeyTestABC2", vaultParams);

				if (rc == true) { Console.WriteLine("Success - Encryption Key written.  It may now be used to encrypt data.");  }
			}

			catch (Exception e) {
				Console.WriteLine("Errors - {0}", e.Message);
			}




		}
    }
}
