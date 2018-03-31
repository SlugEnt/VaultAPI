using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent.Backends;
using System.Threading.Tasks;
using VaultAgent;
using VaultAgent.Models;


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

				await Run_ListKeys();

//				await Run_ReadKey();


				// Create an Encryption Key:
//				Run_CreateKey();
			}

			catch (Exception e) {
				Console.WriteLine("Errors - {0}", e.Message);
			}
		}

		public async Task Run_ListKeys() {
			List<string> keys = await TB.ListEncryptionKeys();
		}


		public async Task Run_ReadKey () {
			// Read an Encryption Key.
			//VaultDataResponseObject vdro = await TB.ReadEncryptionKey("KeyTestABC6");
			TransitKeyInfo TKI = await TB.ReadEncryptionKey("KeyTestABC6");
			Console.WriteLine("Encryption Key Read:");
			Console.ReadKey();
		}




		public async Task Run_CreateKey () {
			// Load parameters to Create an Encryption Key.
			Dictionary<string, string> vaultParams = new Dictionary<string, string>();
			vaultParams.Add("type", "aes256-gcm96");
			vaultParams.Add("derived", "true");
			vaultParams.Add("exportable", "false");
			vaultParams.Add("allow_plaintext_backup", "true");


			// Try with parameters we built above. 
			bool rc = await TB.CreateEncryptionKey("KeyTestABC6", vaultParams);
			if (rc == true) { Console.WriteLine("Success - Encryption Key written.  It may now be used to encrypt data."); }

			// Try with parameters values.
			rc = await TB.CreateEncryptionKey("KeyTestABC7", true, true, EnumTransitKeyType.rsa4096);
			if (rc == true) { Console.WriteLine("Success - Encryption Key written.  It may now be used to encrypt data."); }


		}
	}
}
