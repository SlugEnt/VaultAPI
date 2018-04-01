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
				string eKey = "KeyTestABC7";

				/*
								List<string> transitKeys = await Run_ListKeys();
								//await Run_ReadKey("keyTestABC5");
								Console.WriteLine("Following are the Encryption Keys currently in Transit Backend");

								foreach (string key in transitKeys) {
									TransitKeyInfo TKI = await TB.ReadEncryptionKey(key);
									Console.WriteLine("Key info for:  {0}",TKI.Name);
									Console.WriteLine("  Supports:  Deriv:{0}  Converg:{1}", TKI.SupportsDerivation, TKI.EnableConvergentEncryption);
								}


								// Encrypt Single Item
								Console.WriteLine("Encrypting a single item.");

								await Run_EncryptData(eKey);
				*/



				Console.WriteLine("Encrypting bulk Items");
				// Encrypt Bulk Items
				List<TransitBulkEncryptItem> bulkEnc = new List<TransitBulkEncryptItem>();
				bulkEnc.Add(new TransitBulkEncryptItem("ABC"));
				bulkEnc.Add(new TransitBulkEncryptItem("DEF"));
				bulkEnc.Add(new TransitBulkEncryptItem("GHI"));
				bulkEnc.Add(new TransitBulkEncryptItem("JKL"));
				bulkEnc.Add(new TransitBulkEncryptItem("MNO"));

				TransitEncryptionResultsBulk results = await TB.EncryptBulk(eKey, bulkEnc);
				int sentCnt = bulkEnc.Count;
				int recvCnt = results.Ciphers.Count;
				if (sentCnt == recvCnt) { Console.WriteLine("  - Bulk Encryption completed.  Sent and recived items count same!  SUCCESS!"); }


				foreach (TransitEncryptionResultsSingle encrypted in results.Ciphers) {
					TransitDecryptionResultSingle decrypted = await TB.Decrypt(eKey, encrypted.Ciphertext );
					Console.WriteLine("  - Decrypted Value = {0}", decrypted.DecryptedValue);
				}
				
//				await Run_ReadKey();


				// Create an Encryption Key:
				//Run_CreateKey("keyA");
			}

			catch (Exception e) {
				Console.WriteLine("Errors - {0}", e.Message);
				Console.WriteLine(" Full Exception is:");
				Console.WriteLine(e.ToString());

			}
		}



		public async Task Run_EncryptData (string key) {
			try {


				string a = "abcDEF123$%^";

				TransitEncryptionResultsSingle response = await TB.Encrypt(key, a);
				Console.WriteLine("Encrypt Data Routine:");
				
				//Console.WriteLine(" encrypted: {0} to {1}", a, response[0].Ciphers);

			}
			catch (Exception e) {
				Console.WriteLine("Errors - {0}", e.Message);
				Console.WriteLine(e.ToString());
			}
		}



		public async Task<List<string>> Run_ListKeys() {
			Console.WriteLine("List Transit Encryption Keys");
			List<string> keys = await TB.ListEncryptionKeys();
			foreach (string key in keys) {
				Console.WriteLine("Key: {0}", key);
			}
			return keys;
		}


		public async Task Run_ReadKey (string key) {
			// Read an Encryption Key.
			//VaultDataResponseObject vdro = await TB.ReadEncryptionKey("KeyTestABC6");
			TransitKeyInfo TKI = await TB.ReadEncryptionKey(key);
			Console.WriteLine("Encryption Key Read:");
			Console.ReadKey();
		}




		public async Task Run_CreateKey (string key) {
			// Load parameters to Create an Encryption Key.
			Dictionary<string, string> vaultParams = new Dictionary<string, string>();
			vaultParams.Add("type", "aes256-gcm96");
			//vaultParams.Add("derived", "true");
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
