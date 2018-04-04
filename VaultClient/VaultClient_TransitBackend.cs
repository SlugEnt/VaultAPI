﻿using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent.Backends;
using System.Threading.Tasks;
using VaultAgent;
using VaultAgent.Models;
using VaultAgent.Backends.Transit.Models;
using VaultAgent.Backends.Transit;


namespace VaultClient
{
    public class VaultClient_TransitBackend
    {
		TransitBackend TB;
		

		public VaultClient_TransitBackend (string token, string ip, int port, string db) {
			TB = new TransitBackend(ip, port, token,db);

		}

		public async Task Run(bool runRotateTest = false, bool runRekeyTest = true) {
			try {
				Console.WriteLine("Running thru Vault TransitBackend exercises.");
				string eKey = "KeyTestABC7";

				// List Keys
				List<string> transitKeys = await Run_ListKeys();

				// Read a key
				await Run_ReadKey(eKey);

/*
				Console.WriteLine("Following are the Encryption Keys currently in Transit Backend");

								foreach (string key in transitKeys) {
									TransitKeyInfo TKI = await TB.ReadEncryptionKey(key);
									Console.WriteLine("Key info for:  {0}",TKI.Name);
									Console.WriteLine("  Supports:  Deriv:{0}  Converg:{1}", TKI.SupportsDerivation, TKI.EnableConvergentEncryption);
								}

	*/

				// Encrypt Single Item
				Console.WriteLine("Encrypting a single item.");
				await Run_EncryptData(eKey);



				// Encrypt Bulk Items
				Console.WriteLine("Encrypting bulk Items");
				
				List<TransitBulkItemToEncrypt> bulkEnc = new List<TransitBulkItemToEncrypt>();
				bulkEnc.Add(new TransitBulkItemToEncrypt("ABC"));
				bulkEnc.Add(new TransitBulkItemToEncrypt("DEF"));
				bulkEnc.Add(new TransitBulkItemToEncrypt("GHI"));
				bulkEnc.Add(new TransitBulkItemToEncrypt("JKL"));
				bulkEnc.Add(new TransitBulkItemToEncrypt("MNO"));

				TransitEncryptionResultsBulk results = await TB.EncryptBulk(eKey, bulkEnc);
				int sentCnt = bulkEnc.Count;
				int recvCnt = results.EncryptedValues.Count;
				if (sentCnt == recvCnt) { Console.WriteLine("  - Bulk Encryption completed.  Sent and recived items count same!  SUCCESS!"); }


				foreach (TransitEncryptedItem encrypted in results.EncryptedValues) {
					TransitDecryptedItem decrypted = await TB.Decrypt(eKey, encrypted.EncryptedValue );
					Console.WriteLine("  - Decrypted Value = {0}", decrypted.DecryptedValue);
				}


				// Test Bulk Decryption
				List<TransitBulkItemToDecrypt> bulkDecrypt = new List<TransitBulkItemToDecrypt>();
				foreach (TransitEncryptedItem encrypted in results.EncryptedValues) {
					bulkDecrypt.Add(new TransitBulkItemToDecrypt(encrypted.EncryptedValue));
				}


				// Now decrypt.
				TransitDecryptionResultsBulk resDecrypt = await TB.DecryptBulk(eKey, bulkDecrypt);
				int sentCntD = bulkDecrypt.Count;
				int recvCntD = resDecrypt.DecryptedValues.Count;
				if (sentCntD == recvCntD) { Console.WriteLine("  - Bulk Decryption completed.  Sent and recived items count same!  SUCCESS!"); }

				// Print results:
				foreach(TransitDecryptedItem decrypted in resDecrypt.DecryptedValues) {
					Console.WriteLine("  Bulk Decryption result: {0}", decrypted.DecryptedValue);
				}



				// Rotate the Key.
				if (runRotateTest) {
					Console.WriteLine("Rotating the Key.");
					bool rotateAnswer = await TB.RotateKey(eKey);
					if (rotateAnswer) { Console.WriteLine("  - Key rotation successful."); }
				}

				if (runRekeyTest) {
					Console.WriteLine("Rencrypting a key.");
					await Run_ReEncrypt(eKey);
				}


				// Test Bulk Rewrap.
				TransitEncryptionResultsBulk bulkRewrap = await TB.ReEncryptBulk(eKey, bulkDecrypt);
				foreach(TransitEncryptedItem encrypted in bulkRewrap.EncryptedValues) {
					// Decrypt the value:
					TransitDecryptedItem tdiA = await TB.Decrypt(eKey, encrypted.EncryptedValue);
					Console.WriteLine("  - Decrypted value from bulk Rewrap = {0}", tdiA.DecryptedValue);
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

				TransitEncryptedItem response = await TB.Encrypt(key, a);
				Console.WriteLine("Encrypt Data Routine:");
				
				Console.WriteLine(" encrypted: {0} to {1}", a, response.EncryptedValue);

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
			TransitKeyInfo TKI = await TB.ReadEncryptionKey(key);
			Console.WriteLine("Encryption Key Read:");
			Console.WriteLine("  - {0}", TKI.ToString());
		
		}


		public async Task Run_ReEncrypt (string key) {
			Console.WriteLine("Running Re-Encrypt Data Process:");
			string a = "abcDEF123$%^";

			TransitKeyInfo TKIA = await TB.ReadEncryptionKey(key);
			Console.WriteLine("  -- Encryption Key Current Version is {0}", TKIA.LatestVersionNum);

			TransitEncryptedItem response = await TB.Encrypt(key, a);
			bool success = await TB.RotateKey(key);
			if (!success) {
				Console.WriteLine("  -- Failed to rotate the key.  Stopping the Re-Encryption test.");
				return;
			}
			TransitKeyInfo TKIB = await TB.ReadEncryptionKey(key);
			Console.WriteLine("  -- Encryption Key New Version is {0}", TKIB.LatestVersionNum);

			TransitEncryptedItem response2 = await TB.ReEncrypt(key, response.EncryptedValue);
			if (response2 != null) {
				Console.WriteLine("  -- Reencryption completed.");

				// Now validate by decrypting original value and new value.  Should be same.
				TransitDecryptedItem decryptA = await TB.Decrypt(key, response.EncryptedValue);
				TransitDecryptedItem decryptB = await TB.Decrypt(key, response2.EncryptedValue);
				if (a == decryptB.DecryptedValue) {	Console.WriteLine("  -- ReEncryption successfull.  Original Data = {0} and after re-encrypt value = {1}", a, decryptB.DecryptedValue); }
				else { Console.WriteLine("  -- ReEncryption FAILED.  Original value = {0}, re-Encryption value = {1}.", a, decryptB.DecryptedValue); }

			}

			Console.WriteLine(" encrypted: {0} to {1}", a, response.EncryptedValue);
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
