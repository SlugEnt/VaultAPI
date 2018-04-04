using NUnit.Framework;
using System.Net.Http;
using System.Collections.Generic;
using VaultAgent;
using VaultAgent.Models;
using System;
using System.Threading.Tasks;
using VaultAgentTests;
using VaultAgent.Backends.Transit.Models;
using VaultAgent.Backends;
using VaultAgent.Backends.System;

namespace VaultAgentTests
{
    public class TransitBackendTest
    {
		// The Vault Transit Backend we will be using throughout our testing.
		TransitBackend TB;

		// For system related calls we will use this Backend.
		VaultSystemBackend VSB;


		// Encryption keys we will generally use throughout tests.
		string encKeyA = "Test_A";
		string encKeyB = "Test_B";
		string encKeyC = "Test_C";

		// Transit Backend we will generally use throughout tests.
		string transitBE_A = "transitA";
		string transitBE_B = "transitB";
		string transitBE_C = "transitC";

		string transitBE_A_Path;
		string transitBE_B_Path;
		string transitBE_C_Path;



		[Test, Order(1)]
		public async Task Transit_CreateAndMountCustomTransitBackend() {
			// Create a Transit Backend Mount for this series of tests.
			VSB = new VaultSystemBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

			// Create transitBE_A backend.
			string transitName = transitBE_A;
			string desc = "Transit DB: " + transitName + " backend.";
			bool rc = await VSB.SysMountEnable(transitName, desc, EnumBackendTypes.Transit);
			Assert.AreEqual(true, rc);


			TB = new TransitBackend(VaultServerRef.ipAddress,VaultServerRef.ipPort, VaultServerRef.rootToken,transitName);
		}


		[Test, Order(2)]
		public void  AH_VaultTransitBackendReadyTest() {
			// Make sure we have a root token and an ip address.
			Assert.AreNotEqual(VaultServerRef.rootToken, "");
			Assert.AreNotEqual(VaultServerRef.ipAddress, "");
			Assert.NotNull(TB);
		}


		[Test, Order(20)]
		public async Task Transit_CreateEncryptionKey() {
			try {
				// Try with parameters values.
				bool rc = await TB.CreateEncryptionKey(encKeyA, true, true, EnumTransitKeyType.rsa4096);
				Assert.AreEqual(true, rc);
			}
			catch (Exception e) { }
		}
	

		[Test, Order(30)]
		public async Task Transit_ReadEncryptionKeyInfo() {
			try {
				TransitKeyInfo TKI = await TB.ReadEncryptionKey(encKeyA);
				Assert.AreEqual(encKeyA, TKI.Name);
				Assert.AreEqual(1, TKI.LatestVersionNum);
			}
			catch (Exception e) { }
		}






		[Test, Order(40)]
		public async Task Transit_ListEncryptionKeys_ShouldReturnAllKeys() {
			try {
				// Depending on what's already happened, we cannot be sure of how many keys might be in the backend.
				// so we will grab initial list.  Then add 3 keys.  Then re-grab and make sure the 3 new keys are listed
				// and the count is 3 higher.
				List<string> keysA = await TB.ListEncryptionKeys();
				int countA = keysA.Count;

				string keyName;
				for (int i = 1; i<4; i++) {
					keyName = encKeyB + i.ToString();

					// Create the key.
					await TB.CreateEncryptionKey(keyName, true, false, EnumTransitKeyType.aes256);
				}

				// Now get new list of keys.
				List<string> keysB = await TB.ListEncryptionKeys();
				int countB = keysB.Count;

				// Perform tests.
				Assert.AreEqual(3, (countB - countA));
				for (int i=1; i<4;i++) {
					keyName = encKeyB + i.ToString();
					Assert.That(keysB, Contains.Item(keyName));
				}

				// should be a difference in keys of 3.
				Assert.AreEqual(3, (countB - countA));
				
			}
			catch (Exception e) {
				Console.WriteLine(e.Message);
				Assert.That(false);
			}
		}






		[Test, Order (100)]
		public async Task Transit_EncrypDecryptData_ResultsInSameValue () {
			try {
				// Get a random value to encrypt.
				string toEncrypt = Guid.NewGuid().ToString();

				string encKey = Guid.NewGuid().ToString();

				// Create an encryption key.
				bool rc = await TB.CreateEncryptionKey(encKey, true, true, EnumTransitKeyType.rsa4096);
				Assert.AreEqual(true, rc);

				// Now encrypt with that key.
				TransitEncryptedItem response = await TB.Encrypt(encKey, toEncrypt);
				Assert.IsNotEmpty(response.EncryptedValue);

				// Now decrypt it.
				TransitDecryptedItem responseB = await TB.Decrypt(encKey, response.EncryptedValue);
				Assert.AreEqual(responseB.DecryptedValue, toEncrypt);

			}
			catch (Exception e) { }
		}




		[Test, Order (200)]
		public async Task Transit_RotateKey () {
			try {
				string encKey = Guid.NewGuid().ToString();

				// Create an encryption key.
				bool rc = await TB.CreateEncryptionKey(encKey, true, true, EnumTransitKeyType.rsa4096);
				Assert.AreEqual(true, rc);

				bool rotated = await TB.RotateKey(encKey);
				Assert.AreEqual(rotated, true);

				// Retrieve key.
				TransitKeyInfo TKI = await TB.ReadEncryptionKey(encKey);
				Assert.AreEqual(TKI.LatestVersionNum, 2);
			}
			catch (Exception e) { }
		}


		

		[Test, Order(300)]
		// Test that Reencrypt results in same original un-encrypted value.  
		public async Task Transit_Rencryption_Results_InDecryptedValue_SameAsStartingValue () {
			try {
				string valA = Guid.NewGuid().ToString();
				string key = "ZabcZ";

				// Create key, validate the version and then encrypt some data with that key.
				Assert.True(await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.aes256));
				TransitEncryptedItem encA = await TB.Encrypt(key, valA);
				TransitKeyInfo tkiA = await TB.ReadEncryptionKey(key);

				// Rotate Key, Read value of key version, Re-Encrypt data.  Decrypt Data.
				Assert.True(await TB.RotateKey(key));
				TransitKeyInfo tkiB = await TB.ReadEncryptionKey(key);
				TransitEncryptedItem encB = await TB.ReEncrypt(key, encA.EncryptedValue);
				TransitDecryptedItem decB = await TB.Decrypt(key, encB.EncryptedValue);

				// Validate Results.  Key version incremented by 1.
				Assert.AreEqual(tkiA.LatestVersionNum + 1, tkiB.LatestVersionNum);
				Assert.AreEqual(valA, decB.DecryptedValue);
				}
			catch (Exception e) { }
		}


		[Test, Order (1000)]
		public async Task Transit_BulkEncryptionDecryptionWorks () {
			// Create key, validate the version and then encrypt some data with that key.
			string key = "YabcY";
			bool fa = await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.aes256);
			Assert.True(fa);

			// Confirm key is new:
			TransitKeyInfo TKI = await TB.ReadEncryptionKey(key);
			Assert.AreEqual(TKI.LatestVersionNum, 1);


			// Step A.
			string valueA = "ABC";
			string valueB = "def";
			string valueC = "1234567890";
			string valueD = Guid.NewGuid().ToString();
			string valueE = "123456ABCDEFZYXWVU0987654321aaabbbcccddd";


			// Step B.
			// Encrypt several items in bulk.
			List<TransitBulkItemToEncrypt> bulkEnc = new List<TransitBulkItemToEncrypt>();
			bulkEnc.Add(new TransitBulkItemToEncrypt(valueA));
			bulkEnc.Add(new TransitBulkItemToEncrypt(valueB));
			bulkEnc.Add(new TransitBulkItemToEncrypt(valueC));
			bulkEnc.Add(new TransitBulkItemToEncrypt(valueD));
			bulkEnc.Add(new TransitBulkItemToEncrypt(valueE));

			TransitEncryptionResultsBulk bulkEncResponse = await TB.EncryptBulk(key, bulkEnc);
			int sentCnt = bulkEnc.Count;
			int recvCnt = bulkEncResponse.EncryptedValues.Count;
			Assert.AreEqual(sentCnt, recvCnt);


			// Step C
			// Decrypt in Bulk these Same Items.
			List<TransitBulkItemToDecrypt> bulkDecrypt = new List<TransitBulkItemToDecrypt>();
			foreach (TransitEncryptedItem item in bulkEncResponse.EncryptedValues) {
				bulkDecrypt.Add(new TransitBulkItemToDecrypt(item.EncryptedValue));
			}

			TransitDecryptionResultsBulk bulkDecResponse = await TB.DecryptBulk(key, bulkDecrypt);
			Assert.AreEqual(recvCnt, bulkDecResponse.DecryptedValues.Count);
			Assert.AreEqual(valueA, bulkDecResponse.DecryptedValues[0].DecryptedValue);
			Assert.AreEqual(valueB, bulkDecResponse.DecryptedValues[1].DecryptedValue);
			Assert.AreEqual(valueC, bulkDecResponse.DecryptedValues[2].DecryptedValue);
			Assert.AreEqual(valueD, bulkDecResponse.DecryptedValues[3].DecryptedValue);
			Assert.AreEqual(valueE, bulkDecResponse.DecryptedValues[4].DecryptedValue);


			// Step D
			// Rotate Key.
			Assert.AreEqual(true,( await TB.RotateKey(key)));
			TransitKeyInfo TKI2 = await TB.ReadEncryptionKey(key);
			Assert.AreEqual(TKI2.LatestVersionNum, 2);


			// Step E.
			// Re-encrypt in bulk.
			List<TransitBulkItemToDecrypt> bulkRewrap = new List<TransitBulkItemToDecrypt>();
			foreach (TransitEncryptedItem encItem in bulkEncResponse.EncryptedValues) {
				bulkRewrap.Add(new TransitBulkItemToDecrypt(encItem.EncryptedValue));
			}

			TransitEncryptionResultsBulk rewrapResponse = await TB.ReEncryptBulk(key, bulkRewrap);
			Assert.AreEqual(bulkEnc.Count, rewrapResponse.EncryptedValues.Count);


			// Step F.
			// Decrypt once again in bulk.  
			List<TransitBulkItemToDecrypt> bulkDecrypt2 = new List<TransitBulkItemToDecrypt>();
			foreach (TransitEncryptedItem item in rewrapResponse.EncryptedValues) {
				bulkDecrypt2.Add(new TransitBulkItemToDecrypt(item.EncryptedValue));
			}

			TransitDecryptionResultsBulk bulkDecResponse2 = await TB.DecryptBulk(key, bulkDecrypt2);
			Assert.AreEqual(recvCnt, bulkDecResponse2.DecryptedValues.Count);
			Assert.AreEqual(valueA, bulkDecResponse2.DecryptedValues[0].DecryptedValue);
			Assert.AreEqual(valueB, bulkDecResponse2.DecryptedValues[1].DecryptedValue)	;
			Assert.AreEqual(valueC, bulkDecResponse2.DecryptedValues[2].DecryptedValue);
			Assert.AreEqual(valueD, bulkDecResponse2.DecryptedValues[3].DecryptedValue);
			Assert.AreEqual(valueE, bulkDecResponse2.DecryptedValues[4].DecryptedValue);


		}

	}
}
