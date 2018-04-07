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


		// Used to ensure we have a random key.
		int randomKeyNum = 0;
		string keyPrefix = "xAAAx";


		public async Task Transit_Init () {
			if (TB != null) {
				return;
			}

			
			// Create a Transit Backend Mount for this series of tests.
			VSB = new VaultSystemBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

			// Create transitBE_A backend.
			string transitName = transitBE_A;
			string desc = "Transit DB: " + transitName + " backend.";
			bool rc = await VSB.SysMountEnable(transitName, desc, EnumBackendTypes.Transit);
			Assert.AreEqual(true, rc);

			TB = new TransitBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, transitName);
		}



		[Test, Order(1)]
		public async Task Transit_CreateAndMountCustomTransitBackend() {
			await Transit_Init();
		}


		[Test, Order(2)]
		public void  AH_VaultTransitBackendReadyTest() {
			// Make sure we have a root token and an ip address.
			Assert.AreNotEqual(VaultServerRef.rootToken, "");
			Assert.AreNotEqual(VaultServerRef.ipAddress, "");
			Assert.NotNull(TB);
		}




		[Test, Order(20)]
		public async Task Transit_CreateEncryptionKeyWithMethodParameters() {
			await Transit_Init();
			try {
				// Try with parameters values.
				bool rc = await TB.CreateEncryptionKey(encKeyA, true, true, EnumTransitKeyType.rsa4096);
				Assert.AreEqual(true, rc);
			}
			catch (Exception e) { }
		}
	



		[Test, Order(21)]
		// Ensure we can create an encryption key by specifying parameters thru a dictionary.
		public async Task Transit_CreateEncryptionKeyWithDictionaryParams() {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			Dictionary<string, string> keyParams = new Dictionary<string, string>();
			keyParams.Add("derived", "true");
			keyParams.Add("type", "aes256-gcm96");
			Assert.AreEqual(true, await TB.CreateEncryptionKey(key,keyParams));
		}



		[Test, Order(22)]
		public async Task Transit_CreateEncryptionKey_ConvergentAndDerivedTrue () {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			Assert.AreEqual(true, await TB.CreateEncryptionKey(key, canBeExported: true, keyType: EnumTransitKeyType.chacha20, enableConvergentEncryption: true, enableKeyDerivation: true));

			// Now read key back and make sure parameters are correct.
			TransitKeyInfo TKI = await TB.ReadEncryptionKey(key);
			Assert.AreEqual(true, TKI.IsExportable);
			Assert.AreEqual(true, TKI.IsDerivable);
			Assert.AreEqual(true, TKI.SupportsConvergentEncryption);
			Assert.AreEqual(true, TKI.SupportsDerivation);
			Assert.AreEqual("chacha20-poly1305", TKI.Type);
		}


		[Test, Order(23)]
		public async Task Transit_CreateEncryptionKey_ValidateAllTypes () {
			await Transit_Init();
			string keyStr = "";
			string key = "";

			for (int i = 0; i < 6; i++) {
				switch (i) {
					case 0:
						keyStr = "aes256-gcm96";
						break;
					case 1:
						keyStr = "chacha20-poly1305";
						break;
					case 2:
						keyStr = "ed25519";
						break;
					case 3:
						keyStr = "ecdsa-p256";
						break;
					case 4:
						keyStr = "rsa-2048";
						break;
					case 5:
						keyStr = "rsa-4096";
						break;
				}

				// Create the key.
				randomKeyNum++;
				key = keyPrefix + randomKeyNum.ToString();

				Assert.AreEqual(true, await TB.CreateEncryptionKey(key, false,false, (EnumTransitKeyType) i));
				TransitKeyInfo TKI = await TB.ReadEncryptionKey(key);

				// Validate the key created was what we requested. 
				Assert.AreEqual(keyStr, TKI.EncryptionMethod);
			}
		}


		[Test, Order(24)]
		// Validates that trying to create an encryption key with a setting of KeyDerivation enabled for a 
		// key type that does not support Convergent or key Derivation encryption.  
		public async Task Transit_CreateEncryptionKey_ErrorsOnInvalidKeyTypeKeyDerivationSetting() {
			await Transit_Init();
			string keyStr = "";
			string key = "";

			for (int i = 3; i < 6; i++) {
				switch (i) {
					case 3:
						keyStr = "ecdsa-p256";
						break;
					case 4:
						keyStr = "rsa-2048";
						break;
					case 5:
						keyStr = "rsa-4096";
						break;
				}


				// Create the key.
				randomKeyNum++;
				key = keyPrefix + randomKeyNum.ToString();

				Assert.That(() => TB.CreateEncryptionKey(key, false, false, (EnumTransitKeyType)i, true),
					Throws.Exception
						.TypeOf<ArgumentOutOfRangeException>()
						.With.Property("ParamName")
						.EqualTo("keyType"));
			}
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



		[Test, Order(31)]
		// Validates that looking for a valid key returns true.
		public async Task Transit_KeyExistsReturnsTrue () {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create encryption Key.
			Assert.AreEqual(true, await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.rsa2048));

			Assert.AreEqual(true, await TB.IfExists(key));
		}





		[Test, Order(31)]
		// Validates that looking for a key that does not exist returns false.
		public async Task Transit_KeyExistsReturnsFalse() {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create encryption Key.
			Assert.AreEqual(true, await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.rsa2048));

			// Bump key to a new name 
			randomKeyNum++;
			string keyNew = keyPrefix + randomKeyNum.ToString();

			Assert.AreEqual(false, await TB.IfExists(keyNew));
		}



		[Test, Order(40)]
		// Test to ensure that when executing a change to a key's config values that all valid values are accepted.
		public async Task Transit_ChangeEncryptionKeyInfo_ValidParameters() {
			randomKeyNum++;

			string key = keyPrefix + randomKeyNum.ToString();

			// Create encryption Key.
			bool rc = await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.rsa2048);
			Assert.AreEqual(true, rc);

			// Now make changes to key.  These should all be valid.
			Dictionary<string, string> iParams = new Dictionary<string,string>();
			iParams.Add(TransitConstants.KeyConfig_Allow_Backup, "true");
			iParams.Add(TransitConstants.KeyConfig_DeleteAllowed, "true");
			iParams.Add(TransitConstants.KeyConfig_Exportable, "true");
			iParams.Add(TransitConstants.KeyConfig_MinDecryptVers, "0");
			iParams.Add(TransitConstants.KeyConfig_MinEncryptVers, "0");

			TransitKeyInfo tkiA = await TB.UpdateKey(key, iParams);
			Assert.NotNull(tkiA);
		}




		[Test, Order(41)]
		// Test to ensure that when executing a change to a key's config values that all valid values are accepted.
		public async Task Transit_ChangeEncryptionKeyInfo_InValidParameterThrowsException() {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create encryption Key.
			bool rc = await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.rsa2048);
			Assert.AreEqual(true, rc);

			// Now make changes to key.  These should all be valid.
			Dictionary<string, string> iParams = new Dictionary<string, string>();
			iParams.Add(TransitConstants.KeyConfig_Allow_Backup, "true");
			iParams.Add(TransitConstants.KeyConfig_DeleteAllowed, "true");
			iParams.Add("hello world", "true");

			Assert.That(() => TB.UpdateKey(key, iParams),
				Throws.Exception
					.TypeOf<ArgumentException>()
					.With.Property("ParamName")
					.EqualTo("hello world"));
		}





		[Test, Order(90)]
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



		[Test, Order (105)]
		public async Task Transit_DerivedEncryptDecrypt_Success () {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create encryption Key.
			Assert.AreEqual(true, await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.aes256, true));

			// Get a random value to encrypt.
			string toEncrypt = Guid.NewGuid().ToString();

			// Set the "Context" value for derived encryption.
			string toContext = "ZYXabc";

			// Now encrypt with that key.
			TransitEncryptedItem response = await TB.Encrypt(key, toEncrypt,toContext);
			Assert.IsNotEmpty(response.EncryptedValue);

			// Now decrypt it.
			TransitDecryptedItem responseB = await TB.Decrypt(key, response.EncryptedValue,toContext);
			Assert.AreEqual(responseB.DecryptedValue, toEncrypt);
		}




		[Test, Order(105)]
		// Test decrypting a convergent encrypted value with an invalid context.  Should throw error.
		public async Task Transit_DerivedEncryptDecrypt_WithBadContextFails() {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create encryption Key.
			Assert.AreEqual(true, await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.aes256, true));

			// Get a random value to encrypt.
			string toEncrypt = "123456abcdefzyx";

			// Set the "Context" value for derived encryption.
			string toContext = "ZYXabc";

			// Now encrypt with that key.
			TransitEncryptedItem response = await TB.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);

			// Now decrypt it, but pass invalid context.
			Assert.That(() => TB.Decrypt(key, response.EncryptedValue, "zyxabc"),
				Throws.Exception
					.TypeOf<VaultInvalidDataException>()
					.With.Property("Message")
					.Contains("unable to decrypt"));
		}



		[Test, Order(105)]
		// Tests that when using convergent encryption the same encryption string value is produced for the same context key.
		public async Task Transit_ConvergentEncryption_ProducesEncryptionSameEncryptionValue () {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create encryption Key.
			Assert.AreEqual(true, await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.aes256, true,true));

			// Get a random value to encrypt.
			string toEncrypt = "ABCXYXZ";

			// Set the "Context" value for derived encryption.
			string toContext = "ZYXabc";

			// Now encrypt with that key.
			TransitEncryptedItem response = await TB.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);

			// Now encrypt another item with same unencrypted value and same context.  Should produce same results.
			TransitEncryptedItem response2 = await TB.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);
			Assert.AreEqual(response.EncryptedValue, response2.EncryptedValue);
		}



		[Test, Order(105)]
		// Tests that when using derivation encryption the same encryption string value is unique even with same context key.
		public async Task Transit_KeyDerivationEncryption_ProducesEncryptionWithDifferentValue() {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create encryption Key.
			Assert.AreEqual(true, await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.aes256, true, false));

			// Get a random value to encrypt.
			string toEncrypt = "ABCXYXZ";

			// Set the "Context" value for derived encryption.
			string toContext = "ZYXabc";

			// Now encrypt with that key.
			TransitEncryptedItem response = await TB.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);

			// Now encrypt another item with same unencrypted value and same context.  Should produce same results.
			TransitEncryptedItem response2 = await TB.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);
			Assert.AreNotEqual(response.EncryptedValue, response2.EncryptedValue);
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




		[Test, Order(400)]
		// Test key deletion for a key that has not been enabled for deletion.  Should return false.
		public async Task Transit_DeleteKey_NotEnabledForDelete_Fails () {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create key then delete
			Assert.True(await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.aes256));
			Assert.AreEqual(false, await TB.DeleteKey(key));
		}




		[Test, Order(400)]
		// Test that key deletion exists for a valid key that is enabled for deletion.  Should return true.
		public async Task Transit_DeleteKey_EnabledForDelete_Success() {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create key
			Assert.True(await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.aes256));

			// Change it to be deletable.
			Dictionary<string, string> delParams = new Dictionary<string, string>();
			delParams.Add("deletion_allowed", "true");
			await TB.UpdateKey(key, delParams);

			// Delete
			Assert.AreEqual(true, await TB.DeleteKey(key));

			// See if key exists.
			Assert.AreEqual(false, await TB.IfExists(key));
		}




		[Test, Order(400)]
		// Test key deletion for a key that does not exist.  Should throw an exception.
		public async Task Transit_DeleteKey_BadKeyValue_ThrowsException() {
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// We don't create it however, so it will fail.
			// Delete the key.
			Assert.That(() => TB.DeleteKey(key),
				Throws.Exception
					.TypeOf<VaultInvalidDataException>()
					.With.Property("Message")
					.Contains("could not delete policy; not found"));
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



		[Test, Order(1000)]
		public async Task Transit_BulkEncryptionDecryptionContextual_Works() {
			// Create key, validate the version and then encrypt some data with that key.
			await Transit_Init();
			randomKeyNum++;
			string key = keyPrefix + randomKeyNum.ToString();

			// Create key.
			bool fa = await TB.CreateEncryptionKey(key, true, true, EnumTransitKeyType.aes256,true);
			Assert.True(fa);

			// Confirm key is new:
			TransitKeyInfo TKI = await TB.ReadEncryptionKey(key);
			Assert.AreEqual(TKI.LatestVersionNum, 1);

			// Confirm it supports key derivation.
			Assert.AreEqual(true, TKI.SupportsDerivation);


			// Step A.  Build list of items to encrypt along with contextual encryption value.
			List<KeyValuePair<string, string>> items = new List<KeyValuePair<string, string>>();
			items.Add(new KeyValuePair<string, string>("abc", "123"));
			items.Add(new KeyValuePair<string, string>("ZYX", "argue"));
			items.Add(new KeyValuePair<string, string>("45332092214", "20180623"));


			// Step B.
			// Encrypt several items in bulk.  Storing both the item to encrypt and contextual encryption value.
			List<TransitBulkItemToEncrypt> bulkEnc = new List<TransitBulkItemToEncrypt>();
			foreach (KeyValuePair<string,string> item in items) {
				bulkEnc.Add(new TransitBulkItemToEncrypt(item.Key, item.Value));
			}

			// Encrypt.
			TransitEncryptionResultsBulk bulkEncResponse = await TB.EncryptBulk(key, bulkEnc);
			int sentCnt = bulkEnc.Count;
			int recvCnt = bulkEncResponse.EncryptedValues.Count;

			// It's critical that items received = items sent.
			Assert.AreEqual(sentCnt, recvCnt);


			// Step C
			// Decrypt in Bulk these Same Items.  We need to send the encrypted item as well as the original context value that was used to encrypt
			// that specific item.
			List<TransitBulkItemToDecrypt> bulkDecrypt = new List<TransitBulkItemToDecrypt>();
			for (int i = 0; i < recvCnt; i++) {
				bulkDecrypt.Add(new TransitBulkItemToDecrypt(bulkEncResponse.EncryptedValues[i].EncryptedValue, items[i].Value));
			}

			TransitDecryptionResultsBulk bulkDecResponse = await TB.DecryptBulk(key, bulkDecrypt);

			// Validate.
			Assert.AreEqual(recvCnt, bulkDecResponse.DecryptedValues.Count);
			for (int i=0; i< recvCnt;i++) {
				Assert.AreEqual(items[i].Key, bulkDecResponse.DecryptedValues[i].DecryptedValue);
			}


			// Step D
			// Rotate Key.
			Assert.AreEqual(true, (await TB.RotateKey(key)));
			TransitKeyInfo TKI2 = await TB.ReadEncryptionKey(key);
			Assert.AreEqual(TKI2.LatestVersionNum, 2);


			// Step E.
			// Re-encrypt in bulk.
			List<TransitBulkItemToDecrypt> bulkRewrap = new List<TransitBulkItemToDecrypt>();
			foreach (KeyValuePair<string, string> item in items) {
				bulkRewrap.Add(new TransitBulkItemToDecrypt(item.Key, item.Value));
			}

			TransitEncryptionResultsBulk rewrapResponse = await TB.ReEncryptBulk(key, bulkRewrap);
			Assert.AreEqual(bulkEnc.Count, rewrapResponse.EncryptedValues.Count);


			// Step F.
			// Decrypt once again in bulk.  
			List<TransitBulkItemToDecrypt> bulkDecrypt2 = new List<TransitBulkItemToDecrypt>();
			for (int i = 0; i < recvCnt; i++) {
				bulkDecrypt2.Add(new TransitBulkItemToDecrypt(bulkEncResponse.EncryptedValues[i].EncryptedValue, items[i].Value));
			}


			TransitDecryptionResultsBulk bulkDecResponse2 = await TB.DecryptBulk(key, bulkDecrypt2);


			// Validate.
			Assert.AreEqual(recvCnt, bulkDecResponse2.DecryptedValues.Count);
			for (int i = 0; i < recvCnt; i++) {
				Assert.AreEqual(items[i].Key, bulkDecResponse2.DecryptedValues[i].DecryptedValue);
			}
		}


	}
}
