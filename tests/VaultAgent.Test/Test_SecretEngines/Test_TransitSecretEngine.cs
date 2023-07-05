using NUnit.Framework;
using System.Collections.Generic;
using VaultAgent;
using VaultAgent.Models;
using System;
using System.Threading.Tasks;
using VaultAgent.Backends.Transit.Models;
using VaultAgent.Backends;
using VaultAgent.Backends.System;
using VaultAgent.Backends.Transit;
using VaultAgent.SecretEngines;
using SlugEnt;
using VaultAgentTests;

namespace VaultAgentTests {


	[TestFixture]
	[Parallelizable]
	public class TransitSecretEngine_Test {
		private VaultAgentAPI _vaultAgentAPI;

        private VaultSystemBackend _systemBackend;

		// The Vault Transit Backend we will be using throughout our testing.
		private TransitSecretEngine _transitSecretEngine;


		// Encryption keys we will generally use throughout tests.
		readonly string encKeyA = "Test_A";
		readonly string encKeyB = "Test_B";


		// Used to ensure we have a random key.
		private readonly UniqueKeys _uniqueKeys = new UniqueKeys("_", "__"); // Unique Key generator



		// Setup during first run of this modules testing.
		[OneTimeSetUp]
		public async Task Transit_Init () {
			if ( _vaultAgentAPI != null ) { return; }


			// Build Connection to Vault.
			_vaultAgentAPI = await VaultServerRef.ConnectVault("TransitSecEng");
            //new VaultAgentAPI("transitVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);


            // Create unique name for the transit Backend we will use to test with.
            string transitMountName = _uniqueKeys.GetKey("TRANsit");


            // Get Connection to Vault System backend
            _systemBackend = new VaultSystemBackend(_vaultAgentAPI.TokenID, _vaultAgentAPI);
            Assert.IsTrue(await _systemBackend.CreateSecretBackendMount(EnumSecretBackendTypes.Transit, transitMountName, transitMountName,
                                                                        "Transit Bckend Testing"), "A10:  Failed to Create the Transit Backend");
            _transitSecretEngine = (TransitSecretEngine) _vaultAgentAPI.ConnectToSecretBackend(EnumSecretBackendTypes.Transit, transitMountName, transitMountName);



//            _transitSecretEngine =
	//			(TransitSecretEngine) await _vaultAgentAPI.CreateSecretBackendMount(EnumSecretBackendTypes.Transit, transitMountName, transitMountName,
		//		                                                                    "Transit Bckend Testing");
			Assert.NotNull(_transitSecretEngine, "Transit Backend was returned null upon creation.");
		}



		/// <summary>
		/// Used as shortcut for commonly called code in test methods of Transit Type.
		/// </summary>
		/// <param name="keyType">Type of key to make</param>
		/// <param name="keyDerivation">Boolean.  True if you want a key that supports key derivation.</param>
		/// <param name="convergentKey">Boolean.  True if you want a key that supports convergent encryption.</param>
		/// <returns>string value of the key name.</returns>
		public async Task<string> Transit_InitWithKey (TransitEnumKeyType keyType = TransitEnumKeyType.aes256,
		                                               bool keyDerivation = false,
		                                               bool convergentKey = false) {
			string key = _uniqueKeys.GetKey("Key");

			// Create key.
			bool rc = await _transitSecretEngine.CreateEncryptionKey(key, true, true, keyType, keyDerivation, convergentKey);
			Assert.True(rc);
			return key;
		}



		[Test]
		public async Task CreateEncryptionKeyWithMethodParameters_Success () {
			// Try with parameters values.
			bool rc = await _transitSecretEngine.CreateEncryptionKey(encKeyA, true, true, TransitEnumKeyType.rsa4096);
			Assert.AreEqual(true, rc);
		}




		[Test]

		// Ensure we can create an encryption key by specifying parameters thru a dictionary.
		public async Task CreateEncryptionKeyWithDictionaryParams_Success () {
			string key = _uniqueKeys.GetKey();

			Dictionary<string, string> keyParams = new Dictionary<string, string>
			{
				{"derived", "true"},
				{"type", "aes256-gcm96"}
			};
			Assert.AreEqual(true, await _transitSecretEngine.CreateEncryptionKey(key, keyParams));
		}



		[Test]
		public async Task CreateEncryptionKey_ConvergentAndDerivedTrue () {
			string key = _uniqueKeys.GetKey("Key");

			Assert.AreEqual(
				true,
				await _transitSecretEngine.CreateEncryptionKey(key, canBeExported: true, keyType: TransitEnumKeyType.chacha20, enableConvergentEncryption: true,
				                                               enableKeyDerivation: true));

			// Now read key back and make sure parameters are correct.
			TransitKeyInfo TKI = await _transitSecretEngine.ReadEncryptionKey(key);
			Assert.AreEqual(true, TKI.IsExportable);
			Assert.AreEqual(true, TKI.IsDerivable);
			Assert.AreEqual(true, TKI.SupportsConvergentEncryption);
			Assert.AreEqual(true, TKI.SupportsDerivation);
			Assert.AreEqual("chacha20-poly1305", TKI.Type);
		}



		// Tests to make sure that encryption keys are created with the correct encryption setting in the Vault backend based upon the enum.
		[TestCase(TransitEnumKeyType.aes256, ExpectedResult = "aes256-gcm96")]
		[TestCase(TransitEnumKeyType.chacha20, ExpectedResult = "chacha20-poly1305")]
		[TestCase(TransitEnumKeyType.ed25519, ExpectedResult = "ed25519")]
		[TestCase(TransitEnumKeyType.ecdsa, ExpectedResult = "ecdsa-p256")]
		[TestCase(TransitEnumKeyType.rsa2048, ExpectedResult = "rsa-2048")]
		[TestCase(TransitEnumKeyType.rsa4096, ExpectedResult = "rsa-4096")]

		public string EncryptionKeyMethod_CorrectBasedUponKeyType (int a) {

			string key = _uniqueKeys.GetKey();

			Task<bool> encKey = _transitSecretEngine.CreateEncryptionKey(key, false, false, (TransitEnumKeyType) a);
			encKey.Wait();
			Assert.IsTrue(encKey.Result);

			Task<TransitKeyInfo> TKI = _transitSecretEngine.ReadEncryptionKey(key);
			TKI.Wait();

			return TKI.Result.EncryptionMethod;
		}



		[TestCase(TransitEnumKeyType.ecdsa)]
		[TestCase(TransitEnumKeyType.rsa2048)]
		[TestCase(TransitEnumKeyType.rsa4096)]

		// Validates that trying to create an encryption key with a setting of KeyDerivation enabled for a 
		// key type that does not support Convergent or key Derivation encryption throws an exception.
		public void CreateEncryptionKey_ErrorsOnInvalidKeyTypeKeyDerivationSetting2 (TransitEnumKeyType keyType) {
			string key = _uniqueKeys.GetKey();


			Assert.That(() => _transitSecretEngine.CreateEncryptionKey(key, false, false, keyType, true),
			            Throws.Exception.TypeOf<ArgumentOutOfRangeException>().With.Property("ParamName").EqualTo("keyType"));
		}




		[Test]
		public async Task ReadEncryptionKeyInfo_Success () {
			TransitKeyInfo TKI = await _transitSecretEngine.ReadEncryptionKey(encKeyA);
			Assert.AreEqual(encKeyA, TKI.Name);
			Assert.AreEqual(1, TKI.LatestVersionNum);
		}



		[Test]

		// Validates that looking for a valid key returns true.
		public async Task KeyExists_ReturnsTrue () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.rsa2048);

			Assert.AreEqual(true, await _transitSecretEngine.IfExists(key));
		}





		[Test]

		// Validates that looking for a key that does not exist returns false.
		public async Task KeyExists_ReturnsFalse () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.rsa2048);

			// Bump key to a new name 
			string keyNew = _uniqueKeys.GetKey();

			Assert.AreEqual(false, await _transitSecretEngine.IfExists(keyNew));
		}



		[Test]

		// Test to ensure that when executing a change to a key's config values that all valid values are accepted.
		public async Task ChangeEncryptionKeyInfo_ValidParameters () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.rsa2048);

			// Now make changes to key.  These should all be valid.
			Dictionary<string, string> iParams = new Dictionary<string, string>
			{
				{TransitConstants.KeyConfig_Allow_Backup, "true"},
				{TransitConstants.KeyConfig_DeleteAllowed, "true"},
				{TransitConstants.KeyConfig_Exportable, "true"},
				{TransitConstants.KeyConfig_MinDecryptVers, "0"},
				{TransitConstants.KeyConfig_MinEncryptVers, "0"}
			};

			TransitKeyInfo tkiA = await _transitSecretEngine.UpdateKey(key, iParams);
			Assert.NotNull(tkiA);
		}




		[Test]

		// Test to ensure that when executing a change to a key's config values that all valid values are accepted.
		public async Task ChangeEncryptionKeyInfo_InValidParameterThrowsException () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.rsa2048);

			// Now make changes to key.  These should all be valid.
			Dictionary<string, string> iParams = new Dictionary<string, string>
			{
				{TransitConstants.KeyConfig_Allow_Backup, "true"},
				{TransitConstants.KeyConfig_DeleteAllowed, "true"},
				{"hello world", "true"}
			};

			Assert.That(() => _transitSecretEngine.UpdateKey(key, iParams),
			            Throws.Exception.TypeOf<ArgumentException>().With.Property("ParamName").EqualTo("hello world"));
		}





		[Test]
		public async Task ListEncryptionKeys_ShouldReturnAllKeys () {
			try {
				// Depending on what's already happened, we cannot be sure of how many keys might be in the backend.
				// so we will grab initial list.  Then add 3 keys.  Then re-grab and make sure the 3 new keys are listed
				// and the count is 3 higher.
				List<string> keysA = await _transitSecretEngine.ListEncryptionKeys();
				int countA = keysA.Count;

				string keyName;
				for ( int i = 1; i < 4; i++ ) {
					keyName = encKeyB + i.ToString();

					// Create the key.
					await _transitSecretEngine.CreateEncryptionKey(keyName, true, false, TransitEnumKeyType.aes256);
				}

				// Now get new list of keys.
				List<string> keysB = await _transitSecretEngine.ListEncryptionKeys();
				int countB = keysB.Count;

				// Perform tests.
				Assert.AreEqual(3, (countB - countA));
				for ( int i = 1; i < 4; i++ ) {
					keyName = encKeyB + i.ToString();
					Assert.That(keysB, Contains.Item(keyName));
				}

				// should be a difference in keys of 3.
				Assert.AreEqual(3, (countB - countA));

			}
			catch ( Exception e ) {
				Console.WriteLine(e.Message);
				Assert.That(false);
			}
		}





		/// <summary>
		/// Validate that something encrypted results in same value when decrypted.
		/// </summary>
		/// <returns></returns>
		[Test]
		public async Task EncryptDecrypt_ResultsInSameValue () {
			// Get a random value to encrypt.
			string toEncrypt = Guid.NewGuid().ToString();

			string encKey = Guid.NewGuid().ToString();

			// Create an encryption key.
			bool rc = await _transitSecretEngine.CreateEncryptionKey(encKey, true, true, TransitEnumKeyType.rsa4096);
			Assert.AreEqual(true, rc);

			// Now encrypt with that key.
			TransitEncryptedItem response = await _transitSecretEngine.Encrypt(encKey, toEncrypt);
			Assert.IsNotEmpty(response.EncryptedValue);

			// Now decrypt it.
			TransitDecryptedItem responseB = await _transitSecretEngine.Decrypt(encKey, response.EncryptedValue);
			Assert.AreEqual(responseB.DecryptedValue, toEncrypt);
		}



		[Test]
		public async Task DerivedEncryptDecrypt_ResultsInSameValue () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256, true);

			// Get a random value to encrypt.
			string toEncrypt = Guid.NewGuid().ToString();

			// Set the "Context" value for derived encryption.
			string toContext = "ZYXabc";

			// Now encrypt with that key.
			TransitEncryptedItem response = await _transitSecretEngine.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);

			// Now decrypt it.
			TransitDecryptedItem responseB = await _transitSecretEngine.Decrypt(key, response.EncryptedValue, toContext);
			Assert.AreEqual(responseB.DecryptedValue, toEncrypt);
		}




		[Test]

		// Test decrypting a convergent encrypted value with an invalid context.  Should throw error.
		public async Task DerivedEncryptDecrypt_WithBadContextFails () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256, true);

			// Get a random value to encrypt.
			string toEncrypt = "123456abcdefzyx";

			// Set the "Context" value for derived encryption.
			string toContext = "ZYXabc";

			// Now encrypt with that key.
			TransitEncryptedItem response = await _transitSecretEngine.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);

			// Now decrypt it, but pass invalid context.
			Assert.That(() => _transitSecretEngine.Decrypt(key, response.EncryptedValue, "zyxabc"),
			            Throws.Exception.TypeOf<VaultInvalidDataException>()); //.With.Property("Message").Contains("unable to decrypt"));
		}



		[Test]

		// Tests that when using convergent encryption the same encryption string value is produced for the same context key.
		public async Task ConvergentEncryption_ResultsInSameEncryptionValue () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256, true, true);

			// Get a random value to encrypt.
			string toEncrypt = "ABCXYXZ";

			// Set the "Context" value for derived encryption.
			string toContext = "ZYXabc";

			// Now encrypt with that key.
			TransitEncryptedItem response = await _transitSecretEngine.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);

			// Now encrypt another item with same unencrypted value and same context.  Should produce same results.
			TransitEncryptedItem response2 = await _transitSecretEngine.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);
			Assert.AreEqual(response.EncryptedValue, response2.EncryptedValue);
		}



		[Test]

		// Tests that when using derivation encryption the same encryption string value is unique even with same context key.
		public async Task KeyDerivationEncryption_ProducesEncryptionWithDifferentValue () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256, true);

			// Get a random value to encrypt.
			string toEncrypt = "ABCXYXZ";

			// Set the "Context" value for derived encryption.
			string toContext = "ZYXabc";

			// Now encrypt with that key.
			TransitEncryptedItem response = await _transitSecretEngine.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);

			// Now encrypt another item with same unencrypted value and same context.  Should produce same results.
			TransitEncryptedItem response2 = await _transitSecretEngine.Encrypt(key, toEncrypt, toContext);
			Assert.IsNotEmpty(response.EncryptedValue);
			Assert.AreNotEqual(response.EncryptedValue, response2.EncryptedValue);
		}




		[Test]
		public async Task RotateKey_Works () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256);

			bool rotated = await _transitSecretEngine.RotateKey(key);
			Assert.AreEqual(rotated, true);

			// Retrieve key.
			TransitKeyInfo TKI = await _transitSecretEngine.ReadEncryptionKey(key);
			Assert.AreEqual(TKI.LatestVersionNum, 2);
		}




		[Test]

		// Test that Reencrypt results in same original un-encrypted value.  
		public async Task RencryptionResultsInSameStartingValue () {
			string valA = Guid.NewGuid().ToString();
			string key = _uniqueKeys.GetKey();

			// Create key, validate the version and then encrypt some data with that key.
			Assert.True(await _transitSecretEngine.CreateEncryptionKey(key, true, true, TransitEnumKeyType.aes256));
			TransitEncryptedItem encA = await _transitSecretEngine.Encrypt(key, valA);
			TransitKeyInfo tkiA = await _transitSecretEngine.ReadEncryptionKey(key);

			// Rotate Key, Read value of key version, Re-Encrypt data.  Decrypt Data.
			Assert.True(await _transitSecretEngine.RotateKey(key));
			TransitKeyInfo tkiB = await _transitSecretEngine.ReadEncryptionKey(key);
			TransitEncryptedItem encB = await _transitSecretEngine.ReEncrypt(key, encA.EncryptedValue);
			TransitDecryptedItem decB = await _transitSecretEngine.Decrypt(key, encB.EncryptedValue);

			// Validate Results.  Key version incremented by 1.
			Assert.AreEqual(tkiA.LatestVersionNum + 1, tkiB.LatestVersionNum, "Key Version should have been incremented.");
			Assert.AreEqual(valA, decB.DecryptedValue,
			                "After Key Rotation and Rencryption, expected value of encrypted item to be same, but they are different");
		}




		[Test]

		// Test key deletion for a key that has not been enabled for deletion.  Should return false.
		public async Task DeleteKey_NotEnabledForDelete_Fails () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256);

			// Delete Key
			Assert.That(() => _transitSecretEngine.DeleteKey(key),
			            Throws.Exception.TypeOf<VaultInvalidDataException>().With.Property("Message").Contains("deletion is not allowed for this key"));

		}




		[Test]

		// Test that key deletion exists for a valid key that is enabled for deletion.  Should return true.
		public async Task DeleteKey_EnabledForDelete_Success () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256);

			// Change it to be deletable.
			Dictionary<string, string> delParams = new Dictionary<string, string> {{"deletion_allowed", "true"}};
			await _transitSecretEngine.UpdateKey(key, delParams);

			// Delete
			Assert.AreEqual(true, await _transitSecretEngine.DeleteKey(key));

			// See if key exists.
			Assert.AreEqual(false, await _transitSecretEngine.IfExists(key));
		}




		[Test]

		// Test key deletion for a key that does not exist.  Should throw an exception.
		public void DeleteKey_BadKeyValue_ThrowsException () {
			string key = _uniqueKeys.GetKey();

			// We don't create it however, so it will fail.
			// Delete the key.
			Assert.That(() => _transitSecretEngine.DeleteKey(key),
			            Throws.Exception.TypeOf<VaultInvalidDataException>().With.Property("Message").Contains("could not delete key; not found"));
		}



		[Test]
		public async Task BulkEncryptionDecryption_Works () {
			// Create key, validate the version and then encrypt some data with that key.
			string key = _uniqueKeys.GetKey();
			bool fa = await _transitSecretEngine.CreateEncryptionKey(key, true, true, TransitEnumKeyType.aes256);
			Assert.True(fa);

			// Confirm key is new:
			TransitKeyInfo TKI = await _transitSecretEngine.ReadEncryptionKey(key);
			Assert.AreEqual(TKI.LatestVersionNum, 1);


			// Step A.
			string valueA = "ABC";
			string valueB = "def";
			string valueC = "1234567890";
			string valueD = Guid.NewGuid().ToString();
			string valueE = "123456ABCDEFZYXWVU0987654321aaabbbcccddd";


			// Step B.
			// Encrypt several items in bulk.
			List<TransitBulkItemToEncrypt> bulkEnc = new List<TransitBulkItemToEncrypt>
			{
				new TransitBulkItemToEncrypt(valueA),
				new TransitBulkItemToEncrypt(valueB),
				new TransitBulkItemToEncrypt(valueC),
				new TransitBulkItemToEncrypt(valueD),
				new TransitBulkItemToEncrypt(valueE)
			};

			TransitEncryptionResultsBulk bulkEncResponse = await _transitSecretEngine.EncryptBulk(key, bulkEnc);
			int sentCnt = bulkEnc.Count;
			int recvCnt = bulkEncResponse.EncryptedValues.Count;
			Assert.AreEqual(sentCnt, recvCnt);


			// Step C
			// Decrypt in Bulk these Same Items.
			List<TransitBulkItemToDecrypt> bulkDecrypt = new List<TransitBulkItemToDecrypt>();
			foreach ( TransitEncryptedItem item in bulkEncResponse.EncryptedValues ) { bulkDecrypt.Add(new TransitBulkItemToDecrypt(item.EncryptedValue)); }

			TransitDecryptionResultsBulk bulkDecResponse = await _transitSecretEngine.DecryptBulk(key, bulkDecrypt);
			Assert.AreEqual(recvCnt, bulkDecResponse.DecryptedValues.Count);
			Assert.AreEqual(valueA, bulkDecResponse.DecryptedValues [0].DecryptedValue);
			Assert.AreEqual(valueB, bulkDecResponse.DecryptedValues [1].DecryptedValue);
			Assert.AreEqual(valueC, bulkDecResponse.DecryptedValues [2].DecryptedValue);
			Assert.AreEqual(valueD, bulkDecResponse.DecryptedValues [3].DecryptedValue);
			Assert.AreEqual(valueE, bulkDecResponse.DecryptedValues [4].DecryptedValue);


			// Step D
			// Rotate Key.
			Assert.AreEqual(true, (await _transitSecretEngine.RotateKey(key)));
			TransitKeyInfo TKI2 = await _transitSecretEngine.ReadEncryptionKey(key);
			Assert.AreEqual(TKI2.LatestVersionNum, 2);


			// Step E.
			// Re-encrypt in bulk.
			List<TransitBulkItemToDecrypt> bulkRewrap = new List<TransitBulkItemToDecrypt>();
			foreach ( TransitEncryptedItem encItem in bulkEncResponse.EncryptedValues ) {
				bulkRewrap.Add(new TransitBulkItemToDecrypt(encItem.EncryptedValue));
			}

			TransitEncryptionResultsBulk rewrapResponse = await _transitSecretEngine.ReEncryptBulk(key, bulkRewrap);
			Assert.AreEqual(bulkEnc.Count, rewrapResponse.EncryptedValues.Count);


			// Step F.
			// Decrypt once again in bulk.  
			List<TransitBulkItemToDecrypt> bulkDecrypt2 = new List<TransitBulkItemToDecrypt>();
			foreach ( TransitEncryptedItem item in rewrapResponse.EncryptedValues ) { bulkDecrypt2.Add(new TransitBulkItemToDecrypt(item.EncryptedValue)); }

			TransitDecryptionResultsBulk bulkDecResponse2 = await _transitSecretEngine.DecryptBulk(key, bulkDecrypt2);
			Assert.AreEqual(recvCnt, bulkDecResponse2.DecryptedValues.Count);
			Assert.AreEqual(valueA, bulkDecResponse2.DecryptedValues [0].DecryptedValue);
			Assert.AreEqual(valueB, bulkDecResponse2.DecryptedValues [1].DecryptedValue);
			Assert.AreEqual(valueC, bulkDecResponse2.DecryptedValues [2].DecryptedValue);
			Assert.AreEqual(valueD, bulkDecResponse2.DecryptedValues [3].DecryptedValue);
			Assert.AreEqual(valueE, bulkDecResponse2.DecryptedValues [4].DecryptedValue);
		}



		[Test]

		// Validates that Bulk encryption, decryption and re-encryption works for Key Derivation encryption keys that need contexts.
		public async Task BulkEncryptionDecryptionContextual_Works () {
			// Create key, validate the version and then encrypt some data with that key.
			string key = _uniqueKeys.GetKey();

			// Create key.
			bool fa = await _transitSecretEngine.CreateEncryptionKey(key, true, true, TransitEnumKeyType.aes256, true);
			Assert.True(fa);

			// Confirm key is new:
			TransitKeyInfo TKI = await _transitSecretEngine.ReadEncryptionKey(key);
			Assert.AreEqual(TKI.LatestVersionNum, 1);

			// Confirm it supports key derivation.
			Assert.AreEqual(true, TKI.SupportsDerivation);


			// Step A.  Build list of items to encrypt along with contextual encryption value.
			List<KeyValuePair<string, string>> items = new List<KeyValuePair<string, string>>
			{
				new KeyValuePair<string, string>("abc", "123"),
				new KeyValuePair<string, string>("ZYX", "argue"),
				new KeyValuePair<string, string>("45332092214", "20180623")
			};


			// Step B.
			// Encrypt several items in bulk.  Storing both the item to encrypt and contextual encryption value.
			List<TransitBulkItemToEncrypt> bulkEnc = new List<TransitBulkItemToEncrypt>();
			foreach ( KeyValuePair<string, string> item in items ) { bulkEnc.Add(new TransitBulkItemToEncrypt(item.Key, item.Value)); }

			// Encrypt.
			TransitEncryptionResultsBulk bulkEncResponse = await _transitSecretEngine.EncryptBulk(key, bulkEnc);
			int sentCnt = bulkEnc.Count;
			int recvCnt = bulkEncResponse.EncryptedValues.Count;

			// It's critical that items received = items sent.
			Assert.AreEqual(sentCnt, recvCnt);


			// Step C
			// Decrypt in Bulk these Same Items.  We need to send the encrypted item as well as the original context value that was used to encrypt
			// that specific item.
			List<TransitBulkItemToDecrypt> bulkDecrypt = new List<TransitBulkItemToDecrypt>();
			for ( int i = 0; i < recvCnt; i++ ) {
				bulkDecrypt.Add(new TransitBulkItemToDecrypt(bulkEncResponse.EncryptedValues [i].EncryptedValue, items [i].Value));
			}

			TransitDecryptionResultsBulk bulkDecResponse = await _transitSecretEngine.DecryptBulk(key, bulkDecrypt);

			// Validate.
			Assert.AreEqual(recvCnt, bulkDecResponse.DecryptedValues.Count);
			for ( int i = 0; i < recvCnt; i++ ) { Assert.AreEqual(items [i].Key, bulkDecResponse.DecryptedValues [i].DecryptedValue); }


			// Step D
			// Rotate Key.
			Assert.AreEqual(true, (await _transitSecretEngine.RotateKey(key)));
			TransitKeyInfo TKI2 = await _transitSecretEngine.ReadEncryptionKey(key);
			Assert.AreEqual(TKI2.LatestVersionNum, 2);


			// Step E.
			// Re-encrypt in bulk.
			List<TransitBulkItemToDecrypt> bulkRewrap = new List<TransitBulkItemToDecrypt>();
			foreach ( KeyValuePair<string, string> item in items ) { bulkRewrap.Add(new TransitBulkItemToDecrypt(item.Key, item.Value)); }

			TransitEncryptionResultsBulk rewrapResponse = await _transitSecretEngine.ReEncryptBulk(key, bulkRewrap);
			Assert.AreEqual(bulkEnc.Count, rewrapResponse.EncryptedValues.Count);


			// Step F.
			// Decrypt once again in bulk.  
			List<TransitBulkItemToDecrypt> bulkDecrypt2 = new List<TransitBulkItemToDecrypt>();
			for ( int i = 0; i < recvCnt; i++ ) {
				bulkDecrypt2.Add(new TransitBulkItemToDecrypt(bulkEncResponse.EncryptedValues [i].EncryptedValue, items [i].Value));
			}


			TransitDecryptionResultsBulk bulkDecResponse2 = await _transitSecretEngine.DecryptBulk(key, bulkDecrypt2);


			// Validate.
			Assert.AreEqual(recvCnt, bulkDecResponse2.DecryptedValues.Count);
			for ( int i = 0; i < recvCnt; i++ ) { Assert.AreEqual(items [i].Key, bulkDecResponse2.DecryptedValues [i].DecryptedValue); }
		}



		[Test]

		// Test that Data Key generation works for a basic key with cipher only.
		public async Task GenerateDataKeyCipherTextOnly_Success () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256);

			// Generate a data key.
			TransitDataKey tdk = await _transitSecretEngine.GenerateDataKey(key);

			Assert.AreEqual(null, tdk.PlainText);
			Assert.AreNotEqual("", tdk.CipherText);
		}



		[Test]

		// Test that Data Key generation works for a basic key with full plaintext and cipher returned.
		public async Task GenerateDataKeyCipherAndPlainText_Success () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256);

			// Generate a data key.
			TransitDataKey tdk = await _transitSecretEngine.GenerateDataKey(key, true);

			Assert.AreNotEqual("", tdk.PlainText);
			Assert.AreNotEqual("", tdk.CipherText);
		}




		[Test]

		// Test that we can generate a Data Key that supports derivation encryption.
		public async Task GenerateDataKey_Derivation_Success () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256, true);

			// Generate a data key.
			TransitDataKey tdk = await _transitSecretEngine.GenerateDataKey(key, context: "trully");

			Assert.AreNotEqual("", tdk.PlainText);
			Assert.AreNotEqual("", tdk.CipherText);
		}




		[Test]

		// Test that we get a thrown error if we supply incorrect values for bits.
		public async Task GenerateDataKey_BadBitsValue_ThrowsError () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256, false);

			// Generate a data key.
			Assert.That(() => _transitSecretEngine.GenerateDataKey(key, bits: 456),
			            Throws.Exception.TypeOf<ArgumentOutOfRangeException>().With.Property("Message").Contains("Bits value can only be 128, 256 or 512"));
		}



		[Test]

		// Test that we get a thrown error if we request a data key without supplying context if key is a derivation key type.
		public async Task GenerateDataKey_KeySupportsDerivation_NoContextSupplied_ThrowsError () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256, true);

			// Generate a data key.
			Assert.That(() => _transitSecretEngine.GenerateDataKey(key),
			            Throws.Exception.TypeOf<VaultInvalidDataException>().With.Property("Message").Contains("key was created using a derived key"));
		}



		[Test]

		// Test that we can backup a key that is enabled for backup.
		public async Task BackupKey_Success () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256, true);

			// Allow Backup.
			Dictionary<string, string> keyconfig = new Dictionary<string, string> {{TransitConstants.KeyConfig_Allow_Backup, "true"}};

			TransitKeyInfo tki = await _transitSecretEngine.UpdateKey(key, keyconfig);

			// Back it up.
			TransitBackupRestoreItem tbri = await _transitSecretEngine.BackupKey(key);
			Assert.True(tbri.Success);
			Assert.AreNotEqual(null, tbri.KeyBackup);
		}



		[Test]

		// Test that we get an error when trying to backup a key that cannot be backed up.
		public async Task BackupKey_ThrowsError_WhenNotEnabledForBackup () {
			// Cannot use the Transit_InitWithKey function.  It sets Backup to true and once set that value cannot be changed.
			string key = _uniqueKeys.GetKey();

			// Create key.
			bool rc = await _transitSecretEngine.CreateEncryptionKey(key, true, false, TransitEnumKeyType.aes256);
			Assert.True(rc);


			// Back it up.
			TransitBackupRestoreItem tbri = await _transitSecretEngine.BackupKey(key);
			Assert.False(tbri.Success);
			Assert.True(tbri.ErrorMsg.Contains("PlainTextBackup disabled"));
		}




		[Test]

		// Test that we get an error when trying to backup a key that cannot be backed up.
		public async Task BackupKey_ThrowsError_WhenNotExportable () {
			// Cannot use the Transit_InitWithKey function.  It sets Backup to true and once set that value cannot be changed.
			string key = _uniqueKeys.GetKey("Key");

			// Create key.
			bool rc = await _transitSecretEngine.CreateEncryptionKey(key, false, true, TransitEnumKeyType.aes256);
			Assert.True(rc);


			// Back it up.
			TransitBackupRestoreItem tbri = await _transitSecretEngine.BackupKey(key);
			Assert.False(tbri.Success);
			Assert.True(tbri.ErrorMsg.Contains("Key is not exportable"));
		}



		[Test]

		// Performs a complex set of operations to ensure a backup and restore of a key is successful. Including rotating the key
		// encrypting with the key, etc.
		public async Task RestoreKey_Success () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256);

			// A.  Enable deletion of the key.
			Dictionary<string, string> keyconfig = new Dictionary<string, string> {{TransitConstants.KeyConfig_DeleteAllowed, "true"}};

			TransitKeyInfo tki = await _transitSecretEngine.UpdateKey(key, keyconfig);
			Assert.True(tki.CanDelete);


			// B.  Rotate the key a few times.
			await _transitSecretEngine.RotateKey(key);
			await _transitSecretEngine.RotateKey(key);
			await _transitSecretEngine.RotateKey(key);


			// C.  Encrypt a piece of data.
			string encryptedValue = "ABCzyx123";
			TransitEncryptedItem encItem = await _transitSecretEngine.Encrypt(key, encryptedValue);

			// D.  Rotate Keys a few more times.
			await _transitSecretEngine.RotateKey(key);
			await _transitSecretEngine.RotateKey(key);
			await _transitSecretEngine.RotateKey(key);


			tki = await _transitSecretEngine.ReadEncryptionKey(key);
			Assert.AreEqual(tki.Name, key);


			// E.  Back it up.
			TransitBackupRestoreItem tbri = await _transitSecretEngine.BackupKey(key);
			Assert.True(tbri.Success);
			Assert.AreNotEqual(null, tbri.KeyBackup);


			// F.  Delete key.
			Assert.True(await _transitSecretEngine.DeleteKey(key));


			// G.  Restore the key
			Assert.True(await _transitSecretEngine.RestoreKey(key, tbri));


			// H.  Decrypt an item with restored key.
			TransitDecryptedItem decItem = await _transitSecretEngine.Decrypt(key, encItem.EncryptedValue);
			Assert.AreEqual(encryptedValue, decItem.DecryptedValue);


			// I.  Validate the restore.
			TransitKeyInfo tkiRestore = await _transitSecretEngine.ReadEncryptionKey(key);
			Assert.AreEqual(tki.Type, tkiRestore.Type);
			Assert.AreEqual(tki.LatestVersionNum, tkiRestore.LatestVersionNum);
			Assert.AreEqual(tki.Name, tkiRestore.Name);
			Assert.AreEqual(tki.Keys.Count, tkiRestore.Keys.Count);
		}



		[Test]

		// Performs a complex set of operations to ensure a backup and restore of a key is successful. Including rotating the key
		// encrypting with the key, etc.
		// Note this tests when the key already exists.  Should Fail.
		public async Task RestoreKey_KeyAlreadyExists_ReturnsFalse () {
			string key = await Transit_InitWithKey(TransitEnumKeyType.aes256);

			// E.  Back it up.
			TransitBackupRestoreItem tbri = await _transitSecretEngine.BackupKey(key);
			Assert.True(tbri.Success);
			Assert.AreNotEqual(null, tbri.KeyBackup);


			// B.  Rotate the key a few times so we know the keys are different.
			await _transitSecretEngine.RotateKey(key);
			await _transitSecretEngine.RotateKey(key);


			// Read key, prior to restore.
			TransitKeyInfo tki = await _transitSecretEngine.ReadEncryptionKey(key);
			Assert.AreEqual(tki.Name, key);


			// G.  Restore the key
			Assert.False(await _transitSecretEngine.RestoreKey(key, tbri));
		}



		[Test]

		// Generate random bytes.  Bytes are base64 encoded and then decoded before we receive.  We get straight bytes.
		public async Task GenerateRandomBytes_Base64_Works () {
			string value = await _transitSecretEngine.GenerateRandomBytes(10);
			Assert.AreEqual(10, value.Length);
		}


		[Test]

		// Generate random bytes.  string should be hexidecimal
		public async Task GenerateRandomBytes_Hex_Works () {
			string value = await _transitSecretEngine.GenerateRandomBytes(15, true);
			Assert.AreNotEqual("", value);
		}




		[Test, Order(2103)]

		// Compute the hash of a string.  
		public async Task Transit_ComputeHash_Base64 () {
			string value = await _transitSecretEngine.ComputeHash("abcdefXYZ12", TransitEnumHashingAlgorithm.sha2_512);
			Assert.AreNotEqual("", value);
		}



		[Test, Order(2103)]

		// Generate random bytes.  string should be hexidecimal
		public async Task Transit_ComputeHash_Hex () {
			string value = await _transitSecretEngine.ComputeHash("abcdefXYZ", TransitEnumHashingAlgorithm.sha2_384, true);
			Assert.AreNotEqual("", value);
		}

	}
}