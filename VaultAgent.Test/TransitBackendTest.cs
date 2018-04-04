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
		public async Task AA_CreateAndEnable_TransitA_Backend_() {
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
		public async Task BA_CreateEncryptionKey_encKeyA_WithNewKeyName_ShouldPassTest() {
			try {
				// Try with parameters values.
				bool rc = await TB.CreateEncryptionKey(encKeyA, true, true, EnumTransitKeyType.rsa4096);
				Assert.AreEqual(true, rc);
			}
			catch (Exception e) { }
		}
	

		[Test, Order(30)]
		public async Task BB_ValidateEncryptionKey_encKeyA_wasCreated() {
			try {
				TransitKeyInfo TKI = await TB.ReadEncryptionKey(encKeyA);
				Assert.AreEqual(encKeyA, TKI.Name);
				Assert.AreEqual(1, TKI.LatestVersionNum);
			}
			catch (Exception e) { }
		}






		[Test, Order(40)]
		public async Task CA_ListEncryptionKeys_ShouldReturnAllKeys() {
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
		public async Task DA_ValidateBasicEncryptDecryptWork () {
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
		public async Task EA_ValidateRotateEncryptionKeyWorks () {
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
		public async Task ValidateReEncryption_ResultsInSameOriginalValue () {
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
	}
}
