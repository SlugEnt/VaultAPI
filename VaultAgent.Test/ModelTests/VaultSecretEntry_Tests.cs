using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using SlugEnt;
using VaultAgent;
using VaultAgent.Backends.System;
using VaultAgent.SecretEngines;
using VaultAgent.SecretEngines.KV2.SecretMetaDataInfo;
using VaultAgentTests;

namespace VaultAgentTests
{
	[TestFixture]
	[Parallelizable]
	public class VaultSecretEntry_Tests {
		private KV2SecretEngine _noCASMount = null;
		private KV2SecretEngine _casMount;
		private VaultAgentAPI _vaultAgentAPI;
		private SlugEnt.UniqueKeys _uniqueKey = new UniqueKeys();

        

		[OneTimeSetUp]
		public async Task Setup () {
            if (_vaultAgentAPI != null) { return; }

            // Build Connection to Vault.
            _vaultAgentAPI = new VaultAgentAPI("testa", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);


            // We will create 3 KV2 mounts in the Vault instance.  One for testing with CAS on, one with CAS off, and then a generic default (CAS off).	
            string noCasMountName = _uniqueKey.GetKey("NoCas");
            string casMountName = _uniqueKey.GetKey("CAS");


            // Config settings for all the mounts.
            VaultSysMountConfig config = new VaultSysMountConfig
            {
                DefaultLeaseTTL = "30m",
                MaxLeaseTTL = "90m",
                VisibilitySetting = "hidden"
            };

            _noCASMount = (KV2SecretEngine)await _vaultAgentAPI.CreateSecretBackendMount(EnumSecretBackendTypes.KeyValueV2, noCasMountName, noCasMountName,
                                                                                           "No CAS Mount Test", config);
            _casMount = (KV2SecretEngine)await _vaultAgentAPI.CreateSecretBackendMount(EnumSecretBackendTypes.KeyValueV2, casMountName, casMountName,
                                                                                       "CAS Mount Test", config);

            Assert.NotNull(_noCASMount);
            Assert.NotNull(_casMount);

            // This is required as of Vault 1.0  It now seems to take a second or 2 to upgrade the mount from KV1 to KV2.
            Thread.Sleep(2500);

            // Set backend mount config.
            Assert.True(await _noCASMount.SetBackendConfiguration(8, false));
            Assert.True(await _casMount.SetBackendConfiguration(8, false));
        }


        // Can save a VSE Object to the vault
        [Test]
		public async Task Save_Success () {
			string secretName = _uniqueKey.GetKey("SN");
            VaultSecretEntry secretA = new VaultSecretEntry(_noCASMount,secretName,"");
            bool success = await secretA.VSE_Save();
            Assert.IsTrue(success);
		}


		// Validates we can save a secret, then create a new one with same name,path (so same secret) and can read it from Vault, and they are equal!
		[Test]
		public async Task Read_Success () {
			string secretName = _uniqueKey.GetKey("SNRead");
			VaultSecretEntry secretA = new VaultSecretEntry(_noCASMount, secretName, "");
            secretA.Attributes.Add("KeyA","ValueA");
			bool success = await secretA.VSE_Save();
			Assert.IsTrue(success);

            // Now create a new VSE with same name and path.  We should be able to read it from Vault and get the same secret as the one we just saved
            VaultSecretEntry secretB = new VaultSecretEntry(_noCASMount,secretName,"");
            success = await secretB.VSE_Read();
            Assert.IsTrue(success,"A20:Failed to successfull read the secret back");
            Assert.AreEqual(secretA.Attributes.Count,secretB.Attributes.Count);
		}


        // Validates that trying to read a VSE that does not exist, returns False
		[Test]
		public async Task Read_Failure () {
			string secretName = _uniqueKey.GetKey("SNRead");

			// Now create a new VSE with same name and path.  We should be able to read it from Vault and get the same secret as the one we just saved
			VaultSecretEntry secretB = new VaultSecretEntry(_noCASMount, secretName, "");
			bool success = await secretB.VSE_Read();
			Assert.IsFalse(success, "A10:Failed to successfull read the secret back");
        }


        // Validates that trying to read a VSE that we do not have permission for, does XXXXXXX?
        [Test]
        public async Task Read_NoPermission_Failure () { throw new NotImplementedException();}


        // Validates the VSE_Exists Returns True if the secret is saved in the Vault
        [Test]
        public async Task Exists_ReturnsTrue_IfSecretExists () {
	        string secretName = _uniqueKey.GetKey("SNExistsT");
	        VaultSecretEntry secretA = new VaultSecretEntry(_noCASMount, secretName, "");
	        secretA.Attributes.Add("KeyA", "ValueA");
	        bool success = await secretA.VSE_Save();
	        Assert.IsTrue(success);

            // Now see if it exists in the Vault.
            Assert.IsTrue(await secretA.VSE_Exists());
        }


        // Validates that VSE_Exists Returns False if the secret does not exist in the Vault
        [Test]
        public async Task Exists_ReturnsFalse_IfSecretDoesNotExist()
        {
	        string secretName = _uniqueKey.GetKey("SNExistsF");
	        VaultSecretEntry secretA = new VaultSecretEntry(_noCASMount, secretName, "");

	        // Now see if it exists in the Vault.
	        Assert.IsFalse(await secretA.VSE_Exists());
        }


        // Confirms that deleting a secret deletes it from the Vault.
        [Test]
        public async Task DeleteSuccess () {
	        string secretName = _uniqueKey.GetKey("Del");
	        VaultSecretEntry secretA = new VaultSecretEntry(_noCASMount, secretName, "");
	        secretA.Attributes.Add("KeyA", "ValueA");
	        bool success = await secretA.VSE_Save();
	        Assert.IsTrue(success);

            // Now delete it 
            Assert.IsTrue(await secretA.VSE_Delete());

            // Try to read it
            Assert.IsFalse(await secretA.VSE_Read());
        }


        // Confirms that DestroyAll permanently removes all evidence of the secret from the Vault
        [Test]
        public async Task DestroyAllSuccess()
        {
	        string secretName = _uniqueKey.GetKey("Des");
	        VaultSecretEntry secretA = new VaultSecretEntry(_noCASMount, secretName, "");
	        secretA.Attributes.Add("KeyA", "ValueA");
	        bool success = await secretA.VSE_Save();
	        Assert.IsTrue(success);

	        // Now Destory All it 
	        Assert.IsTrue(await secretA.VSE_DestroyAll());

	        // Try to read it
	        Assert.IsFalse(await secretA.VSE_Read());
        }


        // Validates that we can read the Secret Info Object
        [Test]
        public async Task SecretInfo_Success () {
	        string secretName = _uniqueKey.GetKey("SIS");
	        VaultSecretEntry secretA = new VaultSecretEntry(_noCASMount, secretName, "");
	        secretA.Attributes.Add("KeyA", "ValueA");
	        bool success = await secretA.VSE_Save();
	        Assert.IsTrue(success);

            // Update Secret and save 2x, to create multiple versions
            secretA.Attributes.Add("KeyB","ValueB");
            success = await secretA.VSE_Save();
            Assert.IsTrue(success,"A20: 2nd Save Failed");

            // Update Secret and save 2x, to create multiple versions
            secretA.Attributes.Add("KeyC", "ValueC");
            success = await secretA.VSE_Save();
            Assert.IsTrue(success, "A30: 3rd Save Failed");


            // Get secret Info
            success = await secretA.VSE_Info();
            Assert.IsTrue(success,"A40:  Retrieval of Secret Info failed");
            Assert.AreEqual(3,secretA.Info.Versions.Count,"A50:  Number of versions was unexpected");
            Assert.AreEqual(3,secretA.Info.CurrentVersion,"A60:  Current Version of Secret was incorrect.");
        }



        // Validates that VSE_ReadVersion actually reads the requested secret version
        [Test]
        public async Task VSE_ReadVersion_Success()
        {
	        string secretName = _uniqueKey.GetKey("RV");
	        VaultSecretEntry secretA = new VaultSecretEntry(_noCASMount, secretName, "");
	        secretA.Attributes.Add("KeyA", "ValueA");
	        bool success = await secretA.VSE_Save();
	        Assert.IsTrue(success);
	        int version1 = secretA.Version;
            Assert.AreEqual(1, version1,"A01:  First Save of Secret did not yield a version number of 1");
            

	        // Update Secret and save to create multiple versions
	        secretA.Attributes.Add("KeyB", "ValueB");
	        success = await secretA.VSE_Save();
	        Assert.IsTrue(success, "A20: 2nd Save Failed");

	        // Update Secret and save 2x, to create multiple versions
	        secretA.Attributes.Add("KeyC", "ValueC");
	        success = await secretA.VSE_Save();
	        Assert.IsTrue(success, "A30: 3rd Save Failed");

            // Read Version 1.
            success = await secretA.VSE_ReadVersion(version1);
            Assert.IsTrue(success, "A32: Read of specific version did not work");
            Assert.AreEqual(1, secretA.Attributes.Count,"A34:  Attribute count was not expected value.  Appears we did not read back the version we expected.");


            // Get secret Info
            success = await secretA.VSE_Info();
	        Assert.IsTrue(success, "A40:  Retrieval of Secret Info failed");
	        Assert.AreEqual(3, secretA.Info.Versions.Count, "A50:  Number of versions was unexpected");
	        Assert.AreEqual(3, secretA.Info.CurrentVersion, "A60:  Current Version of Secret was incorrect.");
        }


        #region "VaultSecretEntryCAS Tests"
        // We only need to test the SaveNew and SaveUpdate Methods, all the others are the same as VaultSecretEntry

        [Test]
        public async Task CAS_SaveNew_Success()
        {
	        string secretName = _uniqueKey.GetKey("CASNEW");
	        VaultSecretEntryCAS secretA = new VaultSecretEntryCAS(_casMount, secretName, "");
	        secretA.Attributes.Add("KeyA", "ValueA");
	        bool success = await secretA.VSE_SaveNew();
	        Assert.IsTrue(success);
        }



        [Test]
        public async Task CAS_SaveUpdate_Success()
        {
	        string secretName = _uniqueKey.GetKey("CASNEW");
	        VaultSecretEntryCAS secretA = new VaultSecretEntryCAS(_casMount, secretName, "");
	        secretA.Attributes.Add("KeyA", "ValueA");
	        bool success = await secretA.VSE_SaveNew();
	        Assert.IsTrue(success);

            // Now make some changes to the secret and save them
            secretA.Attributes.Add("KeyB", "ValueB");
            success = await secretA.VSE_SaveUpdate();
            Assert.IsTrue(success);

            // And one more time for confirmation
            secretA.Attributes.Add("KeyC", "ValueC");
            success = await secretA.VSE_SaveUpdate();
            Assert.IsTrue(success);
            Assert.AreEqual(3, secretA.Version);
        }



        #endregion
    }
}