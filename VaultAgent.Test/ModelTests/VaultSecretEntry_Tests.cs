using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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


        // 1/27/2020 1:50:35 PM GMT
        private long _unixEpochTime = 1580133035;
        private DateTimeOffset _theDate = new DateTimeOffset();


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




            // Setup the DateTimeOffset Fields
            _theDate = DateTimeOffset.FromUnixTimeSeconds(_unixEpochTime);

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

        #region "VSE Throw Error Tests"
        // TODO test all the VSE Methods
        [Test]
        public async Task VSE_Read_ThrowsError_IfEngineNotDefined()
        {
            string secretName = _uniqueKey.GetKey("Des");
            VaultSecretEntry secretA = new VaultSecretEntry();
            secretA.Name = "test";
            secretA.Attributes.Add("KeyA", "ValueA");
            Assert.ThrowsAsync<ApplicationException>(() => secretA.VSE_Save());
        }

        #endregion


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

        #region "Attribute Accessor Methods"

        [Test]
        [TestCase(0)]
        [TestCase(-990)]
        [TestCase(2050)]
        public void IntAttributeSet_Success (int value)
        {
            string attrName = "AttrA";
            VaultSecretEntry vseA = new VaultSecretEntry();

            // Save value
            vseA.SetIntAttribute(attrName, value);

            string lookupValue = vseA.Attributes[attrName];
            Assert.AreEqual(value.ToString(),lookupValue);
        }



        // Validates that GetIntAttributeNullable Works
        [Test]
        [TestCase(0)]
        [TestCase(-990)]
        [TestCase(2050)]
        public void IntAttributeGetNullable_Success (int value)
        {
            string attrName = "AttrA";
            VaultSecretEntry vseA = new VaultSecretEntry();

            // Save value
            vseA.SetIntAttribute(attrName, value);

            // Get Value
            int? answer = vseA.GetIntAttributeNullable(attrName);
            Assert.NotNull(answer, "A10:  Expected a number, not a Null value");
            Assert.AreEqual(value, answer);
        }



        // Validates that GetIntAttributeNullable returns null when value does not exist
        [Test]
        public void IntAttributeGetNullable_ReturnsNull()
        {
            string attrName = "AttrA";
            VaultSecretEntry vseA = new VaultSecretEntry();

            // We do not save anything in the Attributes, to force a null
            
            // Get Value
            int? answer = vseA.GetIntAttributeNullable(attrName);
            Assert.IsNull(answer);
        }


        // Validates that GetIntAttributeNullable returns null when empty string
        [Test]
        public void IntAttributeGetNullable_ReturnsNullOnEmptyString_Success()
        {
            string attrName = "AttrA";
            string value = "";

            VaultSecretEntry vseA = new VaultSecretEntry();
            vseA.Attributes[attrName] = value;


            // Get Value
            int? answer = vseA.GetIntAttributeNullable(attrName);
            Assert.IsNull (answer, "A10:  Expected a null value when string is empty");
        }



        [Test]
        public void DateTimeOffsetSet_Success()
        {
            // 1/27/2020 1:50:35 PM GMT

            // Validate the date is correct
            Assert.AreEqual(1,_theDate.Month);
            Assert.AreEqual(27, _theDate.Day);
            Assert.AreEqual(2020,_theDate.Year);
            Assert.AreEqual(13,_theDate.Hour);
            Assert.AreEqual(50,_theDate.Minute);
            Assert.AreEqual(35,_theDate.Second);


            string attrName = "AttrA";
            VaultSecretEntry vseA = new VaultSecretEntry();

            // Save value
            vseA.SetDateTimeOffsetAttribute(attrName, _theDate);

            string lookupValue = vseA.Attributes[attrName];
            Assert.AreEqual(_unixEpochTime.ToString(), lookupValue);
        }



        [Test]
        public void DateTimeOffsetGetNullable_ReturnsNullOnEmptyString_Success()
        {
            string attrName = "AttrA";
            string value = "";

            VaultSecretEntry vseA = new VaultSecretEntry();
            vseA.Attributes[attrName] = value;


            // Get Value
            DateTimeOffset? answer = vseA.GetDateTimeOffsetAttributeNullable(attrName);
            Assert.IsNull(answer, "A10:  Expected a null value when string is empty");
        }




        // Validates that GetDateTimeOffsetAttributeNullable returns null when value does not exist
        [Test]
        public void DateTimeOffsetAttributeGetNullable_ReturnsNull()
        {
            string attrName = "AttrA";
            VaultSecretEntry vseA = new VaultSecretEntry();

            // We do not save anything in the Attributes, to force a null

            // Get Value
            DateTimeOffset? answer = vseA.GetDateTimeOffsetAttributeNullable(attrName);
            Assert.IsNull(answer);
        }




        // Validates that GetDateTimeOffsetAttributeNullable Works
        [Test]
        [TestCase(0)]
        [TestCase(95660023)]
        [TestCase(5450343433)]
        public void DateTimeOffsetAttributeGetNullable_Success(long value)
        {
            string attrName = "AttrA";
            VaultSecretEntry vseA = new VaultSecretEntry();

            DateTimeOffset aDate = new DateTimeOffset();
            aDate = DateTimeOffset.FromUnixTimeSeconds(value);

            // Save value
            vseA.SetDateTimeOffsetAttribute(attrName, aDate);

            // Get Value
            DateTimeOffset? answer = vseA.GetDateTimeOffsetAttributeNullable(attrName);
            Assert.NotNull(answer, "A10:  Expected a DateTime, not a Null value");

            DateTimeOffset answer2 = (DateTimeOffset) answer;

            long unixTimeSeconds = answer2.ToUnixTimeSeconds();

            Assert.AreEqual(value, unixTimeSeconds);
        }


        // Validates that GetDateTimeOffsetAttributeNullable Works
        [Test]
        [TestCase(0)]
        [TestCase(95660023)]
        [TestCase(5450343433)]
        public void DateTimeOffsetAttributeGetDefault_Success(long value)
        {
            string attrName = "AttrA";
            VaultSecretEntry vseA = new VaultSecretEntry();

            DateTimeOffset aDate = new DateTimeOffset();
            aDate = DateTimeOffset.FromUnixTimeSeconds(value);

            // Save value
            vseA.SetDateTimeOffsetAttribute(attrName, aDate);

            // Get Value
            DateTimeOffset answer = vseA.GetDateTimeOffsetAttributeDefault(attrName);
            Assert.NotNull(answer, "A10:  Expected a DateTime, not a Null value");

            long unixTimeSeconds = answer.ToUnixTimeSeconds();

            Assert.AreEqual(value, unixTimeSeconds);
        }



        #endregion
    }
}