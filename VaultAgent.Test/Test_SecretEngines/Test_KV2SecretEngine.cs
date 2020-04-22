using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Threading;
using NUnit.Framework;
using VaultAgent.Backends.System;
using VaultAgent.SecretEngines;
using System.Threading.Tasks;
using VaultAgent.Backends;
using VaultAgent.SecretEngines.KV2.SecretMetaDataInfo;
using VaultAgent;
using VaultAgent.SecretEngines.KV2;
using SlugEnt;


namespace VaultAgentTests {
    [TestFixture, Order (1)]
    [Parallelizable]
    public class Test_KV2SecretEngine {
        private VaultSystemBackend _systemBackend;
        private KV2SecretEngine _casMount;
        private KV2SecretEngine _noCasMount;
        private KV2SecretEngine _defaultMount;

        private VaultAgentAPI _vaultAgentAPI;
        private readonly UniqueKeys _uniqueKey = new UniqueKeys(); // Unique Key generator



        /// <summary>
        /// One Time Setup - Run once per a single Test run exection.
        /// </summary>
        /// <returns></returns>
        [OneTimeSetUp]
        public async Task Secret_Init () {
            if ( _vaultAgentAPI != null ) { return; }

            // Build Connection to Vault.
            _vaultAgentAPI = await VaultServerRef.ConnectVault("KV2SecretEng");
            //new VaultAgentAPI ("testa", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);


            // We will create 3 KV2 mounts in the Vault instance.  One for testing with CAS on, one with CAS off, and then a generic default (CAS off).	
            string casMountName = _uniqueKey.GetKey ("CAS");
            string noCasMountName = _uniqueKey.GetKey ("NoCas");
            string defaultMountName = _uniqueKey.GetKey ("defNoCas");


            // Config settings for all the mounts.
            VaultSysMountConfig config = new VaultSysMountConfig
            {
                DefaultLeaseTTL = "30m",
                MaxLeaseTTL = "90m",
                VisibilitySetting = "hidden"
            };


            // Get Connection to Vault System backend
            _systemBackend = new VaultSystemBackend(_vaultAgentAPI.TokenID, _vaultAgentAPI);
            
            Assert.IsTrue(await _systemBackend.CreateSecretBackendMount(EnumSecretBackendTypes.KeyValueV2, noCasMountName, noCasMountName,
                                                                        "No CAS Mount Test", config),"A10:  Failed to create the NoCas Secret Backend");
            _noCasMount = (KV2SecretEngine) _vaultAgentAPI.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, noCasMountName, noCasMountName);


            Assert.IsTrue(await _systemBackend.CreateSecretBackendMount(EnumSecretBackendTypes.KeyValueV2, casMountName, casMountName,
                                                                        "CAS Mount Test", config), "A20:  Failed to create the CAS Secret Backend");
            _casMount = (KV2SecretEngine)_vaultAgentAPI.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, casMountName, casMountName);



            Assert.IsTrue(await _systemBackend.CreateSecretBackendMount(EnumSecretBackendTypes.KeyValueV2, defaultMountName,
                                                                        defaultMountName, "Default Mount Test", config), "A30:  Failed to create the Default Secret Backend");
            _defaultMount = (KV2SecretEngine)_vaultAgentAPI.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, defaultMountName, defaultMountName);


            //_noCasMount = (KV2SecretEngine) await _vaultAgentAPI.CreateSecretBackendMount (EnumSecretBackendTypes.KeyValueV2, noCasMountName, noCasMountName,
//            "No CAS Mount Test", config);
            //_casMount = (KV2SecretEngine) await _vaultAgentAPI.CreateSecretBackendMount (EnumSecretBackendTypes.KeyValueV2, casMountName, casMountName,
  //                                                                                       "CAS Mount Test", config);
    //        _defaultMount = (KV2SecretEngine) await _vaultAgentAPI.CreateSecretBackendMount (EnumSecretBackendTypes.KeyValueV2, defaultMountName,
      //                                                                                       defaultMountName, "Default Mount Test", config);


            Assert.NotNull (_noCasMount);
            Assert.NotNull (_casMount);
            Assert.NotNull (_defaultMount);

            // This is required as of Vault 1.0  It now seems to take a second or 2 to upgrade the mount from KV1 to KV2.
            Thread.Sleep (2500);

            // Set backend mount config.
            Assert.True (await _casMount.SetBackendConfiguration (6, true));
            Assert.True (await _noCasMount.SetBackendConfiguration (8, false));
            Assert.True (await _defaultMount.SetBackendConfiguration (3, false));


            return;
        }



        [SetUp]

        // Ensure Backend is initialized during each test.
        protected void AppBackendTestInit () { }

        #region "NamePathTests"


        #endregion

        // Confirms that when Reading or Saving a secret, the KV2VaultReadReturnObjData element is read correctly from Vault and updates the secrets properties
        [Test]
        public async Task KV2VaultReadReturnObjData_Works () {
	        KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
	        Assert.AreEqual(true, s.CASRequired, "A1: Expected the Backend to be mounted in CAS Mode, but it was not.  Cannot test further.");


	        // Generate a key.
	        string secName = _uniqueKey.GetKey("KVRRODW");
	        KV2Secret secretV2 = new KV2Secret(secName);
	        KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("a", "1");
            secretV2.Attributes.Add(kv1.Key,kv1.Value);

            // Verify before values
            Assert.AreEqual(DateTimeOffset.MinValue,secretV2.CreatedTime);
            Assert.AreEqual(DateTimeOffset.MinValue, secretV2.DeletionTime);
            Assert.IsFalse(secretV2.IsDestroyed);
            Assert.AreEqual(0,secretV2.Version,"A10:  Initial Secret Version should be 0");


            // Save the Secret, which will updated the Version and Created fields
            Assert.True(await _casMount.SaveSecret(secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist));

	        // Validate the Values
	        Assert.AreEqual(1, secretV2.Version, "A20:  Secret Version was not set correctly after save");
            Assert.AreNotEqual(DateTimeOffset.MinValue,secretV2.CreatedTime,"A30:  Secret Creation Time was not updated during save");
            Assert.AreEqual(DateTimeOffset.MinValue, secretV2.DeletionTime);
            Assert.IsFalse(secretV2.IsDestroyed);



            // 2. Read the secret back in a new secret object to confirm read also sets these values
            KV2Secret s2 = await _casMount.ReadSecret<KV2Secret>(secName);
	        Assert.True(secretV2.Path == s2.Path);
	        Assert.Contains(kv1,s2.Attributes);

	        Assert.AreEqual(1, secretV2.Version, "A100:  Secret Version was not set correctly after save");
	        Assert.AreNotEqual(DateTimeOffset.MinValue, secretV2.CreatedTime, "A100:  Secret Creation Time was not updated during save");
	        Assert.AreEqual(DateTimeOffset.MinValue, secretV2.DeletionTime);
	        Assert.IsFalse(secretV2.IsDestroyed);
        }



        #region "CAS True Testing"


        [Test]
        public async Task Validate_BackendSettings_CAS_Set () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.AreEqual (true, s.CASRequired, "A1: Expected the Backend to be mounted in CAS Mode, but it was not.  Cannot test further.");
            Assert.AreEqual (6, s.MaxVersions, "A10: Expected the backend to have the property MaxVersions set to 6.  But it was: " + s.MaxVersions.ToString());
        }

        
        /// <summary>
        /// Confirms that if the backend is set to require CAS, then a secret without CAS specified will fail.
        /// </summary>
        [Test]
        public async Task BackendWithCAS_FailsSecretSaveWithoutCasOptionSet () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.AreEqual (true, s.CASRequired, "A1: Expected the Backend to be mounted in CAS Mode, but it was not.  Cannot test further.");

            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "/");

            secretV2.Attributes.Add ("Test54", "44");

            // Save Secret passing no CAS options.
            Assert.That (() => _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.AlwaysAllow),
                         Throws.Exception.TypeOf<VaultInvalidDataException>()
                               .With.Property ("Message")
                               .Contains ("The backend storage engine has the CAS property set."));
        }



        // Validate that we can save a secret with CAS set.
        [Test]
        public async Task BackendWithCAS_AllowsSaveOfNewSecretWithCASSet () {
            // Setup backend to allow 6 versions of a key and requires CAS.
            //Assert.True(await casMount.SetBackendConfiguration(6, true));
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.AreEqual (true, s.CASRequired, "A1: Expected the Backend to be mounted in CAS Mode, but it was not.  Cannot test further.");


            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);
            KeyValuePair<string, string> kv2 = new KeyValuePair<string, string> ("b", "2");
            secretV2.Attributes.Add (kv2.Key, kv2.Value);


            // Save Secret passing CAS option of 0 for new update.
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist),
                         "A10: Expected the secret to be saved and return True, but it returned False instead.");

            // Secret Version should have been updated.
            Assert.AreEqual(1,secretV2.Version, "A12:  Secret Version was not set correctly");

            // Read the Secret back to confirm the save.
            KV2Secret s2 = await _casMount.ReadSecret (secretV2);
            Assert.AreEqual (secretV2.Path, s2.Path, "A20: Expected the secret paths to be the same.  They were different.");
            Assert.Contains (kv1, s2.Attributes, "A30:  The secret appears to be missing some Attributes that we requested be saved.");
            Assert.Contains (kv2, s2.Attributes, "A40:  The secret appears to be missing some Attributes that we requested be saved.");
            Assert.AreEqual(1, s2.Version, "A42:  Secret Version was not set correctly");

            TestContext.WriteLine ("Secret Info:");
            TestContext.WriteLine ("  Backend MountPoint:  {0}", _casMount.MountPointPath);
            TestContext.WriteLine ("  Secret Path:             {0}", secretV2.FullPath);
            TestContext.WriteLine ("  Secret Name:             {0}", secretV2.Name);
        }



        /// <summary>
        /// Tests that with a backend with CAS set, That an existing secret can be saved only if current version has been specified.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task BackendWithCAS_AllowsSaveofSecretWithNewVersion () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.AreEqual (true, s.CASRequired, "A1: Expected the Backend to be mounted in CAS Mode, but it was not.  Cannot test further.");


            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName);
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Setup the test scenario:
            // 1. Create a new key with version 1.
            // Save Secret passing CAS option of 0 for new update.
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist));

            // Secret Version should have been updated.
            Assert.AreEqual(1, secretV2.Version, "A12:  Secret Version was not set correctly");



            // 2. Read the secret back and get the version
            KV2Secret s2 = await _casMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path);
            Assert.Contains (kv1, s2.Attributes);
            Assert.AreEqual (1, s2.Version);

            // 3. Now attempt to save the secret back specifying the version.
            KeyValuePair<string, string> kv2 = new KeyValuePair<string, string> ("b", "2");
            secretV2.Attributes.Add (kv2.Key, kv2.Value);
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s2.Version));

            // Secret Version should have been updated.
            Assert.AreEqual(2, secretV2.Version, "A22:  Secret Version was not set correctly");

        }



        /// <summary>
        /// Tests that with a backend with CAS set, That attempting to save a secret without specifying the previous version of that secret
        /// results in an exception being thrown.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task BackendWithCAS_SaveSecretWithInvalidVersionNumFails () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.AreEqual (true, s.CASRequired, "A1: Expected the Backend to be mounted in CAS Mode, but it was not.  Cannot test further.");


            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName);
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Setup the test scenario:
            // 1. Create a new key with version 1.
            // Save Secret passing CAS option of 0 for new update.
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist));


            // 2. Read the secret back and get the version
            KV2Secret s2 = await _casMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path);
            Assert.Contains (kv1, s2.Attributes);
            Assert.AreEqual (1, s2.Version);

            // 3. Now  Update the secret attributes.
            KeyValuePair<string, string> kv2 = new KeyValuePair<string, string> ("b", "2");
            secretV2.Attributes.Add (kv2.Key, kv2.Value);
            KeyValuePair<string, string> kv3 = new KeyValuePair<string, string> ("c", "3");
            secretV2.Attributes.Add (kv3.Key, kv3.Value);

            // 4. Save secret a second time.
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, 1),
                         "A10: Save Secret should have succeeded.");


            // 5. Update secret attributes
            KeyValuePair<string, string> kv4 = new KeyValuePair<string, string> ("d", "4");
            secretV2.Attributes.Add (kv4.Key, kv4.Value);

            // 6. Save Secret, but do not change the version number.  Should fail.
            Assert.That (() => _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, 1),
                         Throws.Exception.TypeOf<VaultInvalidDataException>().With.Property ("Message").Contains ("did not match the current version"));

            var ex = Assert.ThrowsAsync<VaultInvalidDataException> (
                () => _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, 1),
                "A11: Expected exception VaultInvalidDataException to be thrown.");
            Assert.That (ex, Has.Property ("SpecificErrorCode"),
                         "A12: Expected the thrown exception to contain the Property SpecificErrorCode, but it was missing.");
            Assert.AreEqual (EnumVaultExceptionCodes.CAS_VersionMissing, ex.SpecificErrorCode,
                             "A13: Expected the Specific Error Code to be " +
                             EnumVaultExceptionCodes.CAS_VersionMissing +
                             ", but instead it was value: " +
                             ex.SpecificErrorCode);
            Assert.That (ex, Has.Property ("Message").Contains ("did not match the current version"),
                         "Expected the Thrown Exception message to contain certain version text, but it was not in the exception message.");
        }



        /// <summary>
        /// Tests that with a backend with CAS set, That attempting to save a secret with the option - OnlyIfKeyDoesNotExist set results in an exception being thrown if that
        /// secret already exists.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task BackendWithCAS_SaveSecretWith_OnlyIfKeyDoesNotExistOption_ResultsInException () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.AreEqual (true, s.CASRequired, "A1: Expected the Backend to be mounted in CAS Mode, but it was not.  Cannot test further.");


            // Setup the test scenario:
            // 1. Create a new key with version 1.
            // Save Secret passing CAS option of 0 for new update.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName);
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A10:  Saving of initial Secret Value failed.");


            // 2. Read the secret back and get the version - just to confirm we do actually have a saved secret.
            KV2Secret s2 = await _casMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path);
            Assert.Contains (kv1, s2.Attributes, "A20:  Secret read from the Vault Instance did not contain the attributes we saved to it. ");
            Assert.AreEqual (1, s2.Version, "A30:  The version number of the secret that we read back was not what we expected.  It should have been: 1");


            // 3. Now Update the secret attributes.
            KeyValuePair<string, string> kv2 = new KeyValuePair<string, string> ("b", "2");
            secretV2.Attributes.Add (kv2.Key, kv2.Value);


            // 4. Attempt to save Secret, Should fail with SecretAlreadyExists message.
            var ex = Assert.ThrowsAsync<VaultInvalidDataException> (() => _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist, 1),
                                                                    "A40: Expected exception VaultInvalidDataException to be thrown.");
            Assert.That (ex, Has.Property ("SpecificErrorCode"),
                         "A42: Expected the thrown exception to contain the Property SpecificErrorCode, but it was missing.");
            Assert.AreEqual (EnumVaultExceptionCodes.CAS_SecretExistsAlready, ex.SpecificErrorCode,
                             "A44: Expected the Specific Error Code to be " +
                             EnumVaultExceptionCodes.CAS_SecretExistsAlready +
                             ", but instead it was value: " +
                             ex.SpecificErrorCode);
            Assert.That (ex, Has.Property ("Message").Contains ("The secret already exists"),
                         "A46:  Expected the Thrown Exception message to contain certain version text, but it was not in the exception message.");


            // 5. Attempt to save Secret again, but this time with a correct version number.  Should still fail because we set option to .
            var ex2 = Assert.ThrowsAsync<VaultInvalidDataException> (() => _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist, 2),
                                                                     "A50: Expected exception VaultInvalidDataException to be thrown.");
            Assert.That (ex2, Has.Property ("SpecificErrorCode"),
                         "A52: Expected the thrown exception to contain the Property SpecificErrorCode, but it was missing.");
            Assert.AreEqual (EnumVaultExceptionCodes.CAS_SecretExistsAlready, ex.SpecificErrorCode,
                             "A54: Expected the Specific Error Code to be " +
                             EnumVaultExceptionCodes.CAS_SecretExistsAlready +
                             ", but instead it was value: " +
                             ex.SpecificErrorCode);
            Assert.That (ex, Has.Property ("Message").Contains ("The secret already exists"),
                         "A56:  Expected the Thrown Exception message to contain certain version text, but it was not in the exception message.");
        }


        #endregion


        #region "CAS False Testing"


        /// <summary>
        /// Confirms that Backend Settings can be set for No CAS.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task Validate_BackendSettings_CAS_NotSet () {
            KV2SecretEngineSettings s = await _noCasMount.GetBackendConfiguration();
            Assert.AreEqual (false, s.CASRequired);
            Assert.AreEqual (8, s.MaxVersions);
        }



        // Should be able to save a secret without having to set CAS flag.
        [Test]
        public async Task BackendWithOUTCAS_SaveSecret_Success () {
            string secName = _uniqueKey.GetKey ("Sec");
            KV2Secret secretV2 = new KV2Secret (secName, "/");

            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("test54", "44");

            secretV2.Attributes.Add (kv1.Key, kv1.Value);
            Assert.True (await _noCasMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.AlwaysAllow));


            // Read the Secret back to confirm the save.
            KV2Secret s2 = await _noCasMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path);
            Assert.Contains (kv1, s2.Attributes);
        }



        // Should be able to save(update) an existing secret without having to set CAS flag.
        [Test]
        public async Task BackendWithOUTCAS_UpdateExistingSecret_Success () {
            string secName = _uniqueKey.GetKey ("SecNew");
            KV2Secret secretV2 = new KV2Secret (secName, "/folder1/folder2/folder3/folder4/");

            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("test54", "44");

            secretV2.Attributes.Add (kv1.Key, kv1.Value);
            Assert.True (await _noCasMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.AlwaysAllow));


            // Read the Secret back to confirm the save.
            KV2Secret s2 = await _noCasMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path);
            Assert.Contains (kv1, s2.Attributes);

            // Now update it.
            KeyValuePair<string, string> kv2 = new KeyValuePair<string, string> ("b", "2");
            secretV2.Attributes.Add (kv2.Key, kv2.Value);
            Assert.True (await _noCasMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.AlwaysAllow));
        }



        /// <summary>
        /// Tests that with a backend withOUT CAS set, That an existing secret can be saved, even if multiple versions exist.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task BackendWithOUTCAS_SaveSecretWithMultipleVersionsWorks () {
            KV2SecretEngineSettings s = await _noCasMount.GetBackendConfiguration();
            Assert.False (s.CASRequired, "A1: CAS should not be required, but backend is set for CAS.");


            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "/");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Setup the test scenario:
            // 1. Create a new key with version 1.
            // Save Secret passing CAS option of 0 for new update.
            Assert.True (await _noCasMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A2: Save Secret failed.");


            // 2. Read the secret back and get the version
            KV2Secret s2 = await _noCasMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path, "A3: Secret Paths were not equal");
            Assert.Contains (kv1, s2.Attributes, "A4: Secret Attributes did not contain expected value");
            Assert.AreEqual (1, s2.Version, "A5: Version did not match 1.");

            // 3. Now attempt to save the secret back specifying the version.
            KeyValuePair<string, string> kv2 = new KeyValuePair<string, string> ("b", "2");
            secretV2.Attributes.Add (kv2.Key, kv2.Value);


            // 4. Save secret a second time.
            KeyValuePair<string, string> kv3 = new KeyValuePair<string, string> ("c", "3");
            secretV2.Attributes.Add (kv3.Key, kv3.Value);

            Assert.True (await _noCasMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, 1),
                         "A6: Save Secret was expected to be true. ");

            // 5. Now attempt to save the secret again but not with a valid version.
            KeyValuePair<string, string> kv4 = new KeyValuePair<string, string> ("d", "4");
            secretV2.Attributes.Add (kv4.Key, kv4.Value);


            // 6. Save secret a third time.
            Assert.That (() => _noCasMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, 1),
                         Throws.Exception.TypeOf<VaultInvalidDataException>().With.Property ("Message").Contains ("did not match the current version"));
        }


        #endregion



        [Test]
        public async Task SecretReadReturnObjShortcutsWork () {
            KV2SecretEngineSettings s = await _defaultMount.GetBackendConfiguration();
            Assert.False (s.CASRequired, "A1: Backend settings are not what was expected.");


            // Generate a key.
            string secName = _uniqueKey.GetKey ("newSec");
            KV2Secret secretV2 = new KV2Secret (secName, "/");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Save Secret passing CAS option of 0 for new update.
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A2: SaveSecret failed to return True.");

            // Now read the secret back and validate the shortcuts.
            KV2Secret s2 = await _defaultMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path, "A3: Path sent and received are not the same.");
            Assert.Contains (kv1, s2.Attributes, "A4: Secret Attributes are missing expected values");

            // And the shortcuts
            Assert.True (secretV2.Path == s2.Path, "A5: Secret Paths are not the same.");
            Assert.Contains (kv1, s2.Attributes, "A6: Secret did not contain the expected attributes.");

            // Now confirm we can replace the secret object with a new one.
            KV2Secret sv3 = new KV2Secret();
            sv3.Path = "valley";
            KeyValuePair<string, string> kv3 = new KeyValuePair<string, string> ("c", "3");
            sv3.Attributes.Add (kv3.Key, kv3.Value);

            s2 = sv3;

            // Validate secret object was updated:
            Assert.True (sv3.Path == s2.Path, "A7: Secret Paths are not the same.");
            Assert.Contains (kv3, s2.Attributes, "A8: Secrete did not contain the ");
        }



        /// <summary>
        /// Validates WasReadFromVault Property Setting of KV2Secret is set correctly.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task KV2Secret_WasReadFromVault_Works () {
            string secName = _uniqueKey.GetKey ("secWAS");
            KV2Secret secretV2 = new KV2Secret (secName);
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("A1", "aaaa1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);

            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.AlwaysAllow));


            // Read the Secret back to confirm the save.
            KV2Secret s2 = await _defaultMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path);
            Assert.Contains (kv1, s2.Attributes);
            Assert.IsTrue (s2.WasReadFromVault, "A40:  Expected the property WasReadFromVault to be true.");
        }


        /// <summary>
        /// Can save a secret with multiple attributes.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task SaveReadSecret_MultipleAttributes () {
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName);
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("A1", "aaaa1");
            KeyValuePair<string, string> kv2 = new KeyValuePair<string, string> ("B2", "bbbbb2");
            KeyValuePair<string, string> kv3 = new KeyValuePair<string, string> ("C3", "cccccc3");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);
            secretV2.Attributes.Add (kv2.Key, kv2.Value);
            secretV2.Attributes.Add (kv3.Key, kv3.Value);

            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.AlwaysAllow));


            // Read the Secret back to confirm the save.
            KV2Secret s2 = await _defaultMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path);
            Assert.Contains (kv1, s2.Attributes);
            Assert.Contains (kv2, s2.Attributes);
            Assert.Contains (kv3, s2.Attributes);
        }


        /// <summary>
        /// Used to generate a random secret and optionally save it to DB.
        /// </summary>
        /// <param name="saveSecret"></param>
        /// <returns></returns>
        internal async Task<KV2Secret> GenerateASecret(string parentPath = "/", bool saveSecret = true)
        {
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2;

            if (parentPath != "/") secretV2 = new KV2Secret(secName, parentPath);
            else secretV2 = new KV2Secret(secName);

            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("A1", "AAA");
            KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("B2", "bbb");
            KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("C3", "123");
            secretV2.Attributes.Add(kv1.Key, kv1.Value);
            secretV2.Attributes.Add(kv2.Key, kv2.Value);
            secretV2.Attributes.Add(kv3.Key, kv3.Value);

            if (saveSecret) Assert.True(await _defaultMount.SaveSecret(secretV2, KV2EnumSecretSaveOptions.AlwaysAllow), "GenerateASecret:A10:  Failed to save a randomly generated secret.");

            return secretV2;
        }


        /// <summary>
        /// Can List secrets at a given path.
        /// </summary>
        /// <returns></returns>
        [Test]
        [TestCase(1,false,1,Description = "One secret off the root secret")]
        [TestCase(1,true,2, Description = "One root secret off root, but because it has children it will be listed twice")]
        [TestCase(4,false,4, Description = "Two children secrets")]
        [TestCase(4,true,8, Description = "Two children secrets, but because they have children they are listed twice")]
        public async Task ListSecrets (int rootSecretCount, bool ListFolderSecrets, int expectedCount) {
            // Root secret
            KV2Secret secretA = await GenerateASecret();

            List<string> childSecrets = new List<string>(30);

            // Now generate children secrets.  Each with 3 grand children
            for (int i=0; i < rootSecretCount;i++)
            {
                KV2Secret childSecret = await GenerateASecret(secretA.FullPath);
                childSecrets.Add(childSecret.FullPath);
                KV2Secret grandchildSecret = await GenerateASecret(childSecret.FullPath);
                KV2Secret grandchildSecret2 = await GenerateASecret(childSecret.FullPath);
                KV2Secret grandchildSecret3 = await GenerateASecret(childSecret.FullPath);
            }


            // Now get list of secrets at root secret
            List<string> secrets = await (_defaultMount.ListSecretsAtPath (secretA.FullPath,ListFolderSecrets));
            Assert.AreEqual (expectedCount, secrets.Count, "A10:  List secrets did not return the expected number of secret names.");

            // Ensure all children have 3 secrets only
            foreach (string secretPath in childSecrets)
            {
                List<string>  kids = await _defaultMount.ListSecretsAtPath(secretPath);
                Assert.AreEqual(3,kids.Count, "A20:  Kids secret count is incorrect.");
            }
        }



        /// <summary>
        /// List secrets at path with no secrets returns empty list.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task ListSecretsWhereNoSecretsExistReturnsEmptyList () {
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "/");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("A1", "aaaa1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);

            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.AlwaysAllow));

            // Now get list of secrets at root secrt.
            List<string> secrets = await (_defaultMount.ListSecretsAtPath (secName));


            Assert.AreEqual (0, secrets.Count, "Expected secret list to be empty.");
        }


        /// <summary>
        /// Confirms that a secret that exists can be deleted.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task DeleteSecretThatExists_Succeeds () {
            KV2SecretEngineSettings s = await _defaultMount.GetBackendConfiguration();
            Assert.False (s.CASRequired, "A1: Backend settings are not what was expected.");

            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName);
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Save Secret
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.AlwaysAllow), "A2: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s2 = await _defaultMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path, "A3: Secret saved and secret read were not the same.");

            // Now delete it.
            Assert.True (await _defaultMount.DeleteSecretVersion (secretV2), "A4: Deletion of secret failed.");


            // Try to read it to confirm it is gone.
            Thread.Sleep (200);
            KV2Secret s3 = await _defaultMount.ReadSecret (secretV2);
            Assert.IsNull (s3, "A5: Expected ReadSecret to return null object.  Instead it returned an object.  Seems deletion did not work.");
        }



        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task DeleteSecretThatDOESNOTExist_ReturnsNull () {
            KV2SecretEngineSettings s = await _defaultMount.GetBackendConfiguration();
            Assert.False (s.CASRequired, "A1: Backend settings are not what was expected.");

            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "/");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);

            // Try to delete it - It Does not exist so should return null.
            Assert.IsNull (await _defaultMount.ReadSecret (secretV2), "A2: Deletion failed.  Expected Null object to indicate deletion could not find key.");
        }



        /// <summary>
        /// Deletes a specific version of a secret.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task DeleteSecretSpecificVersionThatExists_Succeeds () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.True (s.CASRequired, "A1: Backend settings are not what was expected.");

            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "testapp/folder2/folder3");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Save Secret
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A2: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s2 = await _defaultMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path, "A3: Secret saved and secret read were not the same.");

            // Save a new version
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s2.Version),
                         "A4: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s3 = await _defaultMount.ReadSecret (secretV2);
            Assert.AreEqual (2, s3.Version, "A5: Expected Key version was not received.");


            // And one more time. save another version
            // Save a new version
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s3.Version),
                         "A6: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s4 = await _defaultMount.ReadSecret (secretV2);
            Assert.AreEqual (3, s4.Version, "A7: Expected Key version was not received.");

            // Now delete a specific version.
            Assert.True (await _defaultMount.DeleteSecretVersion (secretV2, s3.Version), "A8: Deletion of secret failed.");

            // Required, sometimes this is to fast for Vault when running on same machine.
            Thread.Sleep (200);

            // Try to read it to confirm it is gone.
            KV2Secret s5 = await _defaultMount.ReadSecret (secretV2, s3.Version);

            Assert.IsNull (s5, "A9: Expected ReadSecret to return null object.  Instead it returned an object.  Seems deletion did not work.");
        }


        /// <summary>
        /// Deletes a specific version of a secret.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task ReadSecretMetaDataWorks () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.True (s.CASRequired, "A1: Backend settings are not what was expected.");

            // Generate a secret key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName);
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Save Secret
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A2: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s2 = await _defaultMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path, "A3: Secret saved and secret read were not the same.");

            // Save a new version
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s2.Version),
                         "A4: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s3 = await _defaultMount.ReadSecret (secretV2);
            Assert.AreEqual (2, s3.Version, "A5: Expected Key version was not received.");


            // And one more time. save another version
            // Save a new version
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s3.Version),
                         "A6: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s4 = await _defaultMount.ReadSecret (secretV2);
            Assert.AreEqual (3, s4.Version, "A7: Expected Key version was not received.");
        }



        /// <summary>
        /// UnDeletes a specific version of a secret.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task UnDeleteSecretSpecificVersion_Succeeds () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.True (s.CASRequired, "A1: Backend settings are not what was expected.");

            // Generate a key.
            string secName = _uniqueKey.GetKey ("DelSecA");
            KV2Secret secretV2 = new KV2Secret (secName, "/");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Save Secret
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A2: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s2 = await _defaultMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path, "A3: Secret saved and secret read were not the same.");

            // Save a new version
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s2.Version),
                         "A4: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s3 = await _defaultMount.ReadSecret (secretV2);
            Assert.AreEqual (2, s3.Version, "A5: Expected Key version was not received.");


            // And one more time. save another version
            // Save a new version
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s3.Version),
                         "A6: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s4 = await _defaultMount.ReadSecret (secretV2);
            Assert.AreEqual (3, s4.Version, "A7: Expected Key version was not received.");

            // Now delete a specific version.
            Assert.True (await _defaultMount.DeleteSecretVersion (secretV2, s3.Version), "A8: Deletion of secret failed.");


            // Try to read it to confirm it is gone.  Sleep 1s - Vault seems to have an issue with sometimes instantoues check backs.
            Thread.Sleep (500);
            KV2Secret s5 = await _defaultMount.ReadSecret (secretV2, s3.Version);

            Assert.IsNull (s5, "A9: Expected ReadSecret to return null object.  Instead it returned an object.  Seems deletion did not work.");

            // Now undelete it.
            Assert.True (await _defaultMount.UndeleteSecretVersion (secretV2, s3.Version), "A10: Undeletion did not work.");

            // Confirm it exists:
            KV2Secret s3B = await _defaultMount.ReadSecret (secretV2);
            Assert.AreEqual (2, s3.Version, "A11: Expected Key version was not received.");
        }



        /// <summary>
        /// Destroys a specific version of a secret.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task DestroySecretSpecificVersion_Succeeds () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.True (s.CASRequired, "A1: Backend settings are not what was expected.");

            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "/");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Save Secret
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A2: SaveSecret failed to return True.");

            // Confirm it exists - we will use the Path version of the method just to exercise both methods:
            KV2Secret s2 = await _defaultMount.ReadSecret<KV2Secret> (secretV2.FullPath);
            Assert.True (secretV2.Path == s2.Path, "A3: Secret saved and secret read were not the same.");

            // Save a new version
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s2.Version),
                         "A4: SaveSecret failed to return True.");

            // Confirm it exists: - This time just pass the SecretObject to test out that version of the method.
            KV2Secret s3 = await _defaultMount.ReadSecret (secretV2);
            Assert.AreEqual (2, s3.Version, "A5: Expected Key version was not received.");


            // And one more time. save another version
            // Save a new version
            Assert.True (await _defaultMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s3.Version),
                         "A6: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s4 = await _defaultMount.ReadSecret (secretV2);
            Assert.AreEqual (3, s4.Version, "A7: Expected Key version was not received.");

            // Destroy it.  Instead of delete.
            Assert.True (await _defaultMount.DestroySecretVersion (secretV2, s3.Version), "A8: Destroy secret failed.");

            // Try to read it to confirm it is gone.
            KV2Secret s5 = await _defaultMount.ReadSecret (secretV2, s3.Version);

            Assert.IsNull (s5, "A9: Expected ReadSecret to return null object.  Instead it returned an object.  Seems deletion did not work.");
        }



        /// <summary>
        /// Completely destroy a secret.
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task CompletelyDestroySecret_Succeeds () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.True (s.CASRequired, "A1: Backend settings are not what was expected.");

            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Save Secret
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A2: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s2 = await _casMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path, "A3: Secret saved and secret read were not the same.");

            // Save a new version
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s2.Version),
                         "A4: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s3 = await _casMount.ReadSecret (secretV2);
            Assert.AreEqual (2, s3.Version, "A5: Expected Key version was not received.");


            // And one more time. save another version
            // Save a new version
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s3.Version),
                         "A6: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s4 = await _casMount.ReadSecret (secretV2);
            Assert.AreEqual (3, s4.Version, "A7: Expected Key version was not received.");


            // Destroy the Metadata
            Assert.True (await _casMount.DestroySecretCompletely (secretV2), "A8: DestroySecretCompletely failed.");

            // Try to read it to confirm it is gone.
            KV2Secret s5 = await _casMount.ReadSecret (secretV2, s3.Version);

            Assert.IsNull (s5, "A9: Expected ReadSecret to return null object.  Instead it returned an object.  Seems deletion did not work.");

            // Try to read version 2
            Assert.IsNull (await _casMount.ReadSecret (secretV2, s3.Version),
                           "A10:  Expected ReadSecret to return null object.  Instead it returned an object.  Deletion did not work");

            // Try to read original version 
            Assert.IsNull (await _casMount.ReadSecret (secretV2, s2.Version),
                           "A10:  Expected ReadSecret to return null object.  Instead it returned an object.  Deletion did not work");
        }



        /// <summary>
        /// Validate we can retrieve Secret MetaData
        /// </summary>
        /// <returns></returns>
        [Test]
        public async Task GetSecretMetaData_Succeeds () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.True (s.CASRequired, "A1: Backend settings are not what was expected.");

            // Generate a key.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "/");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("a", "1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);


            // Save Secret
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A2: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s2 = await _casMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path, "A3: Secret saved and secret read were not the same.");

            // Save a new version
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s2.Version),
                         "A4: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s3 = await _casMount.ReadSecret (secretV2);
            Assert.AreEqual (2, s3.Version, "A5: Expected Key version was not received.");


            // And one more time. save another version
            // Save a new version
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, s3.Version),
                         "A6: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s4 = await _casMount.ReadSecret (secretV2);
            Assert.AreEqual (3, s4.Version, "A7: Expected Key version was not received.");


            // Now get metadata info
            KV2SecretMetaDataInfo k1 = await _casMount.GetSecretMetaData (s3);
            Assert.NotNull (k1, "A8:  Unable to retrieve Secret MetaData");
            Assert.AreEqual (3, k1.Versions.Count, "A9:  Expected 3 versions to be retrieved.");
        }



        [Test]
        public async Task UpdateSecretSettings_Works () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.AreEqual (true, s.CASRequired);
            Assert.AreEqual (6, s.MaxVersions);


            // Create a secret.
            string secName = _uniqueKey.GetKey();
            KV2Secret secretV2 = new KV2Secret (secName, "/");
            KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("A1", "aaaa1");
            secretV2.Attributes.Add (kv1.Key, kv1.Value);

            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "Unable to create secret");

            // Now change the metadata for this secret.  
            Assert.True (await _casMount.UpdateSecretSettings (secName, 9, false));
        }



        [Test]

        // Validate that we can read a secret if it exists or it returns false.
        public async Task TryReadSecret () {
            KV2SecretEngineSettings s = await _casMount.GetBackendConfiguration();
            Assert.True (s.CASRequired, "A1: Backend settings are not what was expected.");

            // Generate a secret key.
            string secName = _uniqueKey.GetKey ("Try");
            KV2Secret secretV2 = new KV2Secret (secName);
            secretV2.Attributes.Add ("a", "1");

            // Save Secret
            Assert.True (await _casMount.SaveSecret (secretV2, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A20: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret s2 = await _casMount.ReadSecret (secretV2);
            Assert.True (secretV2.Path == s2.Path, "A30: Secret saved and secret read were not the same.");


            // Now try the TryVersion.  Should have success.
            (bool success, KV2Secret secReturn) = await _casMount.TryReadSecret<KV2Secret> (secretV2.FullPath);
            Assert.True (success, "A40:  Unable to read the secret back.");
            Assert.IsInstanceOf<KV2Secret> (secReturn);


            // Now try one that does not exist.  It should fail.
            var resultF = await _casMount.TryReadSecret<KV2Secret> (secretV2.FullPath + "jhjhhmvmf");
            Assert.False (resultF.IsSuccess, "A50:  Unable to read the secret back.");
            Assert.IsNull (resultF.Secret);
        }



        // Validate we can read a specific requested version of a secret.
        [Test]
        public async Task SecretReadUsingVersionFromSecretObject_Success () {
            string secretName = _uniqueKey.GetKey ("sec");
            KV2Secret secret = new KV2Secret (secretName);
            secret.Attributes.Add ("attrA", "valueA");
            secret.Attributes.Add ("attrB", "valueB");

            // Save Secret
            Assert.True (await _casMount.SaveSecret (secret, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A10: SaveSecret failed to return True.");

            // Confirm it exists:
            KV2Secret secret2 = await _casMount.ReadSecret (secret);
            Assert.True (secret.Attributes.Count == secret2.Attributes.Count, "A20: Secret saved and secret read were not the same.");

            // Now save some new versions
            KV2Secret secretB = await UpdateSecretRandom (secret2);
            KV2Secret secretC = await UpdateSecretRandom (secretB);
            KV2Secret secretD = await UpdateSecretRandom (secretC);
            KV2Secret secretE = await UpdateSecretRandom (secretD);
            KV2Secret secretF = await UpdateSecretRandom (secretE);

            // Now lets go read SecretE.  
            KV2Secret secretEE = await _casMount.ReadSecret (secretE, -1);
            CollectionAssert.AreEquivalent (secretE.Attributes, secretEE.Attributes,
                                            "A30:  Expected the 2 secrets to contain the exact same attributes.  This is not the case.");
        }



        /// <summary>
        /// Reusable method that updates the provided secret and then returns the updated version.
        /// </summary>
        /// <param name="secret"></param>
        /// <returns></returns>
        private async Task<KV2Secret> UpdateSecretRandom (KV2Secret secret) {
            KV2Secret newSecret = (KV2Secret) secret.Clone();

            newSecret.Attributes.Add (_uniqueKey.GetKey ("attr"), "val");
            Assert.True (await _casMount.SaveSecret (newSecret, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, newSecret.Version),
                         "UpdateSecretRandom:  Failed to save correctly.");
            return await _casMount.ReadSecret (newSecret);
        }



        //TODO - Build Test case that validates the KV2SecretWrapper class returns all the correct information - specifically times on metadata objects.       
    }
}