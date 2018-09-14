using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using VaultAgent.Backends.Secret;
using VaultAgent.Backends.System;
using VaultAgent.Backends.SecretEngines;
using VaultAgentTests;
using System.Threading.Tasks;
using VaultAgent.Backends.SecretEngines.KVV2;
using VaultAgent.Backends.KV_V2;
using VaultAgent;

namespace VaultAgentTests
{
	[Parallelizable]
    public class SecretBE_KeyValueV2_Test
    {
		// The Vault Transit Backend we will be using throughout our testing.

		private KeyValueV2Backend SB;
		private SysBackend VSB;         // For system related calls we will use this Backend.
		private string secretBE_A;       // Secret Backend database name. 

		private object kv2_locker = new object();       // Thread safe lock.

		private UniqueKeys UK = new UniqueKeys();		// Unique Key generator

		[OneTimeSetUp]
		public async Task Secret_Init() {
			if (SB != null) {
				return;
			}


			// Create a new system Backend Mount for this series of tests.
			VSB = new SysBackend(VaultServerRef.ipAddress,VaultServerRef.ipPort,VaultServerRef.rootToken);

			// Create a custom Secret Backend.
			
			secretBE_A = UK.GetKey("SV2");
			string secretName = secretBE_A;
			string desc = "KeyValue V2 DB: " + secretName + " backend.";

			VaultSysMountConfig config = new VaultSysMountConfig {
				DefaultLeaseTTL = "30m",
				MaxLeaseTTL = "90m",
				VisibilitySetting ="hidden"
			};


			bool rc = await VSB.SysMountCreate(secretName, desc, EnumBackendTypes.KeyValueV2,config);
			Assert.AreEqual(true, rc);
			AppBackendTestInit();
			return;
		}



		[SetUp]
		// Ensure Backend is initialized during each test.
		protected void AppBackendTestInit() {
			lock (kv2_locker) {
				if (SB == null) {
					SB = new KeyValueV2Backend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, secretBE_A);
				}
			}
		}


		#region "CAS True Testing"

		[Test, Order(100)]
		public async Task Validate_BackendSettings_CAS_Set() {
			Assert.True(await SB.SetBackendConfiguration(6, true));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.AreEqual(true, s.CASRequired);
			Assert.AreEqual(6, s.MaxVersions);
		}


		[Test, Order(101)]
		/// <summary>
		/// Confirms that if the backend is set to require CAS, then a secret without CAS specified will fail.
		/// </summary>
		public async Task BackendWithCAS_FailsSecretSaveWithoutCasOptionSet () {
			// Setup backend to allow 6 versions of a key and requires CAS.
			Assert.True(await SB.SetBackendConfiguration(6, true));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.AreEqual(true, s.CASRequired);

			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);

			secretV2.Attributes.Add("Test54", "44");

			// Save Secret passing no CAS options.
			Assert.That(() => SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.AlwaysAllow),
				Throws.Exception
					.TypeOf<VaultInvalidDataException>()
					.With.Property("Message")
					.Contains("The backend storage engine has the CAS property set."));
		}


		
		[Test, Order(102)]
		/// <summary>

		/// </summary>
		public async Task BackendWithCAS_AllowsSaveOfNewSecretWithCASSet() {
			// Setup backend to allow 6 versions of a key and requires CAS.
			Assert.True(await SB.SetBackendConfiguration(6, true));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.AreEqual(true, s.CASRequired);


			// Generate a key.
			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("a", "1");
			secretV2.Attributes.Add(kv1.Key,kv1.Value);


			// Save Secret passing CAS option of 0 for new update.
			Assert.True(await SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyIfKeyDoesNotExist));


			// Read the Secret back to confirm the save.
			SecretReadReturnObj s2 = await SB.ReadSecret(secretV2.Path);
			Assert.True(secretV2.Path == s2.Data.SecretObj.Path);
			Assert.Contains(kv1, s2.Data.SecretObj.Attributes);
		}



		[Test, Order(103)]
		/// <summary>
		/// Tests that with a backend with CAS set, That an existing secret can be saved only if current version has been specified.
		/// </summary>
		/// <returns></returns>
		public async Task BackendWithCAS_AllowsSaveofSecretWithNewVersion () {
			// Setup backend to allow 6 versions of a key and requires CAS.
			Assert.True(await SB.SetBackendConfiguration(6, true));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.AreEqual(true, s.CASRequired);


			// Generate a key.
			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("a", "1");
			secretV2.Attributes.Add(kv1.Key, kv1.Value);


			// Setup the test scenario:
			// 1. Create a new key with version 1.
			// Save Secret passing CAS option of 0 for new update.
			Assert.True(await SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyIfKeyDoesNotExist));


			// 2. Read the secret back and get the version
			SecretReadReturnObj s2 = await SB.ReadSecret(secretV2.Path);
			Assert.True(secretV2.Path == s2.Data.SecretObj.Path);
			Assert.Contains(kv1, s2.Data.SecretObj.Attributes);
			Assert.AreEqual(1, s2.Data.Metadata.Version);

			// 3. Now attempt to save the secret back specifying the version.
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("b", "2");
			secretV2.Attributes.Add(kv2.Key, kv2.Value);
			Assert.True(await SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyOnExistingVersionMatch, s2.Data.Metadata.Version));
		}


		[Test, Order(104)]
		/// <summary>
		/// Tests that with a backend with CAS set, That an existing secret can be saved only if current version has been specified.
		/// </summary>
		/// <returns></returns>
		public async Task BackendWithCAS_SaveSecretWithInvalidVersionNumFails() {
			// Setup backend to allow 6 versions of a key and requires CAS.
			Assert.True(await SB.SetBackendConfiguration(6, true));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.AreEqual(true, s.CASRequired);


			// Generate a key.
			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("a", "1");
			secretV2.Attributes.Add(kv1.Key, kv1.Value);


			// Setup the test scenario:
			// 1. Create a new key with version 1.
			// Save Secret passing CAS option of 0 for new update.
			Assert.True(await SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyIfKeyDoesNotExist));


			// 2. Read the secret back and get the version
			SecretReadReturnObj s2 = await SB.ReadSecret(secretV2.Path);
			Assert.True(secretV2.Path == s2.Data.SecretObj.Path);
			Assert.Contains(kv1, s2.Data.SecretObj.Attributes);
			Assert.AreEqual(1, s2.Data.Metadata.Version);

			// 3. Now attempt to save the secret back specifying the version.
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("b", "2");
			secretV2.Attributes.Add(kv2.Key, kv2.Value);


			// 4. Save secret a second time.
			KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("c", "3");
			secretV2.Attributes.Add(kv3.Key, kv3.Value);

			Assert.True(await SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyOnExistingVersionMatch, 1),"A10: Save Secret should have failed.");

			// 5. Now attempt to save the secret back specifying the version.
			KeyValuePair<string, string> kv4 = new KeyValuePair<string, string>("d", "4");
			secretV2.Attributes.Add(kv4.Key, kv4.Value);


			// 6. Save secret a third time.
			Assert.That(() => SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyOnExistingVersionMatch,1),
				Throws.Exception
					.TypeOf<VaultInvalidDataException>()
					.With.Property("Message")
					.Contains("did not match the current version"));
			
		}

		#endregion


		#region "CAS False Testing"

		/// <summary>
		/// Confirms that Backend Settings can be set for No CAS.
		/// </summary>
		/// <returns></returns>
		[Test, Order(200)]
		public async Task Validate_BackendSettings_CAS_NotSet() {
			Assert.True(await SB.SetBackendConfiguration(8, false));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.AreEqual(false, s.CASRequired);
			Assert.AreEqual(8, s.MaxVersions);
		}



		// Should be able to save a secret without having to set CAS flag.
		[Test, Order(201)]
		public async Task BackendWithOUTCAS_SaveSecret_Success() {

			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);

			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string> ("test54", "44" );

			secretV2.Attributes.Add(kv1.Key,kv1.Value);
			Assert.True(await SB.SaveSecret(secretV2,EnumKVv2SaveSecretOptions.AlwaysAllow));


			// Read the Secret back to confirm the save.
			SecretReadReturnObj s2 = await SB.ReadSecret(secretV2.Path);
			Assert.True(secretV2.Path == s2.Data.SecretObj.Path);
			Assert.Contains(kv1, s2.Data.SecretObj.Attributes);
		}



		// Should be able to save(update) an existing secret without having to set CAS flag.
		[Test, Order(202)]
		public async Task BackendWithOUTCAS_UpdateExistingSecret_Success() {

			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);

			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test54", "44");

			secretV2.Attributes.Add(kv1.Key, kv1.Value);
			Assert.True(await SB.SaveSecret(secretV2,EnumKVv2SaveSecretOptions.AlwaysAllow));


			// Read the Secret back to confirm the save.
			SecretReadReturnObj s2 = await SB.ReadSecret(secretV2.Path);
			Assert.True(secretV2.Path == s2.Data.SecretObj.Path);
			Assert.Contains(kv1, s2.Data.SecretObj.Attributes);

			// Now update it.
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("b", "2");
			secretV2.Attributes.Add(kv2.Key, kv2.Value);
			Assert.True(await SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.AlwaysAllow));

		}




		[Test, Order(204)]
		/// <summary>
		/// Tests that with a backend withOUT CAS set, That an existing secret can be saved, even if multiple versions exist.
		/// </summary>
		/// <returns></returns>
		public async Task BackendWithOUTCAS_SaveSecretWithMultipleVersionsWorks() {
			// Setup backend to allow 6 versions of a key and requires CAS.
			Assert.True(await SB.SetBackendConfiguration(6, false));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.False(s.CASRequired, "A1: CAS should not be required, but backend is set for CAS.");


			// Generate a key.
			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("a", "1");
			secretV2.Attributes.Add(kv1.Key, kv1.Value);


			// Setup the test scenario:
			// 1. Create a new key with version 1.
			// Save Secret passing CAS option of 0 for new update.
			Assert.True(await SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyIfKeyDoesNotExist),"A2: Save Secret failed.");


			// 2. Read the secret back and get the version
			SecretReadReturnObj s2 = await SB.ReadSecret(secretV2.Path);
			Assert.True(secretV2.Path == s2.Data.SecretObj.Path,"A3: Secret Paths were not equal");
			Assert.Contains(kv1, s2.Data.SecretObj.Attributes,"A4: Secret Attributes did not contain expected value");
			Assert.AreEqual(1, s2.Data.Metadata.Version,"A5: Version did not match 1.");

			// 3. Now attempt to save the secret back specifying the version.
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("b", "2");
			secretV2.Attributes.Add(kv2.Key, kv2.Value);


			// 4. Save secret a second time.
			KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("c", "3");
			secretV2.Attributes.Add(kv3.Key, kv3.Value);

			Assert.True(await SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyOnExistingVersionMatch, 1), "A6: Save Secret was expected to be true. ");

			// 5. Now attempt to save the secret again but not with a valid version.
			KeyValuePair<string, string> kv4 = new KeyValuePair<string, string>("d", "4");
			secretV2.Attributes.Add(kv4.Key, kv4.Value);


			// 6. Save secret a third time.
			Assert.That(() => SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyOnExistingVersionMatch, 1),
				Throws.Exception
					.TypeOf<VaultInvalidDataException>()
					.With.Property("Message")
					.Contains("did not match the current version"));

		}

		#endregion



		[Test, Order(301)]
		public async Task SecretReadReturnObjShortcutsWork() {
			// Setup backend to allow 6 versions of a key and not require CAS.
			Assert.True(await SB.SetBackendConfiguration(6, false));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.False(s.CASRequired, "A1: Backend settings are not what was expected.");


			// Generate a key.
			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("a", "1");
			secretV2.Attributes.Add(kv1.Key, kv1.Value);


			// Save Secret passing CAS option of 0 for new update.
			Assert.True(await SB.SaveSecret(secretV2, EnumKVv2SaveSecretOptions.OnlyIfKeyDoesNotExist),"A2: SaveSecret failed to return True.");

			// Now read the secret back and validate the shortcuts.
			SecretReadReturnObj s2 = await SB.ReadSecret(secretV2.Path);
			Assert.True(secretV2.Path == s2.Data.SecretObj.Path,"A3: Path sent and received are not the same.");
			Assert.Contains(kv1, s2.Data.SecretObj.Attributes,"A4: Secret Attributes are missing expected values");

			// And the shortcuts
			Assert.True(secretV2.Path == s2.Secret.Path,"A5: Secret Paths are not the same.");
			Assert.Contains(kv1, s2.SecretAttributes,"A6: Secret did not contain the expected attributes.");

			// Now confirm we can replace the secret object with a new one.
			SecretV2 sv3 = new SecretV2();
			sv3.Path = "valley";
			KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("c", "3");
			sv3.Attributes.Add(kv3.Key, kv3.Value);

			s2.Secret = sv3;

			// Validate secret object was updated:
			Assert.True(sv3.Path == s2.Secret.Path,"A7: Secret Paths are not the same.");
			Assert.Contains(kv3, s2.SecretAttributes, "A8: Secrete did not contain the ");
		}



		/// <summary>
		/// Can save a secret with multiple attributes.
		/// </summary>
		/// <returns></returns>
		[Test,Order(302)]
		public async Task SaveReadSecret_MultipleAttributes () {
			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("A1", "aaaa1");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("B2", "bbbbb2");
			KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("C3", "cccccc3");
			secretV2.Attributes.Add(kv1.Key,kv1.Value);
			secretV2.Attributes.Add(kv2.Key,kv2.Value);
			secretV2.Attributes.Add(kv3.Key,kv3.Value);

			Assert.True(await SB.SaveSecret(secretV2,EnumKVv2SaveSecretOptions.AlwaysAllow));


			// Read the Secret back to confirm the save.
			SecretReadReturnObj s2 = await SB.ReadSecret(secretV2.Path);
			Assert.True(secretV2.Path == s2.Data.SecretObj.Path);
			Assert.Contains(kv1, s2.Data.SecretObj.Attributes);
			Assert.Contains(kv2, s2.Data.SecretObj.Attributes);
			Assert.Contains(kv3, s2.Data.SecretObj.Attributes);
		}
	}
}
