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

namespace VaultAgentTests
{
	[Parallelizable]
    public class SecretBE_KeyValueV2_Test
    {
		// The Vault Transit Backend we will be using throughout our testing.

		private KeyValueV2Backend SB;
		private SysBackend VSB;         // For system related calls we will use this Backend.
		private string secretBE_A = "secretV2a";       // Secret Backend database name. 

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
			bool rc = await VSB.SysMountEnable(secretName, desc, EnumBackendTypes.KeyValueV2);
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

		public async Task CanSaveSecretWithCAS_SetToZero () {
			Assert.True(await SB.SetBackendConfiguration(6, true));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.AreEqual(true, s.CASRequired);

			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);

			secretV2.Attributes.Add("Test54", "44");
			Assert.True(await SB.SaveSecret(secretV2));

			// Read the Secret back to confirm the save.
			SecretV2 s2 = await SB.ReadSecret(secretV2.Path);
			Assert.True(s2.Path == secretV2.Path);
	
			Assert.Contains("Test54", s2.Attributes);

		}



		#endregion


		#region "CAS False Testing"

		[Test, Order(200)]
		public async Task Validate_BackendSettings_CAS_NotSet() {
			Assert.True(await SB.SetBackendConfiguration(8, false));
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.AreEqual(false, s.CASRequired);
			Assert.AreEqual(8, s.MaxVersions);
		}


		// Should be able to save a secret without having to set CAS flag.
		[Test, Order(201)]
		public async Task SaveSecret() {

			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);

			secretV2.Attributes.Add("Test54", "44");
			Assert.True(await SB.SaveSecret(secretV2));

			// Read the Secret back to confirm the save.
			SecretV2 s = await SB.ReadSecret(secretV2.Path);
			Assert.True(s.Path == secretV2.Path);
			Assert.Contains("Test54", s.Attributes);
		}


		#endregion



		[Test,Order(301)]
		public async Task ReadSecret () {
			string secName = UK.GetKey();
			SecretV2 secretV2 = new SecretV2(secName);
			secretV2.Attributes.Add("Test", "44");
			secretV2.Attributes.Add("ABC", "large");
			secretV2.Attributes.Add("DEF", "No more trump");
			Assert.True(await SB.SaveSecret(secretV2));


			SecretV2 s = await SB.ReadSecret(secretV2.Path);
			Assert.True(s.Path == secretV2.Path);
		}
	}
}
