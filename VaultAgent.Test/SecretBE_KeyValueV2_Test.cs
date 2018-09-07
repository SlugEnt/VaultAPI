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

namespace VaultAgentTests
{
	[Parallelizable]
    public class SecretBE_KeyValueV2_Test
    {
		// The Vault Transit Backend we will be using throughout our testing.

		private KeyValueV2Backend SB;
		private SysBackend VSB;         // For system related calls we will use this Backend.
		private string secretBE_A = "secretV2a";       // Secret Backend database name. 
		private int randomSecretNum = 0;                // Used to ensure we have a random key.
		private object kv2_locker = new object();		// Thread safe lock.


		[OneTimeSetUp]
		public async Task Secret_Init() {
			if (SB != null) {
				return;
			}


			// Create a Transit Backend Mount for this series of tests.
			VSB = new SysBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

			// Create a custom Secret Backend.
			string secretName = secretBE_A;
			string desc = "KeyValue V2 DB: " + secretName + " backend.";
			bool rc = await VSB.SysMountEnable(secretName, desc, EnumBackendTypes.Secret);
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



		[Test,Order(100)]
		public async Task SetKVV2_BackendSettings () {
			
			Assert.True(await SB.SetBackendConfiguration(8, true));
		}

		[Test, Order(200)]
		public async Task GetKVV2_BackEndSettings () {
			KV_V2_Settings s = await SB.GetBackendConfiguration();
			Assert.AreEqual(true, s.CASRequired);
			Assert.AreEqual(8, s.MaxVersions);

		}
	}
}
