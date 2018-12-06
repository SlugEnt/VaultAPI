using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using VaultAgent.Backends.System;
using System.Threading.Tasks;
using VaultAgent;

namespace VaultAgentTests
{
    [TestFixture]
	[Parallelizable]
	class SystemBackendMountTests
    {
        private VaultAgentAPI _vaultAgentAPI;

        private VaultSystemBackend _vaultSystemBackend;
		private UniqueKeys _uniqueKeys = new UniqueKeys();       // Unique Key generator


		[OneTimeSetUp]
		public async Task Backend_Init() {
			if (_vaultSystemBackend != null) {
				return;
			}

		    // Build Connection to Vault.
		    _vaultAgentAPI = new VaultAgentAPI("transitVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);

            // Create a new system Backend Mount for this series of tests.
		    _vaultSystemBackend = _vaultAgentAPI.System;
		}



        // Validate that the Mount point config options we passed in were indeed saved and set to the Vault Mount.
		[Test]
		public async Task ValidateConfigOptions () {
			int maxTTL = 1800;			// 30min
			int defaultTTL = 600;       // 10min
			string vis = "hidden";		// should not show up in ui lists.

			string key = _uniqueKeys.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";

			VaultSysMountConfig config = new VaultSysMountConfig {
				DefaultLeaseTTL = defaultTTL.ToString(),
				MaxLeaseTTL = maxTTL.ToString(),
				VisibilitySetting = vis
			};


			Assert.True(await _vaultSystemBackend.SysMountCreate(key, desc, EnumSecretBackendTypes.KeyValueV2, config),"Unable to create Mount with key name: {0}",key);

			// Now read back the mount config data.
			VaultSysMountConfig config2 = await _vaultSystemBackend.SysMountReadConfig(key);
			Assert.AreEqual(config.DefaultLeaseTTL, config2.DefaultLeaseTTL,"Default Lease TTL's are not the same.");
			Assert.AreEqual(config.MaxLeaseTTL, config2.MaxLeaseTTL,"Max Lease TTL's are not the same.");
			Assert.AreEqual(config.VisibilitySetting, config2.VisibilitySetting, "Visibility Settings are not the same.");
		}



        // Validate we can change Mount Configuration options after initial creation.
		[Test]
		public async Task ChangeMountConfigOptions() {
			int maxTTL = 1800;          // 30min
			int defaultTTL = 600;       // 10min
			string vis = "hidden";      // should not show up in ui lists.

			string key = _uniqueKeys.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";

			VaultSysMountConfig config = new VaultSysMountConfig {
				DefaultLeaseTTL = defaultTTL.ToString(),
				MaxLeaseTTL = maxTTL.ToString(),
				VisibilitySetting = vis
			};


			Assert.True(await _vaultSystemBackend.SysMountCreate(key, desc, EnumSecretBackendTypes.KeyValueV2, config), "Unable to create Mount with key name: {0}", key);

			// Now read back the mount config data.
			VaultSysMountConfig config2 = await _vaultSystemBackend.SysMountReadConfig(key);
			Assert.AreEqual(config.DefaultLeaseTTL, config2.DefaultLeaseTTL, "Default Lease TTL's are not the same.");
			Assert.AreEqual(config.MaxLeaseTTL, config2.MaxLeaseTTL, "Max Lease TTL's are not the same.");
			Assert.AreEqual(config.VisibilitySetting, config2.VisibilitySetting, "Visibility Settings are not the same.");


			// Now change the config.
			VaultSysMountConfig config3 = new VaultSysMountConfig {
				DefaultLeaseTTL = "56",
				MaxLeaseTTL = "106",
				VisibilitySetting = "unauth"
			};

			Assert.True(await _vaultSystemBackend.SysMountUpdateConfig(key, config3, "changed"), "Unable to successfully change the config of {0} with config3 settings",key);

			// Now retrieve and compare.
			// Now read back the mount config data.
			VaultSysMountConfig config4 = await _vaultSystemBackend.SysMountReadConfig(key);
			Assert.AreEqual(config3.DefaultLeaseTTL, config4.DefaultLeaseTTL, "Default Lease TTL's are not the same.");
			Assert.AreEqual(config3.MaxLeaseTTL, config4.MaxLeaseTTL, "Max Lease TTL's are not the same.");
			Assert.AreEqual(config3.VisibilitySetting, config4.VisibilitySetting, "Visibility Settings are not the same.");

		}



        // Validates that the appropriate error codes are set when trying to create a mount point that already exists.
        [Test]
        public async Task CreateMountBackend_Fails_IfAlreadyExists()
        {
            string mountName = _uniqueKeys.GetKey ("DupMnt");
            Assert.True(await _vaultSystemBackend.SysMountCreate(mountName, "test", EnumSecretBackendTypes.KeyValueV2), "Unable to create Mount with key name: {0}", mountName);
            VaultInvalidDataException e = Assert.ThrowsAsync<VaultInvalidDataException>(async () => await _vaultSystemBackend.SysMountCreate(mountName, "test", EnumSecretBackendTypes.KeyValueV2), "Unable to create Mount with key name: {0}", mountName);
                
            Assert.AreEqual(EnumVaultExceptionCodes.BackendMountAlreadyExists, e.SpecificErrorCode, "A2: Expected the exception Specific Code to be BackendMountAlreadyExists, but it was set to: " + e.SpecificErrorCode);

        }


        // Validate we can actualy delete a mount point backend.
        [Test]
		public async Task DeleteMount () {
			string key = _uniqueKeys.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";

			VaultSysMountConfig config1 = new VaultSysMountConfig { DefaultLeaseTTL = "6556"	};
			Assert.True(await _vaultSystemBackend.SysMountCreate(key, desc, EnumSecretBackendTypes.KeyValueV2,config1));

			// Ensure it was created.
			VaultSysMountConfig config2 = await _vaultSystemBackend.SysMountReadConfig(key);
			Assert.AreEqual(config1.DefaultLeaseTTL, config2.DefaultLeaseTTL, "Default Lease TTL's are not the same.");

			// Delete it.
			Assert.True(await _vaultSystemBackend.SysMountDelete(key), "Deletion of mount did not complete Successfully.");

			// Make sure it is gone.
		}



		/// <summary>
		/// If an invalid mount name is specified to the config options it should throw a VaultInvalidDataException
		/// </summary>
		[Test]
		public void ReadInvalidMountName_ThrowsError () {
			string key = _uniqueKeys.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";

			// This mount should not exist as it was never created.

			//Assert.ThrowsAsync<VaultAgent.VaultInvalidDataException>(VaultSysMountConfig config = await _vaultSystemBackend.SysMountReadConfig(key);
			Assert.That(() => _vaultSystemBackend.SysMountReadConfig(key),
				Throws.Exception
				.TypeOf<VaultInvalidDataException>()
				//.With.Property("ParamName")
				//.EqualTo("hello world")
				);
		}


		/// <summary>
		/// If an invalid mount name is specified to be deleted it should throw a VaultInvalidDataException
		/// </summary>
		[Test]
		public void ChangeConfigInvalidMountName_ThrowsError() {
			string key = _uniqueKeys.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";


			// This mount should not exist as it was never created.
			// Now change the config.
			VaultSysMountConfig config = new VaultSysMountConfig {
				DefaultLeaseTTL = "56",
				MaxLeaseTTL = "106",
				VisibilitySetting = "unauth"
			};

			//Assert.True(await _vaultSystemBackend.SysMountUpdateConfig(key, config, "changed"), "Unable to successfully change the config of {0} with config3 settings", key);

			Assert.That(() => _vaultSystemBackend.SysMountUpdateConfig(key,config,"changed"),
				Throws.Exception
				.TypeOf<VaultInvalidDataException>()
				);
		}
	}
}
