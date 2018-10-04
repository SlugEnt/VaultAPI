using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using VaultAgent.Backends.System;
using System.Threading.Tasks;
using VaultAgent;

namespace VaultAgentTests
{
	[Parallelizable]
	class SystemBackendMountTests
    {
		private SysBackend VSB;
		private UniqueKeys UK = new UniqueKeys();       // Unique Key generator


		[OneTimeSetUp]
		public async Task Backend_Init() {
			if (VSB != null) {
				return;
			}


			// Create a new system Backend Mount for this series of tests.
			VSB = new SysBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);
		}


		[Test]
		public async Task ValidateConfigOptions () {
			int maxTTL = 1800;			// 30min
			int defaultTTL = 600;       // 10min
			string vis = "hidden";		// should not show up in ui lists.

			string key = UK.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";

			VaultSysMountConfig config = new VaultSysMountConfig {
				DefaultLeaseTTL = defaultTTL.ToString(),
				MaxLeaseTTL = maxTTL.ToString(),
				VisibilitySetting = vis
			};


			Assert.True(await VSB.SysMountCreate(key, desc, EnumBackendTypes.KeyValueV2, config),"Unable to create Mount with key name: {0}",key);

			// Now read back the mount config data.
			VaultSysMountConfig config2 = await VSB.SysMountReadConfig(key);
			Assert.AreEqual(config.DefaultLeaseTTL, config2.DefaultLeaseTTL,"Default Lease TTL's are not the same.");
			Assert.AreEqual(config.MaxLeaseTTL, config2.MaxLeaseTTL,"Max Lease TTL's are not the same.");
			Assert.AreEqual(config.VisibilitySetting, config2.VisibilitySetting, "Visibility Settings are not the same.");
		}



		[Test]
		public async Task ChangeMountConfigOptions() {
			int maxTTL = 1800;          // 30min
			int defaultTTL = 600;       // 10min
			string vis = "hidden";      // should not show up in ui lists.

			string key = UK.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";

			VaultSysMountConfig config = new VaultSysMountConfig {
				DefaultLeaseTTL = defaultTTL.ToString(),
				MaxLeaseTTL = maxTTL.ToString(),
				VisibilitySetting = vis
			};


			Assert.True(await VSB.SysMountCreate(key, desc, EnumBackendTypes.KeyValueV2, config), "Unable to create Mount with key name: {0}", key);

			// Now read back the mount config data.
			VaultSysMountConfig config2 = await VSB.SysMountReadConfig(key);
			Assert.AreEqual(config.DefaultLeaseTTL, config2.DefaultLeaseTTL, "Default Lease TTL's are not the same.");
			Assert.AreEqual(config.MaxLeaseTTL, config2.MaxLeaseTTL, "Max Lease TTL's are not the same.");
			Assert.AreEqual(config.VisibilitySetting, config2.VisibilitySetting, "Visibility Settings are not the same.");


			// Now change the config.
			VaultSysMountConfig config3 = new VaultSysMountConfig {
				DefaultLeaseTTL = "56",
				MaxLeaseTTL = "106",
				VisibilitySetting = "unauth"
			};

			Assert.True(await VSB.SysMountUpdateConfig(key, config3, "changed"), "Unable to successfully change the config of {0} with config3 settings",key);

			// Now retrieve and compare.
			// Now read back the mount config data.
			VaultSysMountConfig config4 = await VSB.SysMountReadConfig(key);
			Assert.AreEqual(config3.DefaultLeaseTTL, config4.DefaultLeaseTTL, "Default Lease TTL's are not the same.");
			Assert.AreEqual(config3.MaxLeaseTTL, config4.MaxLeaseTTL, "Max Lease TTL's are not the same.");
			Assert.AreEqual(config3.VisibilitySetting, config4.VisibilitySetting, "Visibility Settings are not the same.");

		}


		[Test]
		public async Task DeleteMount () {
			string key = UK.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";

			VaultSysMountConfig config1 = new VaultSysMountConfig { DefaultLeaseTTL = "6556"	};
			Assert.True(await VSB.SysMountCreate(key, desc, EnumBackendTypes.KeyValueV2,config1));

			// Ensure it was created.
			VaultSysMountConfig config2 = await VSB.SysMountReadConfig(key);
			Assert.AreEqual(config1.DefaultLeaseTTL, config2.DefaultLeaseTTL, "Default Lease TTL's are not the same.");

			// Delete it.
			Assert.True(await VSB.SysMountDelete(key), "Deletion of mount did not complete Successfully.");

			// Make sure it is gone.
		}



		/// <summary>
		/// If an invalid mount name is specified to the config options it should throw a VaultInvalidDataException
		/// </summary>
		[Test]
		public void ReadInvalidMountName_ThrowsError () {
			string key = UK.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";

			// This mount should not exist as it was never created.

			//Assert.ThrowsAsync<VaultAgent.VaultInvalidDataException>(VaultSysMountConfig config = await VSB.SysMountReadConfig(key);
			Assert.That(() => VSB.SysMountReadConfig(key),
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
			string key = UK.GetKey("SYSM");
			string desc = "Test Mount DB: " + key + "KeyValue V2";


			// This mount should not exist as it was never created.
			// Now change the config.
			VaultSysMountConfig config = new VaultSysMountConfig {
				DefaultLeaseTTL = "56",
				MaxLeaseTTL = "106",
				VisibilitySetting = "unauth"
			};

			//Assert.True(await VSB.SysMountUpdateConfig(key, config, "changed"), "Unable to successfully change the config of {0} with config3 settings", key);

			Assert.That(() => VSB.SysMountUpdateConfig(key,config,"changed"),
				Throws.Exception
				.TypeOf<VaultInvalidDataException>()
				);
		}
	}
}
