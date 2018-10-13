using NUnit.Framework;
using VaultAgentTests;
using VaultAgent.Backends.KV_V2;
using VaultAgent.Backends.SecretEngines;

namespace VaultAgent.Test
{
	[Parallelizable]
	class VaultAgentTest {

		private UniqueKeys _uk;

		/// <summary>
		/// One Time Setup - Run once per a single Test run exection.
		/// </summary>
		/// <returns></returns>
		[OneTimeSetUp]
		public void VaultAgentTest_OneTimeSetup() {
			_uk = new UniqueKeys();
		}


		/// <summary>
		/// Setup that is run prior to each test case.
		/// </summary>
		[SetUp]
		public void SetupForEachTestCase() { }


		[Test]
		public void ValidateNameAndMountPointNameonBackends() {
			BETest b = new Test.BETest();
			Assert.AreEqual("test", b.Name);
			Assert.AreEqual("testmount", b.MountPoint);
		}


		[Test]
		public void ValidateVaultInstanceBaseSettings () {
			string name = "testa";
			string IP = "localhost";
			int port = 56000;
			VaultAgentAPI a = new VaultAgentAPI(name,IP,port);
			Assert.AreEqual(name, a.Name);
			Assert.AreEqual(IP, a.IP);
			Assert.AreEqual(port, a.Port);
		}


		// Confirms we can succesfully create the VaultAgentAPI object.
		[Test]
		public void CanCreateVaultAPIObject () {
			string vault = _uk.GetKey("vault");
			string ip = "10.20.60.2";
			int port = 12000;
			VaultAgentAPI api = new VaultAgentAPI(vault, ip,port);
			Assert.AreEqual(vault, api.Name);
			Assert.AreEqual(ip, api.IP);
			Assert.AreEqual(port, api.Port);

		}


		[Test]
		public void CreateKV2Backend () {
			string beName = _uk.GetKey("kv2");

			//VaultAgentAPI vaultAgentAPI = new VaultAgentAPI("vault");
//			vaultAgentAPI.AddBackend(new KV2Backend ()
		}



	}


	// Simulates a backend for Abstract backend validation.
	internal class BETest : VaultBackend {
		public BETest() : base("test", "testmount") { }
	}
}
