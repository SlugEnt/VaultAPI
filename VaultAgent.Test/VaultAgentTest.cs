using NUnit.Framework;
using VaultAgentTests;
using VaultAgent.Backends.KV_V2;
using VaultAgent.Backends.SecretEngines;
using VaultAgent.Models;

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
/*			BETest b = new Test.BETest();
			Assert.AreEqual("test", b.Name);
			Assert.AreEqual("testmount", b.MountPoint);
*/
		}


		[Test]
		public void ValidateVaultInstanceBaseSettings () {
			throw new System.NotImplementedException("Needs to be fully implemented.");
/*
			string name = "testa";
			string IP = "localhost";
			int port = 56000;
			//VaultAgentAPI a = new VaultAgentAPI(name,IP,port);
			Assert.AreEqual(name, a.Name);
			Assert.AreEqual(IP, a.IP);
			Assert.AreEqual(port, a.Port);
*/
		}


		// Confirms we can succesfully create the VaultAgentAPI object.
		[Test]
		public void CanCreateVaultAPIObject () {
			throw new System.NotImplementedException("Needs to be fully implemented.");
/*
			string vault = _uk.GetKey("vault");
			string ip = "10.20.60.2";
			int port = 12000;
			//VaultAgentAPI api = new VaultAgentAPI(vault, ip,port);
			Assert.AreEqual(vault, api.Name);
			Assert.AreEqual(ip, api.IP);
			Assert.AreEqual(port, api.Port);
*/
		}


		[Test]
		public void CreateKV2Backend () {
			string beName = _uk.GetKey("kv2");

			//VaultAgentAPI vaultAgentAPI = new VaultAgentAPI("vault");
//			vaultAgentAPI.AddBackend(new KV2Backend ()
		}



		#region TokenInfoTests
		// Validates that if passed a token value in the constructor that it indeed sets the ID property value to the token value.
		[Test]
		public void TokenInfo_ConstructorSetsID () {
			string id = "abcDEFZ";
			TokenInfo tokenInfo = new TokenInfo(id);
			Assert.AreEqual(tokenInfo.Id, id);
		}


		// Validates that The IsOrphan and HasParent properties are in reality the same property behind the scenes.
		[Test]
		public void TokenInfo_HasParentSameAsIsOrphan () {
			string id = "abcde";
			TokenInfo tokenInfo = new TokenInfo(id);
			Assert.AreEqual(tokenInfo.HasParent, tokenInfo.IsOrphan);
			bool value = !tokenInfo.HasParent;
			Assert.AreNotEqual(value, tokenInfo.HasParent);

			tokenInfo.IsOrphan = value;
			Assert.AreEqual(tokenInfo.HasParent, tokenInfo.IsOrphan);
			Assert.AreEqual(value, tokenInfo.HasParent);

		}
		#endregion

	}


	// Simulates a backend for Abstract backend validation.
/*	internal class BETest : VaultBackend {
//		public BETest() : base("test", "testmount",) { }
	}
	*/
}
