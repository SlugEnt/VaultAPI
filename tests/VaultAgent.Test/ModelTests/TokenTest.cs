using System;
using NUnit.Framework;
using System.Threading.Tasks;
using VaultAgent.Backends.System;
using VaultAgent.Backends;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Models;

namespace VaultAgentTests
{
	// Validates the token object - Note, this only performs local Token actions, this does not test the ability of the Vault API commands to read a token from Vault
    // and make sure the proper fields are filled out.  That testing will be in the TokenAuthEngine_Test class.
	[Parallelizable]
	[TestFixture]
    public class TokenTest
    {
		[Test]
		public void EmptyConstructorSetsReadFromVault_ToFalse () {
			Token a = new Token();
			Assert.IsFalse(a.ReadFromVault);
		}

		/// <summary>
		/// 
		/// </summary>

		[Test]
		public void TokenIDConstructorSetsReadFromVault_ToFalse() {
			Token a = new Token("56665tg");
			Assert.IsFalse(a.ReadFromVault);
		}



		// Validates the JSON Constructor sets expected fields.
		[Test]
		public void TokenJSONConstructorSetsReadFromVault_ToTrue () {
			string t_id = "5kgvkg";
			string t_accessor = "8695ff";
			long createTime = 9999;
			long createTTL = 555;
			System.DateTimeOffset sdto = new System.DateTimeOffset(2018, 11, 01, 16, 45, 19, 888, new System.TimeSpan(-5,0,0));
			Token b = new Token(t_id, t_accessor,createTime,createTTL,"aaa",sdto);

			Assert.IsTrue(b.ReadFromVault, "Expected ReadFromVault property to be true for the JSON Constructor");
			Assert.AreEqual(t_id, b.ID, "Token ID's are not the same");
			Assert.AreEqual(t_accessor, b.AccessorTokenID, "Accesor Token values are not the same.");
			Assert.AreEqual("aaa", b.EntityId);
			Assert.AreEqual(createTTL, b.CreationTTL,"Creation TTL's are not the same.");
			Assert.AreEqual(createTime, b.CreationTime, "Creation Time's are not equal.");
			Assert.AreEqual(sdto, b.IssueTime, "Creation times's are not the same.");
		}



		// Validates that Creation Time in Seconds results in correct DateTime.
		[Test]
		public void TokenCreationConvertsToDateTime_Correctly () {
			int seconds = 59;

			string t_id = "5kgvkg";
			string t_accessor = "8695ff";
			long createTTL = 555;


			System.DateTime dateAD = new System.DateTime(1970,1,1,0,0,59);

			System.DateTimeOffset sdto = new System.DateTimeOffset(2018, 11, 01, 16, 45, 19, 888, new System.TimeSpan(-5,0,0));
			Token b = new Token(t_id,t_accessor, seconds, createTTL, "aaa", sdto);

			Assert.AreEqual(dateAD, b.CreationTime_AsDateTime,"Creation Times are not the same");
		}



	}
}
