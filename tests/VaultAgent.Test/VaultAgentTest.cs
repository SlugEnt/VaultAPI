using NUnit.Framework;
using VaultAgentTests;
using VaultAgent.SecretEngines;
using VaultAgent.Models;
using VaultAgent;
using System.Threading.Tasks;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Backends;
using SlugEnt;
using VaultAgent.SecretEngines.KV2;


namespace VaultAgentTests
{
	[TestFixture]
	[Parallelizable]
	class VaultAgentTest {
		private VaultAgentAPI vault;
		private UniqueKeys _uk;
		private string name;

		/// <summary>
		/// One Time Setup - Run once per a single Test run exection.
		/// </summary>
		/// <returns></returns>
		[OneTimeSetUp]
		public async Task VaultAgentTest_OneTimeSetup() {
			_uk = new UniqueKeys();
			name = _uk.GetKey("vlt");
			vault = await VaultServerRef.ConnectVault(name);
            //new VaultAgentAPI(name, VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

        }


		/// <summary>
		/// Setup that is run prior to each test case.
		/// </summary>
		[SetUp]
		public void SetupForEachTestCase() { }


		[Test]
		public void ValidateVaultInstanceBaseSettings () {
			VaultAgentAPI a = new VaultAgentAPI(name,VaultServerRef.vaultURI);
			Assert.AreEqual(name, vault.Name);
			Assert.AreEqual(VaultServerRef.vaultURI, vault.Uri);			
		}



        // Validate that the token ID and Token properties are set when a valid token is passed.
	    [Test]
	    public async Task TokenPropertiesSet_WhenPassedValidToken() {
            VaultAgentAPI v1 = await VaultServerRef.ConnectVault(name);
            //new VaultAgentAPI(name, VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

            // Vault instance was created in one time setup.
            Assert.AreEqual(VaultServerRef.rootToken, v1.Token.ID);
            Assert.IsNotEmpty(v1.Token.APIPath);
            Assert.Greater(v1.Token.CreationTime,1);
	    }



        // Validates that if we change the Vault token that the HTTP Connector header is changed.
	    [Test]
	    public async Task ChangingToken_ChangesHTTPHeaders() {

            // Get current token:
	        Token currentToken = await vault.RefreshActiveToken();

            // We will need to create a new token.
	        TokenAuthEngine _tokenAuthEngine = (TokenAuthEngine)vault.ConnectAuthenticationBackend(EnumBackendTypes.A_Token);
            TokenNewSettings tokenNewSettings = new TokenNewSettings();
	        tokenNewSettings.Name = "NewToken";
	        tokenNewSettings.MaxTTL = "60s";
	        tokenNewSettings.NumberOfUses = 14;

	        Token newToken = await _tokenAuthEngine.CreateToken (tokenNewSettings);
            Assert.NotNull(newToken, "A1:  Created a token, expected it to not be null.");
            Assert.AreNotEqual(currentToken.ID,newToken.ID);

            // Now set token.
	        vault.Token = newToken;

            // Now retrieve the current token.  This will force it to go back to the Vault instance with the new token.  should be the same as newToken.  
	        Token newCurrentToken = await vault.RefreshActiveToken();
            Assert.AreEqual(newToken.ID,newCurrentToken.ID);
            Assert.AreNotEqual(currentToken.ID,newCurrentToken.ID);

	    }

		#region TokenInfoTests
		// Validates that if passed a token value in the constructor that it indeed sets the ID property value to the token value.
		[Test]
		public void TokenInfo_ConstructorSetsID () {
			string id = "abcDEFZ";
			Token tokenInfo = new Token(id);
			Assert.AreEqual(tokenInfo.ID, id);
		}


		// Validates that The IsOrphan and HasParent properties are in reality the same property behind the scenes.
		[Test]
		public void TokenInfo_HasParentSameAsIsOrphan () {
			string id = "abcde";
			Token tokenInfo = new Token(id);
			Assert.AreNotEqual(tokenInfo.HasParent, tokenInfo.IsOrphan,"M1: IsOrphan and HasParent cannot both be the same value.");

			// Now change one, the other value should also change.
			bool oldHasParent = tokenInfo.HasParent;
			tokenInfo.IsOrphan = !tokenInfo.IsOrphan;
			Assert.AreNotEqual(oldHasParent, tokenInfo.HasParent,"M2: HasParent property should have changed values when the IsOrphan property was changed.");
			Assert.AreNotEqual(tokenInfo.HasParent, tokenInfo.IsOrphan, "M3: IsOrphan and HasParent cannot both be the same value.");
		}
        #endregion


        #region "Pathing Tests"

        // Validates that we combine paths correctly.
        [Test]
        [TestCase("/root/", "/root/")]
        [TestCase("/root", "/root")]
        [TestCase("root", "root")]
        [TestCase("/root/1/2/3", "/root", "1", "2", "3")]
        [TestCase("/root/1/2/3/", "/root", "1", "2", "3/")]
		[TestCase("/root/part2","/root","part2", "","")]

        public void PathCombine(string expected, params string[] paths)
        {
            string result = VaultAgentAPI.PathCombine(paths);
            Assert.AreEqual(expected, result);
        }

        #endregion
    }


    // Simulates a backend for Abstract backend validation.
    /*	internal class BETest : VaultBackend {
    //		public BETest() : base("test", "testmount",) { }
        }
        */
}
