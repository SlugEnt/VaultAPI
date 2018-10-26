using NUnit.Framework;
using System.Threading.Tasks;
using VaultAgent.Backends.System;
using VaultAgent.Backends;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Models;

namespace VaultAgentTests
{
	[TestFixture]
	[Parallelizable]
	class TokenAuthEngine_Test
    {
		private VaultAgentAPI vault;
		private VaultSystemBackend VSB;
		private UniqueKeys UK = new UniqueKeys();       // Unique Key generator
		private TokenAuthEngine _tokenAuthEngine;



		[OneTimeSetUp]
		public void TokenEngineSetup() {
			// Build Connection to Vault.
			vault = new VaultAgentAPI("TokenEngineVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

			_tokenAuthEngine = (TokenAuthEngine)vault.ConnectAuthenticationBackend(EnumBackendTypes.A_Token, "", "");
		}


		[Test]
		public async Task RetrieveCurrentToken_Success () {
			Token tokenInfo =  await _tokenAuthEngine.GetCurrentTokenInfo();
			Assert.IsNotNull(tokenInfo);
			Assert.AreEqual("tokenA", tokenInfo.Id);
		}


		// Validates a token can be created with a settings object
		[Test]
		public async Task CreateTokenWithSettingsObject () {
			string tokenID = UK.GetKey("token");
			int numUses = 19;
			string tokenName = "Name" + tokenID.ToString();
			bool parent = true;

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
				NumberOfUses = numUses,
				NoParentToken = parent
			};

			Assert.True(await _tokenAuthEngine.CreateToken(tokenNewSettings));

			// Read the token we just created.
			Token token = await _tokenAuthEngine.GetToken(tokenID);
			Assert.IsNotNull(token, "M1: No Token returned.  Was expecting one.");

			// Vault seems to prepend the auth backends name to the display name.
			Assert.AreEqual("token-" + tokenName, token.DisplayName, "M2: Token names are not equal");

			Assert.AreEqual(tokenID, token.Id, "M3: Token ID's are not equal"); 
			Assert.AreEqual(numUses, token.NumberOfUses,"M4: Token number of uses are not equal");
			Assert.AreEqual(parent, token.IsOrphan, "M5: Token parent setting is not the same as IsOrphan");
		}
	}
}
