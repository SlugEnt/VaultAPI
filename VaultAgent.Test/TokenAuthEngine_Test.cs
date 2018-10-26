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
		public async Task RetrieveCurrentToken_Success() {
			Token tokenInfo = await _tokenAuthEngine.GetCurrentTokenInfo();
			Assert.IsNotNull(tokenInfo);
			Assert.AreEqual("tokenA", tokenInfo.ID);
		}



		// Validates that trying to retrieve a token that does not exist ...
		[Test]
		public async Task RetrieveInvalidTokenFails() {
			string tokenID = UK.GetKey("tokH");

			Token token = await _tokenAuthEngine.GetToken(tokenID);
			Assert.IsNull(token, "M1: Tried to find an unknown token returned a token object.  This is incorrect.");
		}



		// Validates a token can be created with a settings object
		[Test]
		public async Task CreateTokenWithSettingsObject() {
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

			Assert.AreEqual(tokenID, token.ID, "M3: Token ID's are not equal");
			Assert.AreEqual(numUses, token.NumberOfUses, "M4: Token number of uses are not equal");
			Assert.AreEqual(parent, token.IsOrphan, "M5: Token parent setting is not the same as IsOrphan");
		}




		// Validates a token can be created with a settings object
		[Test]
		public async Task AccessTokenViaAccessor_Success() {
			string tokenID = UK.GetKey("tokenAcc");
			int numUses = 19;
			string tokenName = "N" + tokenID.ToString();
			bool parent = true;

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
				NumberOfUses = numUses,
				NoParentToken = parent
			};

			Assert.True(await _tokenAuthEngine.CreateToken(tokenNewSettings), "M1: Error creating the token");

			// Read the token we just created.
			Token token = await _tokenAuthEngine.GetToken(tokenID);
			Assert.IsNotNull(token, "M2: No Token returned.  Was expecting one.");
			string tDisplayName = "token-" + tokenName;
			Assert.AreEqual(tDisplayName, token.DisplayName,"M3: Token Display name is not what was expected.  Expected {0}, but got {1}",tDisplayName,token.DisplayName);

			// Now try and retrieve via the accessor.
			Token tokenAcc = await _tokenAuthEngine.GetTokenViaAccessor(token.AccessorTokenID);
			Assert.NotNull(tokenAcc, "M4: Token accessor did not find the token.");
			Assert.AreEqual(token.DisplayName, tokenAcc.DisplayName, "M5: Token Accessor did not retrieve the correct token.  Something bad happened.");

		}




		// Confirms specifying an invalid token accessor returns a null token.
		[Test]
		public async Task AccessTokenViaInvalidAccessor_Fails() {
			string tokenID = UK.GetKey("tokenAcc");
			int numUses = 19;
			string tokenName = "N" + tokenID.ToString();
			bool parent = true;

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
				NumberOfUses = numUses,
				NoParentToken = parent
			};

			Assert.True(await _tokenAuthEngine.CreateToken(tokenNewSettings), "M1: Error creating the token");

			// Read the token we just created.
			Token token = await _tokenAuthEngine.GetToken(tokenID);
			Assert.IsNotNull(token, "M2: No Token returned.  Was expecting one.");
			string tDisplayName = "token-" + tokenName;
			Assert.AreEqual(tDisplayName, token.DisplayName, "M3: Token Display name is not what was expected.  Expected {0}, but got {1}", tDisplayName, token.DisplayName);

			// Now try and retrieve via the accessor.
			Token tokenAcc = await _tokenAuthEngine.GetTokenViaAccessor("z");
			Assert.IsNull(tokenAcc, "M3: Expected to receive a null token, but instead received a token");

		}
	}
}
