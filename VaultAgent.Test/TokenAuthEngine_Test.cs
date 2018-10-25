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
		public async Task TokenEngineSetup() {
			// Build Connection to Vault.
			vault = new VaultAgentAPI("TokenEngineVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

			_tokenAuthEngine = (TokenAuthEngine)vault.ConnectAuthenticationBackend(EnumBackendTypes.A_Token, "", "");
		}


		[Test]
		public async Task RetrieveCurrentToken_Success () {
			TokenInfo tokenInfo =  await _tokenAuthEngine.GetCurrentTokenInfo();
			Assert.IsNotNull(tokenInfo);
			Assert.AreEqual("tokenA", tokenInfo.Id);

		}
	}
}
