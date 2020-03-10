using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using SlugEnt;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.AuthenticationEngines.LoginConnectors;
using VaultAgent.Backends;
using VaultAgent.Models;
using VaultAgentTests;

namespace VaultAgentTests
{
    [TestFixture]
    [Parallelizable]
    class LoginConnectorTests
    {
        private VaultAgentAPI _vault;
        private UniqueKeys _UK = new UniqueKeys("", "");       // Unique Key generator


        [OneTimeSetUp]
        public void Setup () {
            _vault = new VaultAgentAPI("TokenEngineVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);
        }


        [Test]
        public async Task TokenLogin () {
            // Load engine and create a token
            TokenAuthEngine tokenAuthEngine = (TokenAuthEngine)_vault.ConnectAuthenticationBackend(EnumBackendTypes.A_Token);

            TokenNewSettings tokenSettings = new TokenNewSettings();
            tokenSettings.Name = "Test";
            tokenSettings.IsRenewable = false;
            tokenSettings.NumberOfUses = 4;

            Token token = await tokenAuthEngine.CreateToken(tokenSettings);
            TokenLoginConnector lc = new TokenLoginConnector(_vault,tokenAuthEngine.MountPoint,tokenAuthEngine.Name);
            lc.TokenId = token.ID;
            Assert.IsTrue(await lc.Connect());
        }


    }
}
