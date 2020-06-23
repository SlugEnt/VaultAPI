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
using VaultAgent.Backends.System;
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

            _vault = new VaultAgentAPI("LoginConnVault", VaultServerRef.vaultURI);
            _vault.TokenID = VaultServerRef.rootToken;

//            _vault = new VaultAgentAPI("LoginConnVault", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);
        }


        [Test]
        [Order(10)]
        public async Task TokenLogin_ValidToken () {
            TokenLoginConnector tlc = new TokenLoginConnector(_vault, "Token Connector Good");
            tlc.TokenId = VaultServerRef.rootToken;
            bool success = await tlc.Connect();
            Assert.IsTrue(success);
        }



        // Validates we can login with a token
        [Test]
        [Order(20)]
        public async Task TokenLogin_InvalidToken () {

            // Load engine and create a token

            VaultAgentAPI vault = new VaultAgentAPI("LoginConnVault", VaultServerRef.vaultURI);
            

            // TODO this test is not valid.  We kind of already test it, because every Test requires a connection to Vault which we do in the VaultServerSetup Class.
            TokenLoginConnector tlc = new TokenLoginConnector(vault,"Token Connector");
            tlc.TokenId = "bbnbb";
            bool success = await tlc.Connect();
            Assert.IsFalse(success);
            /*
            

            TokenAuthEngine tokenAuthEngine = (TokenAuthEngine)_vault.ConnectAuthenticationBackend(EnumBackendTypes.A_Token);

            TokenNewSettings tokenSettings = new TokenNewSettings();
            tokenSettings.Name = "Test";
            tokenSettings.IsRenewable = false;
            tokenSettings.NumberOfUses = 4;

            Token token = await tokenAuthEngine.CreateToken(tokenSettings);
            TokenLoginConnector lc = new TokenLoginConnector(_vault,tokenAuthEngine.MountPoint,tokenAuthEngine.Name);
            lc.TokenId = token.ID;
            Assert.IsTrue(await lc.Connect());
            */
            Assert.IsTrue(true);
        }


        [Test]
        public async Task AppRoleLoginConnector_Test () {
            // PRE-Test 

            VaultSystemBackend vaultSystemBackend =  new VaultSystemBackend(_vault.TokenID, _vault);
            string approleMountName = _UK.GetKey("AppAuth");

            // Create an AppRole authentication connection.
            AppRoleAuthEngine appRoleAuthEngine = (AppRoleAuthEngine)_vault.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, "AppRole", approleMountName);


            // Create an Authentication method of App Role.	- This only needs to be done when the Auth method is created.  
            AuthMethod am = new AuthMethod(approleMountName, EnumAuthMethods.AppRole);
            bool rc = await vaultSystemBackend.AuthEnable(am);

            string rName = _UK.GetKey("Role");
            AppRole roleA = new AppRole(rName);
            Assert.True(await appRoleAuthEngine.SaveRole(roleA));

            string roleID = await appRoleAuthEngine.ReadRoleID(roleA.Name);

            // Now create the a secret
            AppRoleSecret secret_A = await appRoleAuthEngine.GenerateSecretID(roleA.Name);


            // ACTUAL TEST
            // Create Login Connector
            AppRoleLoginConnector loginConnector = new AppRoleLoginConnector(_vault,approleMountName,"Test AppRole",roleID, secret_A.ID);
            bool result = await loginConnector.Connect(true);
            Assert.IsTrue(result,"A10:  Login Failed");
        }

    }
}
