﻿using NUnit.Framework;
using System.Threading.Tasks;
using VaultAgent.Backends.System;
using VaultAgent.Backends;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Models;
using CommonFunctions;
using System.Collections.Generic;

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



		// Validates that trying to retrieve a token that does not exist returns a null value for the token.
		[Test]
		public async Task RetrieveInvalidTokenFails() {
			string tokenID = UK.GetKey("tokH");

			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);
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
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);
			Assert.IsNotNull(token, "M1: No Token returned.  Was expecting one.");

			// Vault seems to prepend the auth backends name to the display name.
			Assert.AreEqual("token-" + tokenName, token.DisplayName, "M2: Token names are not equal");

			Assert.AreEqual(tokenID, token.ID, "M3: Token ID's are not equal");
			Assert.AreEqual(numUses, token.NumberOfUses, "M4: Token number of uses are not equal");
			Assert.AreEqual(parent, token.IsOrphan, "M5: Token parent setting is not the same as IsOrphan");
		}




		// Validates a token can be created and accessed with its accessor property.
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
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);
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
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);
			Assert.IsNotNull(token, "M2: No Token returned.  Was expecting one.");
			string tDisplayName = "token-" + tokenName;
			Assert.AreEqual(tDisplayName, token.DisplayName, "M3: Token Display name is not what was expected.  Expected {0}, but got {1}", tDisplayName, token.DisplayName);

			// Now try and retrieve via the accessor.
			Token tokenAcc = await _tokenAuthEngine.GetTokenViaAccessor("z");
			Assert.IsNull(tokenAcc, "M3: Expected to receive a null token, but instead received a token");

		}



		// Validates that an orphan token can be created with a settings object
		[Test]
		public async Task CreateOrphanToken_WithSettingsObject() {
			string tokenID = UK.GetKey("otok");
			int numUses = 19;
			string tokenName = "Name" + tokenID.ToString();

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
				NumberOfUses = numUses
			};

			Assert.True(await _tokenAuthEngine.CreateOrphanToken(tokenNewSettings));

			// Read the token we just created.
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);
			Assert.IsNotNull(token, "M1: No Token returned.  Was expecting one.");

			// Vault seems to prepend the auth backends name to the display name.
			Assert.AreEqual("token-" + tokenName, token.DisplayName, "M2: Token names are not equal");

			Assert.AreEqual(tokenID, token.ID, "M3: Token ID's are not equal");
			Assert.AreEqual(numUses, token.NumberOfUses, "M4: Token number of uses are not equal");
			Assert.IsTrue(token.IsOrphan, "Was expecting the created token to have the IsOrphan property set to true.  It was false instead.");
		}



		// Validates the renewal of a token
		[Test]
		public async Task RenewToken_Success() {
			string tokenID = UK.GetKey("tok");
			int numUses = 19;
			string tokenName = "Name" + tokenID.ToString();

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
				NumberOfUses = numUses,
				Renewable = true,
				RenewalPeriod = "1800"
			};

			Assert.True(await _tokenAuthEngine.CreateToken(tokenNewSettings));

			// Read the token we just created.
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);
			Assert.IsNotNull(token, "M1: No Token returned.  Was expecting one.");

			// Vault seems to prepend the auth backends name to the display name.
			Assert.AreEqual("token-" + tokenName, token.DisplayName, "M2: Token names are not equal");

			Assert.AreEqual(tokenID, token.ID, "M3: Token ID's are not equal");
			Assert.AreEqual(numUses, token.NumberOfUses, "M4: Token number of uses are not equal");
			Assert.IsTrue(token.IsRenewable);


			// Renew token
			bool result = await _tokenAuthEngine.RenewToken(token.ID);
			Assert.IsTrue(result, "Token was unable to be renewed.");
			
			
		}


		// Validates the renewal of a token with a specified Lease Time.
		[Test]
		public async Task RenewTokenWithLease_Success() {
			string tokenID = UK.GetKey("tok");
			int numUses = 19;
			string tokenName = "Name" + tokenID.ToString();

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
				NumberOfUses = numUses,
				Renewable = true,
//				RenewalPeriod = "1800",
				MaxTTL = "86400"
			};

			Assert.True(await _tokenAuthEngine.CreateToken(tokenNewSettings));

			// Read the token we just created.
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);
			Assert.IsNotNull(token, "M1: No Token returned.  Was expecting one.");

			// Vault seems to prepend the auth backends name to the display name.
			Assert.AreEqual("token-" + tokenName, token.DisplayName, "M2: Token names are not equal");

			Assert.AreEqual(tokenID, token.ID, "M3: Token ID's are not equal");
			Assert.AreEqual(numUses, token.NumberOfUses, "M4: Token number of uses are not equal");
			Assert.IsTrue(token.IsRenewable);


			// Renew token
			TimeUnit tu = new TimeUnit("12h");
			bool result = await _tokenAuthEngine.RenewToken (token.ID,tu);
			Assert.IsTrue(result, "M5:  Token was unable to be renewed successfully.");

			// Retrieve token and validate lease time.
			Token token2 = await _tokenAuthEngine.GetTokenWithID(tokenID);
			Assert.AreEqual(43200, token2.TTL,"M6:  Token lease was not set to expected value.");
		}



		// Validates that providing a valid tokenID, that a token can be revoked.
		[Test]
		public async Task RevokeTokenSucceeds () {
			string tokenID = UK.GetKey("Rev");
			string tokenName = "Name" + tokenID.ToString();

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
			};

			Assert.True(await _tokenAuthEngine.CreateToken(tokenNewSettings),"M1:  Token was not created successfully.");
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);

			// Revoke and validate it is gone.
			Assert.True(await _tokenAuthEngine.RevokeToken(tokenID),"M2:  Revocation of token failed.");

			// If token is null then it has been revoked successfully.
			Token token2 = await _tokenAuthEngine.GetTokenWithID(tokenID);
			Assert.IsNull(token2);
		}



		// Validates that providing an invalid tokenID for revocation still returns a success code.
		[Test]
		public async Task RevokeBadTokenID_ReturnsSuccess() {
			string badID = UK.GetKey("Bad");

			// We test 2 attempts. The reason is that as of Vaule 1.11 Revoke and Revoke-Orphan produce different results if the token is not found.
			// Try to revoke an invalid token without the Orphan children set to true. 
			Assert.True (await _tokenAuthEngine.RevokeToken(badID), "M1:  Revocation of token returned an unexpected value.  Expected True.");
			Assert.True(await _tokenAuthEngine.RevokeToken(badID,true), "M2:  Revocation of token and orphaning children returned an unexpected value.  Expected True.");
		}




		// Validates that a token can revoke itself.
		[Test]
		public async Task RevokeSelfTokenSucceeds() {
			throw new System.NotImplementedException("This test case has not been implemented yet.");
		}



		// Validates that a token can be revoked via its accessor
		[Test]
		public async Task RevokeTokenViaAccessor_Succeeds() {
			string tokenID = UK.GetKey("Rev");
			string tokenName = "Name" + tokenID.ToString();

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
			};

			Assert.True(await _tokenAuthEngine.CreateToken(tokenNewSettings), "M1:  Token was not created successfully.");
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);

			// Revoke and validate it is gone.
			Assert.True(await _tokenAuthEngine.RevokeTokenViaAccessor(token.AccessorTokenID), "M2:  Revocation of token failed.");

			// If token is null then it has been revoked successfully.
			Token token2 = await _tokenAuthEngine.GetTokenWithID(tokenID);
			Assert.IsNull(token2);
		}




		// Validates that trying to revoke a token with an invalid accessor ID (ID does not exist) returns false.
		[Test]
		public async Task RevokeTokenViaAccessor_WithBadAccessor_Succeeds() {
			string tokenID = UK.GetKey("RevNotExists");
			string tokenName = "Name" + tokenID.ToString();


			// Revoke and validate it is gone.
			Assert.False(await _tokenAuthEngine.RevokeTokenViaAccessor(tokenID), "M1:  Revocation of token via invalid accessor failed.");
		}






		[Test]
		public async Task RevokeTokenWithChildren_ChildrenOrphaned () {
			throw new System.NotImplementedException("This test has not been implemented yet.");

			string tokenID = UK.GetKey("Rev");
			string tokenName = "Name" + tokenID.ToString();

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
			};

			Assert.True(await _tokenAuthEngine.CreateToken(tokenNewSettings), "M1:  Token was not created successfully.");
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);

			// Revoke and validate it is gone.
			Assert.True(await _tokenAuthEngine.RevokeToken(tokenID), "M2:  Revocation of token failed.");

		}


		[Test]
		public async Task RevokeTokenWithChildren_ChildrenRevokedAlso() {
			throw new System.NotImplementedException("This test has not been implemented yet.");

			string tokenID = UK.GetKey("Rev");
			string tokenName = "Name" + tokenID.ToString();

			TokenNewSettings tokenNewSettings = new TokenNewSettings() {
				ID = tokenID,
				Name = tokenName,
			};

			Assert.True(await _tokenAuthEngine.CreateToken(tokenNewSettings), "M1:  Token was not created successfully.");
			Token token = await _tokenAuthEngine.GetTokenWithID(tokenID);

			// Revoke and validate it is gone.
			Assert.True(await _tokenAuthEngine.RevokeToken(tokenID,true), "M2:  Revocation of token failed.");

		}



		// Validate we can create a token role.
		[Test]
		public async Task CreateTokenRole_Simple_Success () {
			string roleID = UK.GetKey("TokRole");

			TokenRole tokenRole = new TokenRole();

			tokenRole.Name = roleID;

			Assert.True(await _tokenAuthEngine.SaveTokenRole(tokenRole),"M1:  Creation of TokenRole in Vault failed.");
		}



		// Validate we can create a token role With Policies that do not exist yet.
		[Test]
		public async Task CreateTokenRole_WithNonExistentPolicies_Success() {
			string roleID = UK.GetKey("TokRole");

			TokenRole tokenRole = new TokenRole(roleID);
			tokenRole.AllowedPolicies.Add("Pol1");
			tokenRole.AllowedPolicies.Add("Pol2");

			tokenRole.DisallowedPolicies.Add("DisPol1");
			tokenRole.DisallowedPolicies.Add("DisPol2");

			Assert.True(await _tokenAuthEngine.SaveTokenRole(tokenRole), "M1:  Creation of TokenRole in Vault failed.");

		}



		// Validate we can create a token role With Policies that do not exist yet.
		[Test]
		public async Task CreateTokenRole_WithMinimalFieldsSet_Success() {
			string roleID = UK.GetKey("TokRole");

			TokenRole tokenRole = new TokenRole(roleID);

			Assert.True(await _tokenAuthEngine.SaveTokenRole(tokenRole), "M1:  Creation of TokenRole in Vault failed.");

			// Now read the token role...
			TokenRole role2 = await _tokenAuthEngine.GetTokenRole(roleID);

			// Validate The token Role and its properties.
			Assert.AreEqual(roleID, role2.Name,"M2:  RoleToken Name does not match expected value.");
			Assert.IsNotNull(role2.AllowedPolicies);
			Assert.AreEqual(0, role2.AllowedPolicies.Count);

			// Disallowed Policies
			Assert.IsNotNull(role2.DisallowedPolicies);
			Assert.AreEqual(0, role2.DisallowedPolicies.Count);

			Assert.IsNotNull(role2.BoundCidrs);
			Assert.AreEqual(0, role2.BoundCidrs);
		}



		// Validates that we can retrieve a list of all token roles.
		[Test]
		public async Task ListTokenRoles_Success() {
			string roleID = UK.GetKey("TokRole");

			TokenRole tokenRole = new TokenRole(roleID);
			Assert.True(await _tokenAuthEngine.SaveTokenRole(tokenRole), "M1:  Creation of TokenRole in Vault failed.");

			string roleID2 = UK.GetKey("TokRole");

			TokenRole tokenRole2 = new TokenRole(roleID2);
			Assert.True(await _tokenAuthEngine.SaveTokenRole(tokenRole2), "M2:  Creation of TokenRole in Vault failed.");

			List<string> roles = await _tokenAuthEngine.ListTokenRoles();
			Assert.GreaterOrEqual(roles.Count, 2);
		}



		// Validates that we can delete a role.
		[Test]
		public async Task DeleteValidTokenRole_Success () {
			string roleID = UK.GetKey("DelRole");
			TokenRole tokenRole = new TokenRole(roleID);
			Assert.True(await _tokenAuthEngine.SaveTokenRole(tokenRole), "M1:  Creation of TokenRole in Vault Failed.");

			// Validate token exists.
			TokenRole tokenRole2 = await _tokenAuthEngine.GetTokenRole(roleID);
			Assert.IsNotNull(tokenRole2, "M2:  Retrieval of token role failed.  Expected it to exist.");

			// Delete and validate
			Assert.IsTrue(await _tokenAuthEngine.DeleteTokenRole(roleID),"Deletion of token role failed.");
			TokenRole tokenRole3 = await _tokenAuthEngine.GetTokenRole(roleID);
			Assert.IsNull(tokenRole3, "M3:  Retrieval of token role was successful.  Expected it to be null if deletion had been successful.");
		}


		// Deleting a tokenRole that does not exist still returns success.
		[Test]
		public async Task DeleteInvalidTokenRole_Success () {
			string roleID = UK.GetKey("DelRole");
			TokenRole tokenRole = new TokenRole(roleID);

			Assert.IsTrue(await _tokenAuthEngine.DeleteTokenRole(roleID), "Deletion of token role failed.");
		}



		// Validates that We can retrieve a list of token Accessors.
		[Test]
		public async Task ListTokenAccessors_Success () {
			string roleID = UK.GetKey("ListAcc");
			TokenRole tokenRole = new TokenRole(roleID);
			Assert.True(await _tokenAuthEngine.SaveTokenRole(tokenRole), "M1:  Creation of TokenRole in Vault Failed.");

			List<string> Accessors = await _tokenAuthEngine.ListTokenAccessors();
			Assert.GreaterOrEqual(1, Accessors.Count);
		}
	}
}