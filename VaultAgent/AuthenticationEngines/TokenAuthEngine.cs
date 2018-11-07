﻿using CommonFunctions;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;

namespace VaultAgent.AuthenticationEngines
{
    public class TokenAuthEngine : VaultAuthenticationBackend
	{
		/// <summary>
		/// Constructor for the TokenAuthEngine
		/// </summary>
		/// <param name="httpConnector">VaultAPI_Http object used to communicate with the Vault Instance.</param>
		public TokenAuthEngine (VaultAPI_Http httpConnector) : base ("Token","token", httpConnector) {
			Type = Backends.EnumBackendTypes.A_Token;
			MountPointPrefix = "/v1/auth/";
		}




		/// <summary>
		/// Returns all Token Accessors in the Vault database.  
		/// </summary>
		/// <returns>List<string>> of all token accessors.</string></returns>
		public async Task<List<string>> ListTokenAccessors () {
			string path = MountPointPath + "accessors?list=true";

			VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "ListTokenAccessors");
			if (vdro.Success) {
				string js = vdro.GetDataPackageFieldAsJSON("keys");
				List<string> tokenAccessors = VaultUtilityFX.ConvertJSON<List<string>>(js);
				return tokenAccessors;
			}
			return null;
		}


		/// <summary>
		/// Creates an orphan token (a token with no parent)
		/// </summary>
		/// <param name="tokenSettings">A TokenNewSettings object with the options you would like the new token to have. </param>
		/// <returns>True if token was created successfully.</returns>
		public async Task<bool> CreateOrphanToken (TokenNewSettings tokenSettings) {
			string path = MountPointPath + "create-orphan";

			string json = JsonConvert.SerializeObject(tokenSettings, Formatting.None);

			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "CreateOrphanToken", null, json);
			if (vdro.Success) {
				return true;
			}
			throw new ApplicationException("TokenAuthEngine:  CreateToken returned an unexpected error.");

		}




		/// <summary>
		/// Creates a token that is a child of the calling token.  
		/// </summary>
		/// <param name="tokenSettings">A TokenNewSettings object with the options you would like the new token to have. </param>
		/// <returns>True if token was created successfully.</returns>
		public async Task<bool> CreateToken(TokenNewSettings tokenSettings) {
			string path = MountPointPath + "create";

			string json = JsonConvert.SerializeObject(tokenSettings, Formatting.None);

			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "CreateToken",null,json);
			if (vdro.Success) {
				return true;
			}
			throw new ApplicationException("TokenAuthEngine:  CreateToken returned an unexpected error.");
		}




		/// <summary>
		/// Retrieves the requested token.  Returns Null if the token could not be found.
		/// </summary>
		/// <param name="tokenID">The ID of the token to retrieve.</param>
		/// <returns>Token object of the requested token or null if the token is invalid.  Will throw error for other issues.</returns>
		public async Task<Token> GetTokenWithID(string tokenID) {
			string path = MountPointPath + "lookup";

			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{ "token", tokenID}
			};

			try {
				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "GetToken", contentParams);
				if (vdro.Success) {
					string js = vdro.GetDataPackageAsJSON();
					Token token = VaultUtilityFX.ConvertJSON<Token>(js);
					return token;
				}
				else { throw new VaultUnexpectedCodePathException(); }
			}

			// If Vault is telling us it is a bad token, then return null.
			catch (VaultForbiddenException e) {
				if (e.Message.Contains("bad token")) { return null; }
				else { throw e; }
			}
		}





		/// <summary>
		/// Returns a Token object of the Token that is currently being used to access Vault with.
		/// </summary>
		/// <returns>Token object of the current token used to access Vault Instance with.</returns>
		public async Task<Token> GetCurrentTokenInfo() { 
			string path = MountPointPath + "lookup-self";
			
			try { 
				VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "GetCurrentTokenInfo");
				if (vdro.Success) {
					string js = vdro.GetDataPackageAsJSON();
					Token tokenInfo = VaultUtilityFX.ConvertJSON<Token>(js);
					return tokenInfo;
				}
				else { throw new VaultUnexpectedCodePathException(); }
			}

			// If Vault is telling us it is a bad token, then return null.
			catch (VaultForbiddenException e) {
				if (e.Message.Contains("bad token")) { return null; }
				else { throw e; }
			}
		}



		/// <summary>
		/// Retrieves the token associated with the provided accessor ID.
		/// </summary>
		/// <param name="accessorID">Accessor ID tied to the token you wish to retrieve.</param>
		/// <returns>Token object of the token.  Null if invalid accessor token specified.</returns>
		public async Task<Token> GetTokenViaAccessor(string accessorID) {
			string path = MountPointPath + "lookup-accessor";


			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{ "accessor", accessorID}
			};

			try {
				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "GetTokenViaAccessor", contentParams);
				if (vdro.Success) {
					string js = vdro.GetDataPackageAsJSON();
					Token token = VaultUtilityFX.ConvertJSON<Token>(js);
					token.TokenType = EnumTokenType.Accessor;
					return token;
				}
				else { throw new VaultUnexpectedCodePathException(); }
			}

			// If Vault is telling us it is a bad token, then return null.
			catch (VaultInvalidDataException e) {
				if (e.Message.Contains("invalid accessor")) { return null; }
				else { throw e; }
			}
		}




		/// <summary>
		/// Renews the specified token using the defined lease period defined at token creation
		/// </summary>
		/// <param name="tokenID">The ID of the token to be renewed.</param>
		/// <returns>True if successfully renewed token</returns>
		public async Task<bool> RenewToken (string tokenID) {
			string path = MountPointPath + "renew";

			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{ "token", tokenID}
			};


				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "RenewToken", contentParams);
				if (vdro.Success) {
					return true;
				}
				else { throw new VaultUnexpectedCodePathException(); }
			}



		/// <summary>
		/// Renews the current token being used to access the Vault Instance with using the specified TimeUnit for the new lease period.  This lease period may or may not be honored by the Vault system.
		/// </summary>
		/// <param name="tokenID">ID of the token to be renewed.</param>
		/// <param name="renewalTimeAmount">A suggested amount of time to renew the token for.  Vault has a complex algorithm that is determined at renewal time what the actual Lease Time will be.</param>
		/// <returns>True if token is renewed successfully.</returns>
		public async Task<bool> RenewToken(string tokenID, TimeUnit renewalTimeAmount) {
			string path = MountPointPath + "renew";

			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{ "token", tokenID}
			};
			if (renewalTimeAmount != null) {
				contentParams.Add("increment", renewalTimeAmount.Value);
			}


			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "RenewToken", contentParams);
			if (vdro.Success) {

				return true;
			}
			else { throw new VaultUnexpectedCodePathException(); }
		}




		/// <summary>
		/// Renews the current token being used to access the Vault Instance with using the defined lease period defined at token creation
		/// </summary>
		/// <returns>True if successfully renewed token</returns>
		public async Task<bool> RenewTokenSelf () {
			string path = MountPointPath + "renew-self";

			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "RenewTokenSelf");
			if (vdro.Success) { return true; }
			else { throw new VaultUnexpectedCodePathException(); }
		}




		/// <summary>
		/// Renews the current token.  Will throw error if cannot renew the token.
		/// </summary>
		/// <param name="renewalTimeAmount">Optional TineUnit amount to set the lease time to.  Note, this may or may not be honored by the Vault Instance.  Depends!</param>
		/// <returns>True if successfully renewed token.</returns>
		public async Task<bool> RenewTokenSelf(TimeUnit renewalTimeAmount) {
			string path = MountPointPath + "renew-self";

			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{ "increment", renewalTimeAmount.Value }
			};


			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "RenewTokenSelf", contentParams);
			if (vdro.Success) {	return true; }
			else { throw new VaultUnexpectedCodePathException(); }
		}




		/// <summary>
		/// Revokes the given token and possible all children depending on the revokeChildren parameter.  All dynamic secrets generated with the token are also revoked.
		/// </summary>
		/// <param name="tokenID">ID of the token to revoke.</param>
		/// <param name="revokeChildren">If false [Default] then children tokens will be orphaned.  If true, then all children of the token will also be revoked.</param>
		/// <returns>True if successfull OR if token could not be found - indicating that it never existed, so same as revoking.  False otherwise.</returns>
		public async Task<bool> RevokeToken (string tokenID, bool revokeChildren = false) {
			string path;
			if (revokeChildren == true) { path = MountPointPath + "revoke"; }
			else { path = MountPointPath + "revoke-orphan"; }

			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{ "token", tokenID}
			};


			try {
				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "RevokeToken", contentParams);
				if (vdro.Success) {	return true; }
				else { throw new VaultUnexpectedCodePathException(); }
			}
			catch (VaultInvalidDataException e) {
				if (e.Message.Contains("token to revoke not found")) { return true; }		
				throw e;
			}
		}




		/// <summary>
		/// Revokes the current token and ALL child tokens.  All dynamic secrets generated with the token are also revoked.
		/// </summary>
		/// <returns>True if successfull.  False otherwise.</returns>
		public async Task<bool> RevokeTokenSelf() {
			string path = MountPointPath + "revoke-self";


			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "RevokeTokenSelf");
			if (vdro.Success) {
				return true;
			}
			else { throw new VaultUnexpectedCodePathException(); }
		}



		/// <summary>
		/// Revokes the token associated with a given accessor AND all child tokens.  Meant for purposes where there is no access to the token, but there is a need to revoke it.
		/// </summary>
		/// <param name="AccessorID">The ID of the accessor token that has access to the token you wish to revoke.</param>
		/// <returns>True if the token was revoked.  False if the token could not be found.</returns>
		public async Task<bool> RevokeTokenViaAccessor (string AccessorID) {
			string path = MountPointPath + "revoke-accessor";


			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{ "accessor",AccessorID}
			};

			try {
				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "RevokeTokenViaAccessor", contentParams);
				if (vdro.Success) {
					return true;
				}
				else { throw new VaultUnexpectedCodePathException(); }
			}
			catch (VaultInvalidDataException e) {
				if (e.Message.Contains("invalid accessor") ) { return false; }
				throw e;
			}
		}



		/// <summary>
		/// Creates / Saves a token role.  
		/// </summary>
		/// <param name="tokenRole">The TokenRole object that contains the Token Role to be created / updated.</param>
		/// <returns>True if token Role was successfully created.</returns>
		public async Task<bool> SaveTokenRole (TokenRole tokenRole) {
			string path = MountPointPath + "roles/" + tokenRole.Name;
			string json = JsonConvert.SerializeObject(tokenRole, Formatting.None);

			try {
				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "SaveTokenRole",null,json);
				if (vdro.Success) {
					return true;
				}
				else { throw new VaultUnexpectedCodePathException(); }
			}
			catch (VaultInvalidDataException e) {
				if (e.Message.Contains("invalid accessor")) { return false; }
				throw e;
			}

		}



		/// <summary>
		/// Retrieves a TokenRole object from Vault with the specified name.
		/// </summary>
		/// <param name="tokenRoleName">Name of the tokenRole to retrieve.</param>
		/// <returns>TokenRole object requested if valid name provided.</returns>
		public async Task<TokenRole> GetTokenRole (string tokenRoleName) {
			string path = MountPointPath + "roles/" + tokenRoleName;

			try {
				VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "GetTokenRole");
				if (vdro.Success) {			
					string js = vdro.GetDataPackageAsJSON();
					TokenRole tokenRole = VaultUtilityFX.ConvertJSON<TokenRole>(js);
					return tokenRole;
				}
				else { throw new VaultUnexpectedCodePathException(); }
			}

			// If Vault could not find the tokenRole then return null.
			catch (VaultInvalidPathException e) {
				return null;
			}
		}



		public async Task<List<string>> ListTokenRoles () {
			string path = MountPointPath + "roles?list=true";

			VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "ListTokenRoles");
			if (vdro.Success) {
				string js = vdro.GetDataPackageFieldAsJSON("keys");
				List<string> tokenRoles = VaultUtilityFX.ConvertJSON<List<string>>(js);
				return tokenRoles;
			}
			return null;
		}



		/// <summary>
		/// Deletes the specified tokenRoleName
		/// </summary>
		/// <param name="tokenRoleName">Token Role to be deleted. </param>
		/// <returns>True if token role has been deleted.</returns>
		public async Task<bool> DeleteTokenRole (string tokenRoleName) {
			string path = MountPointPath + "roles/" + tokenRoleName;

			VaultDataResponseObject vdro = await _vaultHTTP.DeleteAsync(path, "DeleteTokenRole");
			if (vdro.Success) {	return true; }
			else { return false; }
		}
		


		// No need to implement at this time.
		//TODO public async Task<bool> TidyMaintenance () /auth/token/tidy


	}
}