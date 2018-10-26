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



		//TODO public async Task<List<string>> ListTokenAccessors () /auth/token/accessors

		public async Task<bool> CreateToken(TokenNewSettings tokenSettings) {
			string path = MountPointPath + "create";

			string json = JsonConvert.SerializeObject(tokenSettings, Formatting.None);

			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "CreateToken",null,json);
			if (vdro.Success) {
				return true;
			}
			throw new ApplicationException("TokenAuthEngine:  CreateToken returned an unexpected error.");
		}



		//TODO public async Task<bool> CreateOrphanToken (params) /auth/token/create-orphan


		public async Task<Token> GetToken(string tokenID) {
			string path = MountPointPath + "lookup";

			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{ "token", tokenID}
			};

			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "GetToken",contentParams);
			if (vdro.Success) {
				string js = vdro.GetDataPackageAsJSON();
				Token token = VaultUtilityFX.ConvertJSON<Token>(js);
				return token;
			}
			return null;

		}





		/// <summary>
		/// Returns a Token object of the Token that is currently being used to access Vault with.
		/// </summary>
		/// <returns>Token object of the current token used to access Vault Instance with.</returns>
		public async Task<Token> GetCurrentTokenInfo() { // /auth/token/lookup-self 
			string path = MountPointPath + "lookup-self";
				VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "GetCurrentTokenInfo");
				if (vdro.Success) {
					string js = vdro.GetDataPackageAsJSON();
					Token tokenInfo = VaultUtilityFX.ConvertJSON<Token>(js);
					return tokenInfo;
				}
				throw new ApplicationException("TokenAuthEngine:  GetCurrentTokenInfo returned an unexpected error.");
		}



		//TODO public async Task<accessor or token object?> GetTokenAccessorInfo () /auth/token/lookup-accessor

		//TODO public async Task<bool> RenewAToken () /auth/token/renew

		//TODO public async Task<bool> RenewToken () /auth/token/renew-self

		//TODO public async Task<bool> RevokeAToken () /auth/token/revoke

		//TODO public async Task<bool> RevokeToken () /auth/token/revoke-self

		//TODO public async Task<bool> RevokeTokenAccessor () /auth/token/revoke-accessor

		//TODO public async Task<bool> RevokeTokenAndOrphanChildred () /auth/token/revoke-orphan

		//TODO public async Task<RoleInfoObject?> GetTokenRole () /auth/token/roles/:role_name

		//TODO public async Task<List<string>> ListTokenRoles () /auth/token/roles

		//TODO public async Task<bool> SaveTokenRole () /auth/token/roles/:role_name
		
		//Todo public async Task<bool> DeleteTokenRole () /auth/token/roles/:role_name

		//TODO public async Task<bool> TidyMaintenance () /auth/token/tidy


	}
}
