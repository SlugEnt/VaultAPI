using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;
using Newtonsoft.Json;


namespace VaultAgent.Backends.AppRole
{
	public class AppRoleBackEnd
	{
		TokenInfo backendToken;
		private VaultAPI_Http vaultHTTP;
		string roleBEPath = "/v1/auth/";
		Uri vaultAppRolePath;



		/// <summary>
		/// Constructor for AppRoleBackEnd
		/// </summary>
		public AppRoleBackEnd (string vaultIP, int port, string Token, string mountPath = "approle") {
			vaultHTTP = new VaultAPI_Http(vaultIP, port, Token);
			backendToken = new TokenInfo();
			backendToken.Id = Token;

			// Mount the AppRole backend at the specified mount point.
			roleBEPath = roleBEPath + mountPath + "/role";

			vaultAppRolePath = new Uri("http://" + vaultIP + ":" + port + roleBEPath);
		}




		public async Task<bool> CreateRole (AppRole art) {
			string path = vaultAppRolePath + "/" + art.Name;
			string json = JsonConvert.SerializeObject(art);


			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "AppRoleBackEnd: CreateRole", null, json);
			if (vdro.Success) {
				return true;
			}
			else { return false; }
		} 




		/// <summary>
		/// Lists all Application Roles.
		/// </summary>
		/// <returns>List[string] of role names.</string></returns>
		public async Task<List<string>> ListRoles () {
			try {
				// Setup List Parameter
				Dictionary<string, string> contentParams = new Dictionary<string, string>() {
					{ "list", "true" }
				};
	

				VaultDataResponseObject vdro = await vaultHTTP.GetAsync(roleBEPath, "ListRoles",contentParams);
				if (vdro.Success) {
					string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "keys");
					List<string> keys = VaultUtilityFX.ConvertJSON<List<string>>(js);
					return keys;
				}
				throw new ApplicationException("AppRoleBackEnd:ListRoles -> Arrived at unexpected code block.");
			}
			// 404 Errors mean there were no roles.  We just return an empty list.
			catch (VaultInvalidPathException e) { return new List<string>(); }
		}



		/// <summary>
		/// Reads the AppRole with the given name.
		/// </summary>
		/// <param name="appRoleName">String name of the app role to retrieve.</param>
		/// <returns>AppRole object.</returns>
		public async Task<AppRole> ReadAppRole (string appRoleName) {
			// The rolename forms the last part of the path
			string path = vaultAppRolePath + "/" + appRoleName;

			VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "ReadAppRole");
			AppRole ART = vdro.GetVaultTypedObject<AppRole>();
			return ART;
		}



		/// <summary>
		/// Deletes the App Role from the vaule.
		/// </summary>
		/// <param name="appRole">AppRole object to be deleted</param>
		/// <returns>Bool:  True if deleted.  False otherwise</returns>
		public async Task<bool> DeleteAppRole (AppRole appRole) {
			return await DeleteAppRole(appRole.Name);
		}




		/// <summary>
		/// Deletes the AppRole with the given name.
		/// </summary>
		/// <param name="appRoleName">AppRole name that should be deleted.</param>
		/// <returns>Bool:  True if deleted OR did not exist.  False otherwise.</returns>
		public async Task<bool> DeleteAppRole (string appRoleName) {
			// The rolename forms the last part of the path
			string path = vaultAppRolePath + "/" + appRoleName;


			try {
				VaultDataResponseObject vdro = await vaultHTTP.DeleteAsync(path, "DeleteAppRole");
				if (vdro.Success) { return true; }
				else { return false; }
			}
/*
				catch (VaultInvalidDataException e) {
				// Search for the error message - it indicates whether it is key could not be found or deletion not allowed.
				if (e.Message.Contains("could not delete policy; not found")) { throw e; }

				if (e.Message.Contains("deletion is not allowed for this policy")) { return false; }

				// not sure - rethrow error.
				throw e;
			}
*/
			catch (Exception e) { throw e; }
		}




		public async Task<string> GetRoleID (string appRoleName) {
			// The rolename forms the last part of the path
			string path = vaultAppRolePath + "/" + appRoleName + "/role-id";


			VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "GetRoleID");
			if (vdro.Success) {
				return  vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "role_id");
			}
			else { return ""; }
		}
	}
}
