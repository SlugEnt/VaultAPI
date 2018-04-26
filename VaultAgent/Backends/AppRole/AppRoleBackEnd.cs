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



	}
}
