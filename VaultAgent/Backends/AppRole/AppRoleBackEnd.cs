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
		string roleBEPath = "/v1/auth/approle/role/";
		Uri vaultAppRolePath;



		/// <summary>
		/// Constructor for AppRoleBackEnd
		/// </summary>
		public AppRoleBackEnd (string vaultIP, int port, string Token) {
			vaultHTTP = new VaultAPI_Http(vaultIP, port, Token);
			backendToken = new TokenInfo();
			backendToken.Id = Token;


			vaultAppRolePath = new Uri("http://" + vaultIP + ":" + port + roleBEPath);
		}




		public async Task<bool> Create (AppRoleToken art) {
			string path = vaultAppRolePath + art.Name;
			string json = JsonConvert.SerializeObject(art);


			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "AppRoleBackEnd_Create", null, json);
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
				VaultDataResponseObject vdro = await vaultHTTP.GetAsync(roleBEPath, "ListRoles");
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






	}
}
