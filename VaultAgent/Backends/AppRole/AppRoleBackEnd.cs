using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;
using Newtonsoft.Json;
using VaultAgent.Models;
using VaultAgent.Backends;

namespace VaultAgent.Backends.AppRole
{
	/// <summary>
	/// The AppRoleBackEnd represents the Vault AppRole backend authentication engine and all the service endpoints it exposes
	/// for the creation, updating, reading and deletion of AppRole's
	/// </summary>
	public class AppRoleBackEnd : VaultAuthenticationBackend
	{
/*
		TokenInfo backendToken;
		private VaultAPI_Http _vaultHTTP;
		string roleBEPath = "/v1/auth/";
		Uri vaultAppRolePath;
*/
		

		/// <summary>
		/// Constructor for AppRoleBackend
		/// </summary>
		public AppRoleBackEnd ( string backendMountName, string backendMountPath, VaultAPI_Http _httpConnector) : base(backendMountName, backendMountPath, _httpConnector) {
			Type = EnumBackendTypes.A_AppRole;
			this.MountPointPrefix = "/v1/auth/";

/*			_vaultHTTP = new VaultAPI_Http(vaultIP, port, Token);
			backendToken = new TokenInfo();
			backendToken.Id = Token;

			// Mount the AppRole backend at the specified mount point.
			roleBEPath = roleBEPath + mountPath + "/role";

			vaultAppRolePath = new Uri("http://" + vaultIP + ":" + port + roleBEPath);
*/
		}



		/// <summary>
		/// Sends the AppRole C# object onto Vault to be created.
		/// Returns True on Success.
		/// </summary>
		/// <param name="art" >The AppRole Object that you wish to be created in Vault.</param>
		/// <returns>True if successful.</returns>
		/// <see cref="AppRole"/>
		public async Task<bool> CreateRole (AppRole art) {
			string path = MountPointPath + "role/" + art.Name;
			string json = JsonConvert.SerializeObject(art);


			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "AppRoleBackEnd: CreateRole", null, json);
			if (vdro.Success) {
				return true;
			}
			else { return false; }
		} 




		/// <summary>
		/// Lists all Application Roles.
		/// </summary>
		/// <returns>List[string] of role names.  Empty list if no roles found.</string></returns>
		public async Task<List<string>> ListRoles () {
			string path = MountPointPath + "role";

			try {
				// Setup List Parameter
				Dictionary<string, string> contentParams = new Dictionary<string, string>() {
					{ "list", "true" }
				};
	

				VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "ListRoles",contentParams);
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
			string path = MountPointPath + "role/" + appRoleName;
			//string path = vaultAppRolePath + "/" + appRoleName;

			VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "ReadAppRole");
			if (vdro.Success) {
				AppRole ART = vdro.GetVaultTypedObject<AppRole>();
				ART.Name = appRoleName;
				return ART;
			}
			return null;
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
			string path = MountPointPath + "role/" + appRoleName;
			//string path = vaultAppRolePath + "/" + appRoleName;


			try {
				VaultDataResponseObject vdro = await _vaultHTTP.DeleteAsync(path, "DeleteAppRole");
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




		/// <summary>
		/// Retrieves the AppRoleID of the given AppRole.
		/// </summary>
		/// <param name="appRoleName"></param>
		/// <returns>Returns a string representing the Role ID as stored in Vault.</returns>
		public async Task<string> GetRoleID (string appRoleName) {
			// The rolename forms the last part of the path
			//string path = vaultAppRolePath + "/" + appRoleName + "/role-id";
			string path = MountPointPath + "role/" + appRoleName + "/role-id";


			VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "GetRoleID");
			if (vdro.Success) {
				return  vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "role_id");
			}
			else { return ""; }
		}



		/// <summary>
		/// Updates the AppRoleID of the given AppRole to the value specified.
		/// </summary>
		/// <param name="appRoleName"></param>
		/// <param name="valueOfRoleID"></param>
		/// <returns>True if update of RoleID was successful.</returns>
		public async Task<bool> UpdateAppRoleID (string appRoleName, string valueOfRoleID) {
			// The keyname forms the last part of the path
			//string path = vaultAppRolePath +"/" + appRoleName + "/role-id";
			string path = MountPointPath + "role/" + appRoleName + "/role-id";

			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{ "role_id", valueOfRoleID }
			};

			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "UpdateAppRoleID", contentParams);
			if (vdro.httpStatusCode == 204) { return true; }
			else { return false; }
		}



		/// <summary>
		/// Generates and issues a new SecretID on an existing AppRole. 
		/// Similar to tokens, the response will also contain a secret_id_accessor value which can be used to read the properties of the SecretID 
		/// without divulging the SecretID itself, and also to delete the SecretID from the AppRole.
		/// </summary>
		/// <param name="appRoleName">Name of the AppRole to create a secret for.</param>
		/// <param name="metadata">Metadata to be tied to the SecretID. This should be a JSON-formatted string containing the metadata in key-value pairs. 
		/// This metadata will be set on tokens issued with this SecretID, and is logged in audit logs in plaintext.</param>
		/// <param name="cidrIPsAllowed">Comma separated string or list of CIDR blocks enforcing secret IDs to be used from specific set of IP addresses. 
		/// If bound_cidr_list is set on the role, then the list of CIDR blocks listed here should be a subset of the CIDR blocks listed on the role.</param>
		/// <returns>AppRoleSecret representing the a secret ID Vault returned.</returns>
		public async Task<AppRoleSecret> CreateSecretID (string appRoleName, Dictionary<string,string> metadata = null, List<string> cidrIPsAllowed = null) {
			// The keyname forms the last part of the path
			//string path = vaultAppRolePath + "/" + appRoleName + "/secret-id";
			string path = MountPointPath + "role/" + appRoleName + "/secret-id";


			Dictionary<string, string> contentParams = new Dictionary<string, string>();
			if (metadata != null) {
				string metadataString = JsonConvert.SerializeObject(metadata);
				contentParams.Add("metadata", metadataString);
			}
			


			if (cidrIPsAllowed != null) {
				string cidrs = JsonConvert.SerializeObject(cidrIPsAllowed);
				contentParams.Add("cidr_list", cidrs); }

			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "CreateSecretID", contentParams);
			if (vdro.Success) {
				return vdro.GetVaultTypedObject<AppRoleSecret>();
			}
			else { return null; }


		}
	}
}
