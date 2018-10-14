using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultAgent.Models;
using VaultAgent.Backends.SecretEngines.KVV2;
using VaultAgent.Backends.KV_V2;
using Newtonsoft.Json;
using System.Text;
using VaultAgent.Backends.KV_V2.KV2SecretMetaData;

namespace VaultAgent.Backends.SecretEngines
{
	public static class Constants
	{
		public const string Error_CAS_Set = "The backend storage engine has the CAS property set.  This requires that all secret saves must have " +
			"the CAS value set to zero upon saving a new key or the latest version of the key must be specified in the version parameter.";
		public const string Error_CAS_InvalidVersion = "The backend storage engine has the CAS property set.  This requires that all secret saves must " +
			"specify the current version of the key in order to update it.  The calling routine provided an incorrect version.";
	}
	

	
	/// <summary>
	/// This backend is for interfacing with the Vault secret Backend Version 2.0.  
	/// One of the unique things is that there are different root mounts within the given backend depending on what you want to do.  So having
	/// a std BackEnd path does not really work with this class.  It generally builds the unique path in each member method.
	/// </summary>
	public class KV2Backend : VaultBackend
	{
		// ==============================================================================================================================================
		/// <summary>
		/// Constructor.  Initializes the connection to Vault and stores the token.
		/// </summary>
		/// <param name="backendName">The name of the secret backend to mount.  This is purely cosmetic.</param>
		/// <param name="backendMountPoint">The actual mount point that the secret is mounted to.  Exclude and prefix such as /v1/ and exclude trailing slash.</param>
		/// <param name="_httpConnector">The VaultAPI_Http object that should be used to make all Vault API calls with.</param>
		public KV2Backend(string backendName,string backendMountPoint, VaultAPI_Http _httpConnector) : base (backendName, backendMountPoint, _httpConnector) {

		}



		#region "Configuration"
		/// <summary>
		/// Configures the Key Value V2 backend. 
		/// </summary>
		/// <param name="maxVersions">The maximum number of versions of a key to keep.  Defaults to 10.</param>
		/// <param name="casRequired">Check-And-Set parameter. If set to True then all writes (creates and updates) to keys will need to have the CAS parameter specified.  
		/// See the Update and Create methods for details about the CAS setting.
		/// <returns></returns>
		public async Task<bool> SetBackendConfiguration (UInt16 maxVersions = 10, bool casRequired = false) {
			try {
				// V2 Secret stores have a unique config path...
				string path = MountPointPath + "config";

				// Build the content parameters, which will contain the maxVersions and casRequired settings.
				Dictionary<string, string> contentParams = new Dictionary<string, string>();
				contentParams.Add("max_versions", maxVersions.ToString());
				contentParams.Add("cas_required", casRequired.ToString());

				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "ConfigureBackend", contentParams);
				if (vdro.Success) { return true; }
				return false;
			}
			catch (Exception e) { throw e; }
		}



		/// <summary>
		/// Returns the configuration settings of the current KeyValue V2 secret store. 
		/// </summary>
		/// <returns>KV2BackendSettings object with the values of the current configuration.</returns>
		public async Task<KV2BackendSettings> GetBackendConfiguration () {
			try {

				// V2 Secret stores have a unique config path...
				string path = MountPointPath + "config";

				VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "GetBackendConfiguration");
				KV2BackendSettings settings = vdro.GetVaultTypedObject<KV2BackendSettings>();
				return settings;
			}
			catch (Exception e) { throw e; }
		}

		#endregion



		//TODO - Elaborate on summary - describe the enum options.
		/// <summary>
		/// Saves the provided KV2Secret object.  You must specify a save option and optionally what the current version of the secret is.
		/// </summary>
		/// <param name="secret">KV2Secret object to be saved.  This must contain minimally the namePath of the secret and one or more optional attributes.</param>
		/// <param name="enumKVv2SaveSecretOption"></param>
		/// <param name="currentVersion">What the current version of the secret is.  Required if the backend is in CAS mode (Default mode).</param>
		/// <returns></returns>
		public async Task<bool> SaveSecret (KV2Secret secret, EnumKVv2SaveSecretOptions enumKVv2SaveSecretOption, int currentVersion = 0) {
			string path = MountPointPath + "data/" + secret.Path;


			Dictionary<string, object> reqData = new Dictionary<string, object>();
			Dictionary<string, string> options = new Dictionary<string, string>();

			// Set CAS depending on option coming from caller.
			switch (enumKVv2SaveSecretOption) {
				case EnumKVv2SaveSecretOptions.OnlyIfKeyDoesNotExist:
					options.Add("cas", "0");
					break;
				case EnumKVv2SaveSecretOptions.OnlyOnExistingVersionMatch:
					if (currentVersion != 0) {
						options.Add("cas", currentVersion.ToString());
					}
					else { throw new ArgumentException("The option OnlyOnExistingVersionMatch was chosen, but the currentVersion parameter was not set.  It must be set to the value of the current version of the key as stored in Vault."); }
					break;				
			}


			// CAS - Check and Set needs to be passed in from caller.
			//options.Add("cas", "");
			reqData.Add("options",options);
			reqData.Add("data", secret);

			try {
				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync2(path, "SaveSecret", reqData);
				if (vdro.Success) { return true; }
				return false;
			}
			catch (VaultInvalidDataException e) {
				if (e.Message.Contains("check-and-set parameter required for this call")) {
					throw new VaultInvalidDataException(Constants.Error_CAS_Set + " | Original Error message was: " + e.Message);
				}
				else if (e.Message.Contains("did not match the current version")) {
					throw new VaultInvalidDataException(Constants.Error_CAS_InvalidVersion + " Version specified was: " + currentVersion + " | Original Error message was: " + e.Message);
				}
				else { throw new VaultInvalidDataException(e.Message); }
			}
		}
		



		/// <summary>
		/// Reads the secret from Vault.  It defaults to reading the most recent version.  Set secretVersion to non zero to retrieve a
		/// specific version.
		/// </summary>
		/// <param name="secretPath">The Name (path) to the secret you wish to read.</param>
		/// <param name="secretVersion">The version of the secret to retrieve.  Leave at default of Zero to read most recent version.</param>
		/// <returns>KV2Secret of the secret as read from Vault.  </returns>
		public async Task<KV2SecretWrapper> ReadSecret (string secretPath, int secretVersion = 0) {
			string path = MountPointPath + "data/" + secretPath;
			try {
				Dictionary<string, string> contentParams = new Dictionary<string, string>() {{ "version", secretVersion.ToString() }};

				VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "ReadSecret",contentParams);
				if (vdro.Success) {
					KV2SecretWrapper secretReadReturnObj = KV2SecretWrapper.FromJson(vdro.GetResponsePackageAsJSON());
					return secretReadReturnObj;
					//return secretReadReturnObj.Data.SecretObj;
				}
				throw new ApplicationException("SecretBackEnd: ReadSecret - Arrived at an unexpected code path.");
			}
			catch (VaultInvalidPathException e) { return null; }
			catch (Exception e) { throw e; }
		}



		/// <summary>
		/// Deletes the most recent version of a secret or a specific version of a secret.
		/// </summary>
		/// <param name="secretPath">The name of the secret to delete.</param>
		/// <param name="version">The version to delete.  Defaults to zero which is the most recent or current version of the key.</param>
		/// <returns>True if successful.  False otherwise.</returns>
		public async Task<bool> DeleteSecretVersion (string secretPath, int version = 0 ) {
			string path;
			VaultDataResponseObject vdro;

			// Paths are different if specifying versions or version = 0 (current)
			if (version != 0) {
				path = MountPointPath + "delete/" + secretPath;

				// Add the version parameter
				string jsonParams = "{\"versions\": [" + version.ToString() + "]}";
				vdro = await _vaultHTTP.PostAsync(path, "DeleteSecretVersion",null,jsonParams);
			}
			else {
				path = MountPointPath + "data/" + secretPath;
				vdro = await _vaultHTTP.DeleteAsync(path, "DeleteSecretVersion");
			}	

			
			if (vdro.Success) { return true; }
			else { return false; }
		}






		/// <summary>
		/// Returns a list of secrets at a given path
		/// </summary>
		/// <param name="namePath">The parent secret (Path to the parent secret) </param>
		/// <returns>List of strings which contain secret names.</returns>
		public async Task<List<string>> ListSecretsAtPath (string namePath) {
			string path = MountPointPath + "metadata/" + namePath + "?list=true";

			try {
				VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "ListSecrets");
				if (vdro.Success) {
					string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "keys");
					List<string> keys = VaultUtilityFX.ConvertJSON<List<string>>(js);
					return keys;
				}
				throw new ApplicationException("KV2Backend:ListSecretsAtPath  Arrived at unexpected code block.");
			}
			// 404 Errors mean there were no sub paths.  We just return an empty list.
			catch (VaultInvalidPathException e) { return new List<string>(); }
		}





		/// <summary>
		/// Allows one to change 2 metadata parameters of a secret - Max # of versions and the CAS setting.  Represents Vaults Update MetaData function for a secret.
		/// </summary>
		/// <param name="namePath"></param>
		/// <param name="maxVersions">The maximum number of versions of this key to keep.</param>
		/// <param name="casRequired">Boolean determining if the CAS parameter needs to be set on save/update of a key.</param>
		/// <returns></returns>
		public async Task<bool> UpdateSecretSettings (string namePath, UInt16 maxVersions, bool casRequired) {
			try {
				// V2 Secret stores have a unique config path...
				string path = MountPointPath + "metadata/" + namePath;

				// Build the content parameters, which will contain the maxVersions and casRequired settings.
				Dictionary<string, string> contentParams = new Dictionary<string, string>();
				contentParams.Add("max_versions", maxVersions.ToString());
				contentParams.Add("cas_required", casRequired.ToString());

				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "UpdateSecretSettings", contentParams);
				if (vdro.Success) { return true; }
				return false;
			}
			catch (Exception e) { throw e; }
		}



		/// <summary>
		/// Undeletes a given secret AND version.  
		/// </summary>
		/// <param name="namePath">The secret name to be undeleted.</param>
		/// <param name="version">The specific version of the secret to be unnamed.</param>
		/// <returns>True if successful.  False otherwise.</returns>
		public async Task<bool> UndeleteSecretVersion (string namePath, int version ) {
			try {
				// V2 Secret stores have a unique undelete path...
				string path = MountPointPath + "undelete/" + namePath;

				// Build the content parameters, which will contain the maxVersions and casRequired settings.
				Dictionary<string, string> contentParams = new Dictionary<string, string>();
				contentParams.Add("versions", version.ToString());

				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "UndeleteSecretVersion", contentParams);
				if (vdro.Success) { return true; }
				return false;
			}
			catch (Exception e) { throw e; }
		}




		/// <summary>
		/// Permanently deletes a given secret version.  This is unable to be undone.
		/// </summary>
		/// <param name="namePath">The secret name to be undeleted.</param>
		/// <param name="version">The specific version of the secret to be unnamed.</param>
		/// <returns>True if successful.  False otherwise.</returns>
		public async Task<bool> DestroySecretVersion (string namePath, int version) {
			try {
				// V2 Secret stores have a unique destroy path...
				string path = MountPointPath + "destroy/" + namePath;

				// Build the content parameters, which will contain the maxVersions and casRequired settings.
				Dictionary<string, string> contentParams = new Dictionary<string, string>();
				contentParams.Add("versions", version.ToString());

				VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "DestroySecretVersion", contentParams);
				if (vdro.Success) { return true; }
				return false;
			}
			catch (Exception e) { throw e; }
		}


		//TODO ReadSecretMetaData routine needed.
		public async Task<KV2SecretMetaDataInfo> GetSecretMetaData (string namePath) {
			try {

				// we need to use the MetaData Path
				string path = MountPointPath + "metadata/" + namePath;

				VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "GetSecretMetaData");
				if (vdro.Success) {
					string ks = vdro.GetDataPackageAsJSON();
					KV2SecretMetaDataInfo kvData = VaultUtilityFX.ConvertJSON<KV2SecretMetaDataInfo>(ks);
					return kvData;
				}
				return null;
			}
			catch (Exception e) { throw e; }

}



/// <summary>
/// Permanently destroys a secret, including all versions and metadata.
/// </summary>
/// <param name="namePath">The name of the secret to delete</param>
/// <returns>True if successful.</returns>
public async Task<bool> DestroySecretCompletely (string namePath) {
			try {
				// we need to use the MetaData Path
				string path = MountPointPath + "metadata/" + namePath;

				VaultDataResponseObject vdro = await _vaultHTTP.DeleteAsync(path, "DestroySecretCompletely");
				if (vdro.Success) { return true; }
				return false;
			}
			catch (Exception e) { throw e; }
		}
	}
}
