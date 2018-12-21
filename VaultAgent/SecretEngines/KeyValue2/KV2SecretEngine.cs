using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultAgent.Backends;
using VaultAgent.SecretEngines.KV2;
using VaultAgent.SecretEngines.KV2.SecretMetaDataInfo;

namespace VaultAgent.SecretEngines {
    public static class Constants {
        public const string Error_CAS_Set = "The backend storage engine has the CAS property set.  This requires that all secret saves must have " +
                                            "the CAS value set to zero upon saving a new key or the latest version of the key must be specified in the version parameter.";

        public const string Error_CAS_InvalidVersion = "The backend storage engine has the CAS property set.  This requires that all secret saves must " +
                                                       "specify the current version of the key in order to update it.  The calling routine provided an incorrect version.";

	    public const string Error_CAS_SecretAlreadyExists =
		    "The backend storage engine has the CAS property set.  In addition, the calling routine specified that the secret save should " +
		    "only happen if the secret does not exist.  The secret already exists and thus cannot be saved.";

    }



    /// <summary>
    /// This backend is for interfacing with the Vault secret Backend Version 2.0.  
    /// One of the unique things is that there are different root mounts within the given backend depending on what you want to do.  So having
    /// a std BackEnd path does not really work with this class.  It generally builds the unique path in each member method.
    /// </summary>
    public class KV2SecretEngine : VaultSecretBackend {
        // ==============================================================================================================================================
        /// <summary>
        /// Constructor.  Initializes the connection to Vault and stores the token.
        /// </summary>
        /// <param name="backendName">The name of the secret backend to mount.  This is purely cosmetic.</param>
        /// <param name="backendMountPoint">The actual mount point that the secret is mounted to.  Exclude and prefix such as /v1/ and exclude trailing slash.</param>
        /// <param name="_httpConnector">The VaultAPI_Http object that should be used to make all Vault API calls with.</param>
        public KV2SecretEngine (string backendName, string backendMountPoint, VaultAgentAPI vaultAgentAPI) : base (backendName, backendMountPoint,
            vaultAgentAPI) {
            Type = EnumBackendTypes.KeyValueV2;
            IsSecretBackend = true;
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
                contentParams.Add ("max_versions", maxVersions.ToString());
                contentParams.Add ("cas_required", casRequired.ToString());

                VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync (path, "ConfigureBackend", contentParams);
                if (vdro.Success) { return true; }

                return false;
            }
            catch (Exception e) { throw e; }
        }



        /// <summary>
        /// Returns the configuration settings of the current KeyValue V2 secret store. 
        /// </summary>
        /// <returns>KV2BackendSettings object with the values of the current configuration.</returns>
        public async Task<KV2SecretEngineSettings> GetBackendConfiguration() {
            try {

                // V2 Secret stores have a unique config path...
                string path = MountPointPath + "config";

                VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync (path, "GetBackendConfiguration");
                KV2SecretEngineSettings settings = vdro.GetVaultTypedObject<KV2SecretEngineSettings>();
                return settings;
            }
            catch (Exception e) { throw e; }
        }

        #endregion



        /// <summary>
        /// Saves the provided KV2Secret object.  You must specify a save option and optionally what the current version of the secret is.
        /// If the CAS setting is set on the backend then the following errors may be returned:
        /// <para></para>
        /// <para>Commonly Throws the Following Errors:</para>
        /// <para>  [VaultForbiddenException] - Erros with access.  The SpecifiedErrorCode field will be set to EnumVaultExceptionCodes.PermissionDenied if token does not have
        /// appropriate permissions to access the path.</para>
        /// <para>   [VaultInvalidDataException]</para>
        /// <para>     [SpecificErrorCode] = EnumVaultExceptionCodes.CheckAndSetMissing - You specified an invalid casSaveOption (AlwaysAllow is not valid for backend with CAS Set)
        ///			or the currentVersion parameter was invalid. </para>
        /// <para>     [SpecificErrorCode] = EnumVaultExceptionCodes.CAS_SecretExistsAlready - You set the casSaveOption to only allow save to succeed if the secret does not yet exist.</para>
        /// <para>     [SpecificErrorCode] = EnumVaultExceptionCodes.CAS_VersionMissing - The version you specified was invalid.  It must be equal to the current version number of the secret.</para>
        /// 
        /// </summary>
        /// <param name="secret">KV2Secret object to be saved.  This must contain minimally the Name and the Path of the secret and one or more optional attributes.</param>
        /// <param name="casSaveOption">This must be set to the CAS option you desired:
        ///   - OnlyIfKeyDoesNotExist = 0,
        ///   - OnlyOnExistingVersionMatch = 1,
        ///   - AlwaysAllow = 2  - Set to this value if the backend is not CAS enabled.  If CAS is enabled then this option will result in an error.
        /// </param>
        /// <param name="currentVersion">What the current version of the secret is.  Required if the backend is in CAS mode (Default mode).</param>
        /// <returns></returns>
        public async Task<bool> SaveSecret (KV2Secret secret, KV2EnumSecretSaveOptions casSaveOption, int currentVersion = 0) {
            string path = MountPointPath + "data/" + secret.FullPath;


            Dictionary<string, object> reqData = new Dictionary<string, object>();
            Dictionary<string, string> options = new Dictionary<string, string>();

            // Set CAS depending on option coming from caller.
            switch (casSaveOption) {
                case KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist:
                    options.Add ("cas", "0");
                    break;
                case KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch:
                    if (currentVersion != 0) { options.Add ("cas", currentVersion.ToString()); }
                    else {
                        throw new ArgumentException (
                            "The option OnlyOnExistingVersionMatch was chosen, but the currentVersion parameter was not set.  It must be set to the value of the current version of the key as stored in Vault.");
                    }

                    break;
            }


            // CAS - Check and Set needs to be passed in from caller.
            reqData.Add ("options", options);
            reqData.Add ("data", secret);

		    try {
		        VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync2 (path, "SaveSecret", reqData);
		        if (vdro.Success) { return true; }

		        return false;
		    }
		    catch (VaultInvalidDataException e) {
		        if (e.Message.Contains ("check-and-set parameter required for this call")) {
		            VaultInvalidDataException eNew = new VaultInvalidDataException (Constants.Error_CAS_Set + " | Original Error message was: " + e.Message);
		            eNew.SpecificErrorCode = EnumVaultExceptionCodes.CheckAndSetMissing;
		            throw eNew;
		        }

		        // Check for Version errors:
		        else if (e.Message.Contains ("did not match the current version")) {
		            // If user requested that the save happen only if the key does not already exist then return customized error message.
		            if (casSaveOption == KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist) {
		                VaultInvalidDataException eNew = new VaultInvalidDataException (Constants.Error_CAS_SecretAlreadyExists +
		                                                                                " | Original Error message was: " + e.Message);
		                eNew.SpecificErrorCode = EnumVaultExceptionCodes.CAS_SecretExistsAlready;
		                throw eNew;
		            }

		            // Customize the version discrepancy message
		            else {
		                VaultInvalidDataException eNew = new VaultInvalidDataException (Constants.Error_CAS_InvalidVersion + " Version specified was: " +
		                                                                                currentVersion +
		                                                                                " | Original Error message was: " + e.Message);
		                eNew.SpecificErrorCode = EnumVaultExceptionCodes.CAS_VersionMissing;
		                throw eNew;
		            }
		        }
		        else { throw new VaultInvalidDataException (e.Message); }
		    }
		    catch (VaultForbiddenException e) {
		        if (e.Message.Contains ("* permission denied")) { e.SpecificErrorCode = EnumVaultExceptionCodes.PermissionDenied;  }
		        throw e;
            }
        }




        /// <summary>
        /// Reads the secret from Vault.  It defaults to reading the most recent version.  Set secretVersion to non zero to retrieve a
        /// specific version.
        /// Returns [VaultForbiddenException] if you do not have permission to read from the path.
        /// Returns the KV2SecretWrapper if a secret was found at the location.
        /// Returns Null if no secret found at location.
        /// </summary>
        /// <param name="secretPath">The Name (path) to the secret you wish to read.</param>
        /// <param name="secretVersion">The version of the secret to retrieve.  (Default) set to 0 to read most recent version. </param>
        /// <returns>KV2Secret of the secret as read from Vault.  Returns null if there is no secret at that path.</returns>
        public async Task<KV2Secret> ReadSecret (string secretPath, int secretVersion = 0) {
            string path = MountPointPath + "data/" + secretPath;
            Dictionary<string, string> contentParams = new Dictionary<string, string>();

            // TODO - Read secret will return an object for a version that has been destroyed or deleted.  We need to interrogate that
            // and try and find the next non deleted version.
            try {
                if (secretVersion > 0) { contentParams.Add ("version", secretVersion.ToString()); }

                VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync (path, "ReadSecret", contentParams);
                if (vdro.Success) {
                    KV2SecretWrapper secretReadReturnObj = KV2SecretWrapper.FromJson (vdro.GetResponsePackageAsJSON());

					// We now need to move some fields from the KV2SecretWrapper into the KV2Secret which is embedded in the 
					// wrapper class.
	                secretReadReturnObj.Secret.CreatedTime = secretReadReturnObj.Data.Metadata.CreatedTime;
	                secretReadReturnObj.Secret.DeletionTime = secretReadReturnObj.Data.Metadata.DeletionTime;
	                secretReadReturnObj.Secret.Destroyed = secretReadReturnObj.Data.Metadata.Destroyed;
	                secretReadReturnObj.Secret.Version = secretReadReturnObj.Data.Metadata.Version;

					// Now get the secret obj, remove it from the wrapper - so the class can be deleted and then return to caller.
	                KV2Secret secret = secretReadReturnObj.Secret;
	                secretReadReturnObj.Secret = null;
	                return secret;
                    }

                throw new ApplicationException ("SecretBackEnd: ReadSecret - Arrived at an unexpected code path.");
            }

            // VaultInvalidPathExceptions are not permission problems - despite what the error text hints at.  Instead they just mean no secret exists at that path.  We return null.	
            catch (VaultInvalidPathException e) { return null; }
            catch (VaultForbiddenException e) {
                if (e.Message.Contains ("* permission denied")) { e.SpecificErrorCode = EnumVaultExceptionCodes.PermissionDenied; }
                throw e;
            }
        }



		 
		/// <summary>
		/// Version of Read Secret that returns a tuple.  First Tuple Value is a boolean and is True if the Secret exists and was able to be read.  Returns false, if it does not exist.
		/// By default it checks against the current version of a secret.
		/// </summary>
		/// <param name="secretPath">The path to the secret to check for existence and retrieve if it does exist.</param>
		/// <returns></returns>
		public async Task<(bool IsSuccess, KV2Secret Secret)> TryReadSecret(string secretPath, int secretVersion = 0) {
		    KV2Secret secret = await ReadSecret(secretPath, secretVersion);

		    if (secret == null) {
			    return (false, null);
		    }
		    else {
			    return (true, secret);
		    }
	    }




        /// <summary>
        /// Deletes the most recent version of a secret or a specific version of a secret.  
        /// </summary>
        /// <param name="secretPath">The name of the secret to delete.</param>
        /// <param name="version">The version to delete.  Defaults to zero which is the most recent or current version of the key.</param>
        /// <returns>True if successful.  False otherwise.</returns>
        public async Task<bool> DeleteSecretVersion (string secretPath, int version = 0) {
            string path;
            VaultDataResponseObject vdro;

            try {
                // Paths are different if specifying versions or version = 0 (current)
                if (version != 0) {
                    path = MountPointPath + "delete/" + secretPath;

                    // Add the version parameter
                    string jsonParams = "{\"versions\": [" + version.ToString() + "]}";
                    vdro = await _parent._httpConnector.PostAsync (path, "DeleteSecretVersion", null, jsonParams);
                }
                else {
                    path = MountPointPath + "data/" + secretPath;
                    vdro = await _parent._httpConnector.DeleteAsync (path, "DeleteSecretVersion");
                }


                if (vdro.Success) { return true; }
                else { return false; }
            }
            catch (VaultForbiddenException e) {
                if (e.Message.Contains("* permission denied")) {
                    e.SpecificErrorCode = EnumVaultExceptionCodes.PermissionDenied;
                }
                throw e;
            }
        }






        /// <summary>
        /// Returns a list of secrets at a given path
        /// </summary>
        /// <param name="secretPath">The path "folder" to retrieve secrets for.  This may be the entire path including the name (if the secret has subfolders) or just a partial path. </param>
        /// <returns>List of strings which contain secret names.</returns>
        public async Task<List<string>> ListSecretsAtPath (string secretPath) {
            string path = MountPointPath + "metadata/" + secretPath + "?list=true";

            try {
                VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync (path, "ListSecrets");
                if (vdro.Success) {
                    string js = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "keys");
                    List<string> keys = VaultUtilityFX.ConvertJSON<List<string>> (js);
                    return keys;
                }

                throw new ApplicationException ("KV2SecretEngine:ListSecretsAtPath  Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no sub paths.  We just return an empty list.
            catch (VaultInvalidPathException e) { return new List<string>(); }
        }





        /// <summary>
        /// Allows one to change 2 metadata parameters of a secret - Max # of versions and the CAS setting.  Represents Vaults Update MetaData function for a secret.
        /// </summary>
        /// <param name="secretsecretNamePath">The secret to be saved.  Includes the entire secret Path plus the Name.</param>
        /// <param name="maxVersions">The maximum number of versions of this key to keep.</param>
        /// <param name="casRequired">Boolean determining if the CAS parameter needs to be set on save/update of a key.</param>
        /// <returns></returns>
        public async Task<bool> UpdateSecretSettings (string secretsecretNamePath, UInt16 maxVersions, bool casRequired) {
            try {
                // V2 Secret stores have a unique config path...
                string path = MountPointPath + "metadata/" + secretsecretNamePath;

                // Build the content parameters, which will contain the maxVersions and casRequired settings.
                Dictionary<string, string> contentParams = new Dictionary<string, string>();
                contentParams.Add ("max_versions", maxVersions.ToString());
                contentParams.Add ("cas_required", casRequired.ToString());

                VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync (path, "UpdateSecretSettings", contentParams);
                if (vdro.Success) { return true; }

                return false;
            }
            catch (Exception e) { throw e; }
        }



        /// <summary>
        /// Undeletes a given secret AND version.  
        /// </summary>
        /// <param name="secretsecretNamePath">The secret name and path to be undeleted.</param>
        /// <param name="version">The specific version of the secret to be unnamed.</param>
        /// <returns>True if successful.  False otherwise.</returns>
        public async Task<bool> UndeleteSecretVersion (string secretsecretNamePath, int version) {
            try {
                // V2 Secret stores have a unique undelete path...
                string path = MountPointPath + "undelete/" + secretsecretNamePath;

                // Build the content parameters, which will contain the maxVersions and casRequired settings.
                Dictionary<string, string> contentParams = new Dictionary<string, string>();
                contentParams.Add ("versions", version.ToString());

                VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync (path, "UndeleteSecretVersion", contentParams);
                if (vdro.Success) { return true; }

                return false;
            }
            catch (Exception e) { throw e; }
        }




        /// <summary>
        /// Permanently deletes a given secret version.  This is unable to be undone.
        /// </summary>
        /// <param name="secretNamePath">The secret name to be undeleted.</param>
        /// <param name="version">The specific version of the secret to be unnamed.</param>
        /// <returns>True if successful.  False otherwise.</returns>
        public async Task<bool> DestroySecretVersion (string secretNamePath, int version) {
            try {
                // V2 Secret stores have a unique destroy path...
                string path = MountPointPath + "destroy/" + secretNamePath;

                // Build the content parameters, which will contain the maxVersions and casRequired settings.
                Dictionary<string, string> contentParams = new Dictionary<string, string>();
                contentParams.Add ("versions", version.ToString());

                VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync (path, "DestroySecretVersion", contentParams);
                if (vdro.Success) { return true; }

                return false;
            }
            catch (VaultForbiddenException e) {
                if (e.Message.Contains ("* permission denied")) { e.SpecificErrorCode = EnumVaultExceptionCodes.PermissionDenied;}
                throw e;
            }
        }



        /// <summary>
        /// Reads the Secret Metadata for the KeyValue V2 secret.  This includes version information, and critical timestamps such as destroy, delete, create etc.
        /// </summary>
        /// <param name="secretNamePath">The path to the secret to get metadata on.</param>
        /// <returns>KV2SecretMetaDataInfo object</returns>
        public async Task<KV2SecretMetaDataInfo> GetSecretMetaData (string secretNamePath) {
            // we need to use the MetaData Path
            string path = MountPointPath + "metadata/" + secretNamePath;

            VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync (path, "GetSecretMetaData");
            if (vdro.Success) {
                string ks = vdro.GetDataPackageAsJSON();
                KV2SecretMetaDataInfo kvData = VaultUtilityFX.ConvertJSON<KV2SecretMetaDataInfo> (ks);
                return kvData;
            }

            return null;
        }



        /// <summary>
        /// Permanently destroys a secret, including all versions and metadata.
        /// </summary>
        /// <param name="secretNamePath">The name of the secret to delete</param>
        /// <returns>True if successful.</returns>
        public async Task<bool> DestroySecretCompletely (string secretNamePath) {
            try {
                // we need to use the MetaData Path
                string path = MountPointPath + "metadata/" + secretNamePath;

                VaultDataResponseObject vdro = await _parent._httpConnector.DeleteAsync (path, "DestroySecretCompletely");
                if (vdro.Success) { return true; }

                return false;
            }
            catch (Exception e) { throw e; }
        }



        #region "KV2Secret Object Methods"

        public async Task<bool> DestroySecretCompletely (KV2Secret secretObj) { return await DestroySecretCompletely (secretObj.FullPath); }
        public async Task<bool> DestroySecretVersion (KV2Secret secretObj, int version) { return await DestroySecretVersion (secretObj.FullPath, version); }
        public async Task<bool> UndeleteSecretVersion (KV2Secret secretObj, int version) { return await UndeleteSecretVersion (secretObj.FullPath, version); }

        public async Task<bool> UpdateSecretSettings (KV2Secret secretObj, UInt16 maxVersions, bool casRequired) {
            return await UpdateSecretSettings (secretObj.FullPath, maxVersions, casRequired);
        }

        public async Task<List<string>> ListSecretsAtPath (KV2Secret secretObj) { return await ListSecretsAtPath (secretObj.FullPath); }
        public async Task<bool> DeleteSecretVersion (KV2Secret secretObj, int version=0) { return await DeleteSecretVersion (secretObj.FullPath, version); }



        /// <summary>
        /// Reads the specified secret from Vault.  It defaults to reading the most recent version of the secret.
        /// <para>Returns [VaultForbiddenException] if you do not have permission to read from the path.</para>
        /// <para>Returns the KV2Secret if a secret was found at the location.</para>
        /// <para>Returns Null if no secret found at location.</para>
        /// </summary>
        /// <param name="secretObj">An existing KV2Secret object that you wish to re-read.  The existing object will be deleted and replaced with the values for the new.</param>
        /// <param name="secretVersion">Version of the secret to retrieve.
        /// <para>  (Default) set to 0 to read most recent version.</para>
        /// <para>  Set to -1 to use the version number specified in the secret object.</para>
        /// <para>  Set to any positive number to read that specific version from the Vault Instance Store.</para>
        /// </param>
        /// <returns>KV2Secret of the secret as read from Vault.  Returns null if there is no secret at that path.</returns>
        public async Task<KV2Secret> ReadSecret (KV2Secret secretObj, int secretVersion = 0) {
            if (secretVersion == -1) { secretVersion = secretObj.Version;}
            return await ReadSecret (secretObj.FullPath, secretVersion);
        }


	    public async Task<(bool IsSuccess, KV2Secret Secret)> TryReadSecret(KV2Secret secretObj, int secretVersion = 0) {
			var result = await TryReadSecret(secretObj.FullPath, secretVersion);
		    return (result.IsSuccess, result.Secret);
		}


		public async Task<KV2SecretMetaDataInfo> GetSecretMetaData (KV2Secret secretObj) { return await GetSecretMetaData (secretObj.FullPath); }

        #endregion


    }
}