using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultAgent.Backends;
using VaultAgent.SecretEngines.KeyValue2;
using VaultAgent.SecretEngines.KV2;
using VaultAgent.SecretEngines.KV2.SecretMetaDataInfo;

namespace VaultAgent.SecretEngines
{
    /// <summary>
    /// Some Constants used by the KV2Secret Engine
    /// </summary>
    public static class Constants
    {
        /// <summary>
        /// Messages explaining the Error_CAS_Set
        /// </summary>
        public const string Error_CAS_Set =
            "The backend storage engine has the CAS property set.  This requires that all secret saves must have " +
            "the CAS value set to zero upon saving a new key or the latest version of the key must be specified in the version parameter.";

        /// <summary>
        /// Message explaining the Error_CAS_InvalidVersion
        /// </summary>
        public const string Error_CAS_InvalidVersion =
            "The backend storage engine has the CAS property set.  This requires that all secret saves must " +
            "specify the current version of the key in order to update it.  The calling routine provided an incorrect version.";

        /// <summary>
        /// Message explaining the Error_CAS_SecretAlreadyExists error
        /// </summary>
        public const string Error_CAS_SecretAlreadyExists =
            "The backend storage engine has the CAS property set.  In addition, the calling routine specified that the secret save should " +
            "only happen if the secret does not exist.  The secret already exists and thus cannot be saved.";
    }


    /// <summary>
    ///     This backend is for interfacing with the Vault secret Backend Version 2.0.
    ///     One of the unique things is that there are different root mounts within the given backend depending on what you
    ///     want to do.  So having
    ///     a std BackEnd path does not really work with this class.  It generally builds the unique path in each member
    ///     method.
    /// </summary>
    public class KV2SecretEngine : VaultSecretBackend
    {
        // ==============================================================================================================================================
        /// <summary>
        ///     Constructor.  Initializes the connection to Vault and stores the token.
        /// </summary>
        /// <param name="backendName">The name of the secret backend to mount.  This is purely cosmetic.</param>
        /// <param name="backendMountPoint">
        ///     The actual mount point that the secret is mounted to.  Exclude and prefix such as /v1/
        ///     and exclude trailing slash.
        /// </param>
        /// <param name="vaultAgentAPI">The Vault API Agent Object that contains connectivity information for authenticating and connecting to the Vault</param>
        public KV2SecretEngine(string backendName, string backendMountPoint, VaultAgentAPI vaultAgentAPI) : base(
            backendName, backendMountPoint,
            vaultAgentAPI)
        {
            Type = EnumBackendTypes.KeyValueV2;
            IsSecretBackend = true;
        }



        /// <summary>
        ///     Deletes the version of the secret requested - or the most recent version if version parameter is zero.
        /// </summary>
        /// <param name="secretPath">The name of the secret to delete.</param>
        /// <param name="version">The version to delete.  Defaults to zero which is the most recent or current version of the key.</param>
        /// <param name="isRecursiveDelete">If true, then a recursive delete is performed, ie, all subfolders / secrets are also deleted.</param>
        /// <returns>True if successful.  False otherwise.</returns>
        public async Task<bool> DeleteSecretVersion(string secretPath, int version = 0, bool isRecursiveDelete = true)
        {
            string path;
            VaultDataResponseObjectB vdro;

            // If recursive is true, then we need to navigate to deepest children and delete them and move up the chain.
            if (isRecursiveDelete)
            {
                // Get a list of children and then call DeleteSecret on each of them.
                KV2ListSecretSettings listSettings = new ()
                {
                    ShouldRecurseFolders = isRecursiveDelete,
                };
                
                List<string> children2 = await ListSecrets(secretPath,listSettings);

                for (int i = children2.Count -1; i > -1; i--)
                {
                        await DeleteSecretVersion(children2[i], 0, false);
                }

            }


            // Now delete the requested secret.
            try
            {
                // Paths are different if specifying versions or version = 0 (current)
                if (version != 0)
                {
                    path = MountPointPath + "delete/" + secretPath;

                    // Add the version parameter
                    string jsonParams = "{\"versions\": [" + version + "]}";
                    vdro = await ParentVault._httpConnector.PostAsync_B(path, "DeleteSecretVersion", jsonParams);
                    if (vdro.Success) return true;
                }
                else
                {
                    VaultDataResponseObjectB vdrb;
                    path = MountPointPath + "data/" + secretPath;
                    vdrb = await ParentVault._httpConnector.DeleteAsync(path, "DeleteSecretVersion");
                    if (vdrb.Success) return true;
                }

                return false;
            }
            catch (VaultForbiddenException e)
            {
                if (e.Message.Contains("* permission denied"))
                    e.SpecificErrorCode = EnumVaultExceptionCodes.PermissionDenied;

                throw e;
            }
        }



        /// <summary>
        ///     Deletes the version of the secret requested (Vault soft Delete) - or the most recent version if version parameter is zero.
        ///     <para> Set secretVersion parameter as follows:</para>
        ///     <para>  (Default) set to 0 to delete the most recent version.</para>
        ///     <para>  Set to -1 to use the version number specified in the secret object as the version to delete.</para>
        ///     <para>  Set to any positive number to delete that specific version from the Vault Instance Store.</para>
        /// </summary>
        /// <param name="secretObj">The KV2Secret object to be deleted from the Vault</param>
        /// <param name="secretVersion">The version of the secret to delete.</param>
        /// <param name="isRecursiveDelete">If true will delete all children secrets that are "folders"</param>
        /// <returns>True if successful.  False otherwise.</returns>
        public async Task<bool> DeleteSecretVersion(IKV2Secret secretObj, int secretVersion = 0, bool isRecursiveDelete = true)
        {
            if (secretVersion == -1) secretVersion = secretObj.Version;

            return await DeleteSecretVersion(secretObj.FullPath, secretVersion, isRecursiveDelete);
        }



        /// <summary>
        ///     Permanently destroys a secret, including all versions and metadata.
        /// </summary>
        /// <param name="secretNamePath">The name of the secret to delete</param>
        /// <returns>True if successful.</returns>
        public async Task<bool> DestroySecretCompletely(string secretNamePath)
        {
            try
            {
                // we need to use the MetaData Path
                string path = MountPointPath + "metadata/" + secretNamePath;

                VaultDataResponseObjectB vdro =
                    await ParentVault._httpConnector.DeleteAsync(path, "DestroySecretCompletely");
                if (vdro.Success) return true;

                return false;
            }
            catch (Exception)
            {
                throw;
            }
        }


        /// <summary>
        /// Completely destroys a secret, removing all evidence of it from the Vault
        /// </summary>
        /// <param name="secretObj">The Secret Object to be permanently removed</param>
        /// <returns></returns>
        public async Task<bool> DestroySecretCompletely(IKV2Secret secretObj)
        {
            return await DestroySecretCompletely(secretObj.FullPath);
        }



        /// <summary>
        ///     Permanently deletes a given secret version.  This is unable to be undone.
        /// </summary>
        /// <param name="secretNamePath">The secret name to be undeleted.</param>
        /// <param name="version">The specific version of the secret to be unnamed.</param>
        /// <returns>True if successful.  False otherwise.</returns>
        public async Task<bool> DestroySecretVersion(string secretNamePath, int version)
        {
            try
            {
                // V2 Secret stores have a unique destroy path...
                string path = MountPointPath + "destroy/" + secretNamePath;

                // Build the content parameters, which will contain the maxVersions and casRequired settings.
                Dictionary<string, string> contentParams = new ();
                contentParams.Add("versions", version.ToString());

                VaultDataResponseObjectB vdro =
                    await ParentVault._httpConnector.PostAsync_B(path, "DestroySecretVersion", contentParams);
                return vdro.Success;
            }
            catch (VaultForbiddenException e)
            {
                if (e.Message.Contains("* permission denied"))
                    e.SpecificErrorCode = EnumVaultExceptionCodes.PermissionDenied;

                throw e;
            }
        }


        /// <summary>
        /// Permanently deletes the given secret.
        /// </summary>
        /// <param name="secretObj">The secret object to be deleted</param>
        /// <param name="version">The specific version of the secret to be deleted.</param>
        /// <returns></returns>
        public async Task<bool> DestroySecretVersion(IKV2Secret secretObj, int version)
        {
            return await DestroySecretVersion(secretObj.FullPath, version);
        }



        /// <summary>
        ///     Returns the configuration settings of the current KeyValue V2 secret store.
        /// </summary>
        /// <returns>KV2BackendSettings object with the values of the current configuration.</returns>
        public async Task<KV2SecretEngineSettings> GetBackendConfiguration()
        {
            try
            {
                // V2 Secret stores have a unique config path...
                string path = MountPointPath + "config";

                VaultDataResponseObjectB
                    vdro = await ParentVault._httpConnector.GetAsync_B(path, "GetBackendConfiguration");
                return await vdro.GetDotNetObject<KV2SecretEngineSettings>();

                //IKV2SecretEngineSettings settings = vdro.GetVaultTypedObject<IKV2SecretEngineSettings>();
                //return settings;
            }
            catch (Exception)
            {
                throw;
            }
        }



        /// <summary>
        ///     Reads the Secret Metadata for the KeyValue V2 secret.  This includes version information, and critical timestamps
        ///     such as destroy, delete, create etc.
        /// </summary>
        /// <param name="secretNamePath">The path to the secret to get metadata on.</param>
        /// <returns>KV2SecretMetaDataInfo object</returns>
        public async Task<KV2SecretMetaDataInfo> GetSecretMetaData(string secretNamePath)
        {
            // we need to use the MetaData Path
            string path = MountPointPath + "metadata/" + secretNamePath;

            VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B(path, "GetSecretMetaData");
            if (vdro.Success)
            {
                KV2SecretMetaDataInfo kvData = await vdro.GetDotNetObject<KV2SecretMetaDataInfo>();
                return kvData;
            }

            return null;
        }



        /// <summary>
        ///     Returns the Secret MetaData Object Information for the provided Secret Object
        /// </summary>
        /// <param name="secretObj"></param>
        /// <returns></returns>
        public async Task<KV2SecretMetaDataInfo> GetSecretMetaData(IKV2Secret secretObj)
        {
            return await GetSecretMetaData(secretObj.FullPath);
        }



        /// <summary>
        /// Lists the secrets that are located at the given SecretPath.  Exactly what is returned is determined by the ListSettings parameter - it is optional
        /// </summary>
        /// <param name="secretPath">The path that you wish to list the secrets from</param>
        /// <param name="listSettings">Contains options that determine exactly which secrets the method will return as well as in what format.</param>
        /// <returns></returns>
        public async Task<List<string>> ListSecrets(string secretPath, KV2ListSecretSettings listSettings = null) { 
            if (listSettings == null)  listSettings = new KV2ListSecretSettings();

            // If recurse is set then ListAsFullPaths must be set.
            if (listSettings.ShouldRecurseFolders) listSettings.ListAsFullPaths = true;

            string path = MountPointPath + "metadata/" + secretPath + "?list=true";

            try
            {
                VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B(path, "ListSecrets");
                if (vdro.Success)
                {
                    List<string> secrets = await vdro.GetDotNetObject<List<string>>("data.keys");


                    // Remove secrets that are not parents (folders) if requested to do so
                    if (listSettings.ParentSecretsOnly)
                    {
                        for (int i = secrets.Count - 1; i > -1; i--)
                            if (!secrets[i].EndsWith("/"))
                                secrets.RemoveAt(i);
                    }


                    if (listSettings.FinalSecretsOnly)
                    {
                        for (int i = secrets.Count - 1; i > -1; i--)
                            if (secrets[i].EndsWith("/"))
                                secrets.RemoveAt(i);
                    }


                    // Add parent path to secret path if FullPath Secrets have been requested
                    if (listSettings.ListAsFullPaths)
                        for (int i = secrets.Count - 1; i > -1; i--)
                            if (secretPath.EndsWith("/"))
                                secrets[i] = secretPath  + secrets[i];
                            else
                                secrets[i] = secretPath + "/" + secrets[i];


                    // Do we need to recurse
                    if (listSettings.ShouldRecurseFolders && !listSettings.FinalSecretsOnly) {
                        List<string> subSecrets;
                        List<string> allSubSecrets = new ();
                        for (int i = secrets.Count - 1; i > -1; i--)
                        {
                            if (secrets[i].EndsWith("/"))
                            {
                                subSecrets = await ListSecrets(secrets[i], listSettings);
                                allSubSecrets.AddRange(subSecrets);
                            }
                        }

                        secrets.AddRange(allSubSecrets);
                    }
                    return secrets;
                }

                throw new ApplicationException("IKV2SecretEngine:ListSecrets Failed for unknown reason.");
            }

            // 404 Errors mean there were no sub paths.  We just return an empty list.
            catch (VaultInvalidPathException)
            {
                return new List<string>();
            }
            catch (Exception)
            {
                return new List<string>();
            }
        }



        /// <summary>
        ///     Returns a list of secrets at a given path.  If the parameter includeFolderSecrets is false (default) then it will
        ///     remove secret names with a trailing slash. This is generally what callers want.
        /// </summary>
        /// <param name="secretPath">
        ///     The path "folder" to retrieve secrets for.  This may be the entire path including the name (if
        ///     the secret has subfolders) or just a partial path.
        /// </param>
        /// <param name="includeFolderSecrets">
        ///     If false (default) it will remove secrets that contain a trailing slash which in
        ///     Vault indicates that this is a folder or parent to other secret objects
        /// </param>
        /// <param name="sorted">Whether the secrets should be sorted in alphabetical order</param>
        /// <returns>List of strings which contain secret names.</returns>
        /// <remarks>https://github.com/SlugEnt/VaultAPI/issues/3</remarks>
        [Obsolete("Use ListSecrets instead")]
        public async Task<List<string>> ListSecretsAtPath(string secretPath, bool includeFolderSecrets = false,
            bool sorted = false)
        {
            string path = MountPointPath + "metadata/" + secretPath + "?list=true";

            try
            {
                VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B(path, "ListSecrets");
                if (vdro.Success)
                {
                    List<string> secrets = await vdro.GetDotNetObject<List<string>>("data.keys");

                    if (includeFolderSecrets) return secrets;

                    // Caller only wants a secret listed once, remove any secrets witParentVaulth trailing slashes as these are the folder secrets.
                    for (int i = secrets.Count - 1; i > -1; i--)
                        if (secrets[i].EndsWith("/"))
                            secrets.RemoveAt(i);

                    // If caller wants to ensure the secrets are sorted, then do so.
                    if (sorted) secrets.Sort();

                    return secrets;
                }

                throw new ApplicationException("IKV2SecretEngine:ListSecretsAtPath  Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no sub paths.  We just return an empty list.
            catch (VaultInvalidPathException)
            {
                return new List<string>();
            }
        }


        /// <summary>
        /// Lists all the children secrets of the provided Secret Object
        /// </summary>
        /// <param name="secretObj">The secret object that you wish to get a list of children of</param>
        /// <returns></returns>
        [Obsolete("Use ListSecrets instead")]
        public async Task<List<string>> ListSecretsAtPath(IKV2Secret secretObj)
        {
            return await ListSecretsAtPath(secretObj.FullPath);
        }



        /// <summary>
        ///     Returns a list of secrets at a given path.  If the parameter includeFolderSecrets is true (default) then it will
        ///     remove secret names with a trailing slash. This is generally what callers want.
        /// </summary>
        /// <param name="secretPath">
        ///     The path "folder" to retrieve secrets for.  This may be the entire path including the name (if
        ///     the secret has subfolders) or just a partial path.
        /// </param>
        /// <param name="includeFolderSecrets">
        ///     If false (default) it will remove secrets that contain a trailing slash which in
        ///     Vault indicates that this is a folder or parent to other secret objects
        /// </param>
        /// <returns>List of strings which contain secret names.</returns>
        /// <remarks>https://github.com/SlugEnt/VaultAPI/issues/3</remarks>
        [Obsolete("There is no compatible replacement, you must implement sorting yourself")]
        public async Task<SortedList<string, string>> ListSecretsSorted(string secretPath,
            bool includeFolderSecrets = false)
        {
            string path = MountPointPath + "metadata/" + secretPath + "?list=true";

            try
            {
                VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B(path, "ListSecrets");
                if (vdro.Success)
                {
                    SortedList<string, string> secrets =
                        await vdro.GetDotNetObject<SortedList<string, string>>("data.keys");

                    if (includeFolderSecrets) return secrets;

                    // Caller only wants a secret listed once, remove any secrets with trailing slashes as these are the folder secrets.
                    for (int i = secrets.Count - 1; i > -1; i--)
                        if (secrets.Keys[i].EndsWith("/"))
                            secrets.RemoveAt(i);

                    return secrets;
                }

                throw new ApplicationException("IKV2SecretEngine:ListSecretsAtPath  Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no sub paths.  We just return an empty list.
            catch (VaultInvalidPathException)
            {
                return new SortedList<string, string>();
            }
        }




        /// <summary>
        ///     Returns a list of secrets at a given path and all child secret folders
        /// </summary>
        /// <param name="secretPath">
        ///     The path "folder" to retrieve secrets for.  This may be the entire path including the name (if
        ///     the secret has subfolders) or just a partial path.
        /// </param>
        /// <param name="recursiveList">If true then it will return a list of all children and there children and there children...</param>
        /// <returns>List of strings which contain secret names.</returns>
        /// <remarks>https://github.com/SlugEnt/VaultAPI/issues/3</remarks>
        [Obsolete("Use ListSecrets instead")]
        public async Task<List<string>> ListSecretFolders(string secretPath, bool recursiveList = false)
        {
            string path = MountPointPath + "metadata/" + secretPath + "?list=true";

            try
            {
                VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B(path, "ListSecrets");
                if (vdro.Success)
                {
                    List<string> secrets = await vdro.GetDotNetObject<List<string>>("data.keys");
                    List<string> allSubSecrets = new ();

                    // Caller only wants a secret listed once, remove any secrets witParentVaulth trailing slashes as these are the folder secrets.
                    for (int i = secrets.Count - 1; i > -1; i--)
                        if (!secrets[i].EndsWith("/"))
                            secrets.RemoveAt(i);
                        else
                            // Prefix the parent full path to this secret value which as returned from Vault is just the name
                            secrets[i] = secretPath + "/" + secrets[i];


                    if (recursiveList)
                    {
                        // Now we are left with secrets with children.
                        // Traverse each of these and add to list.
                        List<string> subSecrets;
                        for (int i = secrets.Count - 1; i > -1; i--)
                        {
                            subSecrets = await ListSecretFolders(secrets[i]);
                            allSubSecrets.AddRange(subSecrets);
                        }

                        secrets.AddRange(allSubSecrets);
                    }

                    return secrets;
                }

                throw new ApplicationException("IKV2SecretEngine:ListSecretsAtPath  Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no sub paths.  We just return an empty list.
            catch (VaultInvalidPathException)
            {
                return new List<string>();
            }
        }



        /// <summary>
        ///     Reads the secret from Vault.  It defaults to reading the most recent version.  Set secretVersion to non zero to
        ///     retrieve a specific version.
        ///     <para>Returns [VaultForbiddenException] if you do not have permission to read from the path.</para>
        ///     <para>Returns the IKV2SecretWrapper if a secret was found at the location.</para>
        ///     <para>Returns Null if no secret found at location.</para>
        /// </summary>
        /// <param name="secretPath">The Name (path) to the secret you wish to read.</param>
        /// <param name="secretVersion">The version of the secret to retrieve.  (Default) set to 0 to read most recent version. </param>
        /// <returns>IKV2Secret of the secret as read from Vault.  Returns null if there is no secret at that path.</returns>
        public async Task<T> ReadSecret<T>(string secretPath, int secretVersion = 0) where T : KV2SecretBase<T>
        {
            string path = MountPointPath + "data/" + secretPath;
            Dictionary<string, string> contentParams = new ();

            // TODO - Read secret will return an object for a version that has been destroyed or deleted.  We need to interrogate that
            // and try and find the next non deleted version.
            try
            {
                if (secretVersion > 0) contentParams.Add("version", secretVersion.ToString());

                VaultDataResponseObjectB vdro =
                    await ParentVault._httpConnector.GetAsync_B(path, "ReadSecret", contentParams);
                if (vdro.Success)
                {
                    KV2SecretWrapper<T> secretReadReturnObj = await vdro.GetDotNetObject<KV2SecretWrapper<T>>("");

                    // We now need to move some fields from the IKV2SecretWrapper into the IKV2Secret which is embedded in the 
                    // wrapper class.
                    secretReadReturnObj.Secret.CreatedTime = secretReadReturnObj.Data.Metadata.CreatedTime;
                    secretReadReturnObj.Secret.DeletionTime = (DateTimeOffset) secretReadReturnObj.Data.Metadata.DeletionTime;
                    secretReadReturnObj.Secret.IsDestroyed = secretReadReturnObj.Data.Metadata.Destroyed;
                    secretReadReturnObj.Secret.Version = secretReadReturnObj.Data.Metadata.Version;

                    // Now get the secret obj, remove it from the wrapper - so the class can be deleted and then return to caller.
                    T secret = secretReadReturnObj.Secret;

                    secretReadReturnObj.Secret = null;
                    return secret;
                }

                throw new ApplicationException("SecretBackEnd: ReadSecret - Arrived at an unexpected code path.");
            }

            // VaultInvalidPathExceptions are not permission problems - despite what the error text hints at.  Instead they just mean no secret exists at that path.  We return null.	
            catch (VaultInvalidPathException)
            {
                return null;
            }
            catch (VaultForbiddenException e)
            {
                if (e.Message.Contains("* permission denied"))
                    e.SpecificErrorCode = EnumVaultExceptionCodes.PermissionDenied;

                throw e;
            }
        }



        /// <summary>
        ///     Reads the specified secret from Vault.  It defaults to reading the most recent version of the secret.
        ///     <para>Returns [VaultForbiddenException] if you do not have permission to read from the path.</para>
        ///     <para>Returns the IKV2Secret if a secret was found at the location.</para>
        ///     <para>Returns Null if no secret found at location.</para>
        /// </summary>
        /// <param name="secretObj">
        ///     An existing IKV2Secret object that you wish to re-read.  The existing object will be deleted
        ///     and replaced with the values for the new.
        /// </param>
        /// <param name="secretVersion">
        ///     Version of the secret to retrieve.
        ///     <para>  (Default) set to 0 to read most recent version.</para>
        ///     <para>  Set to -1 to use the version number specified in the secret object.</para>
        ///     <para>  Set to any positive number to read that specific version from the Vault Instance Store.</para>
        /// </param>
        /// <returns>IKV2Secret of the secret as read from Vault.  Returns null if there is no secret at that path.</returns>
        public async Task<T> ReadSecret<T>(T secretObj, int secretVersion = 0) where T : KV2SecretBase<T>
        {
            if (secretVersion == -1) secretVersion = secretObj.Version;

            return await ReadSecret<T>(secretObj.FullPath, secretVersion);
        }



        /// <summary>
        ///     Saves the provided K2Secret object.  You must specify a save option and optionally what the current version of
        ///     the secret is.  The KV2Secret object's version # will be updated on success with what the new version of the
        ///     secret it.
        ///     If the CAS setting is set on the backend then the following errors may be returned:
        ///     <para></para>
        ///     <para>Commonly Throws the Following Errors:</para>
        ///     <para>
        ///         [VaultForbiddenException] - Errors with access.  The SpecifiedErrorCode field will be set to
        ///         EnumVaultExceptionCodes.PermissionDenied if token does not have
        ///         appropriate permissions to access the path.
        ///     </para>
        ///     <para>   [VaultInvalidDataException]</para>
        ///     <para>
        ///         [SpecificErrorCode] = EnumVaultExceptionCodes.CheckAndSetMissing - You specified an invalid casSaveOption
        ///         (AlwaysAllow is not valid for backend with CAS Set)
        ///         or the currentVersion parameter was invalid.
        ///     </para>
        ///     <para>
        ///         [SpecificErrorCode] = EnumVaultExceptionCodes.CAS_SecretExistsAlready - You set the casSaveOption to
        ///         only allow save to succeed if the secret does not yet exist.
        ///     </para>
        ///     <para>
        ///         [SpecificErrorCode] = EnumVaultExceptionCodes.CAS_VersionMissing - The version you specified was
        ///         invalid.  It must be equal to the current version number of the secret.
        ///     </para>
        /// </summary>
        /// <param name="secret">
        ///     IKV2Secret object to be saved.  This must contain minimally the Name and the Path of the secret
        ///     and one or more optional attributes.
        /// </param>
        /// <param name="casSaveOption">
        ///     This must be set to the CAS option you desired:
        ///     - OnlyIfKeyDoesNotExist = 0,
        ///     - OnlyOnExistingVersionMatch = 1,
        ///     - AlwaysAllow = 2  - Set to this value if the backend is not CAS enabled.  If CAS is enabled then this option will
        ///     result in an error.
        /// </param>
        /// <param name="currentVersion">
        ///     What the current version of the secret is.  Required if the backend is in CAS mode
        ///     (Default mode).
        /// </param>
        /// <returns></returns>
        //public async Task<bool> SaveSecret(IKV2Secret secret, KV2EnumSecretSaveOptions casSaveOption,
        //    int currentVersion = 0)
        public async Task<bool> SaveSecret<T>(T secret, KV2EnumSecretSaveOptions casSaveOption,
                                              int currentVersion = 0) where T : KV2SecretBase<T>
        {
            string path = MountPointPath + "data/" + secret.FullPath;


            Dictionary<string, object> reqData = new ();
            Dictionary<string, string> options = new ();

            // Set CAS depending on option coming from caller.
            switch (casSaveOption)
            {
                case KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist:
                    options.Add("cas", "0");
                    break;
                case KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch:
                    if (currentVersion != 0)
                        options.Add("cas", currentVersion.ToString());
                    else
                        throw new ArgumentException(
                            "The option OnlyOnExistingVersionMatch was chosen, but the currentVersion parameter was not set.  It must be set to the value of the current version of the key as stored in Vault.");

                    break;
            }


            // CAS - Check and Set needs to be passed in from caller.
            reqData.Add("options", options);
            reqData.Add("data", secret);

            try {
	            VaultDataResponseObjectB vdro = await ParentVault._httpConnector.PostAsync_B(path, "SaveSecret", reqData);
	            if ( vdro.Success ) {
		            KV2VaultReadSaveReturnObj obj = await vdro.GetDotNetObject<KV2VaultReadSaveReturnObj>();
		            if ( obj != null ) {
			            secret.Version = obj.Version;
			            secret.CreatedTime = obj.CreatedTime;
			            secret.DeletionTime = (DateTimeOffset) obj.DeletionTime;
			            secret.IsDestroyed = obj.Destroyed;
		            }

		            return true;
	            }

	            return false;
            }
            catch ( VaultInvalidDataException e ) {
	            if ( e.Message.Contains("check-and-set parameter required for this call") ) {
		            VaultInvalidDataException eNew = new (Constants.Error_CAS_Set + " | Original Error message was: " + e.Message);
		            eNew.SpecificErrorCode = EnumVaultExceptionCodes.CheckAndSetMissing;
		            throw eNew;
	            }

	            // Check for Version errors:

	            if ( e.Message.Contains("did not match the current version") ) {
		            // If user requested that the save happen only if the key does not already exist then return customized error message.
		            if ( casSaveOption == KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist ) {
			            VaultInvalidDataException eNew = new (
				            Constants.Error_CAS_SecretAlreadyExists + " | Original Error message was: " + e.Message);
			            eNew.SpecificErrorCode = EnumVaultExceptionCodes.CAS_SecretExistsAlready;
			            throw eNew;
		            }

		            // Customize the version discrepancy message
		            else {
			            VaultInvalidDataException eNew = new (
				            Constants.Error_CAS_InvalidVersion + " Version specified was: " + currentVersion + " | Original Error message was: " + e.Message);
			            eNew.SpecificErrorCode = EnumVaultExceptionCodes.CAS_VersionMissing;
			            throw eNew;
		            }
	            }

	            throw new VaultInvalidDataException(e.Message);
            }
            catch ( VaultForbiddenException e ) {
	            if ( e.Message.Contains("* permission denied") ) e.SpecificErrorCode = EnumVaultExceptionCodes.PermissionDenied;

	            throw;
            }
            catch ( Exception ) { throw; }
        }



        /// <summary>
        ///     Configures the Key Value V2 backend.
        /// </summary>
        /// <param name="maxVersions">The maximum number of versions of a key to keep.  Defaults to 10.</param>
        /// <param name="casRequired">
        ///     Check-And-Set parameter. If set to True then all writes (creates and updates) to keys will need to have the CAS
        ///     parameter specified.
        ///     See the Update and Create methods for details about the CAS setting. </param>
        ///     <returns></returns>
        public async Task<bool> SetBackendConfiguration(ushort maxVersions = 10, bool casRequired = false)
        {
            // V2 Secret stores have a unique config path...
            string path = MountPointPath + "config";

            // Build the content parameters, which will contain the maxVersions and casRequired settings.
            Dictionary<string, string> contentParams = new ();
            contentParams.Add("max_versions", maxVersions.ToString());
            contentParams.Add("cas_required", casRequired.ToString());

            VaultDataResponseObjectB vdro =
                await ParentVault._httpConnector.PostAsync_B(path, "ConfigureBackend", contentParams, false);
            return vdro.Success;
        }



        /// <summary>
        ///     Attempts to read a secret if it exists.  Returns a tuple value (bool success, IKV2Secret secret) as follows:
        ///     <para>If secret was found the first value is True and the 2nd value is the IKV2Secret that was read.</para>
        ///     <para>If not found OR YOU do not have permission, the first value is False and the second value is null.</para>
        /// </summary>
        /// <param name="secretPath">The path to the secret to check for existence and retrieve if it does exist.</param>
        /// <param name="secretVersion">The secret version to be read.  0 for current.</param>
        /// <returns></returns>
        public async Task<(bool IsSuccess, T Secret)> TryReadSecret<T>(string secretPath, int secretVersion = 0)
            where T : KV2SecretBase<T>
        {
            try
            {
                T secret = await ReadSecret<T>(secretPath, secretVersion);

                if (secret == null)
                    return (false, null);
                return (true, secret);
            }
            catch (VaultForbiddenException)
            {
                return (false, null);
            }
        }



        /// <summary>
        ///     Attempts to read a secret if it exists.  Returns a tuple value (bool success, T secret) as follows:
        ///     <para>Returns [VaultForbiddenException] if you do not have permission to read from the path.</para>
        ///     <para>If secret was found the first value is True and the 2nd value is the IKV2Secret that was read.</para>
        ///     <para>If not found, the first value is False and the second value is null.</para>
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="secretName">The name of the secret to retrieve</param>
        /// <param name="secretParentPath">The path that contains the secret</param>
        /// <param name="secretVersion">If you want a specific version of the secret, specify it here.  Otherwise it defaults to current version.</param>
        /// <returns></returns>
        public async Task<(bool IsSuccess, T Secret)> TryReadSecret<T>(string secretName, string secretParentPath,
            int secretVersion = 0) where T : KV2SecretBase<T>
        {
            return await TryReadSecret<T>(secretParentPath + "/" + secretName, secretVersion);
        }



        /// <summary>
        ///     Attempts to read a secret if it exists.  Returns a tuple value (bool success, IKV2Secret secret) as follows:
        ///     <para>Returns [VaultForbiddenException] if you do not have permission to read from the path.</para>
        ///     <para>If secret was found the first value is True and the 2nd value is the IKV2Secret that was read.</para>
        ///     <para>If not found, the first value is False and the second value is null.</para>
        /// </summary>
        /// <param name="secretObj">The secret object that should be Read.</param>
        /// <param name="secretVersion">
        ///     Version of the secret to retrieve.
        ///     <para>  (Default) set to 0 to read most recent version.</para>
        ///     <para>  Set to -1 to use the version number specified in the secret object.</para>
        ///     <para>  Set to any positive number to read that specific version from the Vault Instance Store.</para></param>
        ///     <returns></returns>
        public async Task<(bool IsSuccess, T Secret)> TryReadSecret<T>(T secretObj, int secretVersion = 0)
            where T : KV2SecretBase<T>
        {
            try
            {
                T secret = await ReadSecret<T>(secretObj.FullPath, secretVersion);

                if (secret == null)
                    return (false, null);
                return (true, secret);
            }
            catch (VaultForbiddenException)
            {
                return (false, null);
            }
        }



        /// <summary>
        ///     Undeletes a given secret AND version.
        /// </summary>
        /// <param name="secretsecretNamePath">The secret name and path to be undeleted.</param>
        /// <param name="version">The specific version of the secret to be unnamed.</param>
        /// <returns>True if successful.  False otherwise.</returns>
        public async Task<bool> UndeleteSecretVersion(string secretsecretNamePath, int version)
        {
            try
            {
                // V2 Secret stores have a unique undelete path...
                string path = MountPointPath + "undelete/" + secretsecretNamePath;

                // Build the content parameters, which will contain the maxVersions and casRequired settings.
                Dictionary<string, string> contentParams = new();
                contentParams.Add("versions", version.ToString());

                VaultDataResponseObjectB vdro =
                    await ParentVault._httpConnector.PostAsync_B(path, "UndeleteSecretVersion", contentParams);
                return vdro.Success;
            }
            catch (Exception)
            {
                throw;
            }
        }


        /// <summary>
        /// Undeletes the specified version of a secret
        /// </summary>
        /// <param name="secretObj">The secret object that should be undeleted</param>
        /// <param name="version">The specific version number to be undeleted.</param>
        /// <returns></returns>
        public async Task<bool> UndeleteSecretVersion(IKV2Secret secretObj, int version)
        {
            return await UndeleteSecretVersion(secretObj.FullPath, version);
        }



        /// <summary>
        ///     Allows one to change 2 metadata parameters of a secret - Max # of versions and the CAS setting.  Represents Vaults
        ///     Update MetaData function for a secret.
        /// </summary>
        /// <param name="secretsecretNamePath">The secret to be saved.  Includes the entire secret Path plus the Name.</param>
        /// <param name="maxVersions">The maximum number of versions of this key to keep.</param>
        /// <param name="casRequired">Boolean determining if the CAS parameter needs to be set on save/update of a key.</param>
        /// <returns></returns>
        public async Task<bool> UpdateSecretSettings(string secretsecretNamePath, ushort maxVersions, bool casRequired)
        {
            try
            {
                // V2 Secret stores have a unique config path...
                string path = MountPointPath + "metadata/" + secretsecretNamePath;

                // Build the content parameters, which will contain the maxVersions and casRequired settings.
                Dictionary<string, string> contentParams = new() { 
                    { "max_versions", maxVersions.ToString() },
                    { "cas_required", casRequired.ToString() },
                };
                
                //contentParams.Add("max_versions", maxVersions.ToString());
                //contentParams.Add("cas_required", casRequired.ToString());

                VaultDataResponseObjectB vdro =
                    await ParentVault._httpConnector.PostAsync_B(path, "UpdateSecretSettings", contentParams);
                if (vdro.Success) return true;

                return false;
            }
            catch (Exception)
            {
                throw;
            }
        }


        /// <summary>
        /// Updates the IKV2Secret objects settings based upon the parameters passed in.
        /// </summary>
        /// <param name="secretObj">The Secret Object to be updated</param>
        /// <param name="maxVersions">How many versions of the secret that should be kept</param>
        /// <param name="casRequired">Whether CAS is required or not</param>
        /// <returns></returns>
        public async Task<bool> UpdateSecretSettings(IKV2Secret secretObj, ushort maxVersions, bool casRequired)
        {
            return await UpdateSecretSettings(secretObj.FullPath, maxVersions, casRequired);
        }
    }
}