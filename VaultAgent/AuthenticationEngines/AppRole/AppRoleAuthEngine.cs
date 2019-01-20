using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultAgent.Backends;
using VaultAgent.Models;

namespace VaultAgent.AuthenticationEngines {
    /// <summary>
    /// The AppRoleAuthEngine represents the Vault AppRole backend authentication engine and all the service endpoints it exposes
    /// for the creation, updating, reading and deletion of AppRole's
    /// The following Vault API methods are implemented as indicated:
    ///   ListRoles					- Fully Implemented
    ///   Create Role				- Fully Implemented
    ///   Read Role					- Fully Implemented
    ///   Delete Role				- Fully Implemented
    ///   Read RoleID				- Fully Implemented
    ///   Update RoleID				- Fully Implemented
    ///   Generate New Secret ID	- Fully Implemented
    ///   List Secret ID Accesors			- Fully Implemented
    ///   Read App Role Secret ID			- Partially Implemented - metadata functionality not working correctly.
    ///   Destroy AppRole Secret ID			- Fully Implemented - Although there appears to be an internal Vault bug returning a 204 instead of a 404 or 400.
    ///   Read AppRole Secret Accessor		- Not Implemented
    ///   Destroy AppRole Secret Accessor	- Not Implemented
    ///   Create Custom AppRole Secret ID	- Not Implemented
    ///   Login						- Not Implemented
    ///   Read/Update/Delete Approle Properties		- Not Implemented
    /// 
    /// </summary>
    public class AppRoleAuthEngine : VaultAuthenticationBackend {
        /// <summary>
        /// Constructor for a custom AppRole authentication engine in Vault
        /// </summary>
        /// <param name="backendMountName"></param>
        /// <param name="backendMountPath"></param>
        /// <param name="httpConnector"></param>
        public AppRoleAuthEngine (string backendMountName, string backendMountPath, VaultAgentAPI vault) : base (backendMountName, backendMountPath, vault) {
            Type = EnumBackendTypes.A_AppRole;
            MountPointPrefix = "/v1/auth/";
        }



        /// <summary>
        /// Constructor for the default AppRole authentication backend in Vault.
        /// </summary>
        /// <param name="httpConnector"></param>
        public AppRoleAuthEngine (VaultAgentAPI vault) : base ("AppRole", "approle", vault) {
            Type = EnumBackendTypes.A_AppRole;
            MountPointPrefix = "/v1/auth/";
        }



        /// <summary>
        /// Saves the specified application role.  Creating it if it does not exist, and updating otherwise.  This only returns True or False upon saving.
        /// </summary>
        /// <param name="appRole" >The AppRole Object that you wish to be created or updated in Vault.</param>
        /// <returns>True if successful.</returns>
        /// <see cref="AppRole"/>
        public async Task<bool> SaveRole (AppRole appRole) {
            string path = MountPointPath + "role/" + appRole.Name;
            string json = JsonConvert.SerializeObject (appRole);


            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "AppRoleAuthEngine: SaveRole", json);
            if ( vdro.Success ) { return true; }
            else { return false; }
        }



        /// <summary>
        /// Saves the specified application role.  Creating it if it does not exist, and updating otherwise.  Returns a new version of the passed in appRole object or Null if it encountered an issue.
        /// </summary>
        /// <param name="appRole">The Name the Application Role should be saved under or updated as.</param>
        /// <returns>AppRole object as read from the Vault instance.  It will contain the RoleID token value also.</returns>
        public async Task<AppRole> SaveRoleAndReturnRoleObject (AppRole appRole) {
            if ( await SaveRole (appRole) ) {
                // Now Re-Read it:
                AppRole updatedRole = await ReadRole (appRole.Name, true);
                return updatedRole;
            }
            else { return null; }
        }



        /// <summary>
        /// Lists all Application Roles.  Returns an empty list if no roles found.
        /// </summary>
        /// <returns>List[string] of role names.  Empty list if no roles found.</returns>
        public async Task<List<string>> ListRoles () {
            string path = MountPointPath + "role";

            try {
                // Setup List Parameter
                Dictionary<string, string> contentParams = new Dictionary<string, string>() {{"list", "true"}};


                VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "ListRoles", contentParams);
                if ( vdro.Success ) {
	                List<string> keys = await vdro.GetDotNetObject<List<string>>("data.keys");
//                    string js = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "keys");
//                    List<string> keys = VaultUtilityFX.ConvertJSON<List<string>> (js);
                    return keys;
                }

                throw new ApplicationException ("AppRoleAuthEngine:ListRoles -> Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no roles.  We just return an empty list.
            catch ( VaultInvalidPathException e ) {
                e = null;
                return new List<string>();
            }
        }


		// This is an attempt at optimizing and changing the HTTP calls for faster performance.
	    /// <summary>
	    /// Lists all Application Roles.  Returns an empty list if no roles found.
	    /// </summary>
	    /// <returns>List[string] of role names.  Empty list if no roles found.</returns>
	    public async Task<List<string>> ListRoles_B() {
		    string path = MountPointPath + "role";
			
		    try {
			    // Setup List Parameter
			    Dictionary<string, string> contentParams = new Dictionary<string, string>() { { "list", "true" } };


			    VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B(path, "ListRoles", contentParams);
			    if (vdro.Success) {

				    List<string> keys2 = await vdro.GetDotNetObject<List<string>>("data.keys");
				    return keys2;
					/*
				    //string js = await vdro.AccessResponse();

					string js2 = vdro.GetJSONPropertyValue(js, "keys");
				    //List<string> keys = VaultUtilityFX.ConvertJSON<List<string>>(js2);
				    return keys;
					*/
			    }

			    throw new ApplicationException("AppRoleAuthEngine:ListRoles -> Arrived at unexpected code block.");
		    }

		    // 404 Errors mean there were no roles.  We just return an empty list.
		    catch (VaultInvalidPathException e) {
			    e = null;
			    return new List<string>();
		    }
	    }



/*
		/// <summary>
		/// Reads the AppRole with the given name.  Returns an AppRole object or Null if the AppRole does not exist.
		/// </summary>
		/// <param name="appRoleName">String name of the app role to retrieve.</param>
		/// <returns>AppRole object.</returns>
		public async Task<AppRole> ReadRole (string appRoleName, bool readRoleID = false) {
            string path = MountPointPath + "role/" + appRoleName;

            VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync (path, "ReadRole");
            if ( vdro.Success ) {
                AppRole appRole = vdro.GetVaultTypedObjectV2<AppRole>();
                appRole.Name = appRoleName;

                // Read the roleID if requested to:
                if ( readRoleID ) { appRole.RoleID = await ReadRoleID (appRole.Name); }

                return appRole;
            }

            return null;
        }
		*/


	    /// <summary>
	    /// Reads the AppRole with the given name.  Returns an AppRole object or Null if the AppRole does not exist.
	    /// </summary>
	    /// <param name="appRoleName">String name of the app role to retrieve.</param>
	    /// <returns>AppRole object.</returns>
		public async Task<AppRole> ReadRole(string appRoleName, bool readRoleID = false) {
		    string path = MountPointPath + "role/" + appRoleName;

		    VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B(path, "ReadRole");
		    if (vdro.Success) {
			    AppRole appRole = await vdro.GetDotNetObject<AppRole>("data");
			    appRole.Name = appRoleName;

				// Read the roleID if requested to:
				if (readRoleID) { appRole.RoleID = await ReadRoleID(appRole.Name); }

				return appRole;
			}
		    return null;
	    }


		/// <summary>
		/// Deletes the App Role from the vault.  Returns True if deleted OR did not exist.  False otherwise.
		/// </summary>
		/// <param name="appRole">AppRole object to be deleted</param>
		/// <returns>Bool:  True if deleted.  False otherwise</returns>
		public async Task<bool> DeleteRole (AppRole appRole) { return await DeleteRole (appRole.Name); }



        /// <summary>
        /// Deletes the AppRole with the given name.  Returns True if deleted OR did not exist.  False otherwise.
        /// </summary>
        /// <param name="appRoleName">AppRole name that should be deleted.</param>
        /// <returns>True if deleted OR did not exist.  False otherwise.</returns>
        public async Task<bool> DeleteRole (string appRoleName) {
            string path = MountPointPath + "role/" + appRoleName;


            VaultDataResponseObject vdro = await _parent._httpConnector.DeleteAsync (path, "DeleteRole");
            if ( vdro.Success ) { return true; }
            else { return false; }
        }


		/* Old Code - To be removed at a later time.
				/// <summary>
				/// Retrieves the AppRoleID of the given AppRole.
				/// </summary>
				/// <param name="appRoleName"></param>
				/// <returns>Returns a string representing the Role ID as stored in Vault.  Returns RoleID as empty string if RoleID could not be found.
				/// VaultInvalidPathException with SpecificErrorCode = ObjectDoesNotExist, if the Role does not exist.
				/// </returns>
				public async Task<string> ReadRoleID (string appRoleName) {
					string path = MountPointPath + "role/" + appRoleName + "/role-id";

					try {
						VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync (path, "ReadRoleID");
						return vdro.Success ? vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "role_id") : "";
					}
					catch ( VaultInvalidPathException e ) { return ""; }
				}
		*/

		/// <summary>
		/// Retrieves the AppRoleID of the given AppRole.
		/// </summary>
		/// <param name="appRoleName"></param>
		/// <returns>Returns a string representing the Role ID as stored in Vault.  Returns RoleID as empty string if RoleID could not be found.
		/// VaultInvalidPathException with SpecificErrorCode = ObjectDoesNotExist, if the Role does not exist.
		/// </returns>
		public async Task<string> ReadRoleID(string appRoleName) {
		    string path = MountPointPath + "role/" + appRoleName + "/role-id";

		    try {
			    VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B(path, "ReadRoleID");
			    return vdro.Success ? await vdro.GetDotNetObject<string>("data.role_id") : ""; 
		    }
		    catch (VaultInvalidPathException e) { return ""; }
	    }




		/// <summary>
		/// Updates the AppRoleID of the given AppRole to the value specified.
		/// </summary>
		/// <param name="appRoleName"></param>
		/// <param name="valueOfRoleID"></param>
		/// <returns>True if update of RoleID was successful.</returns>
		public async Task<bool> UpdateAppRoleID (string appRoleName, string valueOfRoleID) {
            string path = MountPointPath + "role/" + appRoleName + "/role-id";

            Dictionary<string, object> contentParams = new Dictionary<string, object>() {{"role_id", valueOfRoleID}};

            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "UpdateAppRoleID", contentParams);
			return vdro.HttpStatusCode == 204 ? true : false;
		}



        /// <summary>
        /// Generates and issues a new SecretID on an existing AppRole. 
        /// Similar to tokens, the response will also contain a secret_id_accessor value which can be used to read the properties of the SecretID 
        /// without divulging the SecretID itself, and also to delete the SecretID from the AppRole.
        /// Returns: AppRoleSecret representing the a secret ID Vault returned OR Null if it could not create the secret.
        /// </summary>
        /// <param name="appRoleName">Name of the AppRole to create a secret for.</param>
        /// <param name="metadata">Metadata to be tied to the SecretID. This should be a JSON-formatted string containing the metadata in key-value pairs. 
        /// This metadata will be set on tokens issued with this SecretID, and is logged in audit logs in plaintext.</param>
        /// <param name="cidrIPsAllowed">Comma separated string or list of CIDR blocks enforcing secret IDs to be used from specific set of IP addresses. 
        /// If bound_cidr_list is set on the role, then the list of CIDR blocks listed here should be a subset of the CIDR blocks listed on the role.</param>
        /// <returns>AppRoleSecret representing the a secret ID Vault returned.</returns>
        public async Task<AppRoleSecret> CreateSecretID (string appRoleName, Dictionary<string, string> metadata = null, List<string> cidrIPsAllowed = null) {
            string path = MountPointPath + "role/" + appRoleName + "/secret-id";


            Dictionary<string, object> contentParams = new Dictionary<string, object>();
            if ( metadata != null ) {
                string metadataString = JsonConvert.SerializeObject (metadata);
                contentParams.Add ("metadata", metadataString);
            }


            if ( cidrIPsAllowed != null ) {
                string cidrs = JsonConvert.SerializeObject (cidrIPsAllowed);
                contentParams.Add ("cidr_list", cidrs);
            }

            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "CreateSecretID", contentParams);
	        if ( vdro.Success ) { return await vdro.GetDotNetObject<AppRoleSecret>("data"); } 
	        else { return null; }
        }


        /// <summary>
        /// Generates a secret ID for a given Application Role.
        /// TODO - At this time this method does not support the cidr_list or token_bound_cidrs properties that restrict the IP addresses that can use a given token.
        /// </summary>
        /// <param name="returnFullSecret">Vault only returns an abbreviated secret object.  If you wish to have a fully populated one then set to true.  Default False.
        /// Note, that this in no way affects the secret itself.  By setting to true, we make an additional call to Vault to re-read the full secret object.  If you do not
        /// need the full secret information then leacing at false is faster.</param>
        /// <param name="vaultMetadata">A Vault MetaData object that should be attached to the given secret. </param>
        /// <returns>AppRoleSecret object.  Whether this is fully populated or contains just the ID and accessor depends upon the returnFullSecret parameter.</returns>
        public async Task<AppRoleSecret> GenerateSecretID (string appRoleName, bool returnFullSecret = false, Dictionary<string, string> vaultMetadata = null) {
            string path = MountPointPath + "role/" + appRoleName + "/secret-id";


            Dictionary<string, object> contentParams = new Dictionary<string, object>();
            if ( vaultMetadata != null ) {
                string metadataString = JsonConvert.SerializeObject (vaultMetadata);
                contentParams.Add ("metadata", metadataString);
            }


/*			if (cidrIPsAllowed != null) {
				string cidrs = JsonConvert.SerializeObject(cidrIPsAllowed);
				contentParams.Add("cidr_list", cidrs);
			}
*/
            try {
                VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "GenerateSecretID", contentParams);
                if ( vdro.Success ) {
                    AppRoleSecret appRoleSecret = await vdro.GetDotNetObject<AppRoleSecret>("data");
                    if ( returnFullSecret ) {
                        AppRoleSecret fullSecret = await ReadSecretID (appRoleName, appRoleSecret.ID);
                        return fullSecret;
                    }
                    else { return appRoleSecret; }

                }
                else { return null; }
            }
            catch ( VaultInvalidPathException e ) {
                if ( e.Message.Contains ("role") && e.Message.Contains ("does not exist") ) {
                    e.SpecificErrorCode = EnumVaultExceptionCodes.ObjectDoesNotExist;
                }

                throw e;
            }
        }



        /// <summary>
        /// Provides a list of all the secret ID accessors that are attached to a given role.
        /// </summary>
        /// <param name="roleName">The Rolename to list the secret ID accessors for.</param>
        /// <returns>List of secret ID accessors for a given role.</returns>
        public async Task<List<string>> ListSecretIDAccessors (string roleName) {
            string path = MountPointPath + "role/" + roleName + "/secret-id";

            try {
                // Setup List Parameter
                Dictionary<string, string> contentParams = new Dictionary<string, string>() {{"list", "true"}};


                VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "ListSecretIDAccessors", contentParams);
                if ( vdro.Success ) {
	                List<string> keys = await vdro.GetDotNetObject<List<string>>("data.keys");
/*
					string js = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "keys");
                    List<string> keys = VaultUtilityFX.ConvertJSON<List<string>> (js);
					*/
                    return keys;
                }

                throw new ApplicationException ("AppRoleAuthEngine:ListRoles -> Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no roles.  We just return an empty list.
            catch ( VaultInvalidPathException e ) {
                e = null;
                return new List<string>();
            }
        }



        /// <summary>
        /// Returns all the properties of a given secretID for a given role.  Returns null if the secretID could not be found.
        /// </summary>
        /// <param name="roleName">The name of the role that the secretID belongs to.</param>
        /// <param name="secretID">The specific secretID to retrieve information on.</param>
        /// <returns>The properties of the secretID</returns>
        public async Task<AppRoleSecret> ReadSecretID (string roleName, string secretID) {
            string path = MountPointPath + "role/" + roleName + "/secret-id/lookup";

            // Setup secret ID Parameter
            Dictionary<string, object> contentParams = new Dictionary<string, object>() {{"secret_id", secretID}};

            try {
                VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "ReadSecretID", contentParams);

                // Note: We cannot test for HTTP Success as Vault returns a 204 if secretID is not found - might be a bug - filed a post on Forum.
                // TODO - Follow up to see if this is a bug or feature.
                if ( vdro.HttpStatusCode == 200 ) {
                    AppRoleSecret secret = await vdro.GetDotNetObject<AppRoleSecret>();

                    // We need to do this as Vault does NOT return the ID of the secret in the data.
                    // TODO - Do we want to blank it out or continue filling it in....?
                    secret.ID = secretID;
                    return secret;
                }
                else { return null; }
            }
            catch ( VaultInvalidPathException e ) {
                e.SpecificErrorCode = EnumVaultExceptionCodes.ObjectDoesNotExist;
                throw e;
            }
        }



        /// <summary>
        /// Deletes the given secretID from the Vault.  Equivalent of Vault Destroy
        /// </summary>
        /// <param name="roleName">The Role that the secret is a part of.</param>
        /// <param name="secretID">The SecretID to delete.</param>
        /// <returns>True if the secret was deleted OR if it never existed.</returns>
        public async Task<bool> DeleteSecretID (string roleName, string secretID) {
            string path = MountPointPath + "role/" + roleName + "/secret-id/destroy";

            // Setup secret ID Parameter
            Dictionary<string, object> contentParams = new Dictionary<string, object>() {{"secret_id", secretID}};

            try {
                VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "DeleteSecretID", contentParams);
                return vdro.Success;
            }
            catch ( VaultInvalidPathException e ) {
                e.SpecificErrorCode = EnumVaultExceptionCodes.ObjectDoesNotExist;
                throw e;
            }
        }



        /// <summary>
        /// Logs the given secretID into the Application Role identified by RoleID.  RoleID is always required; if bind_secret_id is enabled (the default) on the AppRole, secretID is required also.
        /// Returns a populated Token object if successfull.  Returns Null if it failed due to invalid Role or Secret ID
        /// </summary>
        /// <param name="roleID">Required:  The RoleID value that you wish to login to.</param>
        /// <param name="secretID">Optional: The secretID to use to login to the role with.</param>
        /// <returns>Token object that was created, that can be used to access the Vault with.  The parent token has also been set to this same token.</returns>
        /// TODO - Change the return type.
        public async Task<Token> Login (string roleID, string secretID) {
            string path = MountPointPath + "login";

            // Setup roleID and secret ID Parameters
            Dictionary<string, string> contentParams = new Dictionary<string, string>()
            {
                {"role_id", roleID},
                {"secret_id", secretID}
            };

            try {
                VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync (path, "Login", contentParams);

                // Now convert the JSON returned by Vault into a LoginResponse object and then get the Client ID token value out of it.
                string js = vdro.GetResponsePackageFieldAsJSON ("auth");
                LoginResponse loginResponse = VaultUtilityFX.ConvertJSON<LoginResponse> (js);

                // We need to set the token and then refresh it.
                _parent.TokenID = loginResponse.ClientToken;
                await _parent.RefreshActiveToken();
                return _parent.Token;
            }


            catch ( VaultInvalidDataException e ) {
                // This means the secret ID is incorrect.
                if ( e.Message.Contains ("missing secret_id") ) {
                    VaultInvalidDataException newEx = new VaultInvalidDataException (
                        "The secret ID supplied is either not a valid Secret ID or it is not associated with the RoleID supplied.  The secretID must be valid and it must be associated with the provided RoleID.",
                        e);
                    newEx.SpecificErrorCode = EnumVaultExceptionCodes.LoginSecretID_NotFound;
                    throw newEx;
                }

                // RoleID is incorrect.
                else if ( e.Message.Contains ("missing role_id") ) {
                    VaultInvalidDataException newEx = new VaultInvalidDataException ("The RoleID supplied is invalid.  The RoleID must exist in the Vault.", e);
                    newEx.SpecificErrorCode = EnumVaultExceptionCodes.LoginRoleID_NotFound;
                    throw newEx;
                }

                throw e;
            }
        }



        /// <summary>
        /// Determines if a role exists.
        /// </summary>
        /// <param name="roleName">Name of the application Role to check.</param>
        /// <returns>True if the role exists.</returns>
        public async Task<bool> RoleExists (string roleName) {
            try {
                string roleID = await ReadRoleID (roleName);
                return (roleID != "") ? true : false;
            }

            catch ( VaultInvalidPathException e ) {
                if ( e.SpecificErrorCode == EnumVaultExceptionCodes.ObjectDoesNotExist ) { return false; }

                throw e;
            }
        }
    }
}