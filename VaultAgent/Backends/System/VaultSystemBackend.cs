using System;
using System.Collections.Generic;
using System.Data;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Text;
using VaultAgent.Models;
using Newtonsoft.Json;
using VaultAgent.Backends.System;

namespace VaultAgent {
    /// <summary>
    /// This class represents core Vault System Backend object.  This object is used to control the main Vault system such as mounting and enabling
    /// SecretEngines and AuthenticationEngines, policies, etc.
    /// </summary>
    public class VaultSystemBackend : VaultBackend {
        Token sysToken;

        const string pathMounts = "mounts/";



        // ==============================================================================================================================================
        /// <summary>
        /// Constructor.  Initializes the connection to Vault and stores the token.
        /// <param name="token">Token value that has permissions to Vault.</param>
        /// <param name="vaultAgentAPI">The Vault API Connector</param>
        /// <param name="name">The name you wish to give the Vault System backend.  At the present time this is purely cosmetic and does nothing.</param>
        /// </summary>
        public VaultSystemBackend (string token, VaultAgentAPI vaultAgentAPI, string name = "System") : base (name, "sys", vaultAgentAPI) {
            sysToken = new Token() {ID = token};
        }



        #region SysAuths


        /// <summary>
        /// Enables the provided Authentication backend.
        /// </summary>
        /// <param name="am">The AuthMethod object that represents the authentication engine to enable.</param>
        /// <returns>True if authentication engine was successfully enabled. False otherwise.
        /// Throws exception: VaultException with SpecificErrorCode set to BackendMountAlreadyExists if a mount already exists at that location.
        /// </returns>
        public async Task<bool> AuthEnable (AuthMethod am) {
            string path = MountPointPath + "auth/" + am.Name;

            Dictionary<string, string> contentParams = new Dictionary<string, string>();
            contentParams.Add ("path", am.Path);
            contentParams.Add ("description", am.Description);
            contentParams.Add ("type", am.TypeAsString);

            string contentJSON = JsonConvert.SerializeObject (contentParams, Formatting.None);


            StringBuilder jsonConfig;
            string json = "";
            if ( am.Config != null ) {
                jsonConfig = new StringBuilder (JsonConvert.SerializeObject (am.Config));
                jsonConfig.Insert (0, "\"config\":");

                // Combine the 2 JSON's, by stripping trailing closing brace from the content param JSON string.
                StringBuilder jsonParams = new StringBuilder (contentJSON, (contentJSON.Length + jsonConfig.Length + 20));
                jsonParams.Remove (jsonParams.Length - 1, 1);
                jsonParams.Append (",");

                // Remove the opening brace.
                jsonParams.Append (jsonConfig);
                jsonParams.Append ("}");

                json = jsonParams.ToString();
            }
            else { json = contentJSON; }


            try {
                VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "VaultSystemBackend:AuthEnable", json, false);
	            return vdro.Success;
            }
            catch ( VaultInvalidDataException e ) {
                if ( e.Message.Contains ("path is already in use") ) {
                    VaultException ex =
                        new VaultException ("The authentication backend mount point already exists.  Cannot enable another mount point at that location.");
                    ex.SpecificErrorCode = EnumVaultExceptionCodes.BackendMountAlreadyExists;
                    throw ex;
                }
                else
                    throw e;
            }
        }



        /// <summary>
        /// Disables the authentication method at the given path.
        /// </summary>
        /// <param name="authName"></param>
        /// <returns></returns>
        public async Task<bool> AuthDisable (string authName) {
            string path = MountPointPath + "auth/" + authName;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.DeleteAsync (path, "AuthDisable");
            if ( vdro.Success ) { return true; }
            else { return false; }
        }




        /// <summary>
        /// Disables the given authentication method 
        /// </summary>
        /// <param name="am">The AuthMethod that should be disabled</param>
        /// <returns></returns>
        public async Task<bool> AuthDisable (AuthMethod am) { return await AuthDisable (am.Name); }




        /// <summary>
        /// Lists all authentication methods in the current Vault System.
        /// <returns>Dictionary\string,AuthMethod> containing all Authentication Methods</returns>
        /// </summary>
        public async Task<Dictionary<string, AuthMethod>> AuthListAll () {
            string path = MountPointPath + "auth";

            VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "AuthListAll");
            if ( vdro.Success ) {
	            Dictionary<string, AuthMethod> methods = await vdro.GetDotNetObject<Dictionary<string, AuthMethod>>();

                // We need to place the dictionary key into each objects path value. 
                foreach ( KeyValuePair<string, AuthMethod> kv in methods ) { kv.Value.Path = kv.Key; }

                return methods;
            }

            throw new ApplicationException ("KeyValueSecretEngine:ListSecrets  Arrived at unexpected code block.");
        }


        /// <summary>
        /// Returns true if the authentication provider with the given name exists.  False otherwise.
        /// </summary>
        /// <param name="authName"></param>
        /// <returns></returns>
        public async Task<bool> AuthExists(string authName)
        {
            string path = MountPointPath + "auth";

            VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B(path, "AuthExists");
            if (vdro.Success)
            {
                Dictionary<string, AuthMethod> methods = await vdro.GetDotNetObject<Dictionary<string, AuthMethod>>();

                // Now see if path exists - Auth names from vault have a trailing slash.
                if (methods.ContainsKey(authName + "/"))
                {
                    return true;
                }
            }
            return false;
        }

        #endregion


        #region SysAudit


        /// <summary>
        /// Creates a new audit device with the specified name.
        /// </summary>
        /// <param name="auditorName">A name to be given to the audit device</param>
        /// <param name="filePath">A full path and filename specification of where the audit entries should be written.</param>
        /// <param name="description">A description of the audit device.</param>
        /// <returns>True if successfully created.</returns>
        public async Task<bool> AuditEnableFileDevice (string auditorName, string filePath, string description = "Audit to file") {
            string path = MountPointPath + "audit/" + auditorName;

            Dictionary<string, string> contentParams = new Dictionary<string, string>()
            {
                {"description", description},
                {"type", "file"}
            };


	        string inputVarsJSON = VaultSerializationHelper.ToJson(contentParams); //JsonConvert.SerializeObject (contentParams, Formatting.None);
            Dictionary<string, string> optionsList = new Dictionary<string, string>()
            {
                //{ "path",@"c:\temp\avault.log" }
                {"path", filePath}
            };

            // Build entire JSON Body:  Input Params + Bulk Items List.
            string bulkJSON = JsonConvert.SerializeObject (new {options = optionsList}, Formatting.None);


            // Combine the 2 JSON's
            if ( contentParams.Count > 0 ) {
                string newVarsJSON = inputVarsJSON.Substring (1, inputVarsJSON.Length - 2) + ",";
                bulkJSON = bulkJSON.Insert (1, newVarsJSON);
            }


            VaultDataResponseObjectB vdro = await _parent._httpConnector.PutAsync (path, "SysAuditEnableFileDevice", null, bulkJSON);
            return vdro.Success;

            //TODO Cleanup
            //if ( vdro.HttpStatusCode == 204 ) { return true; }
            //else { return false; }
        }



        /// <summary>
        /// Disables (deletes? Not Sure) the specified audit device
        /// </summary>
        /// <param name="auditDeviceName">Name of the Audit device to delete.</param>
        /// <returns>True if audit device successfully deleted.  False otherwise.</returns>
        public async Task<bool> AuditDisable (string auditDeviceName) {
            string path = MountPointPath + "audit/" + auditDeviceName;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.DeleteAsync (path, "SysAuditDisable");
            if ( vdro.Success ) { return true; }
            else { return false; }
        }


        #endregion


        #region "SysCapabilities"


        /// <summary>
        /// Returns a Dictionary of objects and the permissions they contains, as well as an overall Capabilities object that summarizes the
        /// permissions that a Token has on the List of paths provided.
        /// <para>https://www.vaultproject.io/api/system/capabilities.html</para>
        /// </summary>
        /// <param name="tokenID">The Token to evaluate</param>
        /// <param name="paths">A list of paths to check the token against</param>
        /// <returns></returns>
        public async Task<Dictionary<string, List<string>>> GetTokenCapabilityOnPaths (string tokenID, List<string> paths) {
            string path = MountPointPath + "capabilities";

            // Add the token and paths parameters
            Dictionary<string, object> contentParams = new Dictionary<string, object>()
            {
                {"token", tokenID},
                {"paths", paths}
            };


            try {
                VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "GetTokenCapabilityOnPaths", contentParams);
                if ( vdro.Success ) {
	                Dictionary<string, List<string>> capabilities = await vdro.GetDotNetObject<Dictionary<string, List<string>>>();
                    return capabilities;
                }

                throw new ApplicationException ("IdentitySecretEngine:ListEntitiesByName -> Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no entities.  We just return an empty list.
            catch ( VaultInvalidPathException) {
                return null;
            }
        }


        #endregion


        #region SysMounts


        // ==============================================================================================================================================



        /// <summary>
        /// Creates a secret backend of the specified type at the specified mount path.  Upon completion it establishes a connection to the backend.
        /// </summary>
        /// <param name="secretBackendType">The type of backend you wish to connect to.</param>
        /// <param name="backendName">The name you wish to refer to this backend by.  This is NOT the Vault mount path.</param>
        /// <param name="backendMountPath">The path to the vault mount point that this backend is located at.</param>
        /// <param name="description">Description for the backend</param>
        /// <param name="config">(Optional) A VaultSysMountConfig object that contains the connection configuration you wish to use to connect to the backend.  If not specified defaults will be used.</param>
        /// <returns>True if it was able to create the backend and connect to it.  False if it encountered an error.</returns>
        public async Task<bool> CreateSecretBackendMount(EnumSecretBackendTypes secretBackendType,
                                                                  string backendName,
                                                                  string backendMountPath,
                                                                  string description,
                                                                  VaultSysMountConfig config = null)
        {
            VaultSysMountConfig backendConfig;

            if (config == null)
            {
                backendConfig = new VaultSysMountConfig
                {
                    DefaultLeaseTTL = "30m",
                    MaxLeaseTTL = "90m",
                    VisibilitySetting = "hidden"
                };
            }
            else { backendConfig = config; }

            return  await SysMountCreate(backendMountPath, description, secretBackendType, backendConfig);
            //if (rc == true) { return ConnectToSecretBackend(secretBackendType, backendName, backendMountPath); }

//            return null;
        }




        /// <summary>
        /// Creates (Enables in Vault terminology) a new backend secrets engine with the given name, type and configuration settings.
        /// Throws:  [VaultInvalidDataException] when the mount point already exists.  SpecificErrorCode will be set to: [BackendMountAlreadyExists]
        /// <param name="mountPath">The root path to this secrets engine that it will be mounted at.  Is a part of every URL to this backend.</param>
        /// <param name="description">Brief human friendly name for the mount.</param>
        /// <param name="backendType">The type of secrets backend this mount is.  </param>
        /// <param name="config">The configuration to be applied to this mount.</param>
        /// <returns>Bool:  True if successful in creating the backend mount point.  False otherwise.</returns>
        /// </summary>
        public async Task<bool> SysMountCreate (string mountPath, string description, EnumSecretBackendTypes backendType, VaultSysMountConfig config = null) {
        // The keyname forms the last part of the path
        string path = MountPointPath + pathMounts + mountPath;


            // Build out the parameters dictionary.
            Dictionary<string, object> createParams = new Dictionary<string, object>();

            // Build Options Dictionary
            Dictionary<string, string> options = new Dictionary<string, string>();

            string typeName = "";

            switch ( backendType ) {
                case EnumSecretBackendTypes.Transit:
                    typeName = "transit";
                    break;
                case EnumSecretBackendTypes.Secret:
                    typeName = "kv";
                    break;
                case EnumSecretBackendTypes.AWS:
                    typeName = "aws";
                    throw new NotImplementedException();
                case EnumSecretBackendTypes.CubbyHole:
                    typeName = "cubbyhole";
                    throw new NotImplementedException();
                case EnumSecretBackendTypes.Generic:
                    typeName = "generic";
                    throw new NotImplementedException();
                case EnumSecretBackendTypes.PKI:
                    typeName = "pki";
                    throw new NotImplementedException();
                case EnumSecretBackendTypes.SSH:
                    typeName = "ssh";
                    throw new NotImplementedException();
                case EnumSecretBackendTypes.KeyValueV2:

                    // It is the same type as a version 1, but it has an additional config value.
                    typeName = "kv";
                    options.Add ("version", "2");
                    break;
            }

            createParams.Add ("type", typeName);
            createParams.Add ("description", description);
            createParams.Add ("options", options);

            if ( config != null ) { createParams.Add ("config", config); }

            try {
                VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "SysMountEnable", createParams,false);
                if ( vdro.HttpStatusCode == 204 ) { return true; }
                else { return false; }
            }
            catch ( VaultInvalidDataException e ) {
                if ( e.Message.Contains ("path is already in use") ) { e.SpecificErrorCode = EnumVaultExceptionCodes.BackendMountAlreadyExists; }

                throw e;
            }
        }


        /// <summary>
        /// [Not Implemented Yet] Returns a List of Secret Engines
        /// </summary>
        /// <returns></returns>
        public List<string> SysMountListSecretEngines () {
            // Build Path
            string path = MountPointPath + pathMounts;

            throw new NotImplementedException ("SysMountListSecretEngines Not implemented Yet");
        }



        /// <summary>
        /// Deletes the backend Mount.
        /// </summary>
        /// <param name="name">Name of the mount to delete.</param>
        /// <returns>True if successful.  False otherwise.</returns>
        public async Task<bool> SysMountDelete (string name) {
            string path = MountPointPath + pathMounts + name;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.DeleteAsync (path, "SysMountDelete");
            if ( vdro.Success ) { return true; }

            return false;
        }



        /// <summary>
        /// Reads the configuration for the given backend mount point.
        /// </summary>
        /// <param name="mountPath">The Name(path) of the backend to read the configuration for.</param>
        /// <returns><see cref="VaultSysMountConfig"/>VaultSysMountConfig object containing the configuration settings.</returns>
        public async Task<VaultSysMountConfig> SysMountReadConfig (string mountPath) {
            // Build Path
            string path = MountPointPath + pathMounts + mountPath + "/tune";

            VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "SysMountReadConfig",null);
            if ( vdro.Success ) {
	            return await vdro.GetDotNetObject<VaultSysMountConfig>();
            }

            return null;
        }



        /// <summary>
        /// Attempts to read the sys mount config to determine if the path exists or not.  Returns true if the path exists, false otherwise
        /// </summary>
        /// <param name="mountPath">The name (path) of the backend to verify the existence of</param>
        /// <returns></returns>
        public async Task<bool> SysMountExists(string mountPath)
        {
            // Build Path
            string path = MountPointPath + pathMounts + mountPath + "/tune";

            try
            {
                VaultDataResponseObjectB vdro =
                    await _parent._httpConnector.GetAsync_B(path, "SysMountReadConfig", null);
                if (vdro.Success) return true;
            }
            catch (VaultInvalidDataException ve)
            {
                if (ve.Message.Contains("cannot fetch sysview for path")) return false;
                throw ve;
            }

            return false;
        }


        /// <summary>
        /// Updates the configuration of a given system mount point.  If description is null then it will not be updated.
        /// </summary>
        /// <param name="Name">The name of the mount to update</param>
        /// <param name="config"><see cref="VaultSysMountConfig"/>The backend's configuration changes</param>
        /// <param name="description">If set, the description will be updated.  </param>
        /// <returns>True if successfull.  False otherwise.</returns>
        public async Task<bool> SysMountUpdateConfig (string Name, VaultSysMountConfig config, string description = null) {
            string path = MountPointPath + pathMounts + Name + "/tune";

            Dictionary<string, string> content = new Dictionary<string, string>
            {
                {"default_lease_ttl", config.DefaultLeaseTTL},
                {"max_lease_ttl", config.MaxLeaseTTL},
                {"audit_non_hmac_request_keys", config.RequestKeysToNotAuditViaHMAC},
                {"audit_non_hmac_response_keys", config.ResponseKeysToNotAuditViaHMAC},
                {"listing_visibility", config.VisibilitySetting},
                {"passthrough_request_headers", config.PassThruRequestHeaders}
            };


            if ( description != null ) { content.Add ("description", description); }

            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "SysMountUpdateConfig", content,false);
	        return vdro.Success;
        }


        #endregion


        #region SysPolicies


        /// <summary>
        /// Returns a list of all ACL Policies in the Vault Instance
        /// </summary>
        /// <returns>List[string] of all ACL policies by name.</returns>
        public async Task<List<string>> SysPoliciesACLList () {
            // Build Path
            string path = MountPointPath + "policies/acl";

            // Setup List Parameters
            Dictionary<string, string> sendParams = new Dictionary<string, string>();
            sendParams.Add ("list", "true");

            VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "SysPoliciesACLList", sendParams);
	        return  await vdro.GetDotNetObject<List<string>>("data.keys");
			//TODO Cleanup
			/*

			string js = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "keys");

            List<string> keys = VaultUtilityFX.ConvertJSON<List<string>> (js);
            return keys;
			*/
        }



        /// <summary>
        /// Deletes a given policy.  
        /// </summary>
        /// <param name="policyName">The name of the policy to delete.</param>
        /// <returns>True if successful in deleting.</returns>
        public async Task<bool> SysPoliciesACLDelete (string policyName) {
            // Build Path
            string path = MountPointPath + "policies/acl/" + policyName;


            try {
                VaultDataResponseObjectB vdro = await _parent._httpConnector.DeleteAsync (path, "SysPoliciesACLDelete");
                if ( vdro.Success ) { return true; }
                else { return false; }
            }
            catch ( VaultInvalidPathException ) { return false; }

        }



        /// <summary>
        /// Creates or Updates a given policy object.  
        /// </summary>
        /// <param name="policyContainerItem">The VaultPolicyContainer item that should be persisted into the Vault Instance Store.</param>
        /// <returns>True if successfully saved into Vault Instance.  False otherwise.</returns>
        public async Task<bool> SysPoliciesACLCreate (VaultPolicyContainer policyContainerItem) {
            // Build Path
            string path = MountPointPath + "policies/acl/" + policyContainerItem.Name;

            int count = policyContainerItem.PolicyPaths.Count;

            // If no policy paths defined, then return - nothing to do.
            if ( count == 0 ) { return false; }


            // Build the JSON - Lots of string escaping, etc.  fun!

            StringBuilder jsonBody = new StringBuilder();

            // Build the body of the JSON policy out.  We add the prefix part only if there is a body.
            foreach ( VaultPolicyPathItem item in policyContainerItem.PolicyPaths.Values ) { jsonBody.Append (item.ToVaultHCLPolicyFormat()); }

            // If the VaultPolicyPathItem is still at new initialized state then throw error as there is no permission settings to send to Vault.
            if ( jsonBody.Length == 0 ) {
                throw new ArgumentException (
                    "The PolicyContainer contained one or more VaultPolicyPathItem(s) at their initial state - undefined.  You must supply a VaultPolicyPathItem with at least one permission set.");
            }

            jsonBody.Insert (0, "{\"policy\": \"");

            // Issue the policy documents closing quote and then end the JSON.
            jsonBody.Append ("\"}");

            //jsonBody.Append("}");

            string json = jsonBody.ToString();

            VaultDataResponseObjectB vdro = await _parent._httpConnector.PutAsync (path, "SysPoliciesACLCreate", null, json);
            if ( vdro.Success ) { return true; }
            else { return false; }
        }



        /// <summary>
        /// Updates a given policy.  Is merely a wrapper for SysPoliciesACLCreate since Vault has no update function.
        /// </summary>
        /// <param name="policyContainerItem">The VaultPolicyPathItem object that should be updated in Vault.</param>
        /// <returns>True if successful.  False otherwise.</returns>
        public async Task<bool> SysPoliciesACLUpdate (VaultPolicyContainer policyContainerItem) { return await SysPoliciesACLCreate (policyContainerItem); }



        /// <summary>
        /// Returns true if a policy exists, false if it does not.  This is a much more efficient and faster operation than calling Read, if all you need to
        /// know is if the Policy exists.  
        /// </summary>
        /// <param name="policyName"></param>
        /// <returns></returns>
        public async Task<bool> SysPoliciesACLExists(string policyName)
        {
            // Build Path
            string path = MountPointPath + "policies/acl/" + policyName;
            VaultDataResponseObjectB vdro;

            try
            {
                vdro = await _parent._httpConnector.GetAsync_B(path, "SysPoliciesACLRead");
                return true;
            }
            catch (VaultInvalidPathException e)
            {
                return false;
            }

        }



        /// <summary>
        /// Reads the Vault policy with the given name.
        /// <para>Returns the VaultPolicyContainer object or throws an error.</para>
        /// <para>Throws: VaultInvalidPathException with SpecificErrorCode property set to ObjectDoesNotExist if not found</para>
        /// </summary>
        /// <param name="policyName">Name of the policy to retrieve.</param>
        /// <returns>A VaultPolicyContainer object with the values read from Vault.</returns>
        public async Task<VaultPolicyContainer> SysPoliciesACLRead (string policyName) {
            // Build Path
            string path = MountPointPath + "policies/acl/" + policyName;
            VaultDataResponseObjectB vdro;

            try {
                vdro = await _parent._httpConnector.GetAsync_B (path, "SysPoliciesACLRead");
                
            }
            catch ( VaultInvalidPathException e ) {
                e.SpecificErrorCode = EnumVaultExceptionCodes.ObjectDoesNotExist;
                throw e;
            }


            // Now we need to cleanup the returned data and then parse it.
            // Strings we need to replace in the received text.  Must be replaced in this order!
            Dictionary<string, string> replaceStrings = new Dictionary<string, string>()
            {
                {"\r\n", ""},
                {"\\", ""},
                {"\"", ""},
                {"path ", " |PATH| "},
                {"{ capabilities = ", " { |CAPA| "},
                {"[", " [ "}, // Mark start of an array.
                {"]", " ] "} // Mark end of an array.
            };

	        string val = await vdro.GetDotNetObject<string>("data.policy");
	        //vdro.GetDataPackageAsDictionary();
			//string val = vdro.GetDataPackageFieldAsJSON ("policy");


            StringBuilder sb = new StringBuilder (val, val.Length * 2);
            foreach ( string k in replaceStrings.Keys ) { sb.Replace (k, replaceStrings [k]); }


            // Create a policy object and load the paths
            VaultPolicyContainer vp = new VaultPolicyContainer (policyName);


            // Now we need to parse the Paths.  
            ParseACLPaths (sb.ToString(), vp);
            return vp;
        }



        /// <summary>
        /// Internal routine that processes the returned string from Vault and parses it into a VaultPolicyContainer object.
        /// </summary>
        /// <param name="data">The string data returned by Vault.</param>
        /// <param name="vp">VaultPolicyContainer object that should be filled in with the values from Vault.</param>
        /// <returns>True if successful.</returns>
        private bool ParseACLPaths (string data, VaultPolicyContainer vp) {
            string [] strDelimiters = {" ", ","};
            string [] pathObjects = data.Split (strDelimiters, StringSplitOptions.RemoveEmptyEntries);

            bool starting = true;
            const string sPATH = "|PATH|";
            const string sCAPA = "|CAPA|";
            const string sLISTSTART = "{";
            const string sLISTEND = "}";
            const string sARRAYSTART = "[";
            const string sARRAYEND = "]";

            const short iSTARTING = 0;
            const short iPATHLIST = 1;
            const short iPATHOPTIONS = 2;
            const short iCAP = 200;

            List<string> keyWords = new List<string>()
            {
                sPATH,
                sCAPA,
                sLISTSTART,
                sLISTEND,
                sARRAYSTART,
                sARRAYEND
            };


            // We need to create a default object or else it will not compile.  
            VaultPolicyPathItem newPathObj = new VaultPolicyPathItem ("dummy/dummy2");

            // Used so we can determine what type of path the permission is being applied to.  Complicated.  
            string KV2Path = "";


            short iStep = iSTARTING;

            // Now process thru the data elements.
            for ( int i = 0; i < pathObjects.Length; i++ ) {
                switch ( iStep ) {
                    case iSTARTING:

                        // PATH must be first value if starting.
                        if ( pathObjects [i] == sPATH ) {
                            iStep++;
                            starting = true;

                            // Make sure the next item is not a keyword.
                            i++;
                            if ( keyWords.Contains (pathObjects [i]) ) {
                                throw new FormatException ("Found path keyword, but no value supplied for path NAME");
                            }
                            else {
                                VaultPolicyPathItem tempItem = new VaultPolicyPathItem (pathObjects [i]);
                                KV2Path = tempItem.KV2_PathID;

                                // If there is not a Policy permission object for this path in the Policy Container then use the new one.  Otherwise use existing.
                                if ( !vp.PolicyPaths.TryGetValue (tempItem.Key, out newPathObj) ) {
                                    newPathObj = tempItem;
                                    vp.AddPolicyPathObject (newPathObj);
                                }

                            }
                        }
                        else {
                            string err = string.Join ("", "First element must be the PATH identifier.  Found: ", pathObjects [i].ToString(), " instead.");
                            throw new FormatException (err);
                        }

                        break;
                    case iPATHLIST:

                        // We should be looking for the iPATH List identifier - {
                        if ( (pathObjects [i] == sLISTSTART) && (starting) ) {
                            starting = false;

                            // Now see what type of parameter the next item is.
                            i++;
                            switch ( pathObjects [i] ) {
                                case sCAPA:

                                    // It's a capabilities type.  Now add items until we reach the end of the capabilities list.
                                    iStep = iCAP;

                                    // The next item should be opening array.
                                    if ( pathObjects [++i] != sARRAYSTART ) {
                                        throw new FormatException ("Found the capabilities identifier, but did not find the opening array symbol - [");
                                    }

                                    break;
                            } // END switch pathObjects[i]
                        } // END if sLISTSTART && starting

                        break;
                    case iCAP:
                        if ( pathObjects [i] == sLISTSTART ) { iStep++; }
                        else if ( pathObjects [i] == sARRAYEND ) {
                            // Done with the capabilities.  
                            iStep = iPATHOPTIONS;
                        }
                        else {
                            // It must be a valid capability  AND we need to know what the path Prefix is so we can set the appropriate permission.
                            switch ( pathObjects [i] ) {
                                case "create":
                                    newPathObj.CreateAllowed = true;
                                    break;

                                case "read":
                                    switch ( KV2Path ) {
                                        case "":
                                        case "data":
                                            newPathObj.ReadAllowed = true;
                                            break;
                                        case "metadata":
                                            newPathObj.ExtKV2_ViewMetaData = true;
                                            break;
                                    }

                                    newPathObj.ReadAllowed = true;
                                    break;

                                case "update":
                                    switch ( KV2Path ) {
                                        case "":
                                        case "data":
                                            newPathObj.UpdateAllowed = true;
                                            break;
                                        case "delete":
                                            newPathObj.ExtKV2_DeleteAnyKeyVersion = true;
                                            break;
                                        case "undelete":
                                            newPathObj.ExtKV2_UndeleteSecret = true;
                                            break;
                                        case "destroy":
                                            newPathObj.ExtKV2_DestroySecret = true;
                                            break;
                                        default:
                                            throw new DataException (
                                                "Trying to set Update Permission for a VaultPolicyPathItem object resulted in arriving at an unexpected code path.  Do not know what to do.  Aborting.");                                           
                                    }

                                    break;

                                case "delete":
                                    switch ( KV2Path ) {
                                        case "":
                                        case "data":
                                            newPathObj.DeleteAllowed = true;
                                            break;
                                        case "metadata":
                                            newPathObj.ExtKV2_DeleteMetaData = true;
                                            break;
                                        default:
                                            throw new DataException (
                                                "Trying to set Delete permission for a VaultPolicyPathItem object resulted in arriving at an unexpected code path.  Do not know what to do.  Aborting.");
                                    }

                                    break;

                                case "list":
                                    switch ( KV2Path ) {
                                        case "":
                                        case "data":
                                            newPathObj.ListAllowed = true;
                                            break;
                                        case "metadata":
                                            newPathObj.ExtKV2_ListMetaData = true;
                                            break;
                                        default:
                                            throw new DataException (
                                                "Trying to set List permission for a VaultPolicyPathItem object resulted in arriving at an unexpected code path.  Do not know what to do.  Aborting.");
                                    }

                                    break;

                                case "sudo":
                                    newPathObj.SudoAllowed = true;
                                    break;

                                case "deny":
                                    newPathObj.Denied = true;
                                    break;
                            }
                        }

                        break;

                    // Search for PATH options
                    case iPATHOPTIONS:
                        if ( pathObjects [i] == sLISTEND ) {
                            // Done with this path object.
                            iStep = iSTARTING;
                        }

                        break;
                } // END SWITCH istep
            } // END of for loop.

            return true;
        } // END of method.


        #endregion
    }


    // ==============================================================================================================================================
    // ==============================================================================================================================================
    // ==============================================================================================================================================
    // ==============================================================================================================================================
    // ==============================================================================================================================================
}