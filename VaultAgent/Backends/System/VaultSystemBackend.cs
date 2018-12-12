using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text;
using VaultAgent.Models;
using Newtonsoft.Json;
using VaultAgent.Backends.System;

namespace VaultAgent
{

    /// <summary>
    /// This class represents core Vault System Backend object.  This object is used to control the main Vault system such as mounting and enabling
    /// SecretEngines and AuthenticationEngines, policies, etc.
    /// </summary>
	public class VaultSystemBackend : VaultBackend
	{
		Token sysToken;

		const string pathMounts = "mounts/";





		// ==============================================================================================================================================
		/// <summary>
		/// Constructor.  Initializes the connection to Vault and stores the token.
		/// <param name="token">Token value that has permissions to Vault.</param>
		/// <param name="vaultAPI_Http">The Vault API Connector</param>
		/// <param name="name">The name you wish to give the Vault System backend.  At the present time this is purely cosmetic and does nothing.</param>
		/// </summary>
		public VaultSystemBackend(string token, VaultAgentAPI vaultAgentAPI, string name = "System") : base (name,"sys",vaultAgentAPI){

			sysToken = new Token() {
				ID = token
			};
		}



		#region SysAuths

		/// <summary>
		/// Enables the provided Authentication backend.
		/// </summary>
		/// <param name="am">The AuthMethod object that represents the authentication engine to enable.</param>
		/// <returns>True if authentication engine was successfully enabled. False otherwise.
		/// Throws exception: VaultException with SpecificErrorCode set to BackendMountAlreadyExists if a mount already exists at that location.
		/// </returns>
		public async Task<bool> AuthEnable(AuthMethod am) {
			string path = MountPointPath + "auth/" + am.Name;

			Dictionary<string, string> contentParams = new Dictionary<string, string>();
			contentParams.Add("path", am.Path);
			contentParams.Add("description", am.Description);
			contentParams.Add("type", am.TypeAsString);

			string contentJSON = JsonConvert.SerializeObject(contentParams, Formatting.None);


			StringBuilder jsonConfig;
			string json = "";
			if (am.Config != null) {
				jsonConfig = new StringBuilder(JsonConvert.SerializeObject(am.Config));
				jsonConfig.Insert(0, "\"config\":");

				// Combine the 2 JSON's, by stripping trailing closing brace from the content param JSON string.
				StringBuilder jsonParams = new StringBuilder(contentJSON, (contentJSON.Length + jsonConfig.Length + 20));
				jsonParams.Remove(jsonParams.Length - 1, 1);
				jsonParams.Append(",");

				// Remove the opening brace.
				jsonParams.Append(jsonConfig);
				jsonParams.Append("}");

				json = jsonParams.ToString();
			}
			else {
				json = contentJSON;
			}


			try {
				VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync(path, "VaultSystemBackend:AuthEnable", null, json);

				if (vdro.Success) {
					return true;
				}

				return false;
			}
			catch (VaultInvalidDataException e) {
				if (e.Message.Contains("path is already in use")) {
					VaultException ex =
						new VaultException("The authentication backend mount point already exists.  Cannot enable another mount point at that location.");
					ex.SpecificErrorCode = EnumVaultExceptionCodes.BackendMountAlreadyExists;
					throw ex;
				}
				else throw e;
			}
		}



		/// <summary>
		/// Disables the authentication method at the given path.
		/// </summary>
		/// <param name="authName"></param>
		/// <returns></returns>
		public async Task<bool> AuthDisable(string authName) {
			string path = MountPointPath + "auth/" + authName;

			VaultDataResponseObject vdro = await _parent._httpConnector.DeleteAsync(path, "AuthDisable");
			if (vdro.Success) { return true; }
			else { return false; }
		}



		// Disables the given authentication method 
		public async Task<bool> AuthDisable (AuthMethod am) {
			return await AuthDisable(am.Name);
		}



		/// <summary>
		/// Lists all authentication methods in the current Vault System.
		/// </summary>
		/// <returns>Dictionary\<string,AuthMethod> containing all Authentication Methods</string></returns>
		public async Task<Dictionary<string,AuthMethod>> AuthListAll () {
			string path = MountPointPath + "auth";

			VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync(path, "AuthListAll");
			if (vdro.Success) {
				string js = vdro.GetDataPackageAsJSON();
				//string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "");

				string json = vdro.GetDataPackageAsJSON();
				Dictionary<string, AuthMethod> methods = JsonConvert.DeserializeObject<Dictionary<string, AuthMethod>>(json);

				// We need to place the dictionary key into each objects path value. 
				foreach (KeyValuePair<string,AuthMethod> kv in methods) {
					kv.Value.Path = kv.Key;
				}

				return methods;
			}
			throw new ApplicationException("KeyValueSecretEngine:ListSecrets  Arrived at unexpected code block.");
		}
		#endregion


		#region SysAudit

		/// <summary>
		/// Creates a new audit device with the specified name.
		/// </summary>
		/// <param name="auditDeviceName">A name to be given to the audit device</param>
		/// <param name="filePath">A full path and filename specification of where the audit entries should be written.</param>
		/// <param name="description">A description of the audit device.</param>
		/// <returns>True if successfully created.</returns>
		 public async Task<bool> AuditEnableFileDevice (string auditorName, string filePath, string description = "Audit to file") {
			string path = MountPointPath + "audit/" + auditorName;

			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{  "description", description },
				{ "type", "file" }
			};


			string inputVarsJSON = JsonConvert.SerializeObject(contentParams, Formatting.None);
			Dictionary<string, string> optionsList = new Dictionary<string, string>() {
				//{ "path",@"c:\temp\avault.log" }
				{"path", filePath }
			};

			// Build entire JSON Body:  Input Params + Bulk Items List.
			string bulkJSON = JsonConvert.SerializeObject(new
			{
				options = optionsList
			}, Formatting.None);


			// Combine the 2 JSON's
			if (contentParams.Count > 0) {
				string newVarsJSON = inputVarsJSON.Substring(1, inputVarsJSON.Length - 2) + ",";
				bulkJSON = bulkJSON.Insert(1, newVarsJSON);
			}


			VaultDataResponseObject vdro = await _parent._httpConnector.PutAsync(path, "SysAuditEnableFileDevice", null, bulkJSON);
			if (vdro.HttpStatusCode == 204) { return true; }
			else { return false; }
		}



		/// <summary>
		/// Disables (deletes? Not Sure) the specified audit device
		/// </summary>
		/// <param name="auditDeviceName">Name of the Audit device to delete.</param>
		/// <returns>True if audit device successfully deleted.  False otherwise.</returns>
		public async Task<bool> AuditDisable (string auditDeviceName) {
			string path = MountPointPath + "audit/" + auditDeviceName;

			VaultDataResponseObject vdro = await _parent._httpConnector.DeleteAsync(path, "SysAuditDisable");
			if (vdro.Success) { return true; }
			else { return false; }
		}
        #endregion


        #region SysMounts
        // ==============================================================================================================================================

        /// <summary>
        /// Creates (Enables in Vault terminology) a new backend secrets engine with the given name, type and configuration settings.
        /// Throws:  [VaultInvalidDataException] when the mount point already exists.  SpecificErrorCode will be set to: [BackendMountAlreadyExists]
        /// </summary>
        /// <param name="mountPath">The root path to this secrets engine that it will be mounted at.  Is a part of every URL to this backend.
        /// <param name="description">Brief human friendly name for the mount.</param>
        /// <param name="backendType">The type of secrets backend this mount is.  </param>
        /// <param name="config">The configuration to be applied to this mount.</param>
        /// <returns>Bool:  True if successful in creating the backend mount point.  False otherwise.</returns>
        public async Task<bool> SysMountCreate (string mountPath, string description, EnumSecretBackendTypes backendType, VaultSysMountConfig config = null) {
			// The keyname forms the last part of the path
			string path = MountPointPath + pathMounts +  mountPath;


			// Build out the parameters dictionary.
			Dictionary<string, object> createParams = new Dictionary<string, object>();

			// Build Options Dictionary
			Dictionary<string, string> options = new Dictionary<string, string>();

			string typeName = "";

			switch (backendType) {
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
					options.Add("version", "2");
					break;
			}

			createParams.Add("type", typeName);
			createParams.Add("description", description);
			createParams.Add("options", options);

			if (config != null) {
				createParams.Add("config", config);
			}

		    try
		    {
		        VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync2 (path, "SysMountEnable", createParams);
		        if (vdro.HttpStatusCode == 204)
		        {
		            return true;
		        }
		        else
		        {
		            return false;
		        }
		    }
		    catch (VaultInvalidDataException e)
		    {
		        if (e.Message.Contains ("existing mount at "))
		        {
		            e.SpecificErrorCode = EnumVaultExceptionCodes.BackendMountAlreadyExists;
		        }

		        throw e;
		    }
		}




		public List<string> SysMountListSecretEngines () {
			// Build Path
			string path = MountPointPath + pathMounts;

			throw new NotImplementedException("SysMountListSecretEngines Not implemented Yet");
		}



		/// <summary>
		/// Deletes the backend Mount.
		/// </summary>
		/// <param name="Name">Name of the mount to delete.</param>
		/// <returns>True if successful.  False otherwise.</returns>
		public async Task<bool> SysMountDelete(string name) {
			string path = MountPointPath + pathMounts + name;

			VaultDataResponseObject vdro = await _parent._httpConnector.DeleteAsync(path, "SysMountDelete");
			if (vdro.Success) { return true; }
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

			VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync(path, "SysMountReadConfig");
			if (vdro.Success) {
				VaultSysMountConfig config = vdro.GetVaultTypedObject<VaultSysMountConfig>();
				return config;
			}
			return null;

		}




		/// <summary>
		/// Updates the configuration of a given system mount point.  If description is null then it will not be updated.
		/// </summary>
		/// <param name="Name">The name of the mount to update</param>
		/// <param name="config"><see cref="VaultSysMountConfig"/>The backend's configuration changes</param>
		/// <param name="description">If set, the description will be updated.  </param>
		/// <returns>True if successfull.  False otherwise.</returns>
		public async Task<bool> SysMountUpdateConfig(string Name, VaultSysMountConfig config, string description = null) {
			string path = MountPointPath + pathMounts + Name + "/tune";

			Dictionary<string, string> content = new Dictionary<string, string> {
				{ "default_lease_ttl", config.DefaultLeaseTTL },
				{ "max_lease_ttl", config.MaxLeaseTTL },
				{ "audit_non_hmac_request_keys", config.RequestKeysToNotAuditViaHMAC},
				{ "audit_non_hmac_response_keys", config.ResponseKeysToNotAuditViaHMAC},
				{ "listing_visibility", config.VisibilitySetting },
				
				{ "passthrough_request_headers", config.PassThruRequestHeaders }
			};


			if (description != null ) { content.Add("description", description); }

			VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync(path, "SysMountUpdateConfig", content);

			if (vdro.HttpStatusCode == 204) { return true; }
			else { return false; }

		}



		#endregion


		#region SysPolicies
		/// <summary>
		/// Returns a list of all ACL Policies in the Vault Instance
		/// </summary>
		/// <returns>List[string] of all ACL policies by name.</returns>
		public async Task<List<string>> SysPoliciesACLList() {
			// Build Path
			string path = MountPointPath + "policies/acl";

			// Setup List Parameters
			Dictionary<string, string> sendParams = new Dictionary<string, string>();
			sendParams.Add("list", "true");

			VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync(path, "SysPoliciesACLList", sendParams);

			string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "keys");

			List<string> keys = VaultUtilityFX.ConvertJSON<List<string>>(js);
			return keys;
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
				VaultDataResponseObject vdro = await _parent._httpConnector.DeleteAsync(path, "SysPoliciesACLDelete");
				if (vdro.Success) { return true; }
				else { return false; }
			}
			catch (VaultInvalidPathException e) { return false; }
			catch (Exception e) { throw e; }

		}



/* - This logic has been moved into the VaultPolicyPathItem class.
		/// <summary>
		/// Internal method that is used to build the Vault HCL formatted policy from the VaultPolicyPathItem object.
		/// </summary>
		/// <param name="policyPathItemPath"></param>
		/// <returns></returns>
		private string BuildPolicyPathJSON (VaultPolicyPathItem policyPathItemPath) {
			StringBuilder jsonSB = new StringBuilder();


			jsonSB.Append("path \\\"" + policyPathItemPath.FullPath);
			jsonSB.Append("\\\" { capabilities = [");

			if (policyPathItemPath.Denied) { jsonSB.Append("\\\"deny\\\""); }
			else {
				if (policyPathItemPath.CreateAllowed) { jsonSB.Append("\\\"create\\\","); }
				if (policyPathItemPath.ReadAllowed) { jsonSB.Append("\\\"read\\\","); }
				if (policyPathItemPath.DeleteAllowed) { jsonSB.Append("\\\"delete\\\","); }
				if (policyPathItemPath.ListAllowed) { jsonSB.Append("\\\"list\\\","); }
				if (policyPathItemPath.RootAllowed) { jsonSB.Append("\\\"root\\\","); }
				if (policyPathItemPath.SudoAllowed) { jsonSB.Append("\\\"sudo\\\","); }
				if (policyPathItemPath.UpdateAllowed) { jsonSB.Append("\\\"update\\\","); }

				// Remove last comma if there.
				if (jsonSB.Length > 1) {
					char val = jsonSB[jsonSB.Length - 1];
					if (val.ToString() == ",") { jsonSB.Length -= 1; }
				}
			}
			
			// Close out this path enty.
			jsonSB.Append("]} ");

			


			return jsonSB.ToString();
		}
*/


		/// <summary>
		/// Creates or Updates a given policy object.  
		/// </summary>
		/// <param name="policyContainerItem">The VaultPolicyContainer item that should be persisted into the Vault Instance Store.</param>
		/// <returns>True if successfully saved into Vault Instance.  False otherwise.</returns>
		public async Task<bool> SysPoliciesACLCreate(VaultPolicyContainer policyContainerItem) {
			// Build Path
			string path = MountPointPath + "policies/acl/" + policyContainerItem.Name;

			int count = policyContainerItem.PolicyPaths.Count;

			// If no policy paths defined, then return - nothing to do.
			if (count == 0) { return false; }


			// Build the JSON - Lots of string escaping, etc.  fun!
			StringBuilder jsonSB = new StringBuilder();


			// Build the header for JSON Policy.
			jsonSB.Append("{\"policy\": \"");

			foreach (VaultPolicyPathItem item in policyContainerItem.PolicyPaths) {
			    jsonSB.Append (item.ToVaultHCLPolicyFormat());
			    //jsonSB.Append(BuildPolicyPathJSON(item));
			}


			// Issue the policy documents closing quote and then end the JSON.
			jsonSB.Append("\"");
			jsonSB.Append("}");

			string json = jsonSB.ToString();

			VaultDataResponseObject vdro = await _parent._httpConnector.PutAsync(path, "SysPoliciesACLCreate", null, json);
			if (vdro.Success) {
				return true;
			}
			else { return false; }
		}




		/// <summary>
		/// Updates a given policy.  Is merely a wrapper for SysPoliciesACLCreate since Vault has no update function.
		/// </summary>
		/// <param name="policyName">The name of the policy to update.</param>
		/// <param name="policyContainerItem">The VaultPolicyPathItem object that should be updated in Vault.</param>
		/// <returns>True if successful.  False otherwise.</returns>
		public async Task<bool> SysPoliciesACLUpdate (VaultPolicyContainer policyContainerItem) {
			return await SysPoliciesACLCreate(policyContainerItem);
		}




		/// <summary>
		/// Reads the Vault policy with the given name.
		/// </summary>
		/// <param name="policyName">Name of the policy to retrieve.</param>
		/// <returns>A VaultPolicyContainer object with the values read from Vault.</returns>
		public async Task<VaultPolicyContainer> SysPoliciesACLRead(string policyName) {
			// Build Path
			string path = MountPointPath + "policies/acl/" + policyName;
			VaultDataResponseObject vdro;

			try {
				vdro = await _parent._httpConnector.GetAsync(path, "SysPoliciesACLRead");
				vdro.GetDataPackageAsDictionary();
			}
			catch (VaultInvalidPathException e) {		
				e.SpecificErrorCode = EnumVaultExceptionCodes.ObjectDoesNotExist;
				throw e;
			}


			// Now we need to cleanup the returned data and then parse it.
			// Strings we need to replace in the received text.  Must be replaced in this order!
			Dictionary<string, string> replaceStrings = new Dictionary<string, string>() {
				{ "\r\n",""},
				{ "\\", ""},
				{ "\"","" },
				{ "path ", " |PATH| " },
				{ "{ capabilities = ", " { |CAPA| " },
				{ "[", " [ " },						// Mark start of an array.
				{ "]", " ] " }						// Mark end of an array.

			};


			string val = vdro.GetDataPackageFieldAsJSON("policy");


			StringBuilder sb = new StringBuilder(val, val.Length * 2);
			foreach (string k in replaceStrings.Keys) {
				sb.Replace(k, replaceStrings[k]);
			}


			// Create a policy object and load the paths
			VaultPolicyContainer vp = new VaultPolicyContainer(policyName);


			// Now we need to parse the Paths.  
			ParseACLPaths(sb.ToString(), vp);
			return vp;
		}




		/// <summary>
		/// Internal routine that processes the returned string from Vault and parses it into a VaultPolicyContainer object.
		/// </summary>
		/// <param name="data">The string data returned by Vault.</param>
		/// <param name="vp">VaultPolicyContainer object that should be filled in with the values from Vault.</param>
		/// <returns>True if successful.</returns>
		private bool ParseACLPaths (string data, VaultPolicyContainer vp) {
			string[] strDelimiters = { " ", "," };
			string[] pathObjects = data.Split(strDelimiters, StringSplitOptions.RemoveEmptyEntries);

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

			List<string> keyWords = new List<string>() { 
				sPATH,
				sCAPA,
				sLISTSTART,
				sLISTEND,
				sARRAYSTART,
				sARRAYEND
			};


            // We need to create a default object or else it will not compile.  
			VaultPolicyPathItem newPathObj = new VaultPolicyPathItem("dummy/dummy2");

			short iStep = iSTARTING;

			// Now process thru the data elements.
			for (int i=0; i < pathObjects.Length; i++) { 
				switch (iStep) {
					case iSTARTING:
						// PATH must be first value if starting.
						if (pathObjects[i] == sPATH) {
							iStep++;
							starting = true;

							// Make sure the next item is not a keyword.
							i++;
							if (keyWords.Contains(pathObjects[i])) {
								throw new FormatException("Found path keyword, but no value supplied for path NAME");
							}
							else {
								newPathObj = new VaultPolicyPathItem(pathObjects[i]);
								vp.PolicyPaths.Add(newPathObj);
								//vpp.Add(newPathObj);
							}
						}
						else {
							string err = string.Join("", "First element must be the PATH identifier.  Found: ", pathObjects[i].ToString(), " instead.");
							throw new FormatException(err);
						}
						break;
					case iPATHLIST:
						// We should be looking for the iPATH List identifier - {
						if ((pathObjects[i] == sLISTSTART) && (starting)) {
							starting = false;

							// Now see what type of parameter the next item is.
							i++;
							switch (pathObjects[i]) {
								case sCAPA:
									// It's a capabilities type.  Now add items until we reach the end of the capabilities list.
									iStep=iCAP;
									// The next item should be opening array.
									if(pathObjects[++i] != sARRAYSTART) { throw new FormatException("Found the capabilities identifier, but did not find the opening array symbol - ["); }
									break;
							}  // END switch pathObjects[i]
						} // END if sLISTSTART && starting
						break;
					case iCAP:
						if (pathObjects[i] == sLISTSTART) {	iStep++; }
						else if (pathObjects[i] == sARRAYEND) {
							// Done with the capabilities.  
							iStep = iPATHOPTIONS;
						}
						else {
							// It must be a valid capability...Confirm.
							switch (pathObjects[i]) {
								case "create":
									newPathObj.CreateAllowed = true;
									break;
								case "read":
									newPathObj.ReadAllowed = true;
									break;
								case "update":
									newPathObj.UpdateAllowed = true;
									break;
								case "delete":
									newPathObj.DeleteAllowed = true;
									break;
								case "list":
									newPathObj.ListAllowed = true;
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
						if (pathObjects[i] == sLISTEND) {
							// Done with this path object.
							iStep = iSTARTING;
						}
						break;
				}  // END SWITCH istep
			}  // END of for loop.

			return true;
		}  // END of method.


#endregion

	}
	// ==============================================================================================================================================
	// ==============================================================================================================================================
	// ==============================================================================================================================================
	// ==============================================================================================================================================
	// ==============================================================================================================================================

}

