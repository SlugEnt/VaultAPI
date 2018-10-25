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
        /*
		private VaultAPI_Http _vaultHTTP;
		private string sysPath = "/v1/sys/";
		private Uri MountPointPath;
        */
		TokenInfo sysToken;

		const string pathMounts = "mounts/";





		// ==============================================================================================================================================
		/// <summary>
		/// Constructor.  Initializes the connection to Vault and stores the token.
		/// <param name="token">Token value that has permissions to Vault.</param>
		/// <param name="vaultAPI_Http">The Vault API Connector</param>
		/// <param name="name">The name you wish to give the Vault System backend.  At the present time this is purely cosmetic and does nothing.</param>
		/// </summary>
		public VaultSystemBackend(string token, VaultAPI_Http vaultAPI_Http, string name = "System") : base (name,"sys",vaultAPI_Http){

			sysToken = new TokenInfo() {
				Id = token
			};
		}



		#region SysAuths
		/// <summary>
		/// Enables the provided Authentication backend.
		/// </summary>
		/// <param name="am">The AuthMethod object that represents the authentication engine to enable.</param>
		/// <returns>True if authentication engine was successfully enabled. False otherwise.</returns>
		public async Task<bool> AuthEnable (AuthMethod am) {
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
			else { json = contentJSON; }


			
			//string json = contentJSON;
			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "VaultSystemBackend:AuthEnable", null,json);
			if (vdro.Success) { return true; }
			return false;
		}




		/// <summary>
		/// Disables the authentication method at the given path.
		/// </summary>
		/// <param name="authName"></param>
		/// <returns></returns>
		public async Task<bool> AuthDisable(string authName) {
			string path = MountPointPath + "auth/" + authName;

			VaultDataResponseObject vdro = await _vaultHTTP.DeleteAsync(path, "AuthDisable");
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

			VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "AuthListAll");
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
		 public async Task<bool> SysAuditEnable (string Name) {
			string path = MountPointPath + "audit/" + Name;

			Dictionary<string, string> contentParams = new Dictionary<string, string>() {
				{  "description", "Send to file" },
				{ "type", "file" }

			};


			string inputVarsJSON = JsonConvert.SerializeObject(contentParams, Formatting.None);
			Dictionary<string, string> optionsList = new Dictionary<string, string>() {
				{ "path",@"c:\temp\avault.log" }
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




			VaultDataResponseObject vdro = await _vaultHTTP.PutAsync(path, "SysAuditEnable", null, bulkJSON);
			if (vdro.HttpStatusCode == 204) { return true; }
			else { return false; }



		}
		#endregion


		#region SysMounts
		// ==============================================================================================================================================

		/// <summary>
		/// Creates (Enables in Vault terminology) a new backend secrets engine with the given name, type and configuration settings.
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


			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync2(path, "SysMountEnable", createParams);
			if (vdro.HttpStatusCode == 204) { return true; }
			else { return false; }
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

			VaultDataResponseObject vdro = await _vaultHTTP.DeleteAsync(path, "SysMountDelete");
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

			VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "SysMountReadConfig");
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

			VaultDataResponseObject vdro = await _vaultHTTP.PostAsync(path, "SysMountUpdateConfig", content);

			if (vdro.HttpStatusCode == 204) { return true; }
			else { return false; }

		}



		#endregion

		#region SysPolicies
		/// <summary>
		/// Returns a list of all ACL Policies.
		/// </summary>
		/// <returns>List[string] of all ACL policies by name.</returns>
		public async Task<List<string>> SysPoliciesACLList() {
			// Build Path
			string path = MountPointPath + "policies/acl";

			// Setup List Parameters
			Dictionary<string, string> sendParams = new Dictionary<string, string>();
			sendParams.Add("list", "true");

			VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "SysPoliciesACLList", sendParams);

			string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "keys");

			List<string> keys = VaultUtilityFX.ConvertJSON<List<string>>(js);
			return keys;
		}



		public async Task<bool> SysPoliciesACLDelete (string policyName) {
			// Build Path
			string path = MountPointPath + "policies/acl/" + policyName;


			try {
				VaultDataResponseObject vdro = await _vaultHTTP.DeleteAsync(path, "SysPoliciesACLDelete");
				if (vdro.Success) { return true; }
				else { return false; }
			}
			catch (VaultInvalidPathException e) { return false; }
			catch (Exception e) { throw e; }

		}





		private string BuildPolicyPathJSON (VaultPolicyPath policyPath) {
			StringBuilder jsonSB = new StringBuilder();


			jsonSB.Append("path \\\"" + policyPath.Path);
			jsonSB.Append("\\\" { capabilities = [");

			if (policyPath.Denied) { jsonSB.Append("\\\"deny\\\""); }
			else {
				if (policyPath.CreateAllowed) { jsonSB.Append("\\\"create\\\","); }
				if (policyPath.ReadAllowed) { jsonSB.Append("\\\"read\\\","); }
				if (policyPath.DeleteAllowed) { jsonSB.Append("\\\"delete\\\","); }
				if (policyPath.ListAllowed) { jsonSB.Append("\\\"list\\\","); }
				if (policyPath.RootAllowed) { jsonSB.Append("\\\"root\\\","); }
				if (policyPath.SudoAllowed) { jsonSB.Append("\\\"sudo\\\","); }
				if (policyPath.UpdateAllowed) { jsonSB.Append("\\\"update\\\","); }

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



		public async Task<bool> SysPoliciesACLCreate(VaultPolicy policyItem) {
			// Build Path
			string path = MountPointPath + "policies/acl/" + policyItem.Name;

			int count = policyItem.PolicyPaths.Count;

			// If no policy paths defined, then return - nothing to do.
			if (count == 0) { return false; }


			// Build the JSON - Lots of string escaping, etc.  fun!
			StringBuilder jsonSB = new StringBuilder();


			// Build the header for JSON Policy.
			jsonSB.Append("{\"policy\": \"");

			foreach (VaultPolicyPath item in policyItem.PolicyPaths) {
				jsonSB.Append(BuildPolicyPathJSON(item));
			}


			// Issue the policy documents closing quote and then end the JSON.
			jsonSB.Append("\"");
			jsonSB.Append("}");

			string json = jsonSB.ToString();

			VaultDataResponseObject vdro = await _vaultHTTP.PutAsync(path, "SysPoliciesACLCreate", null, json);
			if (vdro.Success) {
				return true;
			}
			else { return false; }
		}




		/// <summary>
		/// Updates a given policy.  Is merely a wrapper for SysPoliciesACLCreate since Vault has no update function.
		/// </summary>
		/// <param name="policyName">The name of the policy to update.</param>
		/// <param name="policyItem">The VaultPolicyPath object that should be updated in Vault.</param>
		/// <returns></returns>
		public async Task<bool> SysPoliciesACLUpdate (VaultPolicy policyItem) {
			return await SysPoliciesACLCreate(policyItem);
		}




		/// <summary>
		/// Reads the Vault policy with the given name.
		/// </summary>
		/// <param name="policyName">Name of the policy to retrieve.</param>
		/// <returns>A VaultPolicy object with the values read from Vault.</returns>
		public async Task<VaultPolicy> SysPoliciesACLRead(string policyName) {
			// Build Path
			string path = MountPointPath + "policies/acl/" + policyName;


			VaultDataResponseObject vdro = await _vaultHTTP.GetAsync(path, "SysPoliciesACLRead");
			vdro.GetDataPackageAsDictionary();



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
			VaultPolicy vp = new VaultPolicy(policyName);


			// Now we need to parse the Paths.  
			ParseACLPaths(sb.ToString(), vp);
			return vp;
		}




		/// <summary>
		/// Internal routine that processes the returned string from Vault and parses it into a VaultPolicy object.
		/// </summary>
		/// <param name="data">The string data returned by Vault.</param>
		/// <param name="vp">VaultPolicy object that should be filled in with the values from Vault.</param>
		/// <returns>True if successful.</returns>
		private bool ParseACLPaths (string data, VaultPolicy vp) {
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



//			List<VaultPolicyPath> vpp = new List<VaultPolicyPath>();
			VaultPolicyPath newPathObj = new VaultPolicyPath("");

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
								newPathObj = new VaultPolicyPath(pathObjects[i]);
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

