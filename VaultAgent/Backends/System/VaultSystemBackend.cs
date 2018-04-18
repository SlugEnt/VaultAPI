using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text;
using VaultAgent.Models;


namespace VaultAgent.Backends.System
{

	public class VaultSystemBackend
	{
		private VaultAPI_Http vaultHTTP;
		private string sysPath = "/v1/sys/";
		private Uri vaultSysPath;
		TokenInfo sysToken;

		const string pathMounts = "mounts/";
		const string pathEncrypt = "encrypt/";
		const string pathDecrypt = "decrypt/";




		// ==============================================================================================================================================
		/// <summary>
		/// Constructor.  Initializes the connection to Vault and stores the token.
		/// </summary>
		/// <param name="vaultIP">The IP address of the Vault Server.</param>
		/// <param name="port">The network port the Vault server listens on.</param>
		/// <param name="Token">The token used to authenticate with.</param>
		public VaultSystemBackend(string vaultIP, int port, string Token) {
			vaultHTTP = new VaultAPI_Http(vaultIP, port, Token);
			sysToken = new TokenInfo();
			sysToken.Id = Token;

			vaultSysPath = new Uri("http://" + vaultIP + ":" + port + sysPath);
		}



		#region SysMounts
		// ==============================================================================================================================================
		public async Task<bool> SysMountEnable (string mountPath, string description, EnumBackendTypes bType) {
			// The keyname forms the last part of the path
			string path = vaultSysPath + pathMounts +  mountPath;


			// Build out the parameters dictionary.
			Dictionary<string, string> createParams = new Dictionary<string, string>();
			string typeName = "";

			switch (bType) {
				case EnumBackendTypes.Transit:
					typeName = "transit";		
					break;
				case EnumBackendTypes.Secret:
					typeName = "kv";
					break;
				case EnumBackendTypes.AWS:
					typeName = "aws";
					throw new NotImplementedException();
				case EnumBackendTypes.CubbyHole:
					typeName = "cubbyhole";
					throw new NotImplementedException();
				case EnumBackendTypes.Generic:
					typeName = "generic";
					throw new NotImplementedException();
				case EnumBackendTypes.PKI:
					typeName = "pki";
					throw new NotImplementedException();
				case EnumBackendTypes.SSH:
					typeName = "ssh";
					throw new NotImplementedException();

			}

			createParams.Add("type", typeName);
			createParams.Add("description", description);

			// AT this time WE ARE NOT SUPPORTING THE Config Options.


			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "SysMountEnable", createParams);
			if (vdro.httpStatusCode == 204) { return true; }
			else { return false; }
		}

		public async Task<List<string>> SysMountListSecretEngines () {
			// Build Path
			string path = vaultSysPath + pathMounts;

			throw new NotImplementedException("SysMountListSecretEngines Not implemented Yet");
		}


		public async Task<List<string>> SysMountDisable(string mountPath) {
			// Build Path
			string path = vaultSysPath + pathMounts + mountPath;

			throw new NotImplementedException("SysMountDisable Not implemented Yet");
		}


		public async Task<bool> SysMountReadConfig (string mountPath) {
			// Build Path
			string path = vaultSysPath + pathMounts + mountPath + "/tune";

			throw new NotImplementedException("SysMountReadConfig Not implemented Yet");
		}
		public async Task<bool> SysMountUpdateConfig(string mountPath) {
			// Build Path
			string path = vaultSysPath + pathMounts + mountPath + "/tune";

			throw new NotImplementedException("SysMountUpdateConfig Not implemented Yet");
		}
		#endregion

		#region SysPolicies
		public async Task<List<string>> SysPoliciesACLList() {
			// Build Path
			string path = vaultSysPath + "policies/acl";

			throw new NotImplementedException("SysPolicies ACL List Not implemented Yet");
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
			string path = vaultSysPath + "policies/acl/" + policyItem.Name;

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

			VaultDataResponseObject vdro = await vaultHTTP.PutAsync(path, "SysPoliciesACLCreate", null, json);
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
			string path = vaultSysPath + "policies/acl/" + policyName;


			VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "SysPoliciesACLRead");
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


		public async Task<bool> SysPoliciesACLDelete(string policyName) {
			// Build Path
			string path = vaultSysPath + "policies/acl/" + policyName;

			throw new NotImplementedException("SysPolicies ACL Update Not implemented Yet");
		}
#endregion

	}
	// ==============================================================================================================================================
	// ==============================================================================================================================================
	// ==============================================================================================================================================
	// ==============================================================================================================================================
	// ==============================================================================================================================================

}

