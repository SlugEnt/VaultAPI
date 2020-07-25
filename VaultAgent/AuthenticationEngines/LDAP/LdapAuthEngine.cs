using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using VaultAgent.AuthenticationEngines.LDAP;
using VaultAgent.Backends;
using VaultAgent.Models;

namespace VaultAgent.AuthenticationEngines
{
	/// <summary>
	/// This is the Vault LDAP Authentication Backend.  One or more instances of this can facilitate the use of an Active Directory or LDAP
	/// server for authenticating users.
	///
	/// Vault API Methods and implementation status:
	///   Configure LDAP						- Fully Implemented
	///   Read LDAP Configuration				- Fully Implemented
	///   List LDAP Groups						- Fully Implemented
	///   Read LDAP Group						- Not Implemented
	///   Create/Update LDAP Group				- Fully Implemented
	///   Delete LDAP Group						- Not Implemented
	///   List LDAP Users						- Fully Implemented
	///   Read LDAP Users						- Not Implemented
	///   Create/Update LDAP Users				- Not Implemented
	///   Delete LDAP Users						- Not Implemented
	///   Login									- Fully Implemented
	/// 
	/// </summary>
	public class LdapAuthEngine : VaultAuthenticationBackend
    {
        /// <summary>
        /// Constructor for the LDAPAuthEngine, which provides a means to login via LDAP.
        /// </summary>
        /// <param name="ldapName">Name to be given to this engine</param>
        /// <param name="backendMountPoint">The MountPoint in Vault that this engine should mount to</param>
        /// <param name="vault">VaultAgentAPI object that contains connection and token information with sufficient access to allow the Engine to perform its tasks.</param>
        public LdapAuthEngine (string ldapName, string backendMountPoint, VaultAgentAPI vault) : base (ldapName, backendMountPoint, vault) {
            Type = EnumBackendTypes.A_LDAP;
            MountPointPrefix = "/v1/auth/";
        }



		/// <summary>
		/// Sets the configuration for the given LDAP Backend.  The configuration is everything need to setup an LDAP connection.
		/// </summary>
		/// <param name="ldapConfig">The LdapConfig object that contains all the LDAP connection information.</param>
		/// <returns></returns>
	    public async Task<bool> ConfigureLDAPBackend (LdapConfig ldapConfig) {
		    string path = MountPointPath + "config";
		    string json  = JsonConvert.SerializeObject(ldapConfig);

		    VaultDataResponseObjectB vdro = await ParentVault._httpConnector.PostAsync_B(path, "LdapAuthEngine: ConfigureLDAPBackend", json,false);
		    return vdro.Success;
		}



		/// <summary>
		/// Reads the LDAP Config from the Vault that corresponds to this engine.  Returns a LdapConfig object if it can find the config.
		/// </summary>
		/// <returns></returns>
	    public async Task<LdapConfig> ReadLDAPConfig () {
		    string path = MountPointPath + "config";


		    VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B(path, "ReadLDAPConfig");
		    if (vdro.Success) {
                return await vdro.GetDotNetObject<LdapConfig>();
		    }

		    return null;
		}



        /// <summary>
        /// Reads the LDAP Config that corresponds to this engine.  Returns the JSON representation of the config.
        /// </summary>
        /// <returns></returns>
        public async Task<string> ReadLDAPConfigAsJSON()
        {
            string path = MountPointPath + "config";

            VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B(path, "ReadLDAPConfigAsJSON");
            if (vdro.Success)
            {
                return await vdro.GetJSON();
            }
            return null;
        }


        #region "Group Methods"

        /// <summary>
        /// Returns a list of the LDAP groups that Vault has policies for.  Please note, this is not all the groups in the LDAP Backend.  If no
        /// groups found it returns an empty List.  
        /// </summary>
        /// <returns></returns>
        public async Task<List<string>> ListGroups () {
		    string path = MountPointPath + "groups";

		    try {
			    // Setup List Parameter
			    Dictionary<string, string> contentParams = new Dictionary<string, string>() { { "list", "true" } };


			    VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B(path, "LdapAuthEngine:ListUsers", contentParams);
			    if (vdro.Success) {
                    return await vdro.GetDotNetObject<List<string>> ("data.keys");
			    }

			    throw new ApplicationException("LdapAuthEngine:ListUsers -> Arrived at unexpected code block.");
		    }

		    // 404 Errors mean there were no roles.  We just return an empty list.
		    catch (VaultInvalidPathException) {
			    return new List<string>();
		    }
		}



		/// <summary>
		/// Creates a mapping between an LDAP Group name and 1 or more Vault Policies.
		/// Note:  Group name is converted to all lowercase per Vault standard unless CaseSensitiveNames parameter is set in the LDAP Engine Configuration.
		/// </summary>
		/// <param name="groupName">This is the name of the LDAP group as it exists in the LDAP backend.</param>
		/// <param name="policies">A list of Vault policies that users in this LDAP group should receive.</param>
		/// <returns></returns>
	    public async Task<bool> CreateGroupToPolicyMapping (string groupName, List<string> policies) {
		    string path = MountPointPath + "groups/" + groupName;

            // Build JSON object parameter containing policies
            JObject json = new JObject();
            string policyValue =  String.Join (",", policies);          
            json.Add("policies", policyValue);

            VaultDataResponseObjectB vdro = await ParentVault._httpConnector.PostAsync_B(path, "LdapAuthEngine: CreateGroupToPolicyMapping", json.ToString(),false);
            return vdro.Success;
		}



        /// <summary>
        /// Retrieves all the Vault policies that have been associated with a given LDAP Group.
        /// <para>An empty list is is returned if the group is invalid or no policies have been assigned to it.</para>
        /// </summary>
        /// <param name="groupName">The name of the group (in lower case)</param>
        /// <returns></returns>
        public async Task<List<string>> GetPoliciesAssignedToGroup (string groupName) {
            string path = MountPointPath + "groups/" + groupName;

            try {
                VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B (path, "LdapAuthEngine:GetPoliciesAssignedToGroup");
                if ( vdro.Success ) {
                    return await vdro.GetDotNetObject<List<string>> ("data.policies");
                }

                throw new ApplicationException ("LdapAuthEngine:GetPoliciesAssignedToGroup -> Arrived at unexpected code block.");
            }

            // Group does not exist or has not had any Policies assigned to it.  Return an empty List.
            catch ( VaultInvalidPathException) { return new List<string>(); }
        }

#endregion


        /// <summary>
        /// Returns a list of the LDAP groups that Vault has policies for.  Please note, this is not all the groups in the LDAP Backend.  If no
        /// groups found it returns an empty list.
        /// </summary>
        /// <returns></returns>
        public async Task<List<string>> ListUsers() {
		    string path = MountPointPath + "users";

		    try {
			    // Setup List Parameter
			    Dictionary<string, string> contentParams = new Dictionary<string, string>() { { "list", "true" } };


			    VaultDataResponseObjectB vdro = await ParentVault._httpConnector.GetAsync_B(path, "LdapAuthEngine:ListUsers", contentParams);
			    if (vdro.Success) {
                    return await vdro.GetDotNetObject<List<string>> ("data.keys");
                    //TODO Cleanup
                    /*
				    string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "keys");

				    List<string> keys = VaultSerializationHelper.FromJson<List<string>>(js); 
				    return keys;
                    */
			    }

			    throw new ApplicationException("LdapAuthEngine:ListUsers -> Arrived at unexpected code block.");
		    }

		    // 404 Errors mean there were no roles.  We just return an empty list.
		    catch (VaultInvalidPathException) {
			    return new List<string>();
		    }

	    }



		/// <summary>
		/// Logs the user into the LDAP backend.
		/// <para>Throws a VaultInvalidaDataException if the login failed for any reason.</para>
		/// </summary>
		/// <param name="userName">The ldap user name that wants to login</param>
		/// <param name="password">The password for said user</param>
		/// <returns></returns>
	    public async Task<LoginResponse> Login (string userName, string password) {
		    string path = MountPointPath + "login/" + userName;
			JObject json = new JObject();
			json.Add("password",password);
            try
            {
                VaultDataResponseObjectB vdro =
                    await ParentVault._httpConnector.PostAsync_B(path, "LdapAuthEngine:Login", json.ToString());
                if (vdro.Success)
                {
                    return await vdro.GetDotNetObject<LoginResponse>("auth");
                }
                else
                {
                    return null;
                }
            }
            catch (Exception e)
            {
                if (e.Message.Contains("LDAP Result Code 200"))
                {
                    VaultException ve = new VaultException("Problems Connecting to the LDAP Server", e);
                    ve.SpecificErrorCode = EnumVaultExceptionCodes.LDAPLoginServerConnectionIssue;
                    throw ve;
                }
                else if (e.Message.Contains("ldap operation failed"))
                {
                    VaultException ve = new VaultException("Invalid username or password", e);
                    ve.SpecificErrorCode = EnumVaultExceptionCodes.LDAPLoginCredentialsFailure;
                    throw ve;
                }
                else throw e;
            }
        }



        /// <summary>
        /// Returns an LDAPConfig object that was initialized from values in a config file.
        /// </summary>
        /// <param name="filename">The file that contains the LDAP configuration you wish to load</param>
        /// <returns></returns>
        public LdapConfig GetLDAPConfigFromFile(string filename)
        {
            // Read a JSON Config file containing LDAP Credentials from a JSON file into the class.       
            JsonSerializer jsonSerializer = new JsonSerializer();
            string json = File.ReadAllText(filename);

            // Append JSON to existing objects values.
            LdapConfig ldapConfig = new LdapConfig();
            jsonSerializer.Populate(new StringReader(json), ldapConfig);
            return ldapConfig;
        }
	}
}
