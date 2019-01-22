using System;
using System.Collections.Generic;
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

		    VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync(path, "LdapAuthEngine: ConfigureLDAPBackend", null, json);
		    return vdro.Success;
		}



		/// <summary>
		/// Reads the LDAP Config that corresponds to this engine.  Returns a LdapConfig object if it can find the config.
		/// </summary>
		/// <returns></returns>
	    public async Task<LdapConfig> ReadLDAPConfig () {
		    string path = MountPointPath + "config";


		    VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync(path, "ReadLDAPConfig");
		    if (vdro.Success) {
				LdapConfig ldapConfig = vdro.GetVaultTypedObjectV2<LdapConfig>();

			    return ldapConfig;
		    }

		    return null;
		}



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


			    VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync(path, "LdapAuthEngine:ListUsers", contentParams);
			    if (vdro.Success) {
				    string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "keys");
				    List<string> keys = VaultSerializationHelper.FromJson<List<string>>(js); 
				    return keys;
			    }

			    throw new ApplicationException("LdapAuthEngine:ListUsers -> Arrived at unexpected code block.");
		    }

		    // 404 Errors mean there were no roles.  We just return an empty list.
		    catch (VaultInvalidPathException) {
			    return new List<string>();
		    }
		}



		/// <summary>
		/// Creates a Vault LDAP group to policy(ies) mapping object.  Note:  Group name is converted to all lowercase per Vault standard unless
		/// CaseSensitiveNames parameter is set in the LDAP Engine Configuration.
		/// </summary>
		/// <param name="groupName">This is the name of the group as it exists in the LDAP backend.</param>
		/// <param name="policies">A list of Vault policies that users in this LDAP group should receive.</param>
		/// <returns></returns>
	    public async Task<bool> SaveGroup (string groupName, List<string> policies) {
		    string path = MountPointPath + "groups/" + groupName;


            // Build JSON object parameter containing policies
            JObject json = new JObject();
            string policyValue =  String.Join (",", policies);          
            json.Add("policies", policyValue);


            VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync(path, "LdapAuthEngine: SaveGroup", null, json.ToString());
		    if (vdro.Success) { return true; }
		    else { return false; }
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
                VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync (path, "LdapAuthEngine:GetPoliciesAssignedToGroup");
                if ( vdro.Success ) {
                    string js = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "policies");
                    List<string> policies = VaultSerializationHelper.FromJson<List<string>> (js);
                    return policies;
                }

                throw new ApplicationException ("LdapAuthEngine:GetPoliciesAssignedToGroup -> Arrived at unexpected code block.");
            }

            // Group does not exist or has not had any Policies assigned to it.  Return an empty List.
            catch ( VaultInvalidPathException) { return new List<string>(); }
        }




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


			    VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync(path, "LdapAuthEngine:ListUsers", contentParams);
			    if (vdro.Success) {
				    string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "keys");

				    List<string> keys = VaultSerializationHelper.FromJson<List<string>>(js); 
				    return keys;
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
		/// <param name="userName"></param>
		/// <param name="password"></param>
		/// <returns></returns>
	    public async Task<LoginResponse> Login (string userName, string password) {
		    string path = MountPointPath + "login/" + userName;
			JObject json = new JObject();
			json.Add("password",password);

		    VaultDataResponseObject vdro = await _parent._httpConnector.PostAsync(path, "LdapAuthEngine:Login", null, json.ToString());
            if ( vdro.Success ) {
                LoginResponse lr = vdro.GetVaultTypedObjectFromResponseField<LoginResponse> ("auth");
                return lr;
            }
            else { return null; }
        }
	}
}
