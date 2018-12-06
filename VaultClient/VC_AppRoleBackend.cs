using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Backends;
using VaultAgent.Backends.System;
using VaultAgent.Models;
using VaultAgent.SecretEngines;
using VaultAgent.SecretEngines.KV2;


namespace VaultClient
{
    public class VC_AppRoleAuthEngine
    {
		AppRoleAuthEngine _appRoleAuthEngine;
		private string _AppRoleName;
	    private VaultAgentAPI _vaultAgent;
	    private UniqueKeys uniqueKeys;
	    private string _AppBEName;

		public VC_AppRoleAuthEngine(VaultAgentAPI vaultAgent) {
			UniqueKeys uniqueKeys = new UniqueKeys();

			// We will create a unique App Role Authentication Engine with the given name.
			_AppBEName = "BEAppRole"; 
			_vaultAgent = vaultAgent;

			_appRoleAuthEngine = (AppRoleAuthEngine)vaultAgent.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _AppBEName, _AppBEName);

		}



		/// <summary>
		/// We will walk thru the following sequence:
		///  - Create a new Vault authentication backend for App Roles
		///  - Create a set of policies that roles will use to restrict access
		///  - Create a set of roles that will be used to provide tokens to "applications"
		///  - Create tokens against those roles.
		///  - Test the access of those tokens to confirm they have the necessary permissions.
		/// </summary>
		/// <returns></returns>
		public async Task Run() {
			try {
				// 1.  Create an App Role Authentication backend. 
				try {
					// Create an Authentication method of App Role.	- This only needs to be done when the Auth method is created.  
					AuthMethod am = new AuthMethod(_AppBEName, EnumAuthMethods.AppRole);
					await _vaultAgent.System.AuthEnable(am);
				}
				// Ignore mount at same location errors.  This can happen if we are not restarting Vault Instance each time we run.  Nothing to worry about.
				catch (VaultException e) {
					if (e.SpecificErrorCode != EnumVaultExceptionCodes.BackendMountAlreadyExists) { Console.WriteLine("Unexpected error in VC_AppRoleBackend.Run method: {0}", e.Message); }
				}
				catch (Exception e)  { Console.WriteLine("Unexpected error in VC_AppRoleBackend.Run method: {0}", e.Message); }


                // Create a KV2 Secret Mount if it does not exist.
			    string KV2SecretEngName = "shKV2";
			    try
			    {
			        await _vaultAgent.System.SysMountCreate (KV2SecretEngName, "Sheakley KeyValue 2 Secrets", EnumSecretBackendTypes.KeyValueV2);
			    }
			    catch (VaultInvalidDataException e)
			    {
			        if (e.SpecificErrorCode == EnumVaultExceptionCodes.BackendMountAlreadyExists)
			        {
                        Console.WriteLine("KV2 Secret Backend already exists.  No need to create it.");
			        }
			        else
			        {
			            Console.WriteLine ("Exception trying to mount the KV2 secrets engine. Aborting the rest of the AppRoleBackend Scenario.   Mount Name: {0} - Error: {1}", KV2SecretEngName, e.Message);
			            return;
			        }
			    }


				// 2.  Create a set of policies to test against.
			    string appNameA = "appA";
				string policyName = await CreatePolicies(KV2SecretEngName, appNameA);


				// 3.  Create a set of Application Roles we can use to grant tokens too.
				// Now lets create a role if it does not exist.
				string A_appRolename = "arA";
				AppRole A_Role;
				if (!(await _appRoleAuthEngine.RoleExists(A_appRolename))) {
					// Role does not exist - so create it.
					A_Role = new AppRole(A_appRolename);
					A_Role.Policies.Add(policyName);
				    A_Role = await _appRoleAuthEngine.SaveRoleAndReturnRoleObject(A_Role);
                    
					if (A_Role == null) {
						Console.WriteLine("Unable to create role: {0} ",A_appRolename);
						return;
					}
				}
				else {
					// Read the role:
					A_Role = await _appRoleAuthEngine.ReadRole(A_appRolename,true);
					if (A_Role == null) {
						Console.WriteLine("Error trying to read existing role {0}",A_appRolename);
						return;
					}

					// See if the existing role has the appropriate policy.
					if (!(A_Role.Policies.Contains(policyName))) {
						A_Role.Policies.Add(policyName);
						await _appRoleAuthEngine.SaveRole(A_Role);
					}
				}


				
                
				// 4.  Now lets create tokens against those roles.
			    AppRoleSecret A_Secret = await _appRoleAuthEngine.CreateSecretID(A_Role.Name);
			    if (A_Secret == null)
			    {
			        Console.WriteLine("Error:  Could not create a secret ID against role: {0}", A_Role.Name);
			        return;
			    }


               // For this sequence of steps we need to create a new instance of the Vault as we will be connecting via the new token.  We connect to the requested backend.
                VaultAgentAPI A_VaultAgentAPI = new VaultAgentAPI("SecretRole A",_vaultAgent.IP,_vaultAgent.Port,"");
			    AppRoleAuthEngine A_appRoleAuthEngine = (AppRoleAuthEngine) A_VaultAgentAPI.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _AppBEName, _AppBEName);
			    KV2SecretEngine A_KV2SecretEngine =
			        (KV2SecretEngine) A_VaultAgentAPI.ConnectToSecretBackend (EnumSecretBackendTypes.KeyValueV2, "Sheakley KV2 Secrets", KV2SecretEngName);


			    string tempRole = A_Role.RoleID;
			    string tempSec = A_Secret.ID;
                Token A;
			    try
			    {
			        A = await A_appRoleAuthEngine.Login (tempRole, tempSec);

                        if (A != null)
			            {
			                Console.WriteLine("Logged in with secret.");
			            }
			            else
			            {
			                Console.WriteLine("Login with secret failed.");
			                return;
			            }
			    }
			    catch (VaultInvalidDataException e)
			    {
                    if (e.SpecificErrorCode == EnumVaultExceptionCodes.LoginRoleID_NotFound) {  Console.WriteLine("The Role ID is invalid.");}
                    if (e.SpecificErrorCode == EnumVaultExceptionCodes.LoginSecretID_NotFound) { Console.WriteLine("The Secret ID is invalid.  It may be an invalid secret_ID or the secret is not tied to this specific role ID.");}

			        return;
			    }


                ///************************************************
                VaultAgentAPI CCAPI = new VaultAgentAPI("SecretRole CC",_vaultAgent.IP,_vaultAgent.Port,A.ID);
			    AppRoleAuthEngine CCEngine = (AppRoleAuthEngine) CCAPI.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _AppBEName, _AppBEName);
			    KV2SecretEngine CCSecEng =
			        (KV2SecretEngine)CCAPI.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, "Sheakley KV2 Secrets", KV2SecretEngName);
			    ///************************************************
			    ///
			    ///
			    ///
			    /// 
                // Now attempt to create some secrets.
                KV2Secret secA1 = new KV2Secret("apps/" + appNameA + "/config");
                secA1.Attributes.Add("RegisteredBy","Scott Herrmann");
			    secA1.Attributes.Add("CreatedBy", "Grand Negus");

			    await CCSecEng.SaveSecret (secA1,KV2EnumSecretSaveOptions.AlwaysAllow);

                // apps/<appName>/connection <RO>   // NOT IMPLEMENTED YET.
                // apps/<appName>/valueA  (RW)
                // apps/<appName>/valueB  (RW)
                // apps/<appName>/valueC  (RW)
                // apps/<appName>/value<N>  (RW)
                // apps/<appName>/options/  (RW)
                // apps/<appName>/options/option1
                // apps/<appName>/options/option2
                // apps/<appName>/options/option3
                // databases/ (RO - List)
                // databases/dbA 
                // databases/dbB 

                //apps /< appName >/ valueA



                // List current roles.  Create role if does not exist.  Read the role.  List the roles again.
                List<string> appRoles = await AppRole_ListRoles();
				if (!appRoles.Contains(_AppRoleName)) {
					await AppRole_Create();
				}

				await ReadRole();

				appRoles = await AppRole_ListRoles();

				// Now get a role ID
				string roleID = await _appRoleAuthEngine.ReadRoleID(_AppRoleName);

				// Now delete the app role.
				bool rc = await _appRoleAuthEngine.DeleteRole(_AppRoleName);
			}
			catch (Exception e) { Console.WriteLine("Error: {0}", e.Message); }
		}



		/// <summary>
		/// Create a set of policies that should be applied to various roles we wish to work with.
		/// </summary>
		/// <returns></returns>
	    public async Task<string> CreatePolicies(string kv2SecretName,string appName) {
			// First lets try to read an existing policy if it exists:
		    string firstPolicies = appName + "_Policies";
		    VaultPolicyContainer firstContainer;

		    try {
			    firstContainer = await _vaultAgent.System.SysPoliciesACLRead(firstPolicies);
		    }
		    catch (VaultInvalidPathException e) {
			    if (e.SpecificErrorCode == EnumVaultExceptionCodes.ObjectDoesNotExist) {
				    firstContainer = new VaultPolicyContainer(firstPolicies);
			    }
			    else
				    {
					    throw new Exception("Looking for policy: " + firstPolicies + " returned the following unexpected error: " + e.Message);
				    }
			    }




            // We will build out the following policy structure:  Everything is prefixed with KV2 secrets engine path
            // apps/<appName>/connection <RO>   // NOT IMPLEMENTED YET.
            // apps/<appName>/valueA  (RW)
            // apps/<appName>/valueB  (RW)
            // apps/<appName>/valueC  (RW)
            // apps/<appName>/value<N>  (RW)
            // apps/<appName>/options/  (RW)
            // apps/<appName>/options/option1
            // apps/<appName>/options/option2
            // apps/<appName>/options/option3
            // databases/ (RO - List)
            // databases/dbA 
            // databases/dbB 


		    // Create policies for an application named ABCapp

            // This allows CRUD on anything below the app root folder, but not the app folder itself.
            VaultPolicyPathItem vppiConnection = new VaultPolicyPathItem(( kv2SecretName + "/data/apps/" + appName + "/*"));
		    vppiConnection.ListAllowed = true;
		    vppiConnection.CRUDAllowed = true;

			firstContainer.PolicyPaths.Add(vppiConnection);

            // This allows CRUD on the actual app folder itself.
/*            VaultPolicyPathItem vpi2 = new VaultPolicyPathItem(kv2SecretName + "/data/apps/" + appName);
		    vpi2.CRUDAllowed = true;
		    vpi2.ListAllowed = true;
            firstContainer.PolicyPaths.Add(vpi2);
            */

			// Create policy item for databases:
		    string db = "databases";
			VaultPolicyPathItem vppiDatabase = new VaultPolicyPathItem((kv2SecretName + "/data/" +  db + "/*"));
		    vppiDatabase.ListAllowed = true;
		    vppiDatabase.ReadAllowed = true;
			firstContainer.PolicyPaths.Add(vppiDatabase);

			// Update Vault with the policies.
		    bool rc = await _vaultAgent.System.SysPoliciesACLCreate(firstContainer);
			if (rc != true ) { Console.WriteLine("Unable to save the policies for the CreateRoles method");}

		    return firstContainer.Name;
		}




		private async Task ReadRole() {
			AppRole art = await _appRoleAuthEngine.ReadRole(_AppRoleName);
			Console.WriteLine("Read token: {0}", art);
		}



		private async Task<List<string>> AppRole_ListRoles() {
			List<string> appRoles = await _appRoleAuthEngine.ListRoles();

			foreach (string role in appRoles) {
				Console.WriteLine("App Role: {0}", role);
			}
			return appRoles;
		}


		private async Task AppRole_Create() {
			AppRole art = new AppRole(_AppRoleName);

			await _appRoleAuthEngine.SaveRole(art);

		}

	}
}
