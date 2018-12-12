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

	/// <summary>
	/// We will use the following path structure in Vault:
	///  /path1
	///    /appA
	///      /values
	///    /appB
	///      /values
	///  /appData
	///    /appA
	///      /config
	///    /appB
	///      /config
	///
	///  /shared
	///    /dbConfig
	///      - Attributes
	///    /Email
	///      - Attributes
	/// 
	/// </summary>
	///

	public static class Constants {
		public const string appData = "appData";
		public const string path1 = "path1";
		public const string appName_A = "appA";
		public const string appName_B = "appB";
		public const string dbConfig = "dbConfig";
		public const string email = "Email";
	}


	public class VC_AppRoleAuthEngine
    {
        private string _beAuthName;
        private string _beKV2Name;


		AppRoleAuthEngine _appRoleAuthEngine;
		private string _AppRoleName;
	    private VaultAgentAPI _vaultAgent;
	    private UniqueKeys uniqueKeys;
	    private string _AppBEName;


        // The Application Roles we will create in this scenario

        // Has full control on everything
        private AppRole roleMaster;
        private VaultPolicyContainer _polRoleMaster;
        private AppRoleSecret _SIDRoleMaster;

        // role1 - Has full control on path1 - This is the Installer
        private AppRole role1;
        private VaultPolicyContainer _polRole1;
        private AppRoleSecret _SIDRole1;

        // Has Read access to path1 - This is the Connector
        private AppRole role2;
        private VaultPolicyContainer _polRole2;
        private AppRoleSecret _SIDRole2;

        // Has RW accesss t to its own app path - apps/AppA
        private AppRole roleAppA;
        private VaultPolicyContainer _polRoleAppA;
        private AppRoleSecret _SIDRoleAppA;

        private AppRole roleAppB;
        private VaultPolicyContainer _polRoleAppB;
        private AppRoleSecret _SIDRoleAppB;

        private VaultPolicyContainer _polSharedDB;
        private VaultPolicyContainer _polSharedEmail;


        public VC_AppRoleAuthEngine(VaultAgentAPI vaultAgent) {
			UniqueKeys uniqueKeys = new UniqueKeys();

			// We will create a unique App Role Authentication Engine with the given name.
			_AppBEName = "BEAppRole"; 
			_vaultAgent = vaultAgent;

			_appRoleAuthEngine = (AppRoleAuthEngine)vaultAgent.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _AppBEName, _AppBEName);

		}



        /// <summary>
        /// Creates the backend Authorization and KeyValue Version 2 Secret Backends
        ///  - Note the routine checks to see if the backends already exist.  If they do (which they might if you leave the Vault Instance up and running across runs
        ///    of this program) then it ignores the errors and continues on.
        /// </summary>
        /// <returns></returns>
        private async Task CreateBackendMounts() {
            _beAuthName = "BEAppRole";
            _beKV2Name = "shKV2";

            // 1.  Create an App Role Authentication backend. 
            try
            {
                // Create an Authentication method of App Role.	- This only needs to be done when the Auth method is created.  
                AuthMethod am = new AuthMethod(_beAuthName, EnumAuthMethods.AppRole);
                await _vaultAgent.System.AuthEnable(am);
            }
            // Ignore mount at same location errors.  This can happen if we are not restarting Vault Instance each time we run.  Nothing to worry about.
            catch (VaultException e)
            {
                if (e.SpecificErrorCode != EnumVaultExceptionCodes.BackendMountAlreadyExists) { Console.WriteLine("Unexpected error in VC_AppRoleBackend.Run method: {0}", e.Message); }
            }
            catch (Exception e) { Console.WriteLine("Unexpected error in VC_AppRoleBackend.Run method: {0}", e.Message); }


            // Create a KV2 Secret Mount if it does not exist.           
            try
            {
                await _vaultAgent.System.SysMountCreate(_beKV2Name, "Sheakley KeyValue 2 Secrets", EnumSecretBackendTypes.KeyValueV2);
            }
            catch (VaultInvalidDataException e)
            {
                if (e.SpecificErrorCode == EnumVaultExceptionCodes.BackendMountAlreadyExists)
                {
                    Console.WriteLine("KV2 Secret Backend already exists.  No need to create it.");
                }
                else
                {
                    Console.WriteLine("Exception trying to mount the KV2 secrets engine. Aborting the rest of the AppRoleBackend Scenario.   Mount Name: {0} - Error: {1}", _beKV2Name, e.Message);
                    return;
                }
            }
        }


        /// <summary>
        /// Creates the policies that this scenario needs.
        ///  - polRoleMaster - Has FC on everything
        ///  - polRole1 - full control on /path1 and everything below it.
        ///  - polRole2 - Read Only access on /path1 and everything below it.  No List capability
        ///  - polAppA  - Full control on /appData/appA 
        ///  - polAppB  - Full control on /appData/appB
        ///  - polShared - Read Only access on /shared/*
        /// </summary>
        /// <returns></returns>
        private async Task CreatePoliciesController() {
            // (Create / Get existing) policyContainer objects.
            _polRoleMaster = await GetPolicy ("polRoleMaster");
            _polRole1 = await GetPolicy("polRole1");
            _polRole2 = await GetPolicy("polRole2");
            _polRoleAppA = await GetPolicy("polRoleAppA");
            _polRoleAppB = await GetPolicy("polRoleAppB");
            _polSharedDB = await GetPolicy ("polSharedDB");
            _polSharedEmail = await GetPolicy ("polSharedEmail");

            // RoleMaster Policy.
            VaultPolicyPathItem vpItem1 = new VaultPolicyPathItem("shKV2/data/*");
            vpItem1.FullControl = true;
            _polRoleMaster.AddPolicyPathObject(vpItem1);
            if (!( await _vaultAgent.System.SysPoliciesACLCreate(_polRoleMaster))) { Console.WriteLine("Unable to save the policies for the CreateRoles method"); }

            // Role1 Policy.  FC on path1 and AppData
            VaultPolicyPathItem vpItem2 = new VaultPolicyPathItem("shKV2/data/path1/*");
            vpItem2.FullControl = true;
            _polRole1.AddPolicyPathObject(vpItem2);
            VaultPolicyPathItem vpItem2B = new VaultPolicyPathItem("shKV2/data/path1");
            vpItem2B.FullControl = true;
            _polRole1.AddPolicyPathObject(vpItem2B);
			//VaultPolicyPathItem vpItem2C = new VaultPolicyPathItem("shKV2/data/" + Constants.appData);
			//vpItem2C.FullControl = true;
			//_polRole1.PolicyPaths.Add(vpItem2C);
			VaultPolicyPathItem vpItem2D = new VaultPolicyPathItem("shKV2/data/" + Constants.appData + "/*");
	        vpItem2D.CreateAllowed = true;
	        _polRole1.AddPolicyPathObject(vpItem2D);
	        VaultPolicyPathItem vpItem2E = new VaultPolicyPathItem("shKV2/metadata/" + Constants.appData + "/*");
	        vpItem2E.ListAllowed = true;
	        _polRole1.AddPolicyPathObject(vpItem2E);

			if (!(await _vaultAgent.System.SysPoliciesACLCreate(_polRole1))) { Console.WriteLine("Unable to save the policies for the Policy {0}", _polRole1.Name); }


            // Role2 Policy.  RO on path1
            VaultPolicyPathItem vpItem3 = new VaultPolicyPathItem("shKV2/data/path1/*");
            vpItem3.ReadAllowed = true;
            _polRole2.AddPolicyPathObject(vpItem3);
            if (!(await _vaultAgent.System.SysPoliciesACLCreate(_polRole2))) { Console.WriteLine("Unable to save the policies for the Policy {0}", _polRole2.Name); }

            // RoleAppA Policy.  FC on apps/AppA
            VaultPolicyPathItem vpItemA1 = new VaultPolicyPathItem("shKV2/data/appData/appA/*");
            vpItemA1.FullControl = true;
            _polRoleAppA.AddPolicyPathObject(vpItemA1);
            if (!(await _vaultAgent.System.SysPoliciesACLCreate(_polRoleAppA))) { Console.WriteLine("Unable to save the policies for the Policy {0}", _polRoleAppA.Name); }

            // RoleAppB Policy.  FC on apps/AppB
            VaultPolicyPathItem vpItemB1 = new VaultPolicyPathItem("shKV2/data/appData/appB/*");
            vpItemB1.FullControl = true;
            _polRoleAppB.AddPolicyPathObject(vpItemB1);
            if (!(await _vaultAgent.System.SysPoliciesACLCreate(_polRoleAppB))) { Console.WriteLine("Unable to save the policies for the Policy {0}", _polRoleAppB.Name); }

            // Shared DB Policy
            VaultPolicyPathItem vpITemDB = new VaultPolicyPathItem("shKV2/data/shared/dbConfig");
            _polSharedDB.AddPolicyPathObject(vpITemDB);
            if (!(await _vaultAgent.System.SysPoliciesACLCreate(_polSharedDB))) { Console.WriteLine("Unable to save the policies for the Policy {0}", _polSharedDB.Name); }

            // Shared Email Policy
            VaultPolicyPathItem vpItemEmail = new VaultPolicyPathItem("shKV2/data/shared/Email");
            _polSharedEmail.AddPolicyPathObject(vpItemEmail);
            if (!(await _vaultAgent.System.SysPoliciesACLCreate(_polSharedEmail))) { Console.WriteLine("Unable to save the policies for the Policy {0}", _polSharedEmail.Name); }
        }



        /// <summary>
        /// Checks to see if a given policy container already exists in the Vault Instance.  If it does, it reads it and returns it.  If not it creates a new PolicyContainer object. 
        /// </summary>
        /// <param name="policyName"></param>
        /// <returns></returns>
        private async Task<VaultPolicyContainer> GetPolicy (string policyName) {
            // First lets try to read an existing policy if it exists:
            VaultPolicyContainer polContainer;

            try {
                polContainer = await _vaultAgent.System.SysPoliciesACLRead(policyName);
                polContainer.PolicyPaths.Clear();
                return polContainer;
            }
            catch (VaultInvalidPathException e)
            {
                if (e.SpecificErrorCode == EnumVaultExceptionCodes.ObjectDoesNotExist) {
                    polContainer = new VaultPolicyContainer(policyName);
                    return polContainer;
                }
                else
                { throw new Exception("Looking for policy: " + policyName + " returned the following unexpected error: " + e.Message); }
            }
       }



		/// <summary>
		/// Creates the specified Role with the specified policies.
		/// </summary>
		/// <param name="roleName"></param>
		/// <param name="policies"></param>
		/// <returns></returns>
		private async Task<AppRole> CreateRole(string roleName, params string[] policies) {
            AppRole role;

            if (!(await _appRoleAuthEngine.RoleExists(roleName)))
            {
                // Role does not exist - so create it.
                role = new AppRole(roleName);
            }
            else
            {
                // Read the role:
                role = await _appRoleAuthEngine.ReadRole(roleName, true);
                if (role == null)
                {
                    Console.WriteLine("Error trying to read existing role {0}", roleName);
                    return null;
                }

                // For this we just clear the existing roles and then re-add the new ones.  This makes testing for this specific demo easier.  Not what you
                // would normally do in production.
                role.Policies.Clear();
            }


            foreach (string policy in policies)
            {
                role.Policies.Add(policy);
            }
            role = await _appRoleAuthEngine.SaveRoleAndReturnRoleObject(role);

            if (role == null)
            {
                Console.WriteLine("Unable to create role: {0} ", roleName);
                return null;
            }

            return role;
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
                // Create the backends if they do not exist.
			    await CreateBackendMounts();

                // Create all the necessary policies.
			    await CreatePoliciesController();

                // Create the roles and assign the policies.
			    roleMaster = await CreateRole ("roleMaster", _polRoleMaster.Name);
			    role1 = await CreateRole ("role1", _polRole1.Name);
			    role2 = await CreateRole("role2", _polRole2.Name);
			    roleAppA = await CreateRole ("roleAppA", _polRoleAppA.Name,_polSharedDB.Name);
			    roleAppB = await CreateRole("roleAppB", _polRoleAppB.Name, _polSharedDB.Name, _polSharedEmail.Name);


                // Create Secret ID's for each of the Application Roles                
			    _SIDRoleMaster = await _appRoleAuthEngine.CreateSecretID (roleMaster.Name);
			    _SIDRole1 = await _appRoleAuthEngine.CreateSecretID(role1.Name);
			    _SIDRole2 = await _appRoleAuthEngine.CreateSecretID(role2.Name);
			    _SIDRoleAppA = await _appRoleAuthEngine.CreateSecretID(roleAppA.Name);
			    _SIDRoleAppB = await _appRoleAuthEngine.CreateSecretID(roleAppB.Name);




               // Main testing logic begins here.

               // For this sequence of steps we need to create a new instance of the Vault as we will be connecting via the new token.  We connect to the requested backend.
                VaultAgentAPI A_VaultAgentAPI = new VaultAgentAPI("SecretRole A",_vaultAgent.IP,_vaultAgent.Port);
			    AppRoleAuthEngine A_appRoleAuthEngine = (AppRoleAuthEngine) A_VaultAgentAPI.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _beAuthName, _beAuthName);
			    KV2SecretEngine A_KV2SecretEngine =
			        (KV2SecretEngine) A_VaultAgentAPI.ConnectToSecretBackend (EnumSecretBackendTypes.KeyValueV2, "Sheakley KV2 Secrets", _beKV2Name);

			    await PerformRoleMasterTasks();
			    await PerformRole1Tasks();


			    return;


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
		/// Performs tasks to setup the RoleMaster Role for use.
		/// </summary>
		/// <returns></returns>
        public async Task PerformRoleMasterTasks() {
            KV2SecretEngine secEngine =
                (KV2SecretEngine) _vaultAgent.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, "Sheakley KV2 Secrets", _beKV2Name);

            // Create the Path1 "secret"
            KV2Secret a = new KV2Secret("path1");
			var result = await secEngine.TryReadSecret(a);
			if (!result.IsSuccess) {
				await secEngine.SaveSecret(a, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist);
			}

			//await secEngine.SaveSecret (a, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist);

			// Create the AppData Folder
			KV2Secret b = new KV2Secret(Constants.appData);
			result = await secEngine.TryReadSecret(b);
			if (!result.IsSuccess) {
				await secEngine.SaveSecret(b, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist);
			}

			return;
        }



		/// <summary>
		/// Performs tasks that the Role1 user would do.
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
        public async Task PerformRole1Tasks() {
			try {
				// Here we will create the AppA and B folders in both the path1 and the appData paths.
				KV2Secret path1AppA = new KV2Secret(Constants.appName_A, "path1");
				KV2Secret path1AppB = new KV2Secret(Constants.appName_B, "path1");
				KV2Secret appDataAppA = new KV2Secret(Constants.appName_A, Constants.appData);
				KV2Secret appDataAppB = new KV2Secret(Constants.appName_B, Constants.appData);
				KV2Secret appData = new KV2Secret(Constants.appData);

				// We need to simulate a session as this Role1 User:
				VaultAgentAPI vault = new VaultAgentAPI("Role1", _vaultAgent.IP, _vaultAgent.Port);
				AppRoleAuthEngine authEngine = (AppRoleAuthEngine) vault.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _AppBEName, _AppBEName);
				KV2SecretEngine secretEngine =
					(KV2SecretEngine) vault.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, "Sheakley KV2 Secrets", _beKV2Name);

				// Now login.            
				Token token = await authEngine.Login(role1.RoleID, _SIDRole1.ID);


				// Create the secrets if they do not exist.  We can attempt to Read the Secret on the path1 paths as we have full control
				var result = await secretEngine.TryReadSecret(path1AppA);
				if (!result.IsSuccess) {
					await secretEngine.SaveSecret(path1AppA, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist);
				}
				result = await secretEngine.TryReadSecret(path1AppB);
				if (!result.IsSuccess) {
					await secretEngine.SaveSecret(path1AppB, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist);
				}

				// We have to list the "folders" or secrets on the AppData path as we only have create and List permissions.
				List<string> appFolders = await secretEngine.ListSecretsAtPath(appData);
				if (!appFolders.Contains(Constants.appName_A)) { await secretEngine.SaveSecret(appDataAppA, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist); }
				if (!appFolders.Contains(Constants.appName_B)) { await secretEngine.SaveSecret(appDataAppB, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist); }

				//	result = await secretEngine.TryReadSecret(appDataAppA);
				//	if (!result.IsSuccess) {
				await secretEngine.SaveSecret(appDataAppA, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist);
			//	}
			//	result = await secretEngine.TryReadSecret(appDataAppB);
			//	if (!result.IsSuccess) {
					await secretEngine.SaveSecret(appDataAppB, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist);
			//	}


			}
			catch (VaultForbiddenException e) { Console.WriteLine("The role does not have permission to perform the requested operation. - Original Error - {0}", e.Message);}
			catch (Exception e) { Console.WriteLine("Error detected in routine - PerformRole1Tasks - Error is - {0}", e.Message); }
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
