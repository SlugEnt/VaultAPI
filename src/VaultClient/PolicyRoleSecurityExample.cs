using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using SlugEnt;
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
    /// The paths for the House that will be stored in Vault.
    /// </summary>
    public class HOUSE
    {
        public const string HOUSE_PATH = "house";
        public const string KITCHEN = HOUSE_PATH + "/kitchen";
        public const string REFRIGERATOR = KITCHEN + "/refrigerator";
        public const string DISHWASHER = KITCHEN + "/dishwasher";
        public const string GARAGE = HOUSE_PATH + "/garage";
        public const string MASTER_BEDROOM = HOUSE_PATH + "/masterbedroom";
        public const string TEEN_BEDROOM = HOUSE_PATH + "/teenbedroom";
        public const string TODDLER_BEDROOM = HOUSE_PATH + "/toddlerbedroom";
        }


    /// <summary>
    /// This demonstrates the Vault Security Model for Secrets.
    /// It is important to remember there can be 2 different secrets for a given path object.  For instance in our hypothetical house below there are 2 things
    /// we need to protect:
    ///   /House  (Which is the House Secret)
    ///   /House/*  (Which is all child secrets of House, or everything below House.
    ///
    ///  
    ///
    /// For this scenario we will be securing a hypothetical household.  The following will be the secure areas:
    ///  - House 
    ///    - Kitchen 
    ///      - Refrigerator
    ///      - Dishwasher
    ///    - Garage
    ///    - Master Bedroom
    ///    - Teenager Bedroom
    ///    - Toddler Bedroom
    ///
    ///  There are 2 ways we could create policies for the above.
    ///   1.  We could create policies per room/object and then assign the policies to the roles
    ///   2.  We could create policies per user
    ///  Depending on the needs you may choose one or the other.  For instance, if you want better control and easier management of the actual permissions for a given object then #1 is the better choice
    /// For this scenario we will choose option 1.  In this case we will create a policy(s) per room.  For example for the Kitchen will provide 2 policies
    ///  Kitchen_Read - Readonly, used by Toddler
    ///  Kitchen_Write - Read/Write, used by Teenager.
    /// 
    ///  The partipants or roles will be:
    ///    - Mother
    ///    - Father
    ///    - Teenager
    ///    - Toddler
    ///
    ///  The Mother rules the house and will be considered the ruler of all!  She will have full access to everything and will be used to create all of the initial secrets
    ///  The Father will have Read on everything and update on certain other objects
    ///  The Teenage will have the following permissions
    ///    House - Read (no inheritance to lower values)
    ///    Kitchen - Update (No inheritance to lower values)
    ///       Refrigerator - Read/Write
    ///       Dishwasher - No Access
    ///    Garage - Read
    ///    Master Bedroom - None
    ///    Teenager Bedroom - Full
    ///    Toddler Bedroom - none
    /// The todder will have the following rights
    ///    Toddler Bedroom - Full
    ///    Kitchen - Read
    /// 
    /// 
    /// </summary>
    class PolicyRoleSecurityExample
    {
        private readonly string _beAuthName = "RoleAuth";
        private readonly string _beKV2Name = "HouseholdSecrets";


        private AppRoleAuthEngine _appRoleAuthEngine;
        private KV2SecretEngine _secretEngine;
        private readonly VaultAgentAPI _masterVaultAgent;
        private readonly VaultSystemBackend _vaultSystemBackend;

        //private readonly IdentitySecretEngine _idEngine;

        private readonly string _AppBEName;

        // Roles
        private AppRole roleMother;
        private AppRole roleFather;
        private AppRole roleTeenager;
        private AppRole roleToddler;

        
        // Secret IDS'
        private AppRoleSecret _sidMother;
        private AppRoleSecret _sidFather;
        private AppRoleSecret _sidTeenager;
        private AppRoleSecret _sidToddler;

        // Policies
        private VaultPolicyContainer _policyHouse_Full;
        private VaultPolicyContainer _policyHouseOnly_Read;
        private VaultPolicyContainer _policyKitchen_Read;
        private VaultPolicyContainer _policyKitchen_Write;
        private VaultPolicyContainer _policyKitchenRefrigerator_Write;
        private VaultPolicyContainer _policyGarage_Read;
        private VaultPolicyContainer _policyTeenagerBedroom_Full;
        private VaultPolicyContainer _policyToddlerBedroom_Full;



        /// <summary>
        /// Constructor for the Family Role/Policy Tutorial
        /// </summary>
        /// <param name="masterVaultAgent"></param>
        public PolicyRoleSecurityExample(VaultAgentAPI masterVaultAgent)
        {
            UniqueKeys uniqueKeys = new UniqueKeys();

            // We will create a unique App Role Authentication Engine with the given name.
            _AppBEName = "BEAppRole";
            _masterVaultAgent = masterVaultAgent;
            _vaultSystemBackend = new VaultSystemBackend(masterVaultAgent.TokenID, masterVaultAgent);
            _appRoleAuthEngine =
                (AppRoleAuthEngine) masterVaultAgent.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _AppBEName,
                    _AppBEName);
            masterVaultAgent.ConnectToSecretBackend(EnumSecretBackendTypes.Identity);
        }



        /// <summary>
        /// Start The Scenario
        /// </summary>
        /// <returns></returns>
        public async Task Run()
        {
            // Create the mounts and policies and store in Vault
            await CreateBackendMounts();
            await CreatePolicies();

            // Mount the Secret Engine
            _secretEngine =
                (KV2SecretEngine)_masterVaultAgent.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, _beKV2Name, _beKV2Name);

            // Mount the Authentication Engine, so roles can login
            _appRoleAuthEngine = (AppRoleAuthEngine)_masterVaultAgent.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _AppBEName, _AppBEName);


            // Create the roles - assigning policies to the roles
            roleMother = await CreateRole("roleMother", _policyHouse_Full.Name);
            roleFather = await CreateRole("roleFather", _policyHouse_Full.Name);
            roleTeenager = await CreateRole("roleTeenager", _policyTeenagerBedroom_Full.Name,
                _policyKitchenRefrigerator_Write.Name, _policyHouseOnly_Read.Name, _policyKitchen_Write.Name);
            roleToddler = await CreateRole("roleToddler", _policyToddlerBedroom_Full.Name);

            // Create Login SIDS for each role
            _sidMother = await _appRoleAuthEngine.CreateSecretID(roleMother.Name);
            _sidFather = await _appRoleAuthEngine.CreateSecretID(roleFather.Name);
            _sidTeenager = await _appRoleAuthEngine.CreateSecretID(roleTeenager.Name);
            _sidToddler = await _appRoleAuthEngine.CreateSecretID(roleToddler.Name);

            // Set the Mother role to have full access.
            KV2Secret a = new KV2Secret(HOUSE.HOUSE_PATH);
            await SaveSecret(_secretEngine,a);


            // It's important to note:  Up to now we have been using the Master token to create objects, secret stores, policies and the initial House Secret.  From here forward each
            // user will login and perform the actions under their user ID. 

            await Perform_MotherTasks();
            await Perform_TeenTasks();
        }


        /// <summary>
        /// Perform tasks the mother wants to do
        /// </summary>
        /// <returns></returns>
        private async Task Perform_MotherTasks()
        {
            // We cannot use the Vault Agent _masterVaultAgent, since it has the Master Token tied to it.  We will create a new VaultAgent and SecretEngine for use during this Task, which will have our
            // Mother role token AND not the master Token.  
            // So, we wire up a new Vault, AppRole and Secret Engines AND use them throughout this routine.
            VaultAgentAPI vault = new VaultAgentAPI("MotherConnector", _masterVaultAgent.Uri);
            AppRoleAuthEngine authEngine = (AppRoleAuthEngine)vault.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _AppBEName, _AppBEName);
            KV2SecretEngine secretEngine =
                (KV2SecretEngine)vault.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, _beKV2Name, _beKV2Name);


            // Login.            
            Token token = await authEngine.Login(roleMother.RoleID, _sidMother.ID);

            // Load the house secret, modify it and save it.
            KV2Secret a = await secretEngine.ReadSecret<KV2Secret>(HOUSE.HOUSE_PATH);
            a.Attributes.Add("Electric","Yes");
            await SaveSecret(secretEngine,a);

            // Create the Kitchen
            KV2Secret b = new KV2Secret(HOUSE.KITCHEN);
            b.Attributes.Add("Dishwasher", "Yes");
            await SaveSecret(secretEngine,b);

            // Refrigerator
            KV2Secret c = new KV2Secret(HOUSE.REFRIGERATOR);
            c.Attributes.Add("Milk", "Chocolate");
            c.Attributes.Add("Cheese", "American");
            await SaveSecret(secretEngine,c);

            // DishWasher
            KV2Secret c1 = new KV2Secret(HOUSE.DISHWASHER);
            c1.Attributes.Add("Drawers","3");
            await SaveSecret(secretEngine, c1);

            // Garage
            KV2Secret d = new KV2Secret(HOUSE.GARAGE);
            d.Attributes.Add("Car","Porsche");
            await SaveSecret(secretEngine,d);

            // Master Bedroom
            KV2Secret e = new KV2Secret(HOUSE.MASTER_BEDROOM);
            e.Attributes.Add("Safe", "Yes");
            await SaveSecret(secretEngine,e);

            // Teen Bedroom
            KV2Secret f = new KV2Secret(HOUSE.TEEN_BEDROOM);
            f.Attributes.Add("CarPoster", "Yes");
            await SaveSecret(secretEngine,f);

            // Toddler Bedroom
            KV2Secret g = new KV2Secret(HOUSE.TODDLER_BEDROOM);
            g.Attributes.Add("BabyMonitor", "On");
            await SaveSecret(secretEngine,g);

        }



        /// <summary>
        /// Performs tasks that the teen wants to to.  
        /// </summary>
        /// <returns></returns>
        private async Task Perform_TeenTasks()
        {
            // We cannot use the Vault Agent _masterVaultAgent, since it has the Master Token tied to it.  We will create a new VaultAgent and SecretEngine for use during this Task, which will have our
            // Mother role token AND not the master Token.  
            // So, we wire up a new Vault, AppRole and Secret Engines AND use them throughout this routine.
            VaultAgentAPI vault = new VaultAgentAPI("TeenConnector", _masterVaultAgent.Uri);
            AppRoleAuthEngine authEngine = (AppRoleAuthEngine)vault.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _AppBEName, _AppBEName);
            KV2SecretEngine secretEngine =
                (KV2SecretEngine)vault.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, _beKV2Name, _beKV2Name);


            // Login.            
            Token token = await authEngine.Login(roleTeenager.RoleID, _sidTeenager.ID);


            
            // Should be able to load the House Secret.  But not updated it.
            KV2Secret a = await secretEngine.ReadSecret<KV2Secret>(HOUSE.HOUSE_PATH);
            a.Attributes["Electric"] = "No";
            
            // Should Fail
            await SaveSecret(secretEngine, a);


            // Should NOT be able to read anything in the Toddler's Bedroom
            ( bool _, KV2Secret _) = await ReadSecret(secretEngine, HOUSE.TODDLER_BEDROOM);
            
            // Should be able to read and update the Kitchen secret
            (bool _, KV2Secret k) = await ReadSecret(secretEngine, HOUSE.KITCHEN);
            k.Attributes["Carrots"] = "Need";
            await SaveSecret(secretEngine, k);

            // Should be able to read and update the Fridge
            (bool _, KV2Secret r) = await ReadSecret(secretEngine, HOUSE.REFRIGERATOR);
            k.Attributes["Cold"] = "True";
            await SaveSecret(secretEngine, r);

            // Should have no writes to the Dishwasher
            (bool _, KV2Secret _) = await ReadSecret(secretEngine, HOUSE.DISHWASHER);
        }

        private async Task Perform_FatherTasks()
        {
            // Now login.            
            await _appRoleAuthEngine.Login(roleFather.RoleID, _sidFather.ID);



        }



        /// <summary>
        /// Saves the given Secret to the Vault
        /// </summary>
        /// <param name="secret">The secret to save</param>
        /// <returns></returns>
        private async Task<bool> SaveSecret(KV2SecretEngine engine, KV2Secret secret)
        {
            try
            {
                return await engine.SaveSecret(secret, KV2EnumSecretSaveOptions.AlwaysAllow);
            }
            catch (VaultForbiddenException)
            {
                return false;
            }
        }


        /// <summary>
        /// Reads the Secret from the Engine
        /// </summary>
        /// <param name="engine"></param>
        /// <param name="secretPath"></param>
        /// <returns></returns>
        private async Task<(bool isSuccess, KV2Secret theSecret)> ReadSecret(KV2SecretEngine engine, string secretPath)
        {
            try
            {
                KV2Secret secret = await engine.ReadSecret<KV2Secret>(secretPath);
                return (true, secret);
            }
            catch (VaultForbiddenException)
            {
                return (false, null);
            }
        }
        



        /// <summary>
        /// Creates the backend Authorization and KeyValue Version 2 Secret Backends
        ///  - Note the routine checks to see if the backends already exist.  If they do (which they might if you leave the Vault Instance up and running across runs
        ///    of this program) then it ignores the errors and continues on.
        /// </summary>
        /// <returns></returns>
        private async Task CreateBackendMounts()
        {
            try
            {
                // Create an Authentication method of App Role.	- This only needs to be done when the Auth method is created.  
                AuthMethod am = new AuthMethod(_beAuthName, EnumAuthMethods.AppRole);
                await _vaultSystemBackend.AuthEnable(am);
            }
            // Ignore mount at same location errors.  This can happen if we are not restarting Vault Instance each time we run.  Nothing to worry about.
            catch (VaultException e)
            {
                if (e.SpecificErrorCode != EnumVaultExceptionCodes.BackendMountAlreadyExists) { Console.WriteLine("Unexpected error in VC_AppRoleBackend.Run method: {0}", e.Message); }
            }
            catch (Exception e) { Console.WriteLine("Unexpected error in VC_AppRoleBackend.Run method: {0}", e.Message); }


            // 2.  Create a KV2 Secret Mount if it does not exist.           
            try
            {
                await _vaultSystemBackend.SysMountCreate(_beKV2Name, "ClientTest KeyValue 2 Secrets", EnumSecretBackendTypes.KeyValueV2);
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
        /// Checks to see if a given policy container already exists in the Vault Instance.  If it does, it reads it and returns it.  If not it creates a new PolicyContainer object, but does not save to Vault. 
        /// </summary>
        /// <param name="policyName"></param>
        /// <returns></returns>
        private async Task<VaultPolicyContainer> GetPolicy(string policyName)
        {
            // First lets try to read an existing policy if it exists:
            VaultPolicyContainer polContainer;

            try
            {
                polContainer = await _vaultSystemBackend.SysPoliciesACLRead(policyName);
                polContainer.PolicyPaths.Clear();
                return polContainer;
            }
            catch (VaultInvalidPathException e)
            {
                if (e.SpecificErrorCode == EnumVaultExceptionCodes.ObjectDoesNotExist)
                {
                    polContainer = new VaultPolicyContainer(policyName);
                    return polContainer;
                }
                else
                { throw new Exception("Looking for policy: " + policyName + " returned the following unexpected error: " + e.Message); }
            }
        }


        /// <summary>
        /// Create all the policies required for this scenario
        /// </summary>
        /// <returns></returns>
        private async Task CreatePolicies()
        {
            _policyHouse_Full = await GetPolicy("policyHouse_F");
            _policyHouseOnly_Read = await GetPolicy(("policyHouse_R"));
            _policyKitchen_Read = await GetPolicy("policyKitchen_CR");
            _policyKitchen_Write = await GetPolicy("policyKitchen_W");
            
            _policyKitchenRefrigerator_Write = await GetPolicy("policyKitchenRefrigerator_W");
            
            _policyGarage_Read = await GetPolicy("policyGarage_R");
            _policyTeenagerBedroom_Full = await GetPolicy("policyTeenBedroom_F");
            _policyToddlerBedroom_Full = await GetPolicy("policyToddler_F");

            // Now set the objects to secure for each policy:
            VaultPolicyPathItem policyItem;
            VaultPolicyContainer policy;

            // # House Full.  We need to Create Policy for Both the "root" folder and children folders.
            policyItem = new VaultPolicyPathItemKV2(_beKV2Name, HOUSE.HOUSE_PATH + "/*");
            policyItem.FullControl = true;
            VaultPolicyPathItem policyItemBase = new VaultPolicyPathItemKV2(_beKV2Name,HOUSE.HOUSE_PATH);
            policyItemBase.FullControl = true;
            policy = _policyHouse_Full;
            policy.AddPolicyPathObject(policyItem);
            policy.AddPolicyPathObject(policyItemBase);
            if (!(await _vaultSystemBackend.SysPoliciesACLCreate(policy))) { Console.WriteLine("Unable to save the policies for the Policy {0}", policy.Name); }


            // House Read of just the House Secret
            policyItem = new VaultPolicyPathItemKV2(_beKV2Name, HOUSE.HOUSE_PATH);
            policyItem.ReadAllowed = true;
            policy = _policyHouseOnly_Read;
            policy.AddPolicyPathObject(policyItem);
            if (!(await _vaultSystemBackend.SysPoliciesACLCreate(policy))) { Console.WriteLine("Unable to save the policies for the Policy {0}", policy.Name); }


            // # Kitchen Child Secrets Read
            policyItem = new VaultPolicyPathItemKV2(_beKV2Name,  HOUSE.KITCHEN + "/*");
            policyItem.ReadAllowed = true;
            policyItemBase = new VaultPolicyPathItemKV2(_beKV2Name, HOUSE.KITCHEN);
            policyItemBase.UpdateAllowed = true;
            policy = _policyKitchen_Read;
            policy.AddPolicyPathObject(policyItem);
            policy.AddPolicyPathObject(policyItemBase);
            if (!(await _vaultSystemBackend.SysPoliciesACLCreate(policy))) { Console.WriteLine("Unable to save the policies for the Policy {0}", policy.Name); }

            // # Kitchen Child Secrets Write
            policyItem = new VaultPolicyPathItemKV2(_beKV2Name,  HOUSE.KITCHEN );
            policyItem.UpdateAllowed = true;
            policyItem.ReadAllowed = true;
            policy = _policyKitchen_Write;
            policy.AddPolicyPathObject(policyItem);
            if (!(await _vaultSystemBackend.SysPoliciesACLCreate(policy))) { Console.WriteLine("Unable to save the policies for the Policy {0}", policy.Name); }

            // # Kitchen Refrigerator (No children Secrets) Write
            policyItem = new VaultPolicyPathItemKV2(_beKV2Name, HOUSE.REFRIGERATOR );
            policyItem.ReadAllowed = true;
            policyItem.UpdateAllowed = true;
            policy = _policyKitchenRefrigerator_Write;
            policy.AddPolicyPathObject(policyItem);
            if (!(await _vaultSystemBackend.SysPoliciesACLCreate(policy))) { Console.WriteLine("Unable to save the policies for the Policy {0}", policy.Name); }

            // # Garage (No Children) Read
            policyItem = new VaultPolicyPathItemKV2(_beKV2Name, HOUSE.GARAGE);
            policyItem.ReadAllowed = true;
            policy = _policyGarage_Read;
            policy.AddPolicyPathObject(policyItem);
            if (!(await _vaultSystemBackend.SysPoliciesACLCreate(policy))) { Console.WriteLine("Unable to save the policies for the Policy {0}", policy.Name); }

            // # Teenager Full - both root and child
            policyItem = new VaultPolicyPathItemKV2(_beKV2Name, HOUSE.TEEN_BEDROOM + "/*");
            policyItem.FullControl = true;
            policyItemBase = new VaultPolicyPathItemKV2(_beKV2Name,HOUSE.TEEN_BEDROOM);
            policyItemBase.FullControl = true;
            policy = _policyTeenagerBedroom_Full;
            policy.AddPolicyPathObject(policyItem);
            policy.AddPolicyPathObject(policyItemBase);
            if (!(await _vaultSystemBackend.SysPoliciesACLCreate(policy))) { Console.WriteLine("Unable to save the policies for the Policy {0}", policy.Name); }

            // # Toddler Full
            policyItem = new VaultPolicyPathItemKV2(_beKV2Name, HOUSE.TODDLER_BEDROOM + "/*");
            policyItem.FullControl = true;
            policyItemBase = new VaultPolicyPathItemKV2(_beKV2Name, HOUSE.TODDLER_BEDROOM);
            policy = _policyToddlerBedroom_Full;
            policy.AddPolicyPathObject(policyItem);
            policy.AddPolicyPathObject(policyItemBase);
            if (!(await _vaultSystemBackend.SysPoliciesACLCreate(policy))) { Console.WriteLine("Unable to save the policies for the Policy {0}", policy.Name); }
        }



        /// <summary>
        /// Creates the specified Role with the specified policies.
        /// </summary>
        /// <param name="roleName"></param>
        /// <param name="policies"></param>
        /// <returns></returns>
        private async Task<AppRole> CreateRole(string roleName, params string[] policies)
        {
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

    }
}
