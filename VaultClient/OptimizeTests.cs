using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using SlugEnt;
using VaultAgent;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Backends;
using VaultAgent.Backends.System;
using VaultAgent.SecretEngines;

namespace VaultClient
{
	/// <summary>
	/// This class was used during optimization processes to test reduction in memory usage, variable count, and performance enhancements.
	/// </summary>
	public class OptimizeTests {
		private VaultAgentAPI _vault;
		private AppRoleAuthEngine _appRoleAuthEngine;
		private KV2SecretEngine _kv2SecretEngine;
		private IdentitySecretEngine _idEngine;

		private string _beAuthName;
		private string _beKV2Name;
		private UniqueKeys _uniqueKeys = new UniqueKeys("_");


		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="vaultAgent"></param>
		public OptimizeTests (VaultAgentAPI vaultAgent) {
			_vault = vaultAgent;

		}


		public async Task Run () {
            await CreateBackendMounts();

            _appRoleAuthEngine = (AppRoleAuthEngine)_vault.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, _beAuthName, _beAuthName);
            _idEngine = (IdentitySecretEngine)_vault.ConnectToSecretBackend(EnumSecretBackendTypes.Identity);
            _kv2SecretEngine =
                (KV2SecretEngine)_vault.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, "KV2 Secrets", _beKV2Name);



            await AppRoleBE_UpdateRoleID(); 
			Console.WriteLine("Finished With Optimization Run.  Press any key to continue.");
			Console.ReadKey();
		}



		/// <summary>
		/// This particular test was running consistently 15x slower than any other test.  ~250ms
		/// </summary>
		/// <returns></returns>
		public async Task AppRoleBE_UpdateRoleID() {
			string rName = _uniqueKeys.GetKey("Role");
			AppRole ar = new AppRole(rName);
			bool rc =  await _appRoleAuthEngine.SaveRole(ar);

			// Now read a Role ID for it.
			string roleID = await _appRoleAuthEngine.ReadRoleID(ar.Name);

			// Update the role ID
			rc = await _appRoleAuthEngine.UpdateAppRoleID(ar.Name, "newDomain");
			string roleIDNew = await _appRoleAuthEngine.ReadRoleID(ar.Name);
			Assert.AreEqual("newDomain", roleIDNew);
			Console.WriteLine("AppRoleBE_UpdateRoleID Finished OK!");
		}





		#region SetupTasks

		/// <summary>
		/// Creates the backend Authorization and KeyValue Version 2 Secret Backends
		///  - Note the routine checks to see if the backends already exist.  If they do (which they might if you leave the Vault Instance up and running across runs
		///    of this program) then it ignores the errors and continues on.
		/// </summary>
		/// <returns></returns>
		private async Task CreateBackendMounts() {
			_beAuthName = _uniqueKeys.GetKey("VCAR");
			_beKV2Name = _uniqueKeys.GetKey("VCKV");


			// 1.  Create an App Role Authentication backend. 
			try {
				// Create an Authentication method of App Role.	- This only needs to be done when the Auth method is created.  
				AuthMethod am = new AuthMethod(_beAuthName, EnumAuthMethods.AppRole);
				await _vault.System.AuthEnable(am);
			}
			// Ignore mount at same location errors.  This can happen if we are not restarting Vault Instance each time we run.  Nothing to worry about.
			catch (VaultException e) {
				if (e.SpecificErrorCode != EnumVaultExceptionCodes.BackendMountAlreadyExists) { Console.WriteLine("Unexpected error in VC_AppRoleBackend.Run method: {0}", e.Message); }
			}
			catch (Exception e) { Console.WriteLine("Unexpected error in VC_AppRoleBackend.Run method: {0}", e.Message); }


			// Create a KV2 Secret Mount if it does not exist.           
			try {
				await _vault.System.SysMountCreate(_beKV2Name, "ClientTest KeyValue 2 Secrets", EnumSecretBackendTypes.KeyValueV2);
			}
			catch (VaultInvalidDataException e) {
				if (e.SpecificErrorCode == EnumVaultExceptionCodes.BackendMountAlreadyExists) {
					Console.WriteLine("KV2 Secret Backend already exists.  No need to create it.");
				}
				else {
					Console.WriteLine("Exception trying to mount the KV2 secrets engine. Aborting the rest of the AppRoleBackend Scenario.   Mount Name: {0} - Error: {1}", _beKV2Name, e.Message);
					return;
				}
			}
		}


		#endregion
	}
}
