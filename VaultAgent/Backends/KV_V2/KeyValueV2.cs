using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultAgent.Models;
using VaultAgent.Backends.SecretEngines.KVV2;
using VaultAgent.Backends.KV_V2;
using Newtonsoft.Json;

namespace VaultAgent.Backends.SecretEngines
{
	/// <summary>
	/// This backend is for interfacing with the Vault secret Backend Version 2.0.  
	/// One of the unique things is that there are different root mounts within the given backend depending on what you want to do.  So having
	/// a std BackEnd path does not really work with this class.  It generally builds the unique path in each member method.
	/// </summary>
	public class KeyValueV2Backend
	{
		TokenInfo secretToken;
		private VaultAPI_Http vaultHTTP;
		private string secretBEName = "secret";
		private string secretBEPath = "/secret/";	


		// ==============================================================================================================================================
		/// <summary>
		/// Constructor.  Initializes the connection to Vault and stores the token.
		/// </summary>
		/// <param name="vaultIP">The IP address of the Vault Server.</param>
		/// <param name="port">The network port the Vault server listens on.</param>
		/// <param name="Token">The token used to authenticate with.</param>
		/// <param name="backendMountName">The name of the secret backend to mount.  For example for a mount at /mine/secretA use mine/secretA as value.</param>
		public KeyValueV2Backend(string vaultIP, int port, string Token, string backendMountName = "secret") {
			vaultHTTP = new VaultAPI_Http(vaultIP, port, Token);
			secretToken = new TokenInfo();
			secretToken.Id = Token;

			secretBEName = backendMountName;
			secretBEPath = "/v1/" + secretBEName + "/";
		}



		#region "Configuration"
		/// <summary>
		/// Configures the Key Value V2 backend. 
		/// </summary>
		/// <param name="maxVersions">The maximum number of versions of a key to keep.  Defaults to 10.</param>
		/// <param name="casRequired">Check-And-Set parameter. If set to True then all writes (creates and updates) to keys will need to have the CAS parameter specified.  
		/// See the Update and Create methods for details about the CAS setting.
		/// <returns></returns>
		public async Task<bool> SetBackendConfiguration (UInt16 maxVersions = 10, bool casRequired = false) {
			try {
				// V2 Secret stores have a unique config path...
				string path = secretBEPath + "config";

				// Build the content parameters, which will contain the maxVersions and casRequired settings.
				Dictionary<string, string> contentParams = new Dictionary<string, string>();
				contentParams.Add("max_versions", maxVersions.ToString());
				contentParams.Add("cas_required", casRequired.ToString());

				VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "ConfigureBackend", contentParams);
				if (vdro.Success) { return true; }
				return false;
			}
			catch (Exception e) { throw e; }
		}



		/// <summary>
		/// Returns the configuration settings of the current KeyValue V2 secret store. 
		/// </summary>
		/// <returns>KV_V2_Settings object with the values of the current configuration.</returns>
		public async Task<KV_V2_Settings> GetBackendConfiguration () {
			try {

				// V2 Secret stores have a unique config path...
				string path = secretBEPath + "config";

				VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "GetBackendConfiguration");
				KV_V2_Settings settings = vdro.GetVaultTypedObject<KV_V2_Settings>();
				return settings;
			}
			catch (Exception e) { throw e; }
		}

		#endregion


		public async Task<bool> SaveSecret (SecretV2 secret) {
			string path = secretBEPath + "data/" + secret.Path;


			Dictionary<string, object> reqData = new Dictionary<string, object>();
			Dictionary<string, string> options = new Dictionary<string, string>();
			// CAS - Check and Set needs to be passed in from caller.
			//options.Add("cas", "");
			reqData.Add("options",options);
			reqData.Add("data", secret);

			VaultDataResponseObject vdro = await vaultHTTP.PostAsync2(path, "SaveSecret",reqData);
			if (vdro.Success) {
				return true;
			}
			return false;
		}



		public async Task<SecretV2> ReadSecret (string secretPath) {
			string path = secretBEPath + "data/" + secretPath;
			try {
				VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "ReadSecret");
				if (vdro.Success) {
					SecretReadReturnObj secretReadReturnObj = SecretReadReturnObj.FromJson(vdro.GetResponsePackageAsJSON());
					return secretReadReturnObj.Data.SecretObj;
				}
				throw new ApplicationException("SecretBackEnd: ReadSecret - Arrived at an unexpected code path.");
			}
			catch (VaultInvalidPathException e) { return null; }
			catch (Exception e) { throw e; }
		}
	}
}
