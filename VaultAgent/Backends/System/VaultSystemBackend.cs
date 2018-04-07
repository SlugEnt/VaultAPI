using System;
using System.Collections.Generic;
using System.Threading.Tasks;
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


		// ==============================================================================================================================================
		// ==============================================================================================================================================
		// ==============================================================================================================================================
		// ==============================================================================================================================================
		// ==============================================================================================================================================

	}
}
