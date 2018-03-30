using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;

namespace VaultAgent.Backends
{
	public class TransitBackend
	{
		TokenInfo transitToken;		
		private VaultAPI_Http vaultHTTP;
		string transitPath = "/v1/transit/keys/";
		Uri vaultTransitPath;



		// ==============================================================================================================================================
		/// <summary>
		/// Constructor.  Initializes the connection to Vault and stores the token.
		/// </summary>
		/// <param name="vaultIP">The IP address of the Vault Server.</param>
		/// <param name="port">The network port the Vault server listens on.</param>
		/// <param name="Token">The token used to authenticate with.</param>
		public TransitBackend (string vaultIP, int port, string Token) {
			vaultHTTP = new VaultAPI_Http(vaultIP, port, Token);
			transitToken = new TokenInfo();
			transitToken.Id = Token;

			vaultTransitPath = new Uri("http://" + vaultIP + ":" + port + transitPath);
		}




		// ==============================================================================================================================================
		public async Task<bool> CreateEncryptionKey(string keyName, Dictionary<string,string> createParams) {
			// The keyname forms the last part of the path
			string path = vaultTransitPath + keyName;

			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, createParams);
			if (vdro.httpStatusCode == 204) { return true; }
			else { return false; }


			//string ans =  await vaultHTTP.PostAsync(path, createParams);
			

			//throw new System.NotImplementedException();
		}



		// ==============================================================================================================================================
		public string Encrypt(string keyName, string data) {
			throw new System.NotImplementedException();
		}




		// ==============================================================================================================================================
		public string Decrypt(string keyName, string data) {
			throw new System.NotImplementedException();
		}



		// ==============================================================================================================================================
		public bool RotateEncryptionKey (string keyName) {
			throw new System.NotImplementedException();
		}




		// ==============================================================================================================================================
		/// <summary>
		/// Re-encrypts the currently encrypted data with the current version of the key.  This is a simplified way
		/// of upgrading the encryption for an element without have to call Decrypt and then Encrypt separately.
		/// </summary>
		/// <param name="keyName">The Encryption key to use to decrypt and re-encrypt the data</param>
		/// <param name="encryptedData">The currently encrypted data element that you want to have upgraded with the 
		/// new encryption key.</param>
		/// <returns>The data element encrypted with the latest version of the encryption key.</returns>
		public string ReEncrypt (string keyName, string encryptedData) {
			throw new System.NotImplementedException();
		}


	}
}
