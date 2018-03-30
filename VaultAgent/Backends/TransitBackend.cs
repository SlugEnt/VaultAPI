using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;
using VaultAgent;

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
		/// <summary>
		/// Creates an Encryptyion key with the specified name.  This one allows greater latitude in defining the parameters.
		/// </summary>
		/// <param name="keyName">This is the actual name of the encryption key.</param>
		/// <param name="createParams">A Dictionary in the Dictionary [string,string] format.  You must have supplied the values for the dictionary
		/// in the calling routing.  The Key should match the Vault API keyname and the Value should be the value in the format vault is expecting.</param>
		/// <returns>True if the key is successfully cresated.</returns>
		public async Task<bool> CreateEncryptionKey(string keyName, Dictionary<string,string> createParams) {
			// The keyname forms the last part of the path
			string path = vaultTransitPath + keyName;

			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, createParams);
			if (vdro.httpStatusCode == 204) { return true; }
			else { return false; }
		}


		// ==============================================================================================================================================
		/// <summary>
		/// Creates an encryption key with the specified name.  Since encryption key parameters cannot be changed after initial creation AND vault does not
		/// return an error telling you a key already exists - it just returns Success, it is best to call the IfKeyExists function first to make sure the
		/// key you want to create will be able to be created with the values you want. 
		/// </summary>
		/// <param name="keyName">This is the actual name of the encryption key.</param>
		/// <param name="canBeExported">Boolean:  If you want to be able to export the key then set this to True.</param>
		/// <param name="allowPlainTextBackup">Boolean.  If you want to be able to perform a plain text backup of the key, set to True.</param>
		/// <param name="keyType">The type of encryption key to use.  Best choices are one of the RSA keys or the AES key.</param>
		/// <returns>True if successful.  However, it could also mean the key already exists, in which case the parameters you set here may not be what the key 
		/// is set to.</returns>
		public async Task<bool> CreateEncryptionKey(string keyName, bool canBeExported = false, bool allowPlainTextBackup = false, EnumTransitKeyType keyType = EnumTransitKeyType.aes256) {
			// The keyname forms the last part of the path
			string path = vaultTransitPath + keyName;

			string keyTypeV;

			switch (keyType) {
				case EnumTransitKeyType.aes256:
					keyTypeV = "aes256-gcm96";
					break;
				case EnumTransitKeyType.chacha20:
					keyTypeV = "chacha20-poly1305";
					break;
				case EnumTransitKeyType.ecdsa:
					keyTypeV = "ecdsa-p256";
					break;
				case EnumTransitKeyType.ed25519:
					keyTypeV = "ed25519";
					break;
				case EnumTransitKeyType.rsa2048:
					keyTypeV = "rsa-2048";
					break;
				case EnumTransitKeyType.rsa4096:
					keyTypeV = "rsa-4096";
					break;
				default:
					keyTypeV = "unknown";
					break;
			}


			//Dictionary<string, string> createParams = new Dictionary<string, string>();
			
			Dictionary<string, string> createParams = new Dictionary<string,string>();
			createParams.Add("exportable", canBeExported ? "true" : "false");
			createParams.Add("allow_plaintext_backup", allowPlainTextBackup ? "true" : "false");
			createParams.Add("type", keyTypeV);

			return await CreateEncryptionKey(keyName, createParams);
		}


		
		// ==============================================================================================================================================
		public async Task<TransitKeyInfo> ReadEncryptionKey(String keyName) {
			// The keyname forms the last part of the path
			string path = vaultTransitPath + keyName;

			VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path);
			TransitKeyInfo TKI = vdro.GetVaultTypedObject<TransitKeyInfo>();
			return TKI;
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
