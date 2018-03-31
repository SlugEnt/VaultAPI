using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;
using VaultAgent;
using System.Text;

namespace VaultAgent.Backends
{
	public class TransitBackend
	{
		TokenInfo transitToken;		
		private VaultAPI_Http vaultHTTP;
		string transitPath = "/v1/transit/";
		Uri vaultTransitPath;

		const string pathKeys = "keys/";
		const string pathEncrypt = "encrypt/";

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
			string path = vaultTransitPath + pathKeys + keyName;

			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "CreateEncryptionKey", createParams);
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
			string path = vaultTransitPath + pathKeys + keyName;

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
			string path = vaultTransitPath + pathKeys + keyName;

			VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "ReadEncryptionKey");
			TransitKeyInfo TKI = vdro.GetVaultTypedObject<TransitKeyInfo>();
			return TKI;
		}




		// ==============================================================================================================================================
		public async Task<List<string>> ListEncryptionKeys() {
			string path = vaultTransitPath + pathKeys;

			// Setup List Parameter
			Dictionary<string, string> sendParams = new Dictionary<string, string>();
			sendParams.Add("list", "true");

			VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "ListEncryptionKeys", sendParams);

			string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "keys");

			List<string> keys = VaultUtilityFX.ConvertJSON<List<string>>(js); 
			return keys;
		}




		/// <summary>
		/// Internal routine that makes the actual Vault API call using the passed in Parameters as input values.
		/// </summary>
		/// <param name="keyName">The encryption key to use to encrypt data.</param>
		/// <param name="contentParams">Dictionary of string value pairs representing all the input parameters to be sent along with the request to the Vault API.</param>
		/// <returns>A List of the encrypted value(s). </returns>
		protected async Task<List<string>> EncryptToVault (string keyName, Dictionary<string,string> contentParams) {
			string path = vaultTransitPath + pathEncrypt + keyName;

			// Call Vault API.
			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "EncryptToVault", contentParams );
			if (vdro.httpStatusCode == 200) {
				string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "data");
				List<string> data = VaultUtilityFX.ConvertJSON<List<string>>(js);
				return data;
			}
			else {	return null; }
		}





		// ==============================================================================================================================================
		/// <summary>
		/// Calls the Vault Encryption API.  
		///  - This version only supports a single data element for encryption at a time.  See the EncryptBulk method for enabling encrypting more than
		///  one value during a single API call.  
		///  - It always encrypts with the latest version of the key, unless you have specified the KeyVersion parameter > 0.
		/// </summary>
		/// <param name="keyName">The name of the encryption key to use to encrypt the data.</param>
		/// <param name="rawStringData">The data to be encrypted in string format.  This should not be base64 encoded.  This routine takes care of that for you.</param>
		/// <param name="keyDerivationContext"></param>
		/// <param name="keyVersion">Version of the key that should be used to encrypt the data.  The default (0) is the latest version of the key.</param>
		/// <returns></returns>
		public async Task<List<string>> Encrypt(string keyName, string rawStringData, string keyDerivationContext = "", int keyVersion = 0) {
			// Setup Post Parameters in body.
			Dictionary<string, string> contentParams = new Dictionary<string, string>();

			// Base64 Encode Data
			contentParams.Add("plaintext", VaultUtilityFX.Base64EncodeAscii(rawStringData));

			if (keyDerivationContext != "") { contentParams.Add("context", VaultUtilityFX.Base64EncodeAscii(keyDerivationContext));	}
			if (keyVersion > 0 ) { contentParams.Add("key_version", keyVersion.ToString()); }

			return await EncryptToVault(keyName, contentParams);
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



		public bool Delete (string keyName) {
			throw new System.NotImplementedException();
		}

	}
}
