using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultAgent.Models;
using Newtonsoft.Json;
using VaultAgent.Backends.Transit.Models;

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
		const string pathDecrypt = "decrypt/";

		// ==============================================================================================================================================
		/// <summary>
		/// Constructor.  Initializes the connection to Vault and stores the token.
		/// </summary>
		/// <param name="vaultIP">The IP address of the Vault Server.</param>
		/// <param name="port">The network port the Vault server listens on.</param>
		/// <param name="Token">The token used to authenticate with.</param>
		/// <param name="backendMountName">The name of the transit backend to mount.  For example for a mount at /mine/transitA use mine/transitA as value.</param>
		public TransitBackend (string vaultIP, int port, string Token, string backendMountName="transit") {
			vaultHTTP = new VaultAPI_Http(vaultIP, port, Token);
			transitToken = new TokenInfo();
			transitToken.Id = Token;

			transitPath = "/v1/" + backendMountName + "/";
			vaultTransitPath = new Uri("http://" + vaultIP + ":" + port + transitPath);
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
		/// <param name="enableKeyDerivation">Enables Key Derivation.  Key derivtion requires that an encryption context must be supplied with each encrypt operation.</param>
		/// <param name="enableConvergentEncryption">Enables Convergent Encryption.  Convergent encryption means that the same plaintext value will aloways result in the
		/// same encrypted ciphertext.</param>
		/// <returns>True if successful.  However, it could also mean the key already exists, in which case the parameters you set here may not be what the key 
		/// is set to.</returns>
		public async Task<bool> CreateEncryptionKey(string keyName, bool canBeExported = false, bool allowPlainTextBackup = false, 
													EnumTransitKeyType keyType = EnumTransitKeyType.aes256, bool enableKeyDerivation = false, bool enableConvergentEncryption = false) {
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

			Dictionary<string, string> createParams = new Dictionary<string,string>();
			createParams.Add("exportable", canBeExported ? "true" : "false");
			createParams.Add("allow_plaintext_backup", allowPlainTextBackup ? "true" : "false");
			createParams.Add("type", keyTypeV);

			// Convergent encryption requires KeyDerivation.
			createParams.Add("convergent_encryption", enableConvergentEncryption ? "true" : "false");
			if (enableConvergentEncryption) { enableKeyDerivation = true; }
			createParams.Add("derived", enableKeyDerivation ? "true" : "false");

			// Validate:
			if (enableKeyDerivation) {
				if ((keyType == EnumTransitKeyType.rsa2048) || (keyType == EnumTransitKeyType.rsa4096) || (keyType == EnumTransitKeyType.ecdsa)) {
					throw new ArgumentOutOfRangeException("keyType", ("Specified keyType: " + keyTypeV + " does not support contextual encryption."));
				}
			}

			return await CreateEncryptionKey(keyName, createParams);
		}





		// ==============================================================================================================================================
		/// <summary>
		/// Creates an Encryptyion key with the specified name.  This one allows greater latitude in defining the parameters.  But there is no parameter
		/// validation or checking to make sure names are correct or values are correct.  It is recommended to use the one with command line parameters.
		/// </summary>
		/// <param name="keyName">This is the actual name of the encryption key.</param>
		/// <param name="createParams">A Dictionary in the Dictionary [string,string] format.  You must have supplied the values for the dictionary
		/// in the calling routing.  The Key should match the Vault API keyname and the Value should be the value in the format vault is expecting.</param>
		/// <returns>True if the key is successfully created.</returns>
		public async Task<bool> CreateEncryptionKey(string keyName, Dictionary<string, string> createParams) {
			// The keyname forms the last part of the path
			string path = vaultTransitPath + pathKeys + keyName;

			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "CreateEncryptionKey", createParams);
			if (vdro.httpStatusCode == 204) { return true; }
			else { return false; }
		}




		// ==============================================================================================================================================
		public async Task<TransitKeyInfo> ReadEncryptionKey(string keyName) {
			// The keyname forms the last part of the path
			string path = vaultTransitPath + pathKeys + keyName;

			VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "ReadEncryptionKey");
			TransitKeyInfo TKI = vdro.GetVaultTypedObject<TransitKeyInfo>();
			return TKI;
		}




		/// <summary>
		/// Returns true or false if a given key exists.
		/// </summary>
		/// <param name="keyName">Name of the key you want to validate if it exists.</param>
		/// <returns>True if key exists.  False if it does not.</returns>
		public async Task<bool>IfExists (string keyName) {
			try {
				TransitKeyInfo TKI = await ReadEncryptionKey(keyName);
				if (TKI != null) { return true; }
				else { return false; }
			}
			catch (VaultInvalidPathException e) {
				return false;
			}
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
		protected async Task<TransitEncryptedItem> EncryptToVault (string keyName, Dictionary<string,string> contentParams) {
			string path = vaultTransitPath + pathEncrypt + keyName;

			// Call Vault API.
			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "EncryptToVault", contentParams );
			if (vdro.httpStatusCode == 200) {
				string js =  vdro.GetDataPackageAsJSON() ;
				TransitEncryptedItem data =  VaultUtilityFX.ConvertJSON<TransitEncryptedItem>(js);
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
		public async Task<TransitEncryptedItem> Encrypt(string keyName, string rawStringData, string keyDerivationContext = "", int keyVersion = 0) {
			// Setup Post Parameters in body.
			Dictionary<string, string> contentParams = new Dictionary<string, string>();

			// Base64 Encode Data
			contentParams.Add("plaintext", VaultUtilityFX.Base64EncodeAscii(rawStringData));

			if (keyDerivationContext != "") { contentParams.Add("context", VaultUtilityFX.Base64EncodeAscii(keyDerivationContext));	}
			if (keyVersion > 0 ) { contentParams.Add("key_version", keyVersion.ToString()); }

			return await EncryptToVault(keyName, contentParams);
		}





		// ==============================================================================================================================================
		/// <summary>
		/// Encrypts multiple items at one time.  It is expected that the caller has maintained an order list of the items to encrypt.  The encrypted 
		/// results will be returned to the caller in a List in the exact same order they were sent.  
		/// </summary>
		/// <param name="keyName">The encryption key to use to encrypt the values.</param>
		/// <param name="bulkItems">The list of items to be encrypted.  Note that you may supply both the item to be encrypted and optionally the context 
		/// that goes along with it, if using contextual encryption.</param>
		/// <param name="keyVersion">Optional numberic value of the key to use to encrypt the data with.  If not specified it defaults to the latest version 
		/// of the encryption key.</param>
		/// <returns>TransitEncryptionResultsBulk which is a list or the encrypted values.</returns>
		public async Task<TransitEncryptionResultsBulk> EncryptBulk(string keyName, List<TransitBulkItemToEncrypt> bulkItems, int keyVersion = 0) {
			string path = vaultTransitPath + pathEncrypt + keyName;


			// Build the Posting Parameters as JSON.  We need to manually create in here as we also need to custom append the 
			// keys to be encrypted into the body.
			Dictionary<string, string> contentParams = new Dictionary<string, string>();
			if (keyVersion > 0)	{ contentParams.Add("key_version", keyVersion.ToString()); }
			//if (keyDerivationContext != "") { contentParams.Add("context", VaultUtilityFX.Base64EncodeAscii(keyDerivationContext)); }

			string inputVarsJSON = JsonConvert.SerializeObject(contentParams, Formatting.None);


			// Build entire JSON Body:  Input Params + Bulk Items List.
			string bulkJSON = JsonConvert.SerializeObject(new
			{
				batch_input = bulkItems
			}, Formatting.None);


			// Combine the 2 JSON's
			if (contentParams.Count > 0) {
				string newVarsJSON = inputVarsJSON.Substring(1, inputVarsJSON.Length - 2) + ",";
				bulkJSON = bulkJSON.Insert(1, newVarsJSON);
			}
			

			// Call Vault API.
			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "EncryptBulk", null, bulkJSON);


			// Pull out the results and send back.  
			string js = vdro.GetDataPackageAsJSON();
			TransitEncryptionResultsBulk bulkData = VaultUtilityFX.ConvertJSON<TransitEncryptionResultsBulk>(js);
			return bulkData;
		}





		// ==============================================================================================================================================
		public async Task<TransitDecryptedItem> Decrypt(string keyName, string encryptedData, string keyDerivationContext = "") {
			string path = vaultTransitPath + pathDecrypt + keyName;


			// Setup Post Parameters in body.
			Dictionary<string, string> contentParams = new Dictionary<string, string>();

			// Build the parameter list.
			contentParams.Add("ciphertext", encryptedData);
			if (keyDerivationContext != "") { contentParams.Add("context", VaultUtilityFX.Base64EncodeAscii(keyDerivationContext)); }


			// Call Vault API.
			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "Decrypt", contentParams);
			if (vdro.httpStatusCode == 200) {
				string js = vdro.GetDataPackageAsJSON();
				TransitDecryptedItem data = VaultUtilityFX.ConvertJSON<TransitDecryptedItem>(js);
				return data;
			}

			// This code should never get hit.  
			throw new VaultUnexpectedCodePathException("TransitBackEnd-Decrypt");
		}



		// ==============================================================================================================================================
		/// <summary>
		/// Decrypts multiple items at one time.  It is expected that the caller has maintained an order list of the items to decrypt.  The decrypted 
		/// results will be returned to the caller in a List in the exact same order they were sent.  
		/// </summary>
		/// <param name="keyName">The encryption key to use to decrypt the values.</param>
		/// <param name="bulkItems">The list of items to be decrypted.  Note that you may supply both the item to be decrypted and optionally the context 
		/// that goes along with it, if using contextual encryption.</param>
		/// <param name="keyVersion">Optional numberic value of the key to use to deecrypt the data with.  If not specified it defaults to the latest version 
		/// of the encryption key.</param>
		/// <returns>TransitEncryptionResultsBulk which is a list or the deecrypted values.</returns>
		public async Task<TransitDecryptionResultsBulk> DecryptBulk(string keyName, List<TransitBulkItemToDecrypt> bulkItems, int keyVersion = 0) {
			string path = vaultTransitPath + "decrypt/" + keyName;


			// Build the Posting Parameters as JSON.  We need to manually create in here as we also need to custom append the 
			// keys to be encrypted into the body.
			Dictionary<string, string> contentParams = new Dictionary<string, string>();
			if (keyVersion > 0) { contentParams.Add("key_version", keyVersion.ToString()); }

			string inputVarsJSON = JsonConvert.SerializeObject(contentParams, Formatting.None);


			// Build entire JSON Body:  Input Params + Bulk Items List.
			string bulkJSON = JsonConvert.SerializeObject(new
			{
				batch_input = bulkItems
			}, Formatting.None);


			// Combine the 2 JSON's
			if (contentParams.Count > 0) {
				string newVarsJSON = inputVarsJSON.Substring(1, inputVarsJSON.Length - 2) + ",";
				bulkJSON = bulkJSON.Insert(1, newVarsJSON);
			}


			// Call Vault API.
			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "DecryptBulk", null, bulkJSON);


			// Pull out the results and send back.  
			string js = vdro.GetDataPackageAsJSON();
			TransitDecryptionResultsBulk bulkData = VaultUtilityFX.ConvertJSON<TransitDecryptionResultsBulk>(js);
			return bulkData;
		}




		// ==============================================================================================================================================
		/// <summary>
		/// Rotates the specified key.  All new encrypt operations will now use the new encryption key.  
		/// </summary>
		/// <param name="keyName">The name of the encryption ket to rotate.</param>
		/// <returns>True if successfull.  Will thrown an error with the reason if unsuccesful.  </returns>
		public async Task<bool> RotateKey (string keyName) {
			string path = vaultTransitPath + pathKeys + keyName + "/rotate";

			// Call Vault API.
			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "RotateKey");
			if (!vdro.Success) {
				// This should not be able to happen.  If it errored, it should have been handled in the PostAsync call.  
				throw new VaultUnexpectedCodePathException("Unexpected response in RotateKey");
				}

			return true;
		}




		// ==============================================================================================================================================
		/// <summary>
		/// Re-encrypts the currently encrypted data with the current version of the key.  This is a simplified way
		/// of upgrading the encryption for an element without have to call Decrypt and then Encrypt separately.
		/// </summary>
		/// <param name="keyName">The Encryption key to use to decrypt and re-encrypt the data</param>
		/// <param name="encryptedData">The currently encrypted data element that you want to have upgraded with the 
		/// new encryption key.</param>
		/// <param name="keyDerivationContext">The context used for key derivation if the key supports that key derivation.</param>
		/// <param name="keyVersion">Version of the key to use.  Defaults to current version (0).</param>
		/// <returns>The data element encrypted with the version of the key specified.  (Default is latest version of the key).  Returns null if operation failed.</returns>
		public async Task<TransitEncryptedItem> ReEncrypt (string keyName, string encryptedData, string keyDerivationContext = "", int keyVersion = 0) {
			string path = vaultTransitPath + "rewrap/" + keyName;
	

			// Setup Post Parameters in body.
			Dictionary<string, string> contentParams = new Dictionary<string, string>();

			// Build the parameter list.
			contentParams.Add("ciphertext", encryptedData);
			if (keyDerivationContext != "") { contentParams.Add("context", VaultUtilityFX.Base64EncodeAscii(keyDerivationContext)); }
			if (keyVersion > 0) { contentParams.Add("key_version", keyVersion.ToString()); }


			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "ReEncrypt", contentParams);
			if (vdro.httpStatusCode == 200) {
				string js = vdro.GetDataPackageAsJSON();
				TransitEncryptedItem data = VaultUtilityFX.ConvertJSON<TransitEncryptedItem>(js);
				return data;
			}
			else { return null; }
		}



		// ==============================================================================================================================================
		/// <summary>
		/// Perform a re-encryption of multiple items at one time.  It is expected that the caller has maintained an order list separate from this list of the items 
		/// that need to be re-encrypted with newer encryption key. The encrypted results will be returned to the caller in a List in the exact same order they were sent.  
		/// </summary>
		/// <param name="keyName">The encryption key to use to encrypt the values.</param>
		/// <param name="bulkItems">The list of items that are currently encrypted that need to be re-encrypted with newer key.  If it is a derived context item then
		/// you need to make sure you supply the context along with each encrypted item.
		/// <param name="keyVersion">Optional numeric value of the key version to use to encrypt the data with.  If not specified it defaults to the latest version 
		/// of the encryption key.</param>
		/// <returns>TransitEncryptionResultsBulk - which is a list or the encrypted values.</returns>
		public async Task<TransitEncryptionResultsBulk> ReEncryptBulk(string keyName, List<TransitBulkItemToDecrypt> bulkItems, int keyVersion = 0) {
			string path = vaultTransitPath + "rewrap/" + keyName;


			// Build the Posting Parameters as JSON.  We need to manually create in here as we also need to custom append the 
			// keys to be encrypted into the body.
			Dictionary<string, string> contentParams = new Dictionary<string, string>();
			if (keyVersion > 0) { contentParams.Add("key_version", keyVersion.ToString()); }

			string inputVarsJSON = JsonConvert.SerializeObject(contentParams, Formatting.None);


			// Build entire JSON Body:  Input Params + Bulk Items List.
			string bulkJSON = JsonConvert.SerializeObject(new
			{
				batch_input = bulkItems
			}, Formatting.None);


			// Combine the 2 JSON's
			if (contentParams.Count > 0) {
				string newVarsJSON = inputVarsJSON.Substring(1, inputVarsJSON.Length - 2) + ",";
				bulkJSON = bulkJSON.Insert(1, newVarsJSON);
			}


			// Call Vault API.
			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "ReEncryptBulk", null, bulkJSON);


			// Pull out the results and send back.  
			string js = vdro.GetDataPackageAsJSON();
			TransitEncryptionResultsBulk bulkData = VaultUtilityFX.ConvertJSON<TransitEncryptionResultsBulk>(js);
			return bulkData;
		}




		public async Task<TransitKeyInfo> UpdateKey(string keyName,  Dictionary<string,string> inputParams) {
			string path = vaultTransitPath + "keys/" + keyName + "/config";

			Dictionary<string, string> contentParams = new Dictionary<string, string>();
			foreach (KeyValuePair<string,string> item in inputParams) {
				if (item.Key.ToLower() == "min_decryption_version") { contentParams.Add(item.Key,item.Value); }
				else if (item.Key.ToLower() == "min_encryption_version") { contentParams.Add(item.Key, item.Value); }
				else if (item.Key.ToLower() == "deletion_allowed") { contentParams.Add(item.Key, item.Value); }
				else if (item.Key.ToLower() == "exportable") { contentParams.Add(item.Key, item.Value); }
				else if (item.Key.ToLower() == "allow_plaintext_backup") { contentParams.Add(item.Key, item.Value); }
				else {
					throw new ArgumentException("Must supply a valid Key Config Parameter of min_decryption_version,min_encryption_version,deletion_allowed,exportable or allow_plaintext_backup", item.Key);
				}
			}  // Foreach KeyValuePair

			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "UpdateKey", contentParams);

			if (vdro.Success) {
				// Read the key and return.
				return await ReadEncryptionKey(keyName);
			}
			else { return null; }
		}




		/// <summary>
		/// Deletes the given key.
		/// </summary>
		/// <param name="keyName">The key to delete.</param>
		/// <returns>True if deletion successful.  False if the key does not allow deletion because its deletion_allowed config parameters is not set to true.
		/// It will throw an error if you do not have permission to the key or the key cannot be found. </returns>
		public async Task<bool> DeleteKey (string keyName) {
			string path = vaultTransitPath + "keys/" + keyName;

			try {
				VaultDataResponseObject vdro = await vaultHTTP.DeleteAsync(path, "DeleteKey");
				if (vdro.Success) { return true; }
				else { return false; }
			}
			catch (VaultInvalidDataException e) {
				// Means the key is not enabled for deletion.
				return false;
			}
			catch (Exception e) { throw e; }
		}

	}
}
