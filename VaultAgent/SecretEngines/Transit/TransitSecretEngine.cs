using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultAgent.Backends;
using VaultAgent.Backends.Transit;
using VaultAgent.Backends.Transit.Models;
using VaultAgent.Models;


namespace VaultAgent.SecretEngines {
    public class TransitSecretEngine : VaultSecretBackend {
        const string PathKeys = "keys/";
        const string PathEncrypt = "encrypt/";
        const string PathDecrypt = "decrypt/";


        // ==============================================================================================================================================
        /// <summary>
        /// Constructor.  Initializes the connection to Vault and stores the token.
        /// </summary>
        /// <param name="backendMountName">The name of the transit backend to mount.  For example for a mount at /mine/transitA use mine/transitA as value.</param>
        /// <param name="backendMountPath">The path to the Transit Backend mountpoint.</param>
        /// <param name="httpConnector">The VaultAPI_http Http Connection object</param>
        public TransitSecretEngine (string backendMountName, string backendMountPath, VaultAgentAPI vaultAgentAPI) : base (
            backendMountName, backendMountPath, vaultAgentAPI) {
            Type = EnumBackendTypes.Transit;
            IsSecretBackend = true;
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
        /// <param name="enableConvergentEncryption">Enables Convergent Encryption.  Convergent encryption means that the same plaintext value will always result in the
        /// same encrypted ciphertext.</param>
        /// <returns>True if successful.  However, it could also mean the key already exists, in which case the parameters you set here may not be what the key 
        /// is set to.</returns>
        public async Task<bool> CreateEncryptionKey (string keyName,
                                                     bool canBeExported = false,
                                                     bool allowPlainTextBackup = false,
                                                     TransitEnumKeyType keyType = TransitEnumKeyType.aes256,
                                                     bool enableKeyDerivation = false,
                                                     bool enableConvergentEncryption = false) {
            // The keyname forms the last part of the path
            string path = MountPointPath + PathKeys + keyName;
            string keyTypeV;

            switch ( keyType ) {
                case TransitEnumKeyType.aes256:
                    keyTypeV = "aes256-gcm96";
                    break;
                case TransitEnumKeyType.chacha20:
                    keyTypeV = "chacha20-poly1305";
                    break;
                case TransitEnumKeyType.ecdsa:
                    keyTypeV = "ecdsa-p256";
                    break;
                case TransitEnumKeyType.ed25519:
                    keyTypeV = "ed25519";
                    break;
                case TransitEnumKeyType.rsa2048:
                    keyTypeV = "rsa-2048";
                    break;
                case TransitEnumKeyType.rsa4096:
                    keyTypeV = "rsa-4096";
                    break;
                default:
                    keyTypeV = "unknown";
                    break;
            }

            Dictionary<string, string> createParams = new Dictionary<string, string>();
            createParams.Add ("exportable", canBeExported ? "true" : "false");
            createParams.Add ("allow_plaintext_backup", allowPlainTextBackup ? "true" : "false");
            createParams.Add ("type", keyTypeV);

            // Convergent encryption requires KeyDerivation.
            createParams.Add ("convergent_encryption", enableConvergentEncryption ? "true" : "false");
            if ( enableConvergentEncryption ) { enableKeyDerivation = true; }

            createParams.Add ("derived", enableKeyDerivation ? "true" : "false");

            // Validate:
            if ( enableKeyDerivation ) {
                if ( (keyType == TransitEnumKeyType.rsa2048) || (keyType == TransitEnumKeyType.rsa4096) || (keyType == TransitEnumKeyType.ecdsa) ) {
                    throw new ArgumentOutOfRangeException ("keyType", ("Specified keyType: " + keyTypeV + " does not support contextual encryption."));
                }
            }

            return await CreateEncryptionKey (keyName, createParams);
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
        public async Task<bool> CreateEncryptionKey (string keyName, Dictionary<string, string> createParams) {
            // The keyname forms the last part of the path
            string path = MountPointPath + PathKeys + keyName;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "CreateEncryptionKey", createParams);
            if ( vdro.HttpStatusCode == 204 ) { return true; }
            else { return false; }
        }



        // ==============================================================================================================================================
        public async Task<TransitKeyInfo> ReadEncryptionKey (string keyName) {
            // The keyname forms the last part of the path
            string path = MountPointPath + PathKeys + keyName;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "ReadEncryptionKey");
	        return await vdro.GetDotNetObject<TransitKeyInfo>();
//            TransitKeyInfo TKI = vdro.GetVaultTypedObject<TransitKeyInfo>();
  //          return TKI;
        }



        /// <summary>
        /// Returns true or false if a given key exists.
        /// </summary>
        /// <param name="keyName">Name of the key you want to validate if it exists.</param>
        /// <returns>True if key exists.  False if it does not.</returns>
        public async Task<bool> IfExists (string keyName) {
            try {
                TransitKeyInfo TKI = await ReadEncryptionKey (keyName);
                if ( TKI != null ) { return true; }
                else { return false; }
            }
            catch ( VaultInvalidPathException e ) { return false; }
        }



        // ==============================================================================================================================================
        public async Task<List<string>> ListEncryptionKeys () {
            string path = MountPointPath + PathKeys;

            // Setup List Parameter
            Dictionary<string, string> sendParams = new Dictionary<string, string>();
            sendParams.Add ("list", "true");

            VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "ListEncryptionKeys", sendParams);

	        return await vdro.GetDotNetObject<List<string>>("data.keys");
//            string js = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "keys");
//
  //          List<string> keys = VaultUtilityFX.ConvertJSON<List<string>> (js);
    //        return keys;
        }



        /// <summary>
        /// Internal routine that makes the actual Vault API call using the passed in Parameters as input values.
        /// </summary>
        /// <param name="keyName">The encryption key to use to encrypt data.</param>
        /// <param name="contentParams">Dictionary of string value pairs representing all the input parameters to be sent along with the request to the Vault API.</param>
        /// <returns>A List of the encrypted value(s). </returns>
        private async Task<TransitEncryptedItem> EncryptToVault (string keyName, Dictionary<string, string> contentParams) {
            string path = MountPointPath + PathEncrypt + keyName;

            // Call Vault API.
            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "EncryptToVault", contentParams);
            if ( vdro.HttpStatusCode == 200 ) {
	            return await vdro.GetDotNetObject<TransitEncryptedItem>();
//                string js = vdro.GetDataPackageAsJSON();
  //              TransitEncryptedItem data = VaultUtilityFX.ConvertJSON<TransitEncryptedItem> (js);
    //            return data;
            }
            else { return null; }
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
        public async Task<TransitEncryptedItem> Encrypt (string keyName, string rawStringData, string keyDerivationContext = "", int keyVersion = 0) {
            // Setup Post Parameters in body.
            Dictionary<string, string> contentParams = new Dictionary<string, string>();

            // Base64 Encode Data
            contentParams.Add ("plaintext", VaultUtilityFX.Base64EncodeAscii (rawStringData));

            if ( keyDerivationContext != "" ) { contentParams.Add ("context", VaultUtilityFX.Base64EncodeAscii (keyDerivationContext)); }

            if ( keyVersion > 0 ) { contentParams.Add ("key_version", keyVersion.ToString()); }

            return await EncryptToVault (keyName, contentParams);
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
        public async Task<TransitEncryptionResultsBulk> EncryptBulk (string keyName, List<TransitBulkItemToEncrypt> bulkItems, int keyVersion = 0) {
            string path = MountPointPath + PathEncrypt + keyName;

			//TODO - This can be optimized, StringBuilder?  Custom JSON Serializer?

            // Build the Posting Parameters as JSON.  We need to manually create in here as we also need to custom append the 
            // keys to be encrypted into the body.
            Dictionary<string, string> contentParams = new Dictionary<string, string>();
            if ( keyVersion > 0 ) { contentParams.Add ("key_version", keyVersion.ToString()); }

            //if (keyDerivationContext != "") { contentParams.Add("context", VaultUtilityFX.Base64EncodeAscii(keyDerivationContext)); }

            string inputVarsJSON = JsonConvert.SerializeObject (contentParams, Formatting.None);


            // Build entire JSON Body:  Input Params + Bulk Items List.
            string bulkJSON = JsonConvert.SerializeObject (new {batch_input = bulkItems}, Formatting.None);


            // Combine the 2 JSON's
            if ( contentParams.Count > 0 ) {
                string newVarsJSON = inputVarsJSON.Substring (1, inputVarsJSON.Length - 2) + ",";
                bulkJSON = bulkJSON.Insert (1, newVarsJSON);
            }


            // Call Vault API.
            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "EncryptBulk",  bulkJSON);


            // Pull out the results and send back.  
			return await vdro.GetDotNetObject<TransitEncryptionResultsBulk>();
//            string js = vdro.GetDataPackageAsJSON();
  //          TransitEncryptionResultsBulk bulkData = VaultUtilityFX.ConvertJSON<TransitEncryptionResultsBulk> (js);
    //        return bulkData;
        }



        // ==============================================================================================================================================
        /// <summary>
        /// Decrypts a single encrypted value.  If the keys supports convergent or derived encryption then you must supply the keyDerivationContext param.
        /// </summary>
        /// <param name="keyName">Name of the encryption key to use to decrypt.</param>
        /// <param name="encryptedData">The encrypted value that you wish to have decrypted.</param>
        /// <param name="keyDerivationContext">The context value that is required to delete a convergent encrypted item.</param>
        /// <returns>TransitDecryptedItem if the value was able to be successfully decrypted.
        /// Throws <VaultInvalidDataException> if unable to decrypt the item due to bad key or context value.</VaultInvalidDataException></returns>
        public async Task<TransitDecryptedItem> Decrypt (string keyName, string encryptedData, string keyDerivationContext = "") {
            string path = MountPointPath + PathDecrypt + keyName;


            // Setup Post Parameters in body.
            Dictionary<string, string> contentParams = new Dictionary<string, string>();

            // Build the parameter list.
            contentParams.Add ("ciphertext", encryptedData);
            if ( keyDerivationContext != "" ) { contentParams.Add ("context", VaultUtilityFX.Base64EncodeAscii (keyDerivationContext)); }


            // Call Vault API.
            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "Decrypt", contentParams);
            if ( vdro.HttpStatusCode == 200 ) {
	            return await vdro.GetDotNetObject<TransitDecryptedItem>();
//                string js = vdro.GetDataPackageAsJSON();
  //              TransitDecryptedItem data = VaultUtilityFX.ConvertJSON<TransitDecryptedItem> (js);
    //            return data;
            }

            // This code should never get hit.  
            throw new VaultUnexpectedCodePathException ("TransitBackEnd-Decrypt");
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
        public async Task<TransitDecryptionResultsBulk> DecryptBulk (string keyName, List<TransitBulkItemToDecrypt> bulkItems, int keyVersion = 0) {
            string path = MountPointPath + "decrypt/" + keyName;

			//TODO - This can be optimized - StringBuilder, customserializer?

            // Build the Posting Parameters as JSON.  We need to manually create in here as we also need to custom append the 
            // keys to be encrypted into the body.
            Dictionary<string, string> contentParams = new Dictionary<string, string>();
            if ( keyVersion > 0 ) { contentParams.Add ("key_version", keyVersion.ToString()); }

            string inputVarsJSON = JsonConvert.SerializeObject (contentParams, Formatting.None);


            // Build entire JSON Body:  Input Params + Bulk Items List.
            string bulkJSON = JsonConvert.SerializeObject (new {batch_input = bulkItems}, Formatting.None);


            // Combine the 2 JSON's
            if ( contentParams.Count > 0 ) {
                string newVarsJSON = inputVarsJSON.Substring (1, inputVarsJSON.Length - 2) + ",";
                bulkJSON = bulkJSON.Insert (1, newVarsJSON);
            }


            // Call Vault API.
            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "DecryptBulk", bulkJSON);


            // Pull out the results and send back.  
	        return await vdro.GetDotNetObject<TransitDecryptionResultsBulk>();
//            string js = vdro.GetDataPackageAsJSON();
  //          TransitDecryptionResultsBulk bulkData = VaultUtilityFX.ConvertJSON<TransitDecryptionResultsBulk> (js);
    //        return bulkData;
        }



        // ==============================================================================================================================================
        /// <summary>
        /// Rotates the specified key.  All new encrypt operations will now use the new encryption key.  
        /// </summary>
        /// <param name="keyName">The name of the encryption ket to rotate.</param>
        /// <returns>True if successfull.  Will thrown an error with the reason if unsuccesful.  </returns>
        public async Task<bool> RotateKey (string keyName) {
            string path = MountPointPath + PathKeys + keyName + "/rotate";

            // Call Vault API.
            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "RotateKey");
            if ( !vdro.Success ) {
                // This should not be able to happen.  If it errored, it should have been handled in the PostAsync call.  
                throw new VaultUnexpectedCodePathException ("Unexpected response in RotateKey");
            }

            return true;
        }



        // ==============================================================================================================================================
        /// <summary>
        /// Re-encrypts the currently encrypted data with the current version of the key.  This is a simplified way
        /// of upgrading the encryption for an element without have to call Decrypt and then Encrypt separately.
        /// </summary>
        /// <param name="keyName">The Encryption key to use to decrypt and re-encrypt the data</param>
        /// <param name="encryptedData">The currently encrypted data element that you want to have upgraded with the new encryption key.</param>
        /// <param name="keyDerivationContext">The context used for key derivation if the key supports that key derivation.</param>
        /// <param name="keyVersion">Version of the key to use.  Defaults to current version (0).</param>
        /// <returns>The data element encrypted with the version of the key specified.  (Default is latest version of the key).  Returns null if operation failed.</returns>
        public async Task<TransitEncryptedItem> ReEncrypt (string keyName, string encryptedData, string keyDerivationContext = "", int keyVersion = 0) {
            string path = MountPointPath + "rewrap/" + keyName;


            // Setup Post Parameters in body.
            Dictionary<string, string> contentParams = new Dictionary<string, string>();

            // Build the parameter list.
            contentParams.Add ("ciphertext", encryptedData);
            if ( keyDerivationContext != "" ) { contentParams.Add ("context", VaultUtilityFX.Base64EncodeAscii (keyDerivationContext)); }

            if ( keyVersion > 0 ) { contentParams.Add ("key_version", keyVersion.ToString()); }


            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "ReEncrypt", contentParams);
            if ( vdro.HttpStatusCode == 200 ) {
	            return await vdro.GetDotNetObject<TransitEncryptedItem>();
//                string js = vdro.GetDataPackageAsJSON();
  //              TransitEncryptedItem data = VaultUtilityFX.ConvertJSON<TransitEncryptedItem> (js);
    //            return data;
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
        public async Task<TransitEncryptionResultsBulk> ReEncryptBulk (string keyName, List<TransitBulkItemToDecrypt> bulkItems, int keyVersion = 0) {
            string path = MountPointPath + "rewrap/" + keyName;


            // Build the Posting Parameters as JSON.  We need to manually create in here as we also need to custom append the 
            // keys to be encrypted into the body.
            Dictionary<string, string> contentParams = new Dictionary<string, string>();
            if ( keyVersion > 0 ) { contentParams.Add ("key_version", keyVersion.ToString()); }

            string inputVarsJSON = JsonConvert.SerializeObject (contentParams, Formatting.None);


            // Build entire JSON Body:  Input Params + Bulk Items List.
            string bulkJSON = JsonConvert.SerializeObject (new {batch_input = bulkItems}, Formatting.None);


            // Combine the 2 JSON's
            if ( contentParams.Count > 0 ) {
                string newVarsJSON = inputVarsJSON.Substring (1, inputVarsJSON.Length - 2) + ",";
                bulkJSON = bulkJSON.Insert (1, newVarsJSON);
            }


            // Call Vault API.
            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "ReEncryptBulk", bulkJSON);


            // Pull out the results and send back.  
	        return await vdro.GetDotNetObject<TransitEncryptionResultsBulk>();
//            string js = vdro.GetDataPackageAsJSON();
  //          TransitEncryptionResultsBulk bulkData = VaultUtilityFX.ConvertJSON<TransitEncryptionResultsBulk> (js);
     //       return bulkData;
        }



        /// <summary>
        /// Updates the configuration settings for the given key.  Use the TransitConstants KeyConfig... values for input to the inputParams Dictionary.
        /// Note: If PlainTextBackup or exportable are already True, you cannot set them to false.
        /// </summary>
        /// <param name="keyName">The encryption key to update configuration settings for.</param>
        /// <param name="inputParams">Dictionary of KeyValue string pairs that contain Vault config values and the value you want that config value to have.</param>
        /// <returns>TransitKeyInfo object with the current settings after Update.</returns>
        public async Task<TransitKeyInfo> UpdateKey (string keyName, Dictionary<string, string> inputParams) {
            string path = MountPointPath + "keys/" + keyName + "/config";

            Dictionary<string, string> contentParams = new Dictionary<string, string>();
            foreach ( KeyValuePair<string, string> item in inputParams ) {
                if ( item.Key.ToLower() == "min_decryption_version" ) { contentParams.Add (item.Key, item.Value); }
                else if ( item.Key.ToLower() == "min_encryption_version" ) { contentParams.Add (item.Key, item.Value); }
                else if ( item.Key.ToLower() == "deletion_allowed" ) { contentParams.Add (item.Key, item.Value); }
                else if ( item.Key.ToLower() == "exportable" ) { contentParams.Add (item.Key, item.Value); }
                else if ( item.Key.ToLower() == "allow_plaintext_backup" ) { contentParams.Add (item.Key, item.Value); }
                else {
                    throw new ArgumentException (
                        "Must supply a valid Key Config Parameter of min_decryption_version,min_encryption_version,deletion_allowed,exportable or allow_plaintext_backup",
                        item.Key);
                }
            } // Foreach KeyValuePair

            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "UpdateKey", contentParams);

            if ( vdro.Success ) {
                // Read the key and return.
                return await ReadEncryptionKey (keyName);
            }
            else { return null; }
        }



        /// <summary>
        /// Deletes the given key.
        /// </summary>
        /// <param name="keyName">The key to delete.</param>
        /// <returns>True if deletion successful.
        /// False if the key does not allow deletion because its deletion_allowed config parameters is not set to true.
        /// Throws VaultInvalidDataException with message of "could not delete policy; not found.</returns>
        public async Task<bool> DeleteKey (string keyName) {
            string path = MountPointPath + "keys/" + keyName;

            try {
                VaultDataResponseObject vdro = await _parent._httpConnector.DeleteAsync (path, "DeleteKey");
                if ( vdro.Success ) { return true; }
                else { return false; }
            }
            catch ( VaultInvalidDataException e ) {
                // Search for the error message - it indicates whether it is key could not be found or deletion not allowed.
                if ( e.Message.Contains ("could not delete policy; not found") ) { throw e; }

                if ( e.Message.Contains ("deletion is not allowed for this policy") ) { return false; }

                // not sure - rethrow error.
                throw e;
            }
            catch ( Exception e ) { throw e; }
        }



        public void ExportKey (string keyName) { throw new NotImplementedException(); }



        /// <summary>
        /// Throws VaultInvalidDataException for a number of errors, including not supplying context for keys that require it.
        /// </summary>
        /// <param name="keyName">Name of the key that should be used to create this Data Key.</param>
        /// <param name="returnCipherAndPlainText">Boolean:  If true, the key returned will contain both the plaintext and cipher text for the key.  IF false, just the cipher is returned.</param>
        /// <param name="context">Optional:  the context value to encrypt with.  Required if Key supports convergent or Derived Encryption.</param>
        /// <param name="bits">128, 256 or 512.  Number of bits the key should have.</param>
        /// <returns></returns>
        public async Task<TransitDataKey> GenerateDataKey (string keyName, bool returnCipherAndPlainText = false, string context = "", int bits = 256) {
            string sType = "";
            if ( returnCipherAndPlainText ) { sType = "plaintext"; }
            else { sType = "wrapped"; }

            if ( (bits != 128) && (bits != 256) && (bits != 512) ) {
                throw new ArgumentOutOfRangeException ("bits", "Bits value can only be 128, 256 or 512.");
            }


            // Build parameters 
            Dictionary<string, string> contentParams = new Dictionary<string, string>();
            contentParams.Add ("bits", bits.ToString());
            if ( context != "" ) { contentParams.Add ("context", VaultUtilityFX.Base64EncodeAscii (context)); }


            string path = MountPointPath + "datakey/" + sType + "/" + keyName;


            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "GenerateDataKey", contentParams);

            // Pull out the results and send back.  
	        return await vdro.GetDotNetObject<TransitDataKey>();
//            string js = vdro.GetDataPackageAsJSON();
  //          TransitDataKey TDK = VaultUtilityFX.ConvertJSON<TransitDataKey> (js);
    //        return TDK;
        }



        /// <summary>
        /// Returns a plaintext backup of the requested key.  Backups contains all configuration data and all keys of all versions along with the 
        /// HMAC key.  The TransitBackupRestoreItem can be used with the RestoreKey method to restore the given key.  Callers should check the 
        /// TransitBackupRestoreItem Success flag to determine if it worked and ErrorMsg to identify any errors if it did not.  The 2 most common
        /// errors are: Export is disabled and PlainTextBackup is disabled.  These need to be enabled on the key prior to backing up. 
        /// </summary>
        /// <param name="keyName">Name of the encryption key to backup.</param>
        /// <returns>TransitBackupRestoreItem containing the full backup of the key.</returns>
        public async Task<TransitBackupRestoreItem> BackupKey (string keyName) {
            string path = MountPointPath + "backup/" + keyName;

            try {
                VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "BackupKey");

				// Pull out the results and send back.  
	            TransitBackupRestoreItem tbri = await vdro.GetDotNetObject<TransitBackupRestoreItem>();

//				string js = vdro.GetDataPackageAsJSON();
  //              TransitBackupRestoreItem tbri = VaultUtilityFX.ConvertJSON<TransitBackupRestoreItem> (js);
                if ( tbri.KeyBackup != null ) { tbri.Success = true; }

                return tbri;
            }
            catch ( VaultInternalErrorException e ) {
                string errMsg = "";
                if ( e.Message.Contains ("exporting is disallowed") ) { errMsg = "Key is not exportable.  Must be exportable to be backed up."; }
                else if ( e.Message.Contains ("plaintext backup is disallowed on the policy") ) {
                    errMsg = "Key has PlainTextBackup disabled.  Backup not possible.";
                }
                else { throw e; }

                TransitBackupRestoreItem tbri = new TransitBackupRestoreItem()
                {
                    Success = false,
                    ErrorMsg = errMsg
                };

                //tbri.Success = false;
                //tbri.ErrorMsg = errMsg;
                return tbri;
            }
        }



        /// <summary>
        /// Restores the given key to the Vault.
        /// </summary>
        /// <param name="keyName">Name of encryption key that should be restored.</param>
        /// <param name="tbri">TransitBackupRestoreItem containing the backup value.</param>
        /// <returns>True if success.</returns>
        public async Task<bool> RestoreKey (string keyName, TransitBackupRestoreItem tbri) {
            string path = MountPointPath + "restore/" + keyName;

            // Setup Post Parameters in body.
            Dictionary<string, string> contentParams = new Dictionary<string, string>();

            try {
                // Build the parameter list.
                contentParams.Add ("backup", tbri.KeyBackup);
                VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "RestoreKey", contentParams);
                return vdro.Success;
            }
            catch ( VaultInternalErrorException e ) {
                if ( e.Message.Contains ("already exists") ) { return false; }
                else { throw e; }
            }
        }



        /// <summary>
        /// Generates random bytes.  Can return data as string or Hexidecimal.  Note, Vault native function returns Base64-encoded.  This routine
        /// decodes it before returning to you.
        /// </summary>
        /// <param name="numBytes">Number of bytes you need.</param>
        /// <param name="hexOutputFormat">true if you want hexidecimal values, False if you want ascii</param>
        /// <returns></returns>
        public async Task<string> GenerateRandomBytes (int numBytes, bool hexOutputFormat = false) {
            string path = MountPointPath + "random/" + numBytes.ToString();

            // Setup Post Parameters in body.
            Dictionary<string, string> contentParams = new Dictionary<string, string>();
            string encodeFormat = "base64";
            if ( hexOutputFormat ) { encodeFormat = "hex"; }

            contentParams.Add ("format", encodeFormat);
            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "GenerateRandomBytes", contentParams);
            if ( vdro.Success ) {
	            string bytes = await vdro.GetDotNetObject<string>("data.random_bytes");
                //string bytes = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "random_bytes");
                if ( hexOutputFormat ) { return bytes; }
                else { return VaultUtilityFX.Base64DecodeAscii (bytes); }
            }

            return "";
        }


        /// <summary>
        /// Returns the cryptographic hashing of given data using the specified algorithm.
        /// </summary>
        /// <param name="input">The data value you wish to have the hashing generated on.</param>
        /// <param name="hashing">The hashing algorithm to use.</param>
        /// <param name="hexOutputFormat">Boolean.  Set to true if you wish the hashing output to be returned in Hexadecimal format. False means Base64 format.</param>
        /// <returns>The hashing of the input data returned in either hexadecimal or Base64 format.</returns>
        public async Task<string> ComputeHash (string input, TransitEnumHashingAlgorithm hashing, bool hexOutputFormat = false) {
            string path = MountPointPath + "hash";

            string hashStr = "";
            switch ( hashing ) {
                case TransitEnumHashingAlgorithm.sha2_224:
                    hashStr = "sha2-224";
                    break;
                case TransitEnumHashingAlgorithm.sha2_256:
                    hashStr = "sha2-256";
                    break;
                case TransitEnumHashingAlgorithm.sha2_384:
                    hashStr = "sha2-384";
                    break;
                case TransitEnumHashingAlgorithm.sha2_512:
                    hashStr = "sha2-512";
                    break;
            }

            // Setup Post Parameters in body.
            Dictionary<string, string> contentParams = new Dictionary<string, string>();
            string encodeFormat = "base64";
            if ( hexOutputFormat ) { encodeFormat = "hex"; }

            contentParams.Add ("format", encodeFormat);
            contentParams.Add ("algorithm", hashStr);

            string inputBase64 = VaultUtilityFX.Base64EncodeAscii (input);

            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "ComputeHash", contentParams);
	        if ( vdro.Success ) {
		        return await vdro.GetDotNetObject<string>("data.sum"); //vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "sum"); }
	        }

	        return "";
        }


        public void GenerateHMAC () { throw new NotImplementedException(); }

        public void SignData () { throw new NotImplementedException(); }

        public void VerifySignedData () { throw new NotImplementedException(); }
    }
}