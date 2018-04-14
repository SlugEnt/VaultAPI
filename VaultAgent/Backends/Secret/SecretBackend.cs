﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;
using Newtonsoft.Json;


namespace VaultAgent.Backends.Secret
{
	public class SecretBackend
	{
		TokenInfo secretToken;
		private VaultAPI_Http vaultHTTP;
		string secretBEPath = "/v1/secret/";
		Uri vaultSecretPath;

		
		// ==============================================================================================================================================
		/// <summary>
		/// Constructor.  Initializes the connection to Vault and stores the token.
		/// </summary>
		/// <param name="vaultIP">The IP address of the Vault Server.</param>
		/// <param name="port">The network port the Vault server listens on.</param>
		/// <param name="Token">The token used to authenticate with.</param>
		/// <param name="backendMountName">The name of the secret backend to mount.  For example for a mount at /mine/secretA use mine/secretA as value.</param>
		public SecretBackend(string vaultIP, int port, string Token, string backendMountName = "secret") {
			vaultHTTP = new VaultAPI_Http(vaultIP, port, Token);
			secretToken = new TokenInfo();
			secretToken.Id = Token;

			secretBEPath = "/v1/" + backendMountName + "/";
			vaultSecretPath = new Uri("http://" + vaultIP + ":" + port + secretBEPath);
		}


		#region Create

		/// <summary>
		/// Creates the given Secret, ONLY if there is not already a secret by this path already.  Returns NULL if secret already exists.  Returns Secret object otherwise.
		/// </summary>
		/// <param name="secret">Secret object to create in Vault.</param>
		/// <returns>New Secret object if it was created in Vault, NULL if it already exists.</returns>
		public async Task<Secret> CreateSecret(Secret secret) {
			// Ensure secret does not exist currently.
			Secret exists = await ReadSecret(secret.Path);
			if (exists != null) { return null; }

			// Create it.
			return await CreateOrUpdateSecret(secret);
		}




		/// <summary>
		/// Creates a secret at the path specified, ONLY if there is not already a secret there.  Returns NULL if there is already a secret there.  Returns a 
		/// Secret object if it was newly created.
		/// </summary>
		/// <param name="secretPath">Where to create the secret at.</param>
		/// <returns>Secret object if it was created.  Null if it already exists.</returns>
		public async Task<Secret> CreateSecret (string secretPath) {
			Secret secret = new Secret(secretPath);
			return await CreateSecret(secret);
		}




		/// <summary>
		/// Creates a secret if it does not exist, updates if it does.  Returns a Secret object read from the Vault. It will return NULL if secret was not created successfully.
		/// This is the equivalent of calling CreateOrUpdateSecretAndReturn along with ReadSecret.
		/// </summary>
		/// <param name="secretPath">The name or full path of the secret.</param>
		/// <returns>Secret object if successful.  Null otherwise</returns>
		public async Task<Secret> CreateOrUpdateSecret (string secretPath) {
			Secret secret = new Secret(secretPath);
			return await CreateOrUpdateSecret(secret);
		}



		/// <summary>
		/// Creates a secret if it does not exist, updates if it does.  Returns a Secret object read from the Vault. It will return NULL if secret was not created successfully.
		/// This is the equivalent of calling CreateOrUpdateSecretAndReturn along with ReadSecret.
		/// </summary>
		/// <param name="secret">Secret object that contains the secret path to be created.</param>
		/// <returns>Secret object populated with the Secret info as read from the Vault.</returns>
		public async Task<Secret> CreateOrUpdateSecret(Secret secret) {
			if (await CreateOrUpdateSecretAndReturn(secret)) {
				return (await ReadSecret(secret.Path));
			}
			else { return null; }
		}



		/// <summary>
		/// Creates a secret if it does not exist, updates if it does.  Returns true if successful, false otherwise.
		/// </summary>
		/// <param name="secretPath">The name or full path of the secret.</param>
		/// <returns>True if successful in creating, false otherwise.</returns>
		public async Task<bool> CreateOrUpdateSecretAndReturn (string secretPath) {
			Secret secret = new Secret(secretPath);
			return await CreateOrUpdateSecretAndReturn(secret);
		}




		/// <summary>
		/// Creates a secret if it does not exist, updates if it does.  Returns true if successful, false otherwise.
		/// </summary>
		/// <param name="secret">The Secret object with at least the secret path populated.</param>
		/// <returns>True if successful in creating the secret in Vault, false otherwise.</returns>
		public async Task<bool> CreateOrUpdateSecretAndReturn(Secret secret) {
			string path = vaultSecretPath + secret.Path;

			// Set TTL to 4 hour if not specified explicitly
			if (secret.RefreshInterval == 0) { secret.RefreshInterval = (4 * 3600); }


			// Build the content parameters, which will contain the TTL and the key value attributes.
			Dictionary<string, string> contentParams = new Dictionary<string, string>();
			contentParams.Add("ttl", secret.RefreshInterval.ToString());
			string contentParamsJSON = JsonConvert.SerializeObject(contentParams, Formatting.None);


			// Build entire JSON Body:  Input Params + Bulk Items List.
			string attrJSON = "";
			if (secret.Attributes.Count > 0) {
				attrJSON = JsonConvert.SerializeObject(secret.Attributes, Formatting.None);

				// Combine the 2 JSON's
				string newVarsJSON = contentParamsJSON.Substring(1, contentParamsJSON.Length - 2) + ",";
				attrJSON = attrJSON.Insert(1, newVarsJSON);
			}
			else { attrJSON = contentParamsJSON; }

			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "CreateOrUpdateSecret",null, attrJSON);
			if (vdro.Success) {
				return true;
			}
			else { return false; }
		}

		#endregion Create




		/// <summary>
		/// Reads the secret that matches the secretPath passed in and returns a Secret object.  Returns NULL if the secret was not found.
		/// </summary>
		/// <param name="secretPath">The full path to the secret.  Also known as the secret's full name.</param>
		/// <returns>Secret object populated with the secret's attributes if successful.  Null if not successful.</returns>
		public async Task<Secret> ReadSecret (string secretPath) {
			string path = vaultSecretPath + secretPath;

			try {
				VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "ReadSecret");
				if (vdro.Success) {
					Secret secret = vdro.GetVaultTypedObjectFromResponse<Secret>();

					// Vault does not populate the path variable.  We need to set.
					secret.Path = secretPath;
					return secret;
				}
				throw new ApplicationException("SecretBackEnd: ReadSecret - Arrived at an unexpected code path.");
			}
			catch (VaultInvalidPathException e) { return null; }
			catch (Exception e) { throw e; }
		}




		/// <summary>
		/// Reads the secret for the Secret passed in and returns a new Secret object.  Returns NULL if the secret was not found.
		/// </summary>
		/// <param name="secret">A Secret Object with at least the secret Path specified.</param>
		/// <returns>Secret Object as read from Vault.</returns>
		public async Task<Secret> ReadSecret (Secret secret) {
			return await ReadSecret(secret.Path);
		}




		/// <summary>
		/// Determines if a secret exists in the Vault Backend.  True if it exists, False otherwise.  Note: If you are checking for existince prior to reading the secret, then it
		/// is better to just call ReadSecret and check for a null return value to see if it exists or not.  IfExists calls ReadSecret to perform its logic!
		/// </summary>
		/// <param name="secret"></param>
		/// <returns></returns>
		public async Task<bool> IfExists (Secret secret) {
			return (await IfExists(secret.Path));
		}


		public async Task<bool> IfExists (string secretPath) {
			Secret exists = await ReadSecret(secretPath);
			if (exists != null) { return true; }
			else { return false; }
		}



		/// <summary>
		/// List all the secrets immediately in the secret path provided.  Note:  This does not list the secret attributes only the secrets themselves.
		/// Because of the way Vault identifies secrets and secrets with sub items (folders), a secret that contains a sub item will be listed 2x in the output.
		/// Once with just the secret name and once with the folder identifier.  so:  (sublevel and sublevel/). 
		/// </summary>
		/// <param name="secretPath">Path that you wish to use as parent to list secrets from.  Only lists immediate children of this secret path.</param>
		/// <returns>List of strings of the secret names.</returns>
		public async Task<List<string>> ListSecrets (string secretPath) {
			string path = vaultSecretPath + secretPath + "?list=true";

			try {
				VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "ListSecrets");
				if (vdro.Success) {
					string js = vdro.GetJSONPropertyValue(vdro.GetDataPackageAsJSON(), "keys");
					List<string> keys = VaultUtilityFX.ConvertJSON<List<string>>(js);
					return keys;
				}
				throw new ApplicationException("SecretBackend:ListSecrets  Arrived at unexpected code block.");
			}
			// 404 Errors mean there were no sub paths.  We just return an empty list.
			catch (VaultInvalidPathException e) { return new List<string>(); }
		}




		/// <summary>
		/// List all the secrets immediately in the secret path provided.  Note:  This does not list the secret attributes only the secrets themselves.
		/// Because of the way Vault identifies secrets and secrets with sub items (folders), a secret that contains a sub item will be listed 2x in the output.
		/// Once with just the secret name and once with the folder identifier.  so:  (sublevel and sublevel/). 
		/// </summary>
		/// <param name="secret">Secret that you wish to use as parent to list secrets from.  Only lists immediate children of this secret.</param>
		/// <returns>List of strings of the secret names.</returns>
		public async Task<List<string>> ListSecrets (Secret secret) {
			return await ListSecrets(secret.Path);
		}




		/// <summary>
		/// Updates an already existing secret OR will create it.  Just another name for CreateOrUpdateSecret.
		/// </summary>
		/// <param name="secret">Secret that should be updated.</param>
		/// <returns>Secret Object with the updated values.</returns>
		public async Task<Secret> UpdateSecret (Secret secret) {
			return await CreateOrUpdateSecret(secret);
			throw new NotImplementedException();
		}





		/// <summary>
		/// Deletes the Vault secret at the path specified.  Returns True AND sets the vault path to nothing and deletes the Secret's attributes, if successful.  
		/// Returns False and does not delete the Secret object if it failed to delete for some reason.  
		/// </summary>
		/// <param name="secret">True for success.  False otherwise.</param>
		/// <returns></returns>
		public async Task<bool> DeleteSecret (Secret secret) {
			if ((await DeleteSecret(secret.Path))) {
				secret.Path = "";
				secret.Attributes.Clear();
				return true;
			}
			else { return false; }
		}




		/// <summary>
		/// Deletes the Vault secret at the secret path specified.  Returns true for success, false otherwise.
		/// </summary>
		/// <param name="secretPath">The path to the Vault secret to permanently delete.</param>
		/// <returns>True for success, False otherwise.</returns>
		public async Task<bool> DeleteSecret(string secretPath) {
			string path = vaultSecretPath + secretPath;

			VaultDataResponseObject vdro = await vaultHTTP.DeleteAsync(path, "DeleteSecret");
			if (vdro.Success) { return true; }
			else { return false; }
		}



	}

}
