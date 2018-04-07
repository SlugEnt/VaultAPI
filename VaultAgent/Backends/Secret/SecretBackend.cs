using System;
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
		string secretPath = "/v1/secret/";
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

			secretPath = "/v1/" + backendMountName + "/";
			vaultSecretPath = new Uri("http://" + vaultIP + ":" + port + secretPath);
		}


		#region Create
		/// <summary>
		/// Create a secre with the given secretPath name and returns a Secret object read from Vault. So this is the equivalent of a Create and Read in one step.
		/// </summary>
		/// <param name="secretPath">The name or full path of the secret.</param>
		/// <returns>Secret object if successful.  Null otherwise</returns>
		public async Task<Secret> CreateSecret (string secretPath) {
			Secret secret = new Secret(secretPath);
			return await CreateSecret(secret);
		}



		/// <summary>
		/// Creates a secret in Vault from the passed in Secret. Returns a new Secret object read from the Vault.  So this is the equivalent of a Create and Read in one step.
		/// </summary>
		/// <param name="secret">Secret object that contains the secret path to be created.</param>
		/// <returns>Secret object populated with the Secret info as read from the Vault.</returns>
		public async Task<Secret> CreateSecret(Secret secret) {
			if (await CreateSecretAndReturn(secret)) {
				return (await ReadSecret(secret.Path));
			}
			else { return null; }
		}



		/// <summary>
		/// Creates a secret with the given secretPath name and returns true if successful, false otherwise.
		/// </summary>
		/// <param name="secretPath">The name or full path of the secret.</param>
		/// <returns>True if successful in creating, false otherwise.</returns>
		public async Task<bool> CreateSecretAndReturn (string secretPath) {
			Secret secret = new Secret(secretPath);
			return await CreateSecretAndReturn(secret);
		}




		/// <summary>
		/// Creates a secret in Vault from the passed in Secret object.  Returns true if successful, false otherwise.
		/// </summary>
		/// <param name="secret">The Secret object with at least the secret path populated.</param>
		/// <returns>True if successful in creating the secret in Vault, false otherwise.</returns>
		public async Task<bool> CreateSecretAndReturn(Secret secret) {
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

			VaultDataResponseObject vdro = await vaultHTTP.PostAsync(path, "CreateSecret",null, attrJSON);
			if (vdro.Success) {
				return true;
			}
			else { return false; }
		}

		#endregion Create


		/// <summary>
		/// Reads the secret that matches the secretPath passed in.
		/// </summary>
		/// <param name="secretPath">The full path to the secret.  Also known as the secret's full name.</param>
		/// <returns>Secret object populated with the secret's attributes if successful.  Null if not successful.</returns>
		public async Task<Secret> ReadSecret (string secretPath) {
			string path = vaultSecretPath + secretPath;

			VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "ReadSecret");
			if (vdro.Success) {
				Secret secret = vdro.GetVaultTypedObjectFromResponse<Secret>();

				// Vault does not populate the path variable.  We need to set.
				secret.Path = secretPath;
				return secret;
			}
			return null;
		}




		/// <summary>
		/// Returns a new secret with refreshed values from the Vault for the secrert passed in.
		/// </summary>
		/// <param name="secret">A Secret Object with at least the secret Path specified.</param>
		/// <returns>Secret Object as read from Vault.</returns>
		public async Task<Secret> ReadSecret (Secret secret) {
			return await ReadSecret(secret.Path);
		}





		public async Task ListSecrets (string secretPath) {
			string path = vaultSecretPath + secretPath + "?list=true";

			VaultDataResponseObject vdro = await vaultHTTP.GetAsync(path, "ListSecrets");
			if (vdro.Success) {

			}
			throw new NotImplementedException();
		}






		public async Task UpdateSecret (string secretPath) {
			throw new NotImplementedException();
		}



		public async Task DeleteSecret (string secretpath) {
			throw new NotImplementedException();
		}
	}

}
