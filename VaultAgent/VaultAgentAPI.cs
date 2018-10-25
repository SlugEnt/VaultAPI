using System;
using System.Collections.Generic;
using VaultAgent.Backends.System;
using VaultAgent.SecretEngines;
using VaultAgent.Models;
using System.Threading.Tasks;
using VaultAgent.Backends;

using VaultAgent.AuthenticationEngines;


namespace VaultAgent
{
	public class VaultAgentAPI
	{
		private Dictionary<string, VaultSecretBackend> _secretBackends;
		private Dictionary<string, VaultAuthenticationBackend> _authenticationBackends;
		private VaultAPI_Http _httpConnector;               // Provides HTTP Calling Methods to the backends.
		private VaultSystemBackend _vault;                          // Connection to the Vault Instance
		private TokenAuthEngine _tokenEngine;			// Connects to token backend to retrieve token information.
        

		/// <summary>
		/// Constructor to create a new VaultAgentAPI object which is used to connect to a single Vault Instance.  An instance can have many backends however.
		/// </summary>
		/// <param name="name">The name this Vault Instance should be known by.  This is purely cosmetic and serves no functional purpose other than being able to uniquely identify this Vault Instance from another.</param>
		/// <param name="port">The network port the Vault instance is listening on.</param>
		/// <param name="vaultIP">The IP address of the Vault instance you want to connect to.</param>
		/// <param name="token">The token to be used to connect to the Vault instance with.</param>
		public VaultAgentAPI(string name, string vaultIP, int port, string token) {
			Name = name;
			IP = vaultIP;
			Port = port;

			TokenInfo tokenValue = new TokenInfo(token);
			Token = tokenValue;


			// Create the Secret Backend list.
			_secretBackends = new Dictionary<string, VaultSecretBackend>();

			// Create the Authentication backends Dictionary
			_authenticationBackends = new Dictionary<string, VaultAuthenticationBackend>();

			// Create HTTP Connector object
			_httpConnector = new VaultAPI_Http(IP, port, token);

			// Establish a connection to the backend
			_vault = new VaultSystemBackend(token,_httpConnector);

			// Establish a connection to the token backend.
			_tokenEngine = (TokenAuthEngine) ConnectAuthenticationBackend(EnumBackendTypes.A_Token, "", "");
		}


		/// <summary>
		/// The name this Vault Instance is known by.  This is purely cosmetic and serves no functional purpose other than being able to uniquely identify this Vault Instance from another.
		/// </summary>
		public string Name { get; private set; }


		/// <summary>
		/// The IP Address of the vault instance.  
		/// </summary>
		public string IP { get; private set; }


		/// <summary>
		/// The IP port the Vault instance is listening on.
		/// </summary>
		public int Port { get; private set; }


		/// <summary>
		/// The token to use to connect to the vault with.
		/// </summary>
		public TokenInfo Token { get; private set; }


        /// <summary>
        /// Provides access to the Vault Core System Backend which provides access to mount new engines/backends and manipulate the main Vault Store.
        /// </summary>
        public VaultSystemBackend System
        {
            get { return _vault; }
        }



		/// <summary>
		/// Establishes a connection to the desired Vault Secret backend at the specified vault MountPath.  The backend mount must already exist.
		/// </summary>
		/// <param name="secretBackendType">The type of backend you wish to connect to.</param>
		/// <param name="backendName">The name you wish to refer to this backend by.  This is NOT the Vault mount path.</param>
		/// <param name="backendMountPath">The path to the vault mount point that this backend is located at.</param>
		/// <returns>True if it was able to successfully connect to the backend.  False if it encountered an error.</returns>
		public VaultBackend ConnectToSecretBackend(EnumSecretBackendTypes secretBackendType, string backendName, string backendMountPath) {
			switch (secretBackendType) {
				case EnumSecretBackendTypes.KeyValueV2:
					KV2SecretEngine kv2Backend = new KV2SecretEngine(backendName, backendMountPath, _httpConnector);
					return kv2Backend;
				case EnumSecretBackendTypes.Secret:
					KeyValueSecretEngine secretBackend = new KeyValueSecretEngine(backendName, backendMountPath, _httpConnector);
					return secretBackend;
				case EnumSecretBackendTypes.Transit:
					TransitSecretEngine transitSecretEngine = new TransitSecretEngine(backendName, backendMountPath, _httpConnector);
					return transitSecretEngine;
			}
			return null;
		}



		/// <summary>
		/// Creates a secret backend of the specified type at the specified mount path.  Upon completion it establishes a connection to the backend.
		/// </summary>
		/// <param name="secretBackendType">The type of backend you wish to connect to.</param>
		/// <param name="backendName">The name you wish to refer to this backend by.  This is NOT the Vault mount path.</param>
		/// <param name="backendMountPath">The path to the vault mount point that this backend is located at.</param>
		/// <param name="config">(Optional) A VaultSysMountConfig object that contains the connection configuration you wish to use to connect to the backend.  If not specified defaults will be used.</param>
		/// <returns>True if it was able to create the backend and connect to it.  False if it encountered an error.</returns>

		public async Task<VaultBackend> CreateSecretBackendMount(EnumSecretBackendTypes secretBackendType, string backendName, string backendMountPath, string description, VaultSysMountConfig config = null) {
			VaultSysMountConfig backendConfig;

			if (config == null) {
				backendConfig = new VaultSysMountConfig {
					DefaultLeaseTTL = "30m",
					MaxLeaseTTL = "90m",
					VisibilitySetting = "hidden"
				};
			}
			else { backendConfig = config; }

			bool rc = await _vault.SysMountCreate(backendMountPath, description, secretBackendType, backendConfig);
			if (rc == true) {
				return ConnectToSecretBackend(secretBackendType, backendName, backendMountPath);
			}
			return null;
		}



		/// <summary>
		/// Connects to the specified Authentication backend.
		/// </summary>
		/// <param name="backendType">The type of backend to connect</param>
		/// <param name="backendName">Name of the backend</param>
		/// <param name="backendMountPath">Mount path to the backend.</param>
		/// <returns></returns>
		public VaultAuthenticationBackend ConnectAuthenticationBackend (EnumBackendTypes backendType, string backendName, string backendMountPath ) {
			switch (backendType) {
				case EnumBackendTypes.A_AppRole:
					AppRoleAuthEngine AppRoleAuthEngine = new AppRoleAuthEngine(backendName, backendMountPath, _httpConnector);
					return AppRoleAuthEngine;
				case EnumBackendTypes.A_Token:
					TokenAuthEngine tokenAuthEngine = new TokenAuthEngine(_httpConnector);
					return tokenAuthEngine;
				default:
					throw new ArgumentOutOfRangeException("Must supply a backendType that is derived from the VaultAuthenticationBackend class");
			}
		}



	}
}
