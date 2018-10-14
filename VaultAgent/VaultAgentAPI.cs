using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent.Backends.System;
using VaultAgent.Backends.SecretEngines;
using VaultAgent.Models;
using System.Threading.Tasks;
using VaultAgent.Backends;


namespace VaultAgent
{
	public class VaultAgentAPI
	{
		private Dictionary<string, VaultBackend> _backends;
		private VaultAPI_Http _httpConnector;               // Provides HTTP Calling Methods to the backends.
		private SysBackend _vault;                          // Connection to the Vault Instance


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


			// Create the Backend list.
			_backends = new Dictionary<string, VaultBackend>();

			// Create HTTP Connector object
			_httpConnector = new VaultAPI_Http(IP, port, token);

			// Establish a connection to the backend
			_vault = new SysBackend(IP, Port, token);
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


		// Adds the given backend to the backend list.  The backend object must already be defined.  See AddExistingBackend for alternative means, just specifying the name.
		public bool AddBackend(VaultBackend vaultBackend) {
			_backends.Add(vaultBackend.Name, vaultBackend);
			return true;
		}



		/// <summary>
		/// Establishes a connection to the desired Vault Secret backend at the specified vault MountPath.  The backend mount must already exist.
		/// </summary>
		/// <param name="secretBackendType">The type of backend you wish to connect to.</param>
		/// <param name="backendName">The name you wish to refer to this backend by.  This is NOT the Vault mount path.</param>
		/// <param name="backendMountPath">The path to the vault mount point that this backend is located at.</param>
		/// <returns>True if it was able to successfully connect to the backend.  False if it encountered an error.</returns>
		public VaultBackend ConnectToSecretBackend(EnumBackendTypes secretBackendType, string backendName, string backendMountPath) {
			switch (secretBackendType) {
				case EnumBackendTypes.KeyValueV2:
					KV2Backend kv2Backend = new KV2Backend(backendName, backendMountPath, _httpConnector);
					return kv2Backend;
				case EnumBackendTypes.Secret:
					break;
				case EnumBackendTypes.Transit:
					TransitBackend transitBackend = new TransitBackend(backendName, backendMountPath, _httpConnector);
					return transitBackend;
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

		public async Task<VaultBackend> CreateSecretBackendMount(EnumBackendTypes secretBackendType, string backendName, string backendMountPath, string description, VaultSysMountConfig config = null) {
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
	}
}
