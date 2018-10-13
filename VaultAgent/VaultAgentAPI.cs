using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent
{
    public class VaultAgentAPI
    {
		private Dictionary<string, VaultBackend> _backends;


		/// <summary>
		/// Constructor to create a new VaultAgentAPI object which is used to connect to a single Vault Instance.  An instance can have many backends however.
		/// </summary>
		/// <param name="name">The name this Vault Instance should be known by.  This is purely cosmetic and serves no functional purpose other than being able to uniquely identify this Vault Instance from another.</param>
		public VaultAgentAPI (string name, string vaultIP, int port) {
			Name = name;
			IP = vaultIP;
			Port = port;


			// Create the Backend list.
			_backends = new Dictionary<string, VaultBackend>();
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


		// Adds the given backend to the backend list.  The backend object must already be defined.  See AddExistingBackend for alternative means, just specifying the name.
		public bool AddBackend(VaultBackend vaultBackend) {
			_backends.Add(vaultBackend.Name, vaultBackend);
			return true;
		}


		public bool Connect () {
			return false;
		}

    }
}
