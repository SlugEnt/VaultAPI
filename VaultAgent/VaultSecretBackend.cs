using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent
{
	/// <summary>
	/// Internal abstract class representing a secret backend.
	/// </summary>
    public abstract class VaultSecretBackend : VaultBackend
    {
		internal VaultSecretBackend (string backendName, string backendMountPoint, VaultAPI_Http _httpConnector) : base (backendName, backendMountPoint, _httpConnector) {
			IsSecretBackend = true;
		}
}
}
