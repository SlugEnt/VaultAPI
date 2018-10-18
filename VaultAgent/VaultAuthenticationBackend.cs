using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent
{
	/// <summary>
	/// Internal abstract class representing an Authentication backend method for Vault.
	/// </summary>
	public abstract class VaultAuthenticationBackend : VaultBackend
	{
		internal VaultAuthenticationBackend(string backendName, string backendMountPoint, VaultAPI_Http httpConnector) : base(backendName, backendMountPoint, httpConnector) {
			IsAuthenticationBackend = true;
		}
	}
}