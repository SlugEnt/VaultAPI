using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent
{
	public abstract class VaultBackend {
		protected  VaultAPI_Http _vaultHTTP;


		/// <summary>
		/// Constructor for the Backend.  
		/// </summary>
		/// <param name="name">The name used to identify this backend, this is not the mount point!</param>
		/// <param name="mountPointName">The name of the mount point in vault to connect to.</param>
		/// <param name="vaultAPI_Http">The VaultAPI_Http object that should be used to make API calls to the Vault Instance.</param>
		public VaultBackend(string name, string mountPointName, VaultAPI_Http vaultAPI_Http, string mountPointPrefix = "/v1/") {
			Name = name;
			MountPoint = mountPointName;
			MountPointPath = mountPointPrefix + mountPointName + "/";
			_vaultHTTP = vaultAPI_Http;
		}


		/// <summary>
		/// The name to be used to identify the backend.
		/// </summary>
		public string Name { get; private set; }


		/// <summary>
		/// The name of the mount point in Vault for the backend.  This must be exact and capitalization matters.
		/// </summary>
		public string MountPoint { get; private set; }


		/// <summary>
		/// The mount path is the exact path in Vault to get to the specific mount Point.  Usually it is /v1/(MountPoint)/
		/// </summary>
		public string MountPointPath { get; private set; }

    }
}
