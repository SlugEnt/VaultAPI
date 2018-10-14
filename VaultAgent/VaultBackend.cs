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
		public VaultBackend(string name, string mountPointName, VaultAPI_Http vaultAPI_Http) {
			Name = name;
			MountPoint = mountPointName;
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

		//public bool Connect (string )
    }
}
