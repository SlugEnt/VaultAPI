using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent.Backends.System;

namespace VaultAgent
{
	public abstract class VaultBackend {
		protected  VaultAPI_Http _vaultHTTP;
		private string _mountPrefix;


		/// <summary>
		/// Constructor for the Backend.  
		/// </summary>
		/// <param name="name">The name used to identify this backend, this is not the mount point!</param>
		/// <param name="mountPointName">The name of the mount point in vault to connect to.</param>
		/// <param name="mountPointPrefix">If the path is prefixed in vault with some value, specify it here.  It defaults to /v1/ which is typical Vault default value.</param>
		/// <param name="vaultAPI_Http">The VaultAPI_Http object that should be used to make API calls to the Vault Instance.</param>
		public VaultBackend( string name, string mountPointName, VaultAPI_Http vaultAPI_Http, string mountPointPrefix = "/v1/") {
			Name = name;
			MountPoint = mountPointName;
			MountPointPrefix = mountPointPrefix;
			_vaultHTTP = vaultAPI_Http;
			Type = EnumBackendTypes.NotDefined;
		}


		/// <summary>
		/// The name to be used to identify the backend.
		/// </summary>
		public string Name { get; private set; }


		/// <summary>
		/// The "name" of the mount point in Vault for the backend.  This must be exact and capitalization matters.
		/// </summary>
		public string MountPoint { get; private set; }


		/// <summary>
		/// The mount path is the exact path in Vault to get to the specific mount Point.  Usually it is /v1/(MountPoint)/
		/// </summary>
		public string MountPointPath { get { return (MountPointPrefix + MountPoint + "/"); } }


		//TODO - Unit Test this.
		public string MountPointPrefix {
			get { return _mountPrefix; }
			protected set {
				if (value.EndsWith("/")) { _mountPrefix = value; }
				else { _mountPrefix = (value + "/"); }
			}
		}
		

		/// <summary>
		/// The exact type of backend this is.  All Authentication backends start with A_.
		/// </summary>
		public EnumBackendTypes Type { get; protected set; }


		/// <summary>
		/// True if this backend is an Authentication Backend.
		/// </summary>
		public bool IsAuthenticationBackend { get; protected set; }


		/// <summary>
		/// True if this backend is a Secret backend.
		/// </summary>
		public bool IsSecretBackend { get; protected set; }
    }
}
