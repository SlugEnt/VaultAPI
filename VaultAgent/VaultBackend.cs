using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent.Backends;

namespace VaultAgent {
    /// <summary>
    /// Represents the Abstract elements of a Vault Backend Object
    /// </summary>
    public abstract class VaultBackend {
        /// <summary>
        /// The Vault Agent API object that this Backend will use to talk to Vault.  
        /// </summary>
        protected VaultAgentAPI _parent;

        //protected  VaultAPI_Http _vaultHTTP;
        private string _mountPrefix;


        /// <summary>
        /// Constructor for the Backend.  
        /// </summary>
        /// <param name="name">The name used to identify this backend, this is not the mount point!</param>
        /// <param name="mountPoint">The name of the mount point in vault to connect to.</param>
        /// <param name="vaultAgentAPI">This is the Vault Agent API object that contains Connection info to the Vault.
        /// It should also contain a Token that has the necessary permissions to do the Backend Tasks</param>
        /// <param name="mountPointPrefix">If the path is prefixed in vault with some value, specify it here.  It defaults to /v1/ which is typical Vault default value.</param>
        public VaultBackend (string name, string mountPoint, VaultAgentAPI vaultAgentAPI, string mountPointPrefix = "/v1/") {
            Name = name;
            MountPoint = mountPoint;
            MountPointPrefix = mountPointPrefix;

            _parent = vaultAgentAPI;

            Type = EnumBackendTypes.NotDefined;
        }


        /// <summary>
        /// The cosmetic name to be used to identify the backend.  This is not used internally in Vault.
        /// </summary>
        public string Name { get; private set; }


        /// <summary>
        /// The "name" of the mount point in Vault for the backend.  This must be exact and capitalization matters.  This is the Name as far as Vault is concerned.
        /// </summary>
        public string MountPoint { get; private set; }


        /// <summary>
        /// The mount path is the exact path in Vault to get to the specific mount Point.  Usually it is /v1/(MountPoint)/
        /// </summary>
        public string MountPointPath {
            get { return (MountPointPrefix + MountPoint + "/"); }
        }


        //TODO - Unit Test this.
        /// <summary>
        /// The Mount Point prefix of the Backend
        /// </summary>
        public string MountPointPrefix {
            get { return _mountPrefix; }
            protected set {
                if ( value.EndsWith ("/") ) { _mountPrefix = value; }
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