using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.System {
    /// <summary>
    /// Enumeration that defines a numeric value for each Secret Backend Type
    /// </summary>
    public enum EnumSecretBackendTypes {
        /// <summary>
        /// A Transit Secret Backend        
        /// </summary>
        Transit = 0,

        /// <summary>
        /// A Vault Secret Backend Version 1
        /// </summary>
        Secret = 1, //    KV, KeyValue or Also known as Secret.

        /// <summary>
        /// An Amazon Web Services Secret Backend
        /// </summary>
        AWS = 2,

        /// <summary>
        /// A CubbyHole Secret Backend
        /// </summary>
        CubbyHole = 3,

        /// <summary>
        /// Not sure why I created this?
        /// </summary>
        Generic = 4,

        /// <summary>
        /// A PKI Certificate Secret Backend
        /// </summary>
        PKI = 5,

        /// <summary>
        /// An SSH Secret Backend
        /// </summary>
        SSH = 6,

        /// <summary>
        /// A Vault Secret Backend Version 2.  Also known as KV2.  This is preferred over the Secret Version 1 backend
        /// </summary>
        KeyValueV2 = 7,

        /// <summary>
        /// An Identity Secret Backend
        /// </summary>
        Identity = 8
    }
}