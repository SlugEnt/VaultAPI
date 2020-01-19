using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent.Backends {
    /// <summary>
    /// Enum representing the possible  backends that Vault can support.  Note, not everything listed here is implemented at this time in this library.
    /// </summary>
    public enum EnumBackendTypes {
        // Never change an existing value!

        // Secret Backends

        /// <summary>
        /// A Transit Secret Backend
        /// </summary>
        Transit = 0,

        /// <summary>
        /// A Vault Secret Backend Version 1
        /// </summary>
        Secret = 1, 

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
        Identity = 8,



        // Auth Backends

        /// <summary>
        /// An Application Role Authentication Method
        /// </summary>
        A_AppRole = 500,

        /// <summary>
        /// An Amazon Web Services Authentication Method
        /// </summary>
        A_AWS = 501,

        /// <summary>
        /// A Google Cloud Authentication Method
        /// </summary>
        A_GoogleCloud = 502,

        /// <summary>
        /// A Kurbernetes Authentication Method
        /// </summary>
        A_Kubernetes = 503,

        /// <summary>
        /// A GitHub Authentication Method
        /// </summary>
        A_GitHub = 504,

        /// <summary>
        /// An LDAP Authentication Method
        /// </summary>
        A_LDAP = 505,

        /// <summary>
        /// A Okta Authentication Method
        /// </summary>
        A_Okta = 506,

        /// <summary>
        /// A TLSCertificate Authentication Method
        /// </summary>
        A_TLSCertificates = 507,

        /// <summary>
        /// A UserNamePassword Authentication Method
        /// </summary>
        A_UsernamePassword = 508,

        /// <summary>
        /// An Azure Authentication Method
        /// </summary>
        A_Token = 509,


        /// <summary>
        /// This is the default.  Unit tests should test each backend and make sure each class overrides the type.
        /// </summary>
        NotDefined = 999,
    }
}