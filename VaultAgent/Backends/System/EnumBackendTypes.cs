using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent.Backends
{
    public enum EnumBackendTypes
    {
		// Never change an existing value!

		// Secret Backends
		Transit = 0,
		Secret = 1,  //    KV, KeyValue or Also known as Secret.
		AWS = 2,
		CubbyHole = 3,
		Generic = 4,
		PKI = 5,
		SSH = 6,
		KeyValueV2 = 7,

		


		// Auth Backends
		A_AppRole = 500,
		A_AWS = 501,
		A_GoogleCloud = 502,
		A_Kubernetes = 503,
		A_GitHub = 504,
		A_LDAP = 505,
		A_Okta = 506,
		A_TLSCertificates = 507,
		A_UsernamePassword = 508,
		A_Token = 509,

		// This is the default.  Unit tests should test each backend and make sure each class overrides the type.
		NotDefined = 999,
	}
}
