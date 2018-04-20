using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.System
{
	public enum EnumAuthMethods
	{
		AppRole = 0,
		AWS = 1,
		GoogleCloud = 2,
		Kubernetes = 3,
		GitHub = 4,
		LDAP = 5,
		Okta = 6,
		Radius = 7,
		TLSCertificates = 8,
		UsernamePassword = 9    //,

		//Azure = 11
	}
}
