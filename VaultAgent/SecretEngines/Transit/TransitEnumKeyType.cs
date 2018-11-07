using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends
{
	public enum TransitEnumKeyType
	{
		aes256 = 0,
		chacha20 = 1,
		ed25519 = 2,
		ecdsa = 3,
		rsa2048 = 4,
		rsa4096 = 5
	}
}
