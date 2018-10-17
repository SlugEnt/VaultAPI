using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.KV_V2
{
	public enum EnumKVv2SaveSecretOptions
	{
		OnlyIfKeyDoesNotExist = 0,
		OnlyOnExistingVersionMatch = 1,
		AlwaysAllow = 2

	}
}
