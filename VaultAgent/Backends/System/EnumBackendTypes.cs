using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.System
{

	public enum EnumBackendTypes
	{
		Transit = 0,
		Secret = 1,  //    KV, KeyValue or Also known as Secret.
		AWS = 2,
		CubbyHole = 3,
		Generic = 4,
		PKI = 5,
		SSH = 6,
		KeyValueV2 = 7
	}
}
