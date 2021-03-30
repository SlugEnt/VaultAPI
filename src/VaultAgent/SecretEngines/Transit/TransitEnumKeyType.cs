using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

#pragma warning disable CS1591

namespace VaultAgent.Backends {
	/// <summary>
	/// Transit Key Types
	/// </summary>
	public enum TransitEnumKeyType {
		aes256 = 0, 
		chacha20 = 1, 
		ed25519 = 2, 
		ecdsa = 3, 
		rsa2048 = 4, 
		rsa4096 = 5
	}
}