using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends {
	/// <summary>
	/// The Hashing Methods supported by Transit
	/// </summary>
	public enum TransitEnumHashingAlgorithm {
		/// <summary>
		/// 224 bit Key Length
		/// </summary>
		sha2_224 = 0,

		/// <summary>
		/// 256 bit Key Length
		/// </summary>
		sha2_256 = 1,

		/// <summary>
		/// 384 bit Key Length
		/// </summary>
		sha2_384 = 2,

		/// <summary>
		/// 512 bit Key Length
		/// </summary>
		sha2_512 = 3
	}
}