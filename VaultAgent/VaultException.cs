using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent
{
	[Serializable]
	public class VaultFieldNotFoundException : Exception

	{
		private const string defaultMsg = "Unable to find the requested field.";

		public VaultFieldNotFoundException() : base(defaultMsg) { }
		public VaultFieldNotFoundException(string message) : base(message) { }
		public VaultFieldNotFoundException(string message, System.Exception innerException) : base(message, innerException) { }
		protected VaultFieldNotFoundException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
	}




	// ==============================================================================================================================================
	// Deals with Vault Sealed Errors.
	[Serializable]
	public class VaultSealedException : Exception
	{
		private const string defaultMsg = "The vault is sealed.  It must be unsealed in order to be accessible to programs.  Only Vault Admins can do this.";
		
		public VaultSealedException() : base(defaultMsg) { }
		public VaultSealedException(string message) : base(message) { }
		public VaultSealedException(string message, System.Exception innerException) : base(message, innerException) { }
		protected VaultSealedException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

		public VaultSealedException(Exception inner) : base("") { }
	}
}
