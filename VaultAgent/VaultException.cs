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



	[Serializable]
	public class VaultInvalidDataException : Exception
	{
		private const string defaultMsg = "Invalid or missing data was supplied.";

		public VaultInvalidDataException() : base(defaultMsg) { }
		public VaultInvalidDataException(string message) : base(message) { }
		public VaultInvalidDataException(string message, System.Exception innerException) : base(message, innerException) { }
		protected VaultInvalidDataException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
	}


	[Serializable]
	public class VaultForbiddenException : Exception
	{
		private const string defaultMsg = "Authentication details are either incorrect, permission to access feature is denied or a CORS request failure occurred. ";

		public VaultForbiddenException() : base(defaultMsg) { }
		public VaultForbiddenException(string message) : base(message) { }
		public VaultForbiddenException(string message, System.Exception innerException) : base(message, innerException) { }
		protected VaultForbiddenException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
	}



	[Serializable]
	public class VaultInvalidPathException : Exception
	{
		private const string defaultMsg = "Permission Denied to the the path specified.  In some cases this can also mean a path does not exist.";

		public VaultInvalidPathException() : base(defaultMsg) { }
		public VaultInvalidPathException(string message) : base(message) { }
		public VaultInvalidPathException(string message, System.Exception innerException) : base(message, innerException) { }
		protected VaultInvalidPathException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
	}




	[Serializable]
	public class VaultInternalErrorException : Exception
	{
		private const string defaultMsg = "Internal Vault Error Occured.  Try Again at later time.";

		public VaultInternalErrorException() : base(defaultMsg) { }
		public VaultInternalErrorException(string message) : base(message) { }
		public VaultInternalErrorException(string message, System.Exception innerException) : base(message, innerException) { }
		protected VaultInternalErrorException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
	}



	[Serializable]
	public class VaultStandbyNodesErrorException : Exception
	{
		private const string defaultMsg = "Standby Vault nodes are in a warning state.";

		public VaultStandbyNodesErrorException() : base(defaultMsg) { }
		public VaultStandbyNodesErrorException(string message) : base(message) { }
		public VaultStandbyNodesErrorException(string message, System.Exception innerException) : base(message, innerException) { }
		protected VaultStandbyNodesErrorException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
	}





	// ==============================================================================================================================================
	// Deals with Vault Sealed Errors.
	[Serializable]
	public class VaultSealedException : Exception
	{
		private const string defaultMsg = "The vault is sealed.  It must be unsealed in order to be accessible to programs.  Only Vault Admins can do this.  Vault Server may also be down.";
		
		public VaultSealedException() : base(defaultMsg) { }
		public VaultSealedException(string message) : base(message) { }
		public VaultSealedException(string message, System.Exception innerException) : base(message, innerException) { }
		protected VaultSealedException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

		public VaultSealedException(Exception inner) : base("") { }
	}
}
