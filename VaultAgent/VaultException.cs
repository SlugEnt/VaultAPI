using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent {
    /// <summary>
    /// Used to specifically identify certain Vault Errors as to the exact cause or reason.
    /// </summary>
    public enum EnumVaultExceptionCodes {
        /// <summary>
        /// The default value for all VaultExceptions.  Indicates we have not classified the error any more specifically than what Vault provided.
        /// </summary>
        UnclassifiedError =0,

        /// <summary>
        /// Indicates that there is already a backend mounted at the specified location.
        /// </summary>
        BackendMountAlreadyExists = 1,


        /// <summary>
        /// The object cannot be found
        /// </summary>
        ObjectDoesNotExist = 2,


        /// <summary>
        /// Indicates that login failed because the login RoleID was invalid.
        /// </summary>
        LoginRoleID_NotFound = 3,

        /// <summary>
        /// Indicates that the login failed because the login SecretID supplied is not valid.
        /// </summary>
        LoginSecretID_NotFound = 4,


        /// <summary>
        /// The Check and Set (CAS) parameter was missing.  This is required on some KV2 keystores depending on config.
        /// </summary>
        CheckAndSetMissing = 5,


        /// <summary>
        /// The Check and Set (CAS) secret version was missing OR the secret already exists, but was told it should only save if it does not exist.
        /// </summary>
        CAS_VersionMissing = 6,


        /// <summary>
        /// The Check and Set (CAS) is set and User requested that the Save only happen if the secret does not already exist.  Secret exists and so this error.
        /// </summary>
        CAS_SecretExistsAlready = 7,


        /// <summary>
        /// Indicates a token does not have permission to a specific path.
        /// </summary>
        PermissionDenied = 8, 

        /// <summary>
        /// Problems connecting to the LDAP server, check name, protocol, ports, tls, etc
        /// </summary>
        LDAPLoginServerConnectionIssue = 9,

        /// <summary>
        /// Invalid username or password supplied for LDAP Login
        /// </summary>
        LDAPLoginCredentialsFailure = 10
    }



    /// <summary>
    /// Represents a Vault Custom Exception
    /// </summary>
    [Serializable]
    internal class VaultCustomException : Exception {
        /// <summary>
        /// The specific Exception Code returned by Vault
        /// </summary>
        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }

        /// <summary>
        /// Constructor for a Custom Vault Exception
        /// </summary>
        public VaultCustomException () : base() { }

        /// <summary>
        /// Constructor for a custom Vault Exception
        /// </summary>
        /// <param name="message">Message to be stored with the Exception</param>
        public VaultCustomException (string message) : base (message) { }


        /// <summary>
        /// Constructor for a custom Vault Exception
        /// </summary>
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        public VaultCustomException (string message, System.Exception innerException) : base (message, innerException) { }

        /// <summary>
        /// Allows Serializing of the exception
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultCustomException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }


    /// <summary>
    /// Represents a generic unclassified VaultException
    /// </summary>
    [Serializable]
    public class VaultException : Exception {
        private const string defaultMsg = "Unclassified Vault Error Occurred.";


        /// <summary>
        /// The specific Exception Code returned by Vault
        /// </summary>
        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }


        /// <summary>
        /// Constructor for a Generic Unclassified Vault Exception
        /// </summary>
        public VaultException () : base (defaultMsg) { }


        /// <summary>
        /// Constructor for a Generic Unclassified Vault Exception
        /// </summary>
        /// <param name="message">Message to be stored with the Exception</param>
        public VaultException (string message) : base (defaultMsg + message) { }


        /// <summary>
        /// Constructor for a Generic Unclassified Vault Exception
        /// </summary>
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        public VaultException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }


        /// <summary>
        /// Serializer for the VaultException Class
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

    }


    /// <summary>
    /// Represents a Vault Error that indicates a field was not found
    /// </summary>
    [Serializable]
    public class VaultFieldNotFoundException : Exception {
        private const string defaultMsg = "Unable to find the requested field.";


        /// <summary>
        /// The specific Exception Code returned by Vault
        /// </summary>
        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }

        /// <summary>
        /// Constructor for a Vault Field Not Found Exception
        /// </summary>
        public VaultFieldNotFoundException () : base (defaultMsg) { }


        /// <summary>
        /// Constructor for a Vault Field Not Found Exception
        /// <param name="message">Message to be stored with the Exception</param>
        /// </summary>
        public VaultFieldNotFoundException (string message) : base (defaultMsg + message) { }


        /// <summary>
        /// Constructor for a Vault Field Not Found Exception
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        /// </summary>
        public VaultFieldNotFoundException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }

        
        /// <summary>
        /// Serializer for Vault Field Not Found Exception
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultFieldNotFoundException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }


    /// <summary>
    /// Represents A Vault Error that indicates that the provided data was incorrect, improperly formatted or some other type of Data related issue
    /// </summary>
    [Serializable]
    public class VaultInvalidDataException : Exception {
        private const string defaultMsg = "Invalid or missing data was supplied.";


        /// <summary>
        /// The specific Exception Code returned by Vault
        /// </summary>
        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }


        /// <summary>
        /// Constructor for a Vault Invalid Data Exception
        /// </summary>
        public VaultInvalidDataException () : base (defaultMsg) { }


        /// <summary>
        /// Constructor for a Vault Invalid Data Exception
        /// <param name="message">Message to be stored with the Exception</param>
        /// </summary>
        public VaultInvalidDataException (string message) : base (defaultMsg + message) { }


        /// <summary>
        /// Constructor for a Vault Invalid Data Exception
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        /// </summary>
        public VaultInvalidDataException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }

        
        /// <summary>
        /// Serializer
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultInvalidDataException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }



    /// <summary>
    /// Vault Forbidden Exception.  Authentication details may be incorrect.  or Permission or CORS request issue is going on.
    /// </summary>
    [Serializable]
    public class VaultForbiddenException : Exception {
        private const string defaultMsg =
	        "Authentication details are either incorrect, permission to access feature is denied or a CORS request failure occurred. ";


        /// <summary>
        /// The specific Exception Code returned by Vault
        /// </summary>
        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }
        

        /// <summary>
        /// Constructor for a Vault Forbidden Exception which usually indicates a permission error, but sometimes is thrown if a path just does not exist.
        /// </summary>
        public VaultForbiddenException () : base (defaultMsg) { }


        /// <summary>
        /// Constructor for a Vault Forbidden Exception which usually indicates a permission error, but sometimes is thrown if a path just does not exist.
        /// <param name="message">Message to be stored with the Exception</param>
        /// </summary>
        public VaultForbiddenException (string message) : base (defaultMsg + message) { }


        /// <summary>
        /// Constructor for a Vault Forbidden Exception which usually indicates a permission error, but sometimes is thrown if a path just does not exist.
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        /// </summary>
        public VaultForbiddenException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }


        /// <summary>
        /// Serializer
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultForbiddenException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }


    }



    /// <summary>
    /// There was an issue with the Path provided to the Vault Methods.  Either the caller does not have permission or the path may not exist.
    /// </summary>
    [Serializable]
    public class VaultInvalidPathException : Exception {
        private const string defaultMsg = "Permission Denied to the the path specified.  In some cases this can also mean a path does not exist.";

        /// <summary>
        /// The specific Exception Code returned by Vault
        /// </summary>
        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }


        /// <summary>
        /// Constructor for a Vault Invalid Path Exception which usually indicates a permission error, but sometimes is thrown if a path just does not exist.
        /// </summary>
        public VaultInvalidPathException () : base (defaultMsg) { }


        /// <summary>
        /// Constructor for a Vault Invalid Path Exception which usually indicates a permission error, but sometimes is thrown if a path just does not exist.
        /// <param name="message">Message to be stored with the Exception</param>
        /// </summary>
        public VaultInvalidPathException (string message) : base (defaultMsg + message) { }


        /// <summary>
        /// Constructor for a Vault Invalid Path Exception which usually indicates a permission error, but sometimes is thrown if a path just does not exist.
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        /// </summary>
        public VaultInvalidPathException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }


        /// <summary>
        /// Serialization
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultInvalidPathException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }


    /// <summary>
    /// There was an internal error detected in Vault
    /// </summary>
    [Serializable]
    public class VaultInternalErrorException : Exception {
        private const string defaultMsg = "Internal Vault Error Occured.  Try Again at later time.";


        /// <summary>
        /// The specific Exception Code returned by Vault
        /// </summary>
        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }


        /// <summary>
        /// Constructor for a Vault Internal Error Exception which usually indicates sometype of issue with the Vault System.
        /// </summary>
        public VaultInternalErrorException () : base (defaultMsg) { }


        /// <summary>
        /// Constructor for a Vault Internal Error Exception which usually indicates sometype of issue with the Vault System.
        /// <param name="message">Message to be stored with the Exception</param>
        /// </summary>
        public VaultInternalErrorException (string message) : base (defaultMsg + message) { }


        /// <summary>
        /// Constructor for a Vault Internal Error Exception which usually indicates sometype of issue with the Vault System.
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        /// </summary>
        public VaultInternalErrorException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }

        /// <summary>
        /// Serializer
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultInternalErrorException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }



    /// <summary>
    /// There is an error with the Vault Standby Nodes
    /// </summary>
    [Serializable]
    public class VaultStandbyNodesErrorException : VaultException {
        private const string defaultMsg = "Standby Vault nodes are in a warning state.";


        /// <summary>
        /// Constructor for a Vault StandBy Nodes Exception
        /// </summary>
        public VaultStandbyNodesErrorException () : base (defaultMsg) { }


        /// <summary>
        /// Constructor for a Vault StandBy Nodes Exception
        /// <param name="message">Message to be stored with the Exception</param>
        /// </summary>
        public VaultStandbyNodesErrorException (string message) : base (defaultMsg + message) { }


        /// <summary>
        /// Constructor for a Vault StandBy Nodes Exception
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        /// </summary>
        public VaultStandbyNodesErrorException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }


        /// <summary>
        /// Serializer
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultStandbyNodesErrorException (System.Runtime.Serialization.SerializationInfo info,
                                                   System.Runtime.Serialization.StreamingContext context) { }
    }


    /// <summary>
    /// The Vault is Sealed
    /// </summary>
    [Serializable]
    public class VaultSealedException : VaultException {
        private const string defaultMsg =
            "The vault is sealed.  It must be unsealed in order to be accessible to programs.  Only Vault Admins can do this.  Vault Server may also be down.";


        /// <summary>
        /// Constructor for a Vault Sealed Exception
        /// </summary>
        public VaultSealedException () : base (defaultMsg) { }


        /// <summary>
        /// Constructor for a Vault StandBy Nodes Exception
        /// <param name="message">Message to be stored with the Exception</param>
        /// </summary>
        public VaultSealedException (string message) : base (defaultMsg + message) { }


        /// <summary>
        /// Constructor for a Vault Sealed Exception
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        /// </summary>
        public VaultSealedException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }


        /// <summary>
        /// Serializer
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultSealedException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }


        /// <summary>
        /// Constructor for a Vault Sealed Exception
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        /// </summary>
        public VaultSealedException (Exception innerException) : base ("") { }
    }


    /// <summary>
    /// An Unexpected Vault Code Path was executed
    /// </summary>
    [Serializable]
    public class VaultUnexpectedCodePathException : VaultException {
        private const string defaultMsg = "A piece of the code that was not expected to be run, was reached.";

        /// <summary>
        /// Constructor for a Vault Unexpected Code Path Error
        /// </summary>
        public VaultUnexpectedCodePathException () : base (defaultMsg) { }


        /// <summary>
        /// Constructor for a Vault Unexpected Code Path Error
        /// <param name="message">Message to be stored with the Exception</param>
        /// </summary>
        public VaultUnexpectedCodePathException (string message) : base (defaultMsg + message) { }


        /// <summary>
        /// Constructor for a Vault Unexpected Code Path Error
        /// <param name="message">Message to be stored with the Exception</param>
        /// <param name="innerException">The original Exception if this was triggered by another error</param>
        /// </summary>
        public VaultUnexpectedCodePathException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }


        /// <summary>
        /// Serializer
        /// </summary>
        /// <param name="info"></param>
        /// <param name="context"></param>
        protected VaultUnexpectedCodePathException (System.Runtime.Serialization.SerializationInfo info,
                                                    System.Runtime.Serialization.StreamingContext context) { }
        }
}