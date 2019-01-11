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
        UnclassifiedError =
            0, // The default value for all VaultExceptions.  Indicates we have not classified the error any more specifically than what Vault provided.
        BackendMountAlreadyExists = 1, // Indicates that there is already a backend mounted at the specified location.
        ObjectDoesNotExist = 2, // Indicates that a given path, policy, secret does not exist in Vault.
        LoginRoleID_NotFound = 3, // Indicates that login failed because the login RoleID was invalid.
        LoginSecretID_NotFound = 4, // Indicates that the login failed because the login SecretID supplied is not valid.
        CheckAndSetMissing = 5, // The Check and Set (CAS) parameter was missing.  This is required on some KV2 keystores depending on config.

        CAS_VersionMissing =
            6, // The Check and Set (CAS) secret version was missing OR the secret already exists, but was told it should only save if it does not exist.

        CAS_SecretExistsAlready =
            7, // The Check and Set (CAS) is set && User requested that the Save only happen if the secret does not already exist.  Secret exists and so this error.
        PermissionDenied = 8 // Indicates a token does not have permission to a specific path.
    }



    [Serializable]
    internal class VaultCustomException : Exception {
        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }

        public VaultCustomException () : base() { }
        public VaultCustomException (string message) : base (message) { }
        public VaultCustomException (string message, System.Exception innerException) : base (message, innerException) { }
        protected VaultCustomException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }



    [Serializable]
    public class VaultException : Exception {
        private const string defaultMsg = "Unclassified Vault Error Occurred.";



        public VaultException () : base (defaultMsg) { }
        public VaultException (string message) : base (defaultMsg + message) { }
        public VaultException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }
        protected VaultException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }
    }



    [Serializable]
    public class VaultFieldNotFoundException : Exception {
        private const string defaultMsg = "Unable to find the requested field.";

        public VaultFieldNotFoundException () : base (defaultMsg) { }
        public VaultFieldNotFoundException (string message) : base (defaultMsg + message) { }
        public VaultFieldNotFoundException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }
        protected VaultFieldNotFoundException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }
    }



    [Serializable]
    public class VaultInvalidDataException : Exception {
        private const string defaultMsg = "Invalid or missing data was supplied.";

        public VaultInvalidDataException () : base (defaultMsg) { }
        public VaultInvalidDataException (string message) : base (defaultMsg + message) { }
        public VaultInvalidDataException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }
        protected VaultInvalidDataException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }
    }


    [Serializable]
    public class VaultForbiddenException : Exception {
        private const string defaultMsg =
            "Authentication details are either incorrect, permission to access feature is denied or a CORS request failure occurred. ";

        public VaultForbiddenException () : base (defaultMsg) { }
        public VaultForbiddenException (string message) : base (defaultMsg + message) { }
        public VaultForbiddenException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }
        protected VaultForbiddenException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }
    }



    [Serializable]
    public class VaultInvalidPathException : Exception {
        private const string defaultMsg = "Permission Denied to the the path specified.  In some cases this can also mean a path does not exist.";

        public VaultInvalidPathException () : base (defaultMsg) { }
        public VaultInvalidPathException (string message) : base (defaultMsg + message) { }
        public VaultInvalidPathException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }
        protected VaultInvalidPathException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }
    }



    [Serializable]
    public class VaultInternalErrorException : Exception {
        private const string defaultMsg = "Internal Vault Error Occured.  Try Again at later time.";

        public VaultInternalErrorException () : base (defaultMsg) { }
        public VaultInternalErrorException (string message) : base (defaultMsg + message) { }
        public VaultInternalErrorException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }
        protected VaultInternalErrorException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }
    }



    [Serializable]
    public class VaultStandbyNodesErrorException : VaultException {
        private const string defaultMsg = "Standby Vault nodes are in a warning state.";

        public VaultStandbyNodesErrorException () : base (defaultMsg) { }
        public VaultStandbyNodesErrorException (string message) : base (defaultMsg + message) { }
        public VaultStandbyNodesErrorException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }


        protected VaultStandbyNodesErrorException (System.Runtime.Serialization.SerializationInfo info,
                                                   System.Runtime.Serialization.StreamingContext context) { }
    }



    // ==============================================================================================================================================
    // Deals with Vault Sealed Errors.
    [Serializable]
    public class VaultSealedException : VaultException {
        private const string defaultMsg =
            "The vault is sealed.  It must be unsealed in order to be accessible to programs.  Only Vault Admins can do this.  Vault Server may also be down.";

        public VaultSealedException () : base (defaultMsg) { }
        public VaultSealedException (string message) : base (defaultMsg + message) { }
        public VaultSealedException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }
        protected VaultSealedException (System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }

        public VaultSealedException (Exception inner) : base ("") { }
    }



    [Serializable]
    public class VaultUnexpectedCodePathException : VaultException {
        private const string defaultMsg = "A piece of the code that was not expected to be run, was reached.";

        public VaultUnexpectedCodePathException () : base (defaultMsg) { }
        public VaultUnexpectedCodePathException (string message) : base (defaultMsg + message) { }
        public VaultUnexpectedCodePathException (string message, System.Exception innerException) : base (defaultMsg + message, innerException) { }


        protected VaultUnexpectedCodePathException (System.Runtime.Serialization.SerializationInfo info,
                                                    System.Runtime.Serialization.StreamingContext context) { }


        public EnumVaultExceptionCodes SpecificErrorCode { get; set; }
    }
}