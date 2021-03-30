using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.Transit.Models {
    /// <summary>
    /// Constants used by the Transit Backend
    /// </summary>
    public static class TransitConstants {
        /// <summary>
        /// Minimum Decryption version
        /// </summary>
        public static readonly string KeyConfig_MinDecryptVers = "min_decryption_version";

        /// <summary>
        /// Min Encytpyion Version
        /// </summary>
        public static readonly string KeyConfig_MinEncryptVers = "min_encryption_version";

        /// <summary>
        /// Deletion Allowed
        /// </summary>
        public static readonly string KeyConfig_DeleteAllowed = "deletion_allowed";

        /// <summary>
        /// Is Exportable
        /// </summary>
        public static readonly string KeyConfig_Exportable = "exportable";

        /// <summary>
        /// Plaintext Backup is allowed
        /// </summary>
        public static readonly string KeyConfig_Allow_Backup = "allow_plaintext_backup";
    }
}