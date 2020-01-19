using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;

namespace VaultAgent.SecretEngines.KeyValue2
{
    /// <summary>
    /// Interface for a KV2Secret Object functionality that derived objects must implement
    /// </summary>
    public interface IKV2Secret
    {
        /// <summary>
        /// Name of the Secret
        /// </summary>
        string Name { get; set; }


        /// <summary>
        /// Path where the Secret should be placed
        /// </summary>
        string Path { get; set; }
        
        
        /// <summary>
        /// Returns the Full path and name of the secret, so path/path/path/secretName
        /// </summary>
        string FullPath { get; }


        /// <summary>
        /// If true then this secret was read from Vault, versus being created in C#
        /// </summary>
        bool WasReadFromVault { get; }

        /// <summary>
        /// The Attributes of the secret.  These are the names and values that are being stored in this secret.
        /// </summary>
        Dictionary<string, string> Attributes { get; set; }


        /// <summary>
        /// Additional data that should be stored in this secret
        /// </summary>
        Dictionary<string, string> Metadata { get; set; }


        /// <summary>
        /// When the secret was created
        /// </summary>
        DateTimeOffset CreatedTime { get; }


        /// <summary>
        /// When the secret was deleted.
        /// </summary>
        string DeletionTime { get; }


        /// <summary>
        /// If true then the secret has been permanently deleted from Vault
        /// </summary>
        bool IsDestroyed { get;   }


        /// <summary>
        /// Version number of this iteration of the secret, if using versioning.
        /// </summary>
        int Version { get;  }
    }
}
