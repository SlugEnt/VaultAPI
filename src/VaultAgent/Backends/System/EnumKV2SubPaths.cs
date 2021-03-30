using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent.SecretEngines.KV2.SecretMetaDataInfo;

namespace VaultAgent.Backends.System
{
    /// <summary>
    /// Represent the various subfolders that KeyValue V2 Backend secrets have that maintain various states of the secret.
    /// </summary>
    public enum EnumKV2SubPaths
    {
        /// <summary>
        /// The Metadata folder
        /// </summary>
        Metadata = 0,

        /// <summary>
        /// The Delete folder
        /// </summary>
        Delete = 1,

        /// <summary>
        /// The Destroy Folder
        /// </summary>
        Destroy = 2,

        /// <summary>
        /// The Undelete Folder
        /// </summary>
        Undelete = 3
    }
}
