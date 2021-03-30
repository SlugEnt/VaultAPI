using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent.Backends.System
{
    /// <summary>
    /// A Vault Policy Path Item object that represents Vault Permissions for a given path in a KV2 secret database.  See VaultPolicyPathItem class info for all
    /// implementation details.
    /// </summary>
    public class VaultPolicyPathItemKV2 : VaultPolicyPathItem
    {
        /// <summary>
        /// Constructor for creating a KeyValue2 (KV2) type of policy object.  The protectedPath parameter MUST NOT contain the KV2 path prefix (data, metadata, etc).
        /// If it does you will end up with a true protected path of /backend/data/data/pathA/pathB/secret
        /// <param name="backendMount">The name/path to the backend that this policy applies to.  Note, all leading/trailing slashes are removed.</param>
        /// <param name="protectedPath">The path that this policy is applicable to.  If the path ends with a trailing slash or a trailing /* then it is considered
        /// a SubFolderPolicyType (Meaning its permissions apply to subsecrets only).</param>
        /// </summary>
        public VaultPolicyPathItemKV2(string backendMount, string protectedPath) : base(true, backendMount, protectedPath) { }


    }
}
