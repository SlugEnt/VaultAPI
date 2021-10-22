using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent.SecretEngines.KeyValue2
{
    /// <summary>
    /// Properties that determine how the ListSecrets Method will function
    /// </summary>
    public class KV2ListSecretSettings
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public KV2ListSecretSettings () { }

        /// <summary>
        /// If true, the list will contain all secrets including the entire hierarchy of children secrets
        /// </summary>
        public bool ShouldRecurseFolders { get; set; } = false;

        /// <summary>
        /// Only list secrets that are parents of other secrets
        /// </summary>
        public bool ParentSecretsOnly { get; set; } = false;

        /// <summary>
        /// Only list secrets that ARE NOT parents of other secrets
        /// </summary>
        public bool FinalSecretsOnly { get; set; } = false;

        /// <summary>
        /// If true, then all secrets will be listed with their full path names.  Otherwise just the name of the secret is returned.
        /// </summary>
        public bool ListAsFullPaths { get; set; } = false;

    }
}
