using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;


namespace VaultAgent.SecretEngines.KV2 {
    /// <summary>
    /// Represents a Vault Key Value Backend Version 2 settings object.
    /// </summary>
    public class KV2SecretEngineSettings {
        /// <summary>
        /// True if Check and Set operations are mandated to use version number
        /// </summary>
        [JsonProperty ("cas_required")] public bool CASRequired;

        /// <summary>
        /// Maximum number of versions that can be stored for a particular secret.  Defaults to 10.
        /// </summary>
        [JsonProperty ("max_versions")] public int MaxVersions;
    }
}