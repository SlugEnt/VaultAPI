using System;
using Newtonsoft.Json;
using System.Collections.Generic;
using VaultAgent.SecretEngines.KeyValue2;


namespace VaultAgent.SecretEngines.KV2 {
    /// <summary>
    /// Represents a secret read from the Vault.  Secrets can have zero to many attributes which are just Key Value Pairs of a name and some data value.
    /// However, a secret without at least one attribute is not a secret, for the attributes are where the value for the secret is retrieved from.  
    /// Important is that when saving a secret, you must save it with all it's attributes or else any that are missing on the save will be removed from 
    /// the vault.  So, if upon reading a secret it has attributes of canDelete:True and connection:db1 and you save it, but the only attribute in the 
    /// list upon save is connection:db1 then canDelete will no longer exist after the save.  
    /// 
    /// Therefore it is best to read the secret, make changes to any existing attributes and then add any new ones, then save it.
    /// </summary>
    public class KV2Secret : KV2SecretBase<KV2Secret>
    {
        /// <summary>
        /// Creates a new KV2Secret object
        /// </summary>
        public KV2Secret() : base() { }


        /// <summary>
        /// Creates a new KV2Secret object with the provided name and path/
        /// </summary>
        /// <param name="secretName"></param>
        /// <param name="path"></param>
        public KV2Secret (string secretName, string path = "") : base (secretName, path) { }
    }
}