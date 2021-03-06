﻿using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Collections.Generic;

namespace VaultAgent.Models {

    /// <summary>
    /// A Token and its related properties that represent a Role
    /// </summary>
    public class TokenRole {

        /// <summary>
        /// Constructs a new TokenRole Object
        /// </summary>
        [JsonConstructor()]
        public TokenRole () {
            // This is required for now as Vault has not implemented the BoundCIDRS functionality yet, so it comes back null.  This 
            // prevents errors until it does.
            BoundCidrs = new List<string>();
        }


        /// <summary>
        /// Constructor for non-JSON
        /// </summary>
        /// <param name="roleName"></param>
        public TokenRole (string roleName) {
            Name = roleName;

            AllowedPolicies = new List<string>();
            BoundCidrs = new List<string>();
            DisallowedPolicies = new List<string>();
        }


        /// <summary>
        /// If set, tokens can be created with any subset of the policies in this list, rather than the normal semantics of tokens being a subset of the 
        /// calling token's policies. The parameter is a comma-delimited string of policy names. If at creation time no_default_policy is not set and "default" 
        /// is not contained in disallowed_policies, the "default" policy will be added to the created token automatically.
        /// </summary>
        [JsonProperty ("allowed_policies")]
        public List<string> AllowedPolicies { get; set; }


        /// <summary>
        /// If set, restricts usage of the generated token to client IPs falling within the range of the specified CIDR(s). Unlike most other 
        /// role parameters, this is not reevaluated from the current role value at each usage; it is set on the token itself. Root tokens with no TTL will 
        /// not be bound by these CIDRs; root tokens with TTLs will be bound by these CIDRs
        /// </summary>
        [JsonProperty ("bound_cidrs")]
        public List<string> BoundCidrs { get; set; }


        /// <summary>
        /// If set, successful token creation via this role will require that no policies in the given list are requested. The parameter is a 
        /// comma-delimited string of policy names. Adding "default" to this list will prevent "default" from being added automatically to created tokens.
        /// </summary>
        [JsonProperty ("disallowed_policies")]
        public List<string> DisallowedPolicies { get; set; }


        /// <summary>
        /// Provides a maximum lifetime for any tokens issued against this role, including periodic tokens. 
        /// Unlike direct token creation, where the value for an explicit max TTL is stored in the token, for roles this check will always use the 
        /// current value set in the role. The main use of this is to provide a hard upper bound on periodic tokens, which otherwise can live forever 
        /// as long as they are renewed. This is an integer number of seconds
        /// </summary>
        [JsonProperty ("explicit_max_ttl")]
        public long ExplicitMaxTtl { get; set; }


        /// <summary>
        /// The name of the token role
        /// </summary>
        [JsonProperty ("name")]
        public string Name { get; set; }


        /// <summary>
        /// If True, tokens created against this role will not have parents and thus not automatically revoked by the revocation of any other token.
        /// </summary>
        [JsonProperty ("orphan")]
        public bool IsOrphan { get; set; }


        /// <summary>
        /// If set, tokens created against this role will have the given suffix as part of their path in addition to the role name. 
        /// This can be useful in certain scenarios, such as keeping the same role name in the future but revoking all tokens created against it before some point in time. 
        /// The suffix can be changed, allowing new callers to have the new suffix as part of their path, and then tokens with the old suffix can be revoked 
        /// via /sys/leases/revoke-prefix.
        /// </summary>
        [JsonProperty ("path_suffix")]
        public string PathSuffix { get; set; }


        /// <summary>
        /// If specified, the token will be periodic; it will have no maximum TTL (unless an "explicit-max-ttl" is also set) but every renewal will use 
        /// the given period. Requires a root/sudo token to use
        /// </summary>
        [JsonProperty ("period")]
        public string Period { get; set; }


        /// <summary>
        /// Set to false to disable the ability of the token to be renewed past its initial TTL. 
        /// Setting the value to true will allow the token to be renewable up to the system/mount maximum TTL
        /// </summary>
        [JsonProperty ("renewable")]
        public bool IsRenewable { get; set; }
    }
}