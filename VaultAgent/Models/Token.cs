﻿using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;
using SlugEnt;


namespace VaultAgent.Models {
    /// <summary>
    /// Represents a Vault token.  
    /// 
    /// Note:  An Accessor Token does not have an ID value.
    /// </summary>
    public class Token {
        // The Time To Live value for this token in seconds.
        private long _ttl;

        /// <summary>
        /// The ID or unique identifier of the token.  This is usually set to a random value by the Vault backend upon token creation.
        /// </summary>
        [JsonProperty ("id")]
        public string ID { get; set; }


        /// <summary>
        /// A name or description for the token for informational purposes only.
        /// </summary>
        [JsonProperty ("display_name")]
        public string DisplayName { get; set; }


        /// <summary>
        /// Readonly field.  The path where the token was created at.
        /// </summary>
        [JsonProperty ("path")]
        public string APIPath { get; private set; }



        //TODO figure out what type of value this is, long, DateTimeOffset and change property type accordingly
        /// <summary>
        /// When (Date and Time) the Token is set to expire
        /// Example from Vault docs:  expire_time         2018-01-11T20:21:17.900969673Z
        /// </summary>
        [JsonProperty ("expire_time")]
        public string ExpireTimeStr { get; private set; }



        /// <summary>
        /// Returns the ExpireTime as a valid C# DateTime object.
        /// </summary>
        /// <returns></returns>
        public DateTime ExpireTimeAsDateTime () {
            DateTime d = DateTime.Now;
            bool success = DateTime.TryParse (ExpireTimeStr, out d);
            if ( success ) { return d; }
            else { throw new InvalidDataException ("ExpireTime could not be decoded into a valid DateTime:  ExpireTimeStr = " + ExpireTimeStr); }
        }



        /// <summary>
        /// An Explicit maximum lifetime for the token.  This value is a hard limit and cannot be exceeded.  
        /// </summary>
        [JsonProperty ("explicit_max_ttl")]
        public long MaxTTL { get; set; }



        /// <summary>
        /// Metadata is used to attach arbitrary string-type metadata to the token.  This data is displayed in the audit log.
        /// </summary>
        [JsonProperty ("meta")]
        public Dictionary<string, string> Metadata { get; set; }


        /// <summary>
        /// A maximum number of times that this token can be used.  After the last use the token is automatically revoked by the Vault Instance.  Zero is unlimited.
        /// </summary>
        [JsonProperty ("num_uses")]
        public long NumberOfUses { get; set; }


        /// <summary>
        /// Whether the token has a parent token or is without parent.
        /// </summary>
        [JsonProperty ("orphan")]
        public bool IsOrphan { get; set; }



        /// <summary>
        /// Indicates that the token should never expire. It should be renewed before the end of the period and it will be renewed for the value specified.
        /// </summary>
        [JsonProperty ("period")]
        public string Period { get; set; }


        /// <summary>
        /// A list of policies that this token is associated with.  This is the combined total of policies from the backend that supplied the token and the
        /// identity associated with this token.  IE.  TokenPolicies + IdentityPolicies
        /// </summary>
        [JsonProperty ("policies")]
        public List<string> Policies { get; set; }


        /// <summary>
        /// Indicates if this token is renewable.
        /// </summary>
        [JsonProperty ("renewable")]
        public bool IsRenewable { get; set; }


        /// <summary>
        /// The TTL or number of seconds until the Token expires
        /// </summary>
        [JsonProperty ("ttl")]
        public long TTL {
            get { return _ttl; }
            set { _ttl = value; }
        }



        /// <summary>
        /// Alternative method of getting/setting the TTL of the token in a more readable TimeUnit Class.
        /// </summary>
        public TimeUnit TTLasTimeUnit {
            get { return new TimeUnit (_ttl); }
            set { _ttl = value.InSecondsLong; }
        }


        // The following properties can only be set during Token Reading from Vault.	


        /// <summary>
        /// The accessor token ID that can be used to access this root token without knowing the root token ID.
        /// </summary>
        [JsonProperty ("accessor")]
        public string AccessorTokenID { get; private set; }


        /// <summary>
        /// The policies that this token has received from the actual authentication backend object (appRole, userRole, etc)
        /// </summary>
        [JsonProperty ("token_policies")]
        public List<string> TokenPolicies { get; internal set; }


        /// <summary>
        /// The policies that this token has received from the entity that it is related too.
        /// </summary>
        [JsonProperty ("identity_policies")]
        public List<string> IdentityPolicies { get; internal set; }


        #region "CreateTime and TTL"


        /// <summary>
        /// The time in seconds since 1/1/1970 that the token was created.  Read Only.
        /// </summary>
        [JsonProperty ("creation_time")]
        public long CreationTime { get; private set; }



        /// <summary>
        /// Returns the CreationTime of the token as a DateTime Object
        /// </summary>
        public DateTime CreationTime_AsDateTime {
            get { return VaultUtilityFX.ConvertUnixTimeStamp (CreationTime); }
        }


        /// <summary>
        /// The TTL time period the token originally had upon creation.  This value does not change.  Not sure this has an real use?
        /// </summary>
        [JsonProperty ("creation_ttl")]
        public long CreationTTL { get; private set; }


        #endregion



        /// <summary>
        /// The Entity The token is associated with if any.
        /// </summary>
        [JsonProperty ("entity_id")]
        public string EntityId { get; private set; }


        /// <summary>
        /// The Date and Time the token was originally issued.
        /// </summary>
        [JsonProperty ("issue_time")]
        public DateTimeOffset IssueTime { get; private set; }


        /// <summary>
        /// True if this token information was retrieved from the Vault Instance.  Used internally for a few items.
        /// </summary>
        public bool ReadFromVault { get; private set; }


        /// <summary>
        /// This value should never be set by a caller.  Only read.
        /// </summary>
        public EnumTokenType TokenType { get;  internal set; }


        /// <summary>
        /// Default JSON Constructor
        /// </summary>
        [JsonConstructor]
        public Token (string id, string accessor, long creation_time, long creation_ttl, string entity_id, DateTimeOffset issue_time) {
            ID = id;
            AccessorTokenID = accessor;
            CreationTime = creation_time;
            CreationTTL = creation_ttl;
            EntityId = entity_id;
            IssueTime = issue_time;
            ReadFromVault = true;
        }



        /// <summary>
        /// Default empty constructor.  Initializes the Metadata dictionary.
        /// </summary>
        public Token () {
            ReadFromVault = false;
            Metadata = new Dictionary<string, string>();
        }


        /// <summary>
        /// Constructor that accepts the token ID value
        /// </summary>
        /// <param name="tokenID"></param>
        public Token (string tokenID) {
            ID = tokenID;
            ReadFromVault = false;
        }


        /// <summary>
        /// Returns True if this token has a parent token.
        /// </summary>
        public bool HasParent {
            get { return !IsOrphan; }
            set { IsOrphan = !value; }
        }
    }
}