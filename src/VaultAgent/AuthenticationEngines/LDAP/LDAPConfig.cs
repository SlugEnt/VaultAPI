using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Globalization;
using Newtonsoft.Json;


namespace VaultAgent.AuthenticationEngines.LDAP {
	/// <summary>
	/// LdapConfig is a class used to set or retrieve the Configuration of a Vault LDAP Backend.  The configuration contains
	/// all properties required to establish a connection to an LDAP Server to use for Authentication.
	/// <para>When an LDAP Config is stored in a json file, it is imperative that the DN_Suffix be the the first value if you are going to use it.</para>
	/// </summary>
	public partial class LdapConfig
    {
        private string _bindDN = "";
        private string _groupDN = "";
        private string _userDN = "";
		private string _dnSuffix = "";
        private bool _isActiveDirectory = false;

        #region Constructors


        /// <summary>
        /// Constructor that build config with Vault default values, provides for ability to specify the common dn_suffix so it does not need to be specified everywhere and can automatically set some AD properties
        /// <param name="dn_Suffix">This value will be appended to the end of the userdn, groupdn and binddn properties. Example:  dn_suffix=dc=testcompany,dc=org</param>
        /// <param name="isActiveDirectoryConnector">Set to true if this LDAP config is for connecting to Active Directory.  If so, it automatically sets certain fields to their expected AD values</param>
        /// </summary>
        public LdapConfig(string dn_Suffix = "", bool isActiveDirectoryConnector = false)
        {
            _dnSuffix = dn_Suffix;

            if (isActiveDirectoryConnector)
            {
                SetActiveDirectoryDefaults();
            }
        }


        /// <summary>
        /// Default constructor that creates an empty LDAP config object
        /// </summary>
        public LdapConfig() { }

        #endregion

        /// <summary>
        /// The LDAP server to connect to. Examples: ldap://ldap.myorg.com, ldaps://ldap.myorg.com:636. Multiple URLs can be
        /// specified with commas, e.g. ldap://ldap.myorg.com,ldap://ldap2.myorg.com; these will be tried in-order
        /// </summary>
        [JsonProperty("url")]
        public string LDAPServers { get; set; } = "";



		/// <summary>
		/// Distinguished name of object to bind when performing user search. Example: cn=vault,ou=Users,dc=example,dc=com
		/// </summary>
		[JsonProperty("binddn")]
		public string BindDN {
			get => _bindDN;
			set { _bindDN = FullDNValue(value); }
		}



        /// <summary>
        /// The password to perform the bind against.
        /// </summary>
        [JsonProperty("bindpass")]
        public string BindPassword { get; set; } = "";


        /// <summary>
        /// If set, user and group names assigned to policies within the backend will be case sensitive. Otherwise, names will
        /// be normalized to lower case. Case will still be preserved when sending the username to the LDAP server at login time;
        /// this is only for matching local user/group definitions
        /// <para>Default is False</para>
        /// </summary>
        [JsonProperty("case_sensitive_names")]
        public bool CaseSensitiveNames { get; set; } = false;


		/// <summary>
		/// CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded
		/// </summary>
		[JsonProperty("certificate")]
		public string Certificate { get; set; } = "";


        /// <summary>
        /// This option prevents users from bypassing authentication when providing an empty password.
        /// </summary>
        [JsonProperty("deny_null_bind")]
        public bool DenyNullBind { get; set; } = true;


        /// <summary>
        ///  Use anonymous bind to discover the bind DN of a user.
        /// </summary>
        [JsonProperty("discoverdn")]
        public bool DiscoverDN { get; set; } = false;


        /// <summary>
        ///  LDAP attribute to follow on objects returned by groupfilter in order to enumerate user group membership. Examples:
        /// for groupfilter queries returning group objects, use: cn. For queries returning user objects, use: memberOf.
        /// </summary>
        [JsonProperty("groupattr")]
        public string GroupAttr { get; set; } = "";


		/// <summary>
		/// LDAP search base to use for group membership search. This can be the root containing either groups or users.
		/// <para>Example: ou=Groups,dc=example,dc=com</para>
		/// </summary>
		[JsonProperty("groupdn")]
		public string GroupDN {
			get => _groupDN;
			set { _groupDN = FullDNValue(value); }
		}


        /// <summary>
        /// Go template used when constructing the group membership query. The template can access the following context
        /// variables: [UserDN, Username]. The default is (|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}})),
        /// which is compatible with several common directory schemas. To support nested group resolution for Active Directory,
        /// instead use the following query: ( [AMPERSANd] (objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))
        /// <para>See the SetADGroupFilter to automatically set it to the correct value for AD.</para>
        /// </summary>
        [JsonProperty("groupfilter")]
        public string GroupFilter { get; set; } = "";



        /// <summary>
        ///  If true, skips LDAP server SSL certificate verification - insecure, use with caution!
        /// </summary>
        [JsonProperty("insecure_tls")]
        public bool InsecureTLS { get; set; } = true;


        /// <summary>
        /// True if this is an Active Directory LDAP Connection
        /// </summary>
        [JsonProperty("is_activedirectory")]
        public bool IsActiveDirectoryConnection
        {
            get { return _isActiveDirectory; }
            set
            {
                _isActiveDirectory = value;
                // If True then set the AD defaults.
                if (value)
                {
                    SetActiveDirectoryDefaults();
                }
            }
        }


        /// <summary>
		/// If true, issues a StartTLS command after establishing an unencrypted connection.
		/// </summary>
		[JsonProperty("starttls")]
		public bool StartTLS { get; set; } = false;


		/// <summary>
		/// Maximum TLS version to use. Accepted values are tls10, tls11 or tls12
		/// </summary>
		[JsonProperty("tls_max_version")]
		public string TLSMaxVersion { get; set; } = "tls12";


        /// <summary>
        /// Minimum TLS version to use. Accepted values are tls10, tls11 or tls12
        /// </summary>
        [JsonProperty("tls_min_version")]
		public string TLSMinVersion { get; set; } = "tls12";


		/// <summary>
		/// The userPrincipalDomain used to construct the UPN string for the authenticating user. The constructed UPN will
		/// appear as [username]@UPNDomain. Example: example.com, which will cause vault to bind as username@example.com.
		/// </summary>
		[JsonProperty("upndomain")]
		public string Upndomain { get; set; } = "";


        //TODO - Find out what this does.
        /// <summary>
        /// Unknown what this does or is used for.
        /// </summary>
        [JsonProperty("use_token_groups")]
        public bool UseTokenGroups { get; set; } = false;


        /// <summary>
        /// The Attribute to Use for UserID.  AD set to samaccountname
        /// </summary>
        [JsonProperty("userattr")]
        public string UserAttr { get; set; } = "";


		/// <summary>
		/// Base DN under which to perform user search. Example: ou=Users,dc=example,dc=com.
		/// <para>IF DN_Suffix has been set, then the Suffix is automatically appended to the end of the value passed in.</para>
		/// </summary>
		[JsonProperty("userdn")]
		public string UserDN {
			get => _userDN;
			set { _userDN = FullDNValue(value); }
		}



		/// <summary>
		/// This is used so that you can default the DistinguishedNames to all use the same suffix and not have to specify it each time.
		/// The following properties will use this if it is set.  Must be set BEFORE assigning any of the following properties
		/// <para>userdn</para>
		/// <para>groupdn</para>
		/// <para>binddn</para>
		/// </summary>
		public string DN_Suffix {
			get => _dnSuffix;
            set
            {
                _dnSuffix = value; 
            }
		}




		/// <summary>
		/// Sets Certain fields to their expected Active Directory Defaults.
		/// </summary>
		public void SetActiveDirectoryDefaults () {
            GroupFilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))";
            GroupAttr = "cn";
            UserAttr = "samaccountname";
            UseTokenGroups = false;
            UsePre111Groups = false;
        }



        /// <summary>
        /// Uses Pre Vault 1.11 Group Behavior.  See Vault Documentation for details
        /// </summary>
        [JsonProperty("use_pre111_group_cn_behavior")]
        public bool UsePre111Groups { get; set; } = false;
		
        
        /// <summary>
        /// Takes the passed in dn and appends the DN_Suffix to it, returning the full value.
        /// </summary>
        /// <param name="dn"></param>
        /// <returns></returns>
        internal string FullDNValue (string dn) {
			if ( _dnSuffix == "" ) { return dn; }

			return dn + "," + _dnSuffix;
		}
	}
}