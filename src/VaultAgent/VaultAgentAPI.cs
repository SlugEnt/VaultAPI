using System;
using System.Collections.Generic;
using System.Text;
using VaultAgent.Backends.System;
using VaultAgent.SecretEngines;
using VaultAgent.Models;
using System.Threading.Tasks;
using VaultAgent.Backends;
using VaultAgent.AuthenticationEngines;


namespace VaultAgent {
    /// <summary>
    /// The VaultAgentAPI is the main connector between an application and a Vault Instance.  It provides a number of different types of backends that can be accessed thru it.
    /// There are 2 general categories of backends -
    ///   - Authentication backends - which utilize an external 3rd party system to validate credentials.  Once validated a token is provided for all further access.
    ///   - Secret backends - These are used to store secrets.
    /// An important concept is that the Token stored by this object is used by all of its backends.  This means anytime the token is changed all subsequent calls to the Vault
    /// will utilize that new token value.  Typically it is expected you will only need to supply or get a token (via an authentication methods login method) once.   But be aware
    /// that privilege escalation could happen if you change the token from its initial value.  It is generally best that if you need to work with multiple token values in Vault
    /// that you create multiple VaultAgentAPI objects for each one.
    ///
    /// It establishes a connection to the requested Vault Instance using the supplied
    /// Token value.  It automatically establishes a connection to the Vault Instance upon initial construction of the object.  It can also optionally connect to the system
    /// backend during construction if requested to do so AND the supplied token has permission.
    /// The typical usage scenario is that a calling program uses this object to establish a connection to the Vault Instance and then requests attachment to one or more
    /// authorization or secret backends which it then uses to communicate to the Vault Store with.
    /// </summary>
    public class VaultAgentAPI {
        //  A Container that stores all of the Secret Backends that this object has been requested to use.
        private Dictionary<string, VaultSecretBackend> _secretBackends;

        // A List that stores all of the Authorization Engines that this object has been requested to utilize.
        private Dictionary<string, VaultAuthenticationBackend> _authenticationBackends;

        // An HTTP Connector object that is used for every connection to the Vault store.  Marked internal so that backends can access it.
        internal VaultAPI_Http _httpConnector;

        // The connector to the Vault System Backend for manipulating and gathering information on the Vault Instance.  This is only populated if the 
        // class was supplied with a token that has access to the System Backend AND the caller requested that we connect to the System Backend.  Otherwise it remains null.
        private VaultSystemBackend _vault;

        // Connection to the Token Engine.
        private TokenAuthEngine _tokenEngine;

        // The Token used to access Vault with.  We also keep the TokenID separate.  In case something happens and we cannot retrieve the provided token from the Vault Instance
        // we still have the original passed in ID we can try again with.  Ultimately this may not be necessary.
        internal Token _vaultAccessToken;
        internal string _vaultAccessTokenID;


        /// <summary>
        /// Constructor
        /// </summary>
        public VaultAgentAPI () { }


        /// <summary>
        /// Constructor to create a new VaultAgentAPI object which is used to connect to a single Vault Instance.  Automatically connects to the Token Backend and will optionally connect
        /// to system backend if requested.
        /// <para>Will Throw ApplicationException if unable to establish a connection to the backend vault server.</para>
        /// </summary>
        /// <param name="name">The name this Vault Instance should be known by.  This is purely cosmetic and serves no functional purpose other than being able to uniquely identify this Vault Instance from another.</param>
        /// <param name="port">The network port the Vault instance is listening on.</param>
        /// <param name="vaultIP">The IP address of the Vault instance you want to connect to.</param>
        public VaultAgentAPI (string name, Uri vaultUri) {
            Initialize(name,vaultUri);
        }



        /// <summary>
        /// Sets up the vault
        /// </summary>
        /// <param name="name"></param>
        /// <param name="vaultUri"></param>
        public void Initialize (string name, Uri vaultUri) {
            Name = name;
            Uri = vaultUri;

            _vaultAccessTokenID = string.Empty;

            // Create the Secret Backend list.
            _secretBackends = new Dictionary<string, VaultSecretBackend>();

            // Create the Authentication backends Dictionary
            _authenticationBackends = new Dictionary<string, VaultAuthenticationBackend>();

            try
            {
                // Create HTTP Connector object
                _httpConnector = new VaultAPI_Http(vaultUri);


                // Establish a connection to the token backend.
                _tokenEngine = (TokenAuthEngine)ConnectAuthenticationBackend(EnumBackendTypes.A_Token);
            }
            catch (Exception e)
            {
                if (e.InnerException != null)
                    if (e.InnerException.Message.StartsWith("No connection"))
                    {
                        throw new ApplicationException("Unable to establish connection to remote Vault Server.");
                    }
                throw e;
            }
        }



        /// <summary>
        /// The name this Vault Instance is known by.  This is purely cosmetic and serves no functional purpose other than being able to uniquely identify this Vault Instance from another.
        /// </summary>
        public string Name { get;  set; }


        /*
        /// <summary>
        /// The IP Address of the vault instance.  
        /// </summary>
//        public string IP { get; private set; }



        /// <summary>
        /// The IP port the Vault instance is listening on.
        /// </summary>
//        public int Port { get; private set; }
*/

        /// <summary>
        /// The Vault Uri connection string to the Vault server
        /// </summary>
        public Uri Uri { get;  set; }


        /// <summary>
        /// The Security Token used to perform actions in the Vault Instance.
        /// Note:  This token's information (TTL, ExpireTime and NumberOfUses) will get stale over time.
        /// You should call RefreshActiveToken if you need to see its Current TTL, ExpireTime or NumberOfUses left values.
        /// </summary>
        public Token Token {
            get => _vaultAccessToken;
            set {
                _vaultAccessToken = value;
                _vaultAccessTokenID = value.ID;
                _httpConnector.SetTokenHeader (_vaultAccessTokenID);
            }
        }


        /// <summary>
        ///  Used to get/set the TokenID that this object will use to communicate with Vault with.  If you change the token value it becomes effective 
        /// immediately.When set it will retrieve the latest version of the Token object from Vault and updates the Token object of this class.
        /// </summary>
        public string TokenID {
            get => _vaultAccessTokenID;
            internal set {
                _vaultAccessTokenID = value;
                _httpConnector.SetTokenHeader(_vaultAccessTokenID);

                //  Now retrieve token details from Vault.
                Task<Token> task = Task.Run<Token>(async () => await this.RefreshActiveToken());
                _vaultAccessToken = task.Result;
            }
        } 



        /// <summary>
        /// Establishes a connection to the desired Vault Secret backend at the specified vault MountPath.  The backend mount must already exist.
        /// </summary>
        /// <param name="secretBackendType">The type of backend you wish to connect to.</param>
        /// <param name="backendName">The name you wish to refer to this backend by.  This is NOT the Vault mount path.</param>
        /// <param name="backendMountPath">The path to the vault mount point that this backend is located at.</param>
        /// <returns>True if it was able to successfully connect to the backend.  False if it encountered an error.</returns>
        public VaultBackend ConnectToSecretBackend(EnumSecretBackendTypes secretBackendType, string backendName = "", string backendMountPath = "")
        {
            switch (secretBackendType)
            {
                case EnumSecretBackendTypes.KeyValueV2:
                    KV2SecretEngine kv2Backend = new KV2SecretEngine(backendName, backendMountPath, this);
                    return kv2Backend;
                case EnumSecretBackendTypes.Secret:
                    KeyValueSecretEngine secretBackend = new KeyValueSecretEngine(backendName, backendMountPath, this);
                    return secretBackend;
                case EnumSecretBackendTypes.Transit:
                    TransitSecretEngine transitSecretEngine = new TransitSecretEngine(backendName, backendMountPath, this);
                    return transitSecretEngine;
                case EnumSecretBackendTypes.Identity:

                    // There is only 1 backend of this type, so no need for backend mount path or name.
                    IdentitySecretEngine identitySecretEngine = new IdentitySecretEngine(this);
                    return identitySecretEngine;
            }

            return null;
        }





        /// <summary>
        /// Connects to the specified Authentication backend.
        /// </summary>
        /// <param name="backendType">The type of backend to connect</param>
        /// <param name="backendName">Name of the backend</param>
        /// <param name="backendMountPath">Mount path to the backend.</param>
        /// <returns></returns>
        public VaultAuthenticationBackend ConnectAuthenticationBackend (EnumBackendTypes backendType, string backendName, string backendMountPath) {
            switch ( backendType ) {
                case EnumBackendTypes.A_AppRole:
                    AppRoleAuthEngine AppRoleAuthEngine = new AppRoleAuthEngine (backendName, backendMountPath, this);
                    return AppRoleAuthEngine;
                case EnumBackendTypes.A_Token:
                    TokenAuthEngine tokenAuthEngine = new TokenAuthEngine (this);
                    return tokenAuthEngine;
                case EnumBackendTypes.A_LDAP:
                    LdapAuthEngine ldapAuthEngine = new LdapAuthEngine(backendName,backendMountPath,this);
                    return ldapAuthEngine;
                default: throw new ArgumentOutOfRangeException ("Must supply a backendType that is derived from the VaultAuthenticationBackend class");
            }
        }



        /// <summary>
        /// Connects the specified Authentication backend at its default Vault Path
        /// </summary>
        /// <param name="backendType"></param>
        /// <returns></returns>
        public VaultAuthenticationBackend ConnectAuthenticationBackend (EnumBackendTypes backendType) {
            switch ( backendType ) {
                case EnumBackendTypes.A_AppRole:
                    AppRoleAuthEngine AppRoleAuthEngine = new AppRoleAuthEngine (this);
                    return AppRoleAuthEngine;
                case EnumBackendTypes.A_Token:
                    TokenAuthEngine tokenAuthEngine = new TokenAuthEngine (this);
                    return tokenAuthEngine;
                default: throw new ArgumentOutOfRangeException ("Must supply a backendType that is derived from the VaultAuthenticationBackend class AND that supports a default backend mount.");
            }
        }



        #region "Pathing Functions"

        /// <summary>
        /// Combines multiple string arguments into a single Vault Path
        /// </summary>
        /// <param name="paths">One or more string arguments that should be used to built the path</param>
        /// <returns></returns>
        public static string PathCombine(params string[] paths)
        {
            if (paths == null)
                throw new ArgumentNullException("paths");

            // Compute how big a string builder cache to create.  For each found path we add path length + 1 for the new separator character
            int finalSize = 0;
            for (int i = 0; i < paths.Length; i++)
            {
                if (paths[i] == null) continue;
                if (paths[i].Length == 0) continue;
                finalSize += paths[i].Length + 1;
            }


            StringBuilder newPath = new StringBuilder(finalSize + 2);
            for (int i = 0; i < paths.Length; i++)
            {
                // If Empty path, skip it
                if ( paths [i] == null ) continue;
                if (paths[i].Length == 0) continue;

                // If there are already paths in the new path, then append the separator
                if (newPath.Length > 0) newPath.Append("/");

                newPath.Append(paths[i]);
            }

            return newPath.ToString();
        }


        #endregion

        #region "CurrentToken Methods"


        /// <summary>
        /// Retrieves the latest information for the Token currently being used to access Vault with from the Vault Token Database.  While the entire token is refreshed, this practically means
        /// that the following properties are updated:  NumberOfUses, TTL, ExpireTime.  Returns a Token object on success and Null on failure.
        /// </summary>
        /// <returns>Token if successfull.  Null if unsuccessful</returns>
        public async Task<Token> RefreshActiveToken () {
            Token token = await _tokenEngine.GetCurrentTokenInfo();
            if ( token != null ) {
                _vaultAccessToken = token;
                _vaultAccessTokenID = token.ID;
                return token;
            }

            return null;
        }



        /// <summary>
        /// Revokes the token currently being used to access Vault.  No further access with this token will be permitted.
        /// </summary>
        /// <returns></returns>
        public async Task<bool> RevokeActiveToken () {
            bool rc = await _tokenEngine.RevokeTokenSelf();
            if ( rc ) {
                _vaultAccessTokenID = "";
                _vaultAccessToken = null;
                _httpConnector.SetTokenHeader ("");
                return true;
            }

            return false;
        }



        /// <summary>
        /// Renews the current token.  Returns a refreshed copy of the token or Null if the renewal failed.
        /// </summary>
        /// <returns></returns>
        public async Task<Token> RenewActiveToken () {
            bool rc = await _tokenEngine.RenewTokenSelf();
            if ( rc ) { return await RefreshActiveToken(); }
            else { return null; }
        }


        #endregion
    }
}