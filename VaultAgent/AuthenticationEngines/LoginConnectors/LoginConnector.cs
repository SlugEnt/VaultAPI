using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using VaultAgent.Models;

namespace VaultAgent.AuthenticationEngines.LoginConnectors {
    /// <summary>
    /// LoginConnector abstract class that defines core properties and methods for an object that provides the requisite properties for a given type of Authenticated Login
    /// </summary>
    public abstract class LoginConnector {
        /// <summary>
        /// The Vault Object to connect to
        /// </summary>
        protected VaultAgentAPI _vaultAgent;

        /// <summary>
        /// JSON JObject that contains the parameters that need to be passed  during the Connection Process
        /// </summary>
        protected JObject _loginParameters;

        private string _description;
        private string _mountPath = "";


        /// <summary>
        /// Constructs a LoginConnector object.
        /// </summary>
        /// <param name="vaultAgent">The Vault that contains the authentication backend we wish to login with</param>
        /// <param name="authenticatorMountName">The name of the authentication mount point.</param>
        /// <param name="description">A description of what this LoginConnector is for.  Example  ABC company Prod LDAP</param>
        public LoginConnector (VaultAgentAPI vaultAgent, string authenticatorMountName, string description) {
            _vaultAgent = vaultAgent;
            AuthenticationMountName = authenticatorMountName;
            _description = description;
        }


        /// <summary>
        /// The name of the Authentication mount point in the vault.
        /// </summary>
        public string AuthenticationMountName { get; protected set; } 


        /// <summary>
        /// The entire Response object returned by the called Authentication Engine login process
        /// </summary>
        public LoginResponse Response { get; protected set; }


        /// <summary>
        /// Performs the Login method to the authenticated backend.  Returns True if successfull, False if it failed.
        /// You can check the Response object afterward, to retrieve all the relevant information about the login.
        /// </summary>
        /// <param name="setVaultToken">If True, then the Vault Token used to perform Vault commands against is set to the Token returned by the login method.
        /// If False, then the caller must set this value.</param>
        /// <para>TokenLoginConnector ignores this parameter and ALWAYS replaces the Vault token with the token ID passed in.</para>
        /// <returns></returns>
        public async Task<bool> Connect (bool setVaultToken = true) {
            _loginParameters = new JObject();

            _mountPath = GetAuthenticationMountPath();

            BuildLoginParameters();

            bool success = await InternalConnection();
            if ( !success ) return false;

            if (setVaultToken) _vaultAgent.TokenID = Response.ClientToken;
            return true;
        }



        /// <summary>
        /// Performs the actual Connection to the requested Authentication Engine.  Should return true if successful. false otherwise.
        /// <para>Classes that override this should ensure they set LoginResponse and return true or false to indicate success or failure.</para>
        /// </summary>
        /// <returns></returns>
        protected virtual async Task<bool> InternalConnection () {
            try
            {
                VaultDataResponseObjectB vdro = await _vaultAgent._httpConnector.PostAsync_B(_mountPath, _description, _loginParameters.ToString());
                if (vdro.Success)
                {
                    Response = await vdro.GetDotNetObject<LoginResponse>("auth");
                    return true;
                }
                else
                {
                    Response = new LoginResponse();
                    return false;
                }
            }
            catch (Exception e)
            {
                ErrorHandler(e);
                return false;
            }

        }



        /// <summary>
        /// Adds the Login Parameter to the parameter list that is provided during the call to the backend login method
        /// </summary>
        /// <param name="paramName">The name of the parameter that the authentication method is expecting</param>
        /// <param name="paramValue">The string value for that parameter</param>
        protected void AddLoginParameter (string paramName, string paramValue) {
            _loginParameters.Add(paramName, paramValue);
        }



        /// <summary>
        /// Returns the full url path of the authentication backend
        /// <para>Derived classes must implement.  This should return the entire Vault URL endpoint for performing a login to the requested backend</para>
        /// </summary>
        /// <returns></returns>
        protected abstract string GetAuthenticationMountPath ();


        /// <summary>
        /// This method will be called by the Connect method to set any parameter arguments needed by the Vault endpoint for the backend
        /// </summary>
        protected abstract void BuildLoginParameters ();


        /// <summary>
        /// Derived classes that need to handle specific error situations should override this method.  It will be called if there is a problem during the Connect call.
        /// </summary>
        /// <param name="e"></param>
        protected virtual void ErrorHandler (Exception e) { throw e; }
    }
}


