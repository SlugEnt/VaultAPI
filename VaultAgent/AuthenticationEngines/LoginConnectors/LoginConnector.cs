﻿using System;
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
        private VaultAgentAPI _vaultAgent;
        protected JObject _loginParameters;
        private string _description;


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
        /// <returns></returns>
        public async Task<bool> Connect () {
            _loginParameters = new JObject();

            string mountPath = GetAuthenticationMountPath();

            BuildLoginParameters();

            try {
                VaultDataResponseObjectB vdro = await _vaultAgent._httpConnector.PostAsync_B(mountPath, _description, _loginParameters.ToString());
                if ( vdro.Success ) {
                    Response = await vdro.GetDotNetObject<LoginResponse>("auth");
                    return true;
                }
                else {
                    Response = new LoginResponse();
                    return false;
                }
            }
            catch ( Exception e ) {
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
        /// </summary>
        /// <returns></returns>
        protected abstract string GetAuthenticationMountPath ();


        protected abstract void BuildLoginParameters ();

        protected virtual void ErrorHandler (Exception e) { throw e; }
    }
}


