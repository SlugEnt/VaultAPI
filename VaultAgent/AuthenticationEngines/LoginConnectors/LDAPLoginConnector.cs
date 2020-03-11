using System;
using System.ComponentModel;
using VaultAgent.Models;

namespace VaultAgent.AuthenticationEngines.LoginConnectors
{
    /// <summary>
    /// Provides the ability to login to Vault via LDAP
    /// </summary>
    public class LDAPLoginConnector : LoginConnector
    {
        /// <summary>
        /// Constructs an LDAP Login Connector object, that provides ability to login to Vault via LDAP Credentials
        /// </summary>
        /// <param name="vaultAgent">The Vault the LDAP Backend is in</param>
        /// <param name="authenticatorMountPoint">The Vault Mount Point name for the LDAP Backend</param>
        /// <param name="description">Human Readable description of the Vault</param>
        /// <param name="ldapUserName">The LDAP UserId to login as</param>
        /// <param name="password">The LDAP password for the UserID</param>
        public LDAPLoginConnector (VaultAgentAPI vaultAgent, string authenticatorMountPoint, string description, string ldapUserName, string password) : base(
            vaultAgent, authenticatorMountPoint, description) {
            UserName = ldapUserName;
            Password = password;
        }

        /// <summary>
        /// Constructs an LDAP Login Connector object, that provides ability to login to Vault via LDAP Credentials
        /// </summary>
        /// <param name="vaultAgent">The Vault the LDAP Backend is in</param>
        /// <param name="authenticatorMountPoint">The Vault Mount Point name for the LDAP Backend</param>
        /// <param name="description">Human Readable description of the Vault</param>
        public LDAPLoginConnector(VaultAgentAPI vaultAgent, string authenticatorMountPoint, string description) : base(
            vaultAgent, authenticatorMountPoint, description)
        {
        }


        /// <summary>
        /// The LDAP UserName
        /// </summary>
        public string UserName { get; set; } = "";

        /// <summary>
        /// The LDAP User's password
        /// </summary>
        public string Password { get; set; } = "";


        /// <summary>
        /// Returns the Full Mount point to login with the specified LDAP Backend
        /// </summary>
        /// <returns></returns>
        protected override string GetAuthenticationMountPath()
        {
            return  "v1/auth/" + AuthenticationMountName + "/login/" + UserName;
        }


        /// <summary>
        /// Adds the Password attribute to the Login Parameters
        /// </summary>
        protected override void BuildLoginParameters()
        {
            AddLoginParameter("password",Password);
        }


        /// <summary>
        /// Error Handling for LDAP Erros
        /// </summary>
        /// <param name="e"></param>
        protected override void ErrorHandler (Exception e) {
            if (e.Message.Contains("LDAP Result Code 200"))
            {
                VaultException ve = new VaultException("Problems Connecting to the LDAP Server", e);
                ve.SpecificErrorCode = EnumVaultExceptionCodes.LDAPLoginServerConnectionIssue;
                throw ve;
            }
            else if (e.Message.Contains("ldap operation failed"))
            {
                VaultException ve = new VaultException("Invalid username or password", e);
                ve.SpecificErrorCode = EnumVaultExceptionCodes.LDAPLoginCredentialsFailure;
                throw ve;
            }
            else throw e;
        }

    }
}
