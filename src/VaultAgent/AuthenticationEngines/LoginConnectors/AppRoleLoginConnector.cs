using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent.AuthenticationEngines.LoginConnectors
{
    /// <summary>
    /// Provides a LoginConnector for Vault Application Roles
    /// </summary>
    public class AppRoleLoginConnector : LoginConnector
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="vaultAgent">The Vault the LDAP Backend is in</param>
        /// <param name="authenticatorMountPoint">The Vault Mount Point name for the LDAP Backend</param>
        /// <param name="description">Human Readable description of the Vault</param>
        /// <param name="roleID">The RoleID to login with</param>
        /// <param name="secretID">The SecretID to login with</param>
        public AppRoleLoginConnector (VaultAgentAPI vaultAgent, string authenticatorMountPoint, string description, string roleID, string secretID) : base(
            vaultAgent, authenticatorMountPoint, description) {
            RoleID = roleID;
            SecretID = secretID;
        }



        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="vaultAgent">The Vault the LDAP Backend is in</param>
        /// <param name="authenticatorMountPoint">The Vault Mount Point name for the LDAP Backend</param>
        /// <param name="description">Human Readable description of the Vault</param>
        /// <param name="roleID">The RoleID to login with</param>
        /// <param name="secretID">The SecretID to login with</param>
        public AppRoleLoginConnector(VaultAgentAPI vaultAgent, string authenticatorMountPoint, string description) : base(
            vaultAgent, authenticatorMountPoint, description)
        { }


        /// <summary>
        /// The RoleID to login with
        /// </summary>
        public string RoleID { get; set; }
        
        
        /// <summary>
        /// The SecretID to login with
        /// </summary>
        public string SecretID { get; set; }


        /// <summary>
        /// The parameters required for login
        /// </summary>
        protected override void BuildLoginParameters()
        {
            AddLoginParameter("role_id", RoleID);
            AddLoginParameter("secret_id", SecretID);
        }


        /// <summary>
        /// Login Mount Point
        /// </summary>
        /// <returns></returns>
        protected override string GetAuthenticationMountPath() {
            return "v1/auth/" + AuthenticationMountName + "/login";
        }
    }
}
