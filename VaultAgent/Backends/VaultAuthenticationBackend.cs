using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;

namespace VaultAgent {
    /// <summary>
    /// Internal abstract class representing an Authentication backend method for Vault.  The following expectations are made of derived classes.
    ///  - That they will provide some type of a login method.  That method cannot be abstracted due to the fact that different backends have
    ///    different requirements for logging in (some require user id and password, others just a token, others a role ID and secretID.  It is left up to the
    ///    backends to validate that they have the necessary information.  See CanLogin method below.
    ///     Example:  public bool Credentials (string userName, string password).
    ///  - The login method must call this classes AfterLogin method.  
    ///  - The login method should return true on success.  False otherwise.
    ///  
    /// </summary>
    public abstract class VaultAuthenticationBackend : VaultBackend {
        // TODO - fix params for httpcon
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="backendName">A Name for the backend.  This is noy used or stored internally in Vault anywhere. </param>
        /// <param name="backendMountPoint">The mount point where the backend is mounted at.</param>
        /// <param name="httpConnector">The HTTP Connector object used to establish a connection to Vault.</param>
        internal VaultAuthenticationBackend (string backendName, string backendMountPoint, VaultAgentAPI vault) : base (backendName, backendMountPoint, vault) {
            IsAuthenticationBackend = true;
        }



        /// <summary>
        /// Returns a Token object of the Token that is currently being used to access Vault with.  This routine also exists within the VaultAuthentication Backend.
        /// </summary>
        /// <remarks>This routine and the one in VaultAuthenticationBackend should be kept in sync.</remarks>
        /// <returns>Token object of the current token used to access Vault Instance with.</returns>
        public async Task<Token> GetMyTokenInfo () {
            string path = "/v1/auth/token/lookup-self";

            try {
                VaultDataResponseObject vdro = await _parent._httpConnector.GetAsync (path, "GetMyTokenInfo");
                if ( vdro.Success ) {
                    string js = vdro.GetDataPackageAsJSON();
                    Token tokenInfo = VaultUtilityFX.ConvertJSON<Token> (js);
                    return tokenInfo;
                }
                else { throw new VaultUnexpectedCodePathException(); }
            }

            // If Vault is telling us it is a bad token, then return null.
            catch ( VaultForbiddenException e ) {
                if ( e.Message.Contains ("bad token") ) { return null; }
                else { throw e; }
            }
        }
    }
}