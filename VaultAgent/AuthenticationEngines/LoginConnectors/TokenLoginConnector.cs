using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;

namespace VaultAgent.AuthenticationEngines.LoginConnectors
{
    public class TokenLoginConnector : LoginConnector {
        private TokenAuthEngine _tokenAuthEngine;


        public TokenLoginConnector (VaultAgentAPI vaultAgent, string description, string authenticatorMountName = TokenAuthEngine.TOKEN_DEFAULT_MOUNT_NAME) : base(
            vaultAgent, authenticatorMountName, description) {
            _tokenAuthEngine = new TokenAuthEngine(vaultAgent);
        }


        public TokenLoginConnector (VaultAgentAPI vaultAgent, string description, string tokenId, string authenticatorMountName = TokenAuthEngine.TOKEN_DEFAULT_MOUNT_NAME) : base(
            vaultAgent, authenticatorMountName, description) {
            _tokenAuthEngine = new TokenAuthEngine(vaultAgent);
            TokenId = tokenId;
        }


        /// <summary>
        /// The Token Id to be used to login with
        /// </summary>
        public string TokenId { get; set; } = "";



        /// <summary>
        /// Establishes a connection with the specified token. 
        /// </summary>
        /// <returns></returns>
        protected override async Task<bool> InternalConnection () {
            try {
                // We must replace the Vault Token if the value is currently empty, We need something to connect to Vault with.  
                if ( _vaultAgent.TokenID == string.Empty ) _vaultAgent._vaultAccessTokenID = TokenId;

                // In reality, we are not connecting anything.  Tokens are a unique case, in which you either know the token value or you do not.
                // If you know it, then we just validate it is a token and copy its information to the Response object.
                Token token = await _tokenAuthEngine.GetCurrentTokenInfo();

                Response = new LoginResponse();
                if ( token == null ) { return false; }

                // We need to move some of the values from the Token to the response object
                Response.ClientToken = token.ID;
                Response.Policies = token.Policies;
                Response.IdentityPolicies = token.IdentityPolicies;
                Response.Accessor = token.AccessorTokenID;
                Response.Renewable = token.IsRenewable;
                Response.EntityId = token.EntityId;
                Response.Metadata = token.Metadata;

                // TODO - Adjust
                //Response.TokenType = token.TokenType;

                return true;
            }
            catch ( Exception e ) { throw e; }
        }


        /// <summary>
        /// There are no parameters for tokens
        /// </summary>
        protected override void BuildLoginParameters()
        { }


        /// <summary>
        /// There is no need for this in this connector
        /// </summary>
        /// <returns></returns>
        protected override string GetAuthenticationMountPath () { return string.Empty; }
    }
}
