using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Models;

namespace VaultAgent.AuthenticationEngines.LoginConnectors
{
    public class TokenLoginConnector : LoginConnector {
        private TokenAuthEngine _tokenAuthEngine;


        public TokenLoginConnector (VaultAgentAPI vaultAgent, string authenticatorMountName, string description) : base(
            vaultAgent, authenticatorMountName, description) {
            _tokenAuthEngine = new TokenAuthEngine(vaultAgent);
        }


        public TokenLoginConnector (VaultAgentAPI vaultAgent, string authenticatorMountName, string description, string tokenId) : base(
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
        /// <param name="setVaultToken"></param>
        /// <returns></returns>
        public override async Task<bool> Connect (bool setVaultToken = true) {
            // In reality, we are not connecting anything.  Tokens are a unique case, in which you either know the token value or you do not.
            // If you know it, then we just validate it is a token and copy its information to the Response object.
            Token token = await _tokenAuthEngine.GetCurrentTokenInfo();

            Response = new LoginResponse();
            if ( token == null ) {
                return false;
            }

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
