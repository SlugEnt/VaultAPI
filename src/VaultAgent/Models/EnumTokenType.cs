namespace VaultAgent.Models {
    /// <summary>
    /// The Type of Token
    /// </summary>
    public enum EnumTokenType { 
        /// <summary>
        /// The token is a root token.  These should almost never be used.
        /// </summary>
        Root = 0, 

        /// <summary>
        /// Token is a client token. This is the typical type of token
        /// </summary>
        Client = 5, 

        /// <summary>
        /// Token is an accessor token.
        /// </summary>
        Accessor = 10 
    }
}