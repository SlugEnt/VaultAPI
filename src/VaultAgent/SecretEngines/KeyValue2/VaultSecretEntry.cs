using System.Runtime.CompilerServices;
using System.Threading.Tasks;

// Allow Testing project to access KV2SecretWrapper to perform tests.
[assembly: InternalsVisibleTo("VaultAgent.Test")]


namespace VaultAgent.SecretEngines
{
	/// <summary>
	/// Represents a "Smart" Vault Secret (KV2Secret) for KV2 Secret Engines.  This secret type can only be used with KV2SecretEngines that DO NOT
	/// support the Check and Set Operations.  There is a separate class VaultSecretEntryCAS for those secret types.
	/// While all of the functionality exposed by this class can be done with a combination of the
	/// KV2SecretEngine and the KV2SecretBase objects, it puts that functionality into a single class, that makes for much less lines of code and a
	/// much easier to work with functionality when it comes to moving a KV2Secret's information to and from the Vault.
	/// <para>The main add is a set of VSE_ methods that enable the reading, saving, deleting, getting info on the secret you are working with</para>
	/// </summary>
	public class VaultSecretEntry : VaultSecretEntryBase {
		/// <summary>
		/// Constructor
		/// </summary>
		public VaultSecretEntry() : base () { }


		/// <summary>
		/// Constructs a VaultSecretEntry object Without CAS functionality
		/// </summary>
		/// <param name="secretEngine"></param>
		public VaultSecretEntry (KV2SecretEngine secretEngine) : base (secretEngine) { }


		/// <summary>
		/// Constructs a VaultSecretEntry object Without CAS functionality
		/// </summary>
		/// <param name="secretEngine">The Secret Engine this Entry should be saved/read to/from</param>
		/// <param name="name">The Name of this secret</param>
		/// <param name="path">The Path of this secret</param>
		public VaultSecretEntry (KV2SecretEngine secretEngine, string name, string path) : base (secretEngine,name,path) { }


        /// <summary>
        /// Constructs a VaultSecretEntry object Without the Secret Engine specified.  Needs to be specified at a later time
        /// </summary>
        /// <param name="name">The Name of this secret</param>
        /// <param name="path">The Path of this secret</param>
        public VaultSecretEntry (string name, string path) : base (name, path) { }


        /// <summary>
        /// Saves the object to the Vault
        /// </summary>
        /// <returns></returns>
        public new async Task<bool> VSE_Save () { return await base.VSE_Save(); }

    
		/// <summary>
		/// Constructs a VaultSecretEntry object Without CAS functionality
		/// </summary>
		/// <param name="secretEngine">The Secret Engine this Entry should be saved/read to/from</param>
		/// <param name="fullPathAndName">The full path and name to the secret</param>
		public VaultSecretEntry (KV2SecretEngine secretEngine, string fullPathAndName) : base(secretEngine, fullPathAndName) { }
	}
}
