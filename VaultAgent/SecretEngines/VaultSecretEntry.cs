using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Backends;

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
		/// <param name="secretEngine"></param>
		/// <param name="name">The Name of this secret</param>
		/// <param name="path">The Path of this secret</param>
		public VaultSecretEntry (KV2SecretEngine secretEngine, string name, string path) : base (secretEngine,name,path) { }


		/// <summary>
		/// Saves the object to the Vault
		/// </summary>
		/// <returns></returns>
		public new async Task<bool> VSE_Save () { return await base.VSE_Save(); }
	}
}
