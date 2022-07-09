using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.SecretEngines
{
	/// <summary>
	/// Represents a "Smart" Vault Secret (KV2Secret) for KV2 Secret Engines that require Check And Set Functionality when saving secrets.
	/// While all of the functionality exposed by this class can be done with a combination of the
	/// KV2SecretEngine and the KV2SecretBase objects, it puts that functionality into a single class, that makes for much less lines of code and a
	/// much easier to work with functionality when it comes to moving a KV2Secret's information to and from the Vault.
	/// <para>The main add is a set of VSE_ methods that enable the reading, saving, deleting, getting info on the secret you are working with</para>
	/// </summary>
	public class VaultSecretEntryCAS : VaultSecretEntryBase
	{
		/// <summary>
		/// Constructor a VaultSecretEntry object that supports the Vault Check And Set Operations
		/// </summary>
		public VaultSecretEntryCAS () : base() { }


		/// <summary>
		/// Constructor a VaultSecretEntry object that supports the Vault Check And Set Operations
		/// </summary>
		/// <param name="secretEngine">The KV2SecretEngine that this secret should operate with</param>
		public VaultSecretEntryCAS (KV2SecretEngine secretEngine) : base(secretEngine) { }


		/// <summary>
		/// Constructor a VaultSecretEntry object that supports the Vault Check And Set Operations
		/// </summary>
		/// <param name="secretEngine">The KV2SecretEngine that this secret should operate with</param>
		/// <param name="name">The Name of this secret</param>
		/// <param name="path">The Path of this secret</param>
		public VaultSecretEntryCAS (KV2SecretEngine secretEngine, string name, string path) : base(secretEngine, name, path) { }


		/// <summary>
		/// Saves the secret to the Vault if it has never existed in the Vault before.  Use SaveUpdate for updates
		/// </summary>
		/// <returns></returns>
		public new async Task<bool> VSE_SaveNew() { return await base.VSE_SaveNew(); }


		/// <summary>
		/// Saves the secret to the Vault, using a Check and Set operation.  This means the version of the secret currently saved in Vault
		/// must be the same as the version we are trying to save now.  If they are the same, then the save is allowed, and the version on
		/// this object is incremented to match the Vault version.
		/// <para>If it fails, then you may need to re-read the secret from the Vault, apply your changes and then save.</para>
		/// </summary>
		/// <returns></returns>
		public new async Task<bool> VSE_SaveUpdate() { return await base.VSE_SaveUpdate(); }
	}
}
