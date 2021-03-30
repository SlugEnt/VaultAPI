using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends {
	/// <summary>
	/// The options that determine when a KeyValue2 Type Secret will be allowed to be saved to the Vault.
	/// </summary>
	public enum KV2EnumSecretSaveOptions {
		/// <summary>
		/// Saving of the Secret in Vault will be permitted only if it does not already exist in the Vault.
		/// </summary>
		OnlyIfKeyDoesNotExist = 0,


		/// <summary>
		/// Only allow the saving of the Secret, if the caller has provided the current version of the Secret.
		/// <para>This prevents distributed apps, in which multiple apps attempt to overwrite a secret.</para>
		/// <para>Only an app that knows the current version number of the secret will be allowed to save the secret</para>
		/// </summary>
		OnlyOnExistingVersionMatch = 1, 


		/// <summary>
		/// The save should always be allowed - allows overwriting the current version of a secret.
		/// </summary>
		AlwaysAllow = 2
	}
}