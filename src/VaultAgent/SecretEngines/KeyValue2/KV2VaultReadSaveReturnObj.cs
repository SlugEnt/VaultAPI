using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace VaultAgent.SecretEngines.KeyValue2
{
	/// <summary>
	/// This class represents data that Vault returns on certain KV2 Secret Engine functions, such as Read and Save Secret.
	/// It mostly consists of TimeStamps, a Destroyed Flag and the Version that was operated on.
	/// </summary>
	internal class KV2VaultReadSaveReturnObj {
		// This is needed, because DeletedTime is nulled in Vault, until the secret is actually deleted.
		private DateTimeOffset _deletedTime = DateTimeOffset.MinValue;

		public KV2VaultReadSaveReturnObj () { }


		/// <summary>
		/// When this particular secret version was created.
		/// </summary>
		[JsonProperty("created_time")]
		public DateTimeOffset CreatedTime { get; internal set; }


		/// <summary>
		/// When this particular secret version was deleted.  Note, you will need to case the Get to DateTimeOffset, since the property accepts DateTimeOffset Nullable
		/// </summary>
		[JsonProperty("deletion_time")]
		public DateTimeOffset? DeletionTime {
			get { return _deletedTime;}
			internal set {
				if ( value != null ) _deletedTime = (DateTimeOffset) value;
				else _deletedTime = DateTimeOffset.MinValue;
			}
		}


		/// <summary>
		/// Boolean - Whether this particular secret version is soft deleted.
		/// </summary>
		[JsonProperty("destroyed")]
		public bool Destroyed { get; internal set; }


		/// <summary>
		/// The version number of this particular secret version.
		/// </summary>
		[JsonProperty("version")]
		public int Version { get; internal set; }
	}
}
