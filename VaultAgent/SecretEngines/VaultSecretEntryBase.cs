using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Backends;
using VaultAgent.SecretEngines;
using VaultAgent.SecretEngines.KeyValue2;
using VaultAgent.SecretEngines.KV2;
using VaultAgent.SecretEngines.KV2.SecretMetaDataInfo;

namespace VaultAgent.SecretEngines
{
	/// <summary>
	/// Represents a "Smart" Vault Secret (KV2Secret).  While all of the functionality exposed by this class can be done with a combination of the
	/// KV2SecretEngine and the KV2SecretBase objects, it puts that functionality into a single class, that makes for much less lines of code and a
	/// much easier to work with functionality when it comes to moving a KV2Secret's information to and from the Vault.
	/// <para>The main add is a set of VSE_ methods that enable the reading, saving, deleting, getting info on the secret you are working with</para>
	/// </summary>
	public abstract class VaultSecretEntryBase : IKV2Secret { //: KV2SecretBase<VaultSecretEntryNoCAS> {
		private KV2SecretEngine _kv2SecretEngine = null;
		private KV2Secret _secret;
		private KV2SecretMetaDataInfo _info;


		/// <summary>
		/// Constructor
		/// </summary>
		public VaultSecretEntryBase () { 
			InitializeNew();

		}


		/// <summary>
		/// Constructor accepting the SecretEngine that this secret's Vault Operations (VSE) should be applied to.
		/// </summary>
		/// <param name="secretEngine">The KV2SecretEngine that this secret should operate with</param>
		public VaultSecretEntryBase (KV2SecretEngine secretEngine) {
			InitializeNew();
			_kv2SecretEngine = secretEngine;
		}


		/// <summary>
		/// Constructor accepting the SecretEngine that this secret's Vault Operations (VSE) should be applied to.
		/// </summary>
		/// <param name="secretEngine">The KV2SecretEngine that this secret should operate with</param>
		/// <param name="name">The Name of this secret</param>
		/// <param name="path">The Path of this secret</param>
		public VaultSecretEntryBase (KV2SecretEngine secretEngine ,string name, string path) {
			InitializeNew();
			SecretEngine = secretEngine;
			
			_secret.Name = name;
			_secret.Path = path;
		}

		
		/// <summary>
		/// Initializes this class' variables to initial values
		/// </summary>
		private void InitializeNew () {
			_secret = new KV2Secret();
			_info = null;
		}


		/// <summary>
		/// The Secret Engine that this secret will read from and save to.
		/// </summary>
		public KV2SecretEngine SecretEngine {
			get { return _kv2SecretEngine; }
			set {
				_kv2SecretEngine = value;
				IsEngineDefined = true;
			}
		}


		/// <summary>
		/// Returns true if the Engine property has been initialized to a value.
		/// </summary>
		public bool IsEngineDefined { get; private set; } = false;


		/// <summary>
		/// Returns True if this secrets extended Information has been read from the Vault.  You must specifically request this thru the VSE_Info method
		/// </summary>
		public bool IsSecretInfoLoaded { get; private set; } = false;


		/// <summary>
		/// The KV2SecretMetaData Information about this secret.  If it returns null, then you have not requested this information (Run VSE_Info).
		/// </summary>
		public KV2SecretMetaDataInfo Info {
			get { return _info; }
		}



		/// <summary>
		/// The Name of this Secret
		/// </summary>
		public string Name {
			get { return _secret.Name; }
			set { _secret.Name = value; }
		}


		/// <summary>
		/// The Parent path of this secret
		/// </summary>
		public string Path {
			get { return _secret.Path;}
			set { _secret.Path = value; }
		}


		/// <summary>
		/// The full path to this secret (path + name)
		/// </summary>
		public string FullPath {
			get { return _secret.FullPath; }
		}


		/// <summary>
		/// True if this secret's data was read from the Vault
		/// </summary>
		public bool WasReadFromVault {
			get { return _secret.WasReadFromVault; }
		}


		/// <summary>
		/// The Dictionary of items that this secret is storing.
		/// </summary>
		public Dictionary<string, string> Attributes {
			get { return _secret.Attributes;} 
		}


		/// <summary>
		/// Access to the Vault MetaData for this particular secret.  Each secret can have additional data stored with it.
		/// </summary>
		public Dictionary<string, string> Metadata {
			get { return _secret.Metadata;}
			set { _secret.Metadata = value; }
		}


		/// <summary>
		/// When this secret was created.
		/// </summary>
		public DateTimeOffset CreatedTime {
			get { return _secret.CreatedTime; }
		}


		/// <summary>
		/// When this secret was deleted
		/// </summary>
		public DateTimeOffset DeletionTime {
			get { return _secret.DeletionTime; }
		}


		/// <summary>
		/// If this secret is currently destroyed.
		/// </summary>
		public bool IsDestroyed {
			get { return _secret.IsDestroyed; }
		}

		/// <summary>
		/// The Version of this secret.  This will be the version of this secret as it was last Read or Saved to Vault.  
		/// </summary>
		public int Version {
			get { return _secret.Version; }
			set { _secret.Version = value; }
		}


		// Methods that interact with the Vault
		#region "Vault CRUD Methods"

		/// <summary>
		/// Reads this VSE's Vault Secret data from the Vault.  Returns True on Success.  Note, this will overwrite any existing values that exist
		/// in this VSE's secret object that have not been saved to the Vault.
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_Read() {
			if ( !IsEngineDefined ) return false;
			KV2Secret newSecret = await _kv2SecretEngine.ReadSecret<KV2Secret>(FullPath, 0);
			if (newSecret == null) return false;
			_secret = newSecret;
			return true;
		}


		/// <summary>
		/// Reads the requested version of this VSE's Vault Secret data from the Vault.  Returns True on Success.  Note, this will overwrite any existing values that exist
		/// in this VSE's secret object that have not been saved to the Vault.
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_ReadVersion(int versionNumber) {
			if ( !IsEngineDefined ) return false;
			KV2Secret newSecret = await _kv2SecretEngine.ReadSecret<KV2Secret>(FullPath, versionNumber);
			if (newSecret == null) return false;
			_secret = newSecret;
			return true;
		}


		/// <summary>
		/// Saves this secret to the Vault.  Returns True on Success
		/// </summary>
		/// <returns></returns>
		protected async Task<bool> VSE_Save()
		{
			if (!IsEngineDefined) return false;
			bool success = await _kv2SecretEngine.SaveSecret(_secret, KV2EnumSecretSaveOptions.AlwaysAllow);
			return success;
		}


		/// <summary>
		/// Saves this secret to the Vault.  It will succeed only if this is the First time this secret has ever been saved.
		/// <para>Only applies to secret that are stored in Engines using Check And Set</para>
		/// </summary>
		/// <returns></returns>
		protected async Task<bool> VSE_SaveNew () {
			if (!IsEngineDefined) return false;
			bool success = await _kv2SecretEngine.SaveSecret(_secret, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist);
			return success;
		}


		/// <summary>
		/// Saves this secret to the Vault.  It will succeed only if the version of the secret in Vault matches the Version property on this
		/// Object.  If someone else has saved an updated version since the time you last read it, you will need to re-read it and then try
		/// your save again.
		/// <para>Only applies to secret that are stored in Engines using Check And Set</para>
		/// </summary>
		/// <returns></returns>
		protected async Task<bool> VSE_SaveUpdate ()
		{
			if (!IsEngineDefined) return false;
			bool success = await _kv2SecretEngine.SaveSecret(_secret, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch,this.Version);
			return success;
		}


		/// <summary>
		/// Returns True if a VSE with this name and path, already exist in the Vault.  False if it does not Exist.
		/// <para>If you are going to end up reading the Vault Entry anyway, then it is more efficient to use VSE_Read instead.</para>
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_Exists () {
			if (!IsEngineDefined) return false;
			KV2Secret newSecret = await _kv2SecretEngine.ReadSecret<KV2Secret>(FullPath, 0);
			if (newSecret == null) return false;
			return true;
		}


		/// <summary>
		/// Deletes this secret's current version from the Vault
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_Delete () {
			if (!IsEngineDefined) return false;
			bool success = await _kv2SecretEngine.DeleteSecretVersion(_secret);
			return success;
		}


		/// <summary>
		/// Performs a read of the Vault Secret's MetaData Information which mostly provides version information about the secret, including
		/// Current Version, Max # of versions it keeps, the oldest version and timestamp information about each of the versions.
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_Info () {
			if (!IsEngineDefined) return false;
			KV2SecretMetaDataInfo info = await _kv2SecretEngine.GetSecretMetaData(_secret);
			if ( info == null ) return false;

			_info = info;
			IsSecretInfoLoaded = true;
			return true;
		}


		
		/// <summary>
		/// Completely Destroys this secret from the Vault.  All Versions are removed as though it never existed.
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_DestroyAll () {
			if (!IsEngineDefined) return false;
			bool success = await _kv2SecretEngine.DestroySecretCompletely(_secret);
			_secret.IsDestroyed = true;
			return success;
		}



		/// <summary>
		/// Destroys the given version of the secret, resulting in the complete removal of all evidence THIS VERSION of the secret ever existed in the vault
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_Destroy()
		{
			if (!IsEngineDefined) return false;
			throw new NotImplementedException();
			//	bool success = await _kv2SecretEngine.DestroySecretVersion(_secret);
		}



		/// <summary>
		/// Allows the Saving of this secret under a new name and path.
		/// </summary>
		/// <param name="name"></param>
		/// <param name="path"></param>
		/// <param name="secretEngine"></param>
		/// <returns></returns>
		public async Task<VaultSecretEntryBase> VSE_SaveAs (string name, string path, KV2SecretEngine secretEngine = null) {
			throw new NotImplementedException();
		}
		#endregion
	}
}
