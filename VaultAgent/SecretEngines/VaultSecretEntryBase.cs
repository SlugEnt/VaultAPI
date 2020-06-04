using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultAgent.Backends;
using VaultAgent.SecretEngines;
using VaultAgent.SecretEngines.KeyValue2;
using VaultAgent.SecretEngines.KV2;
using VaultAgent.SecretEngines.KV2.SecretMetaDataInfo;

// Allow Testing project to access KV2SecretWrapper to perform tests.
[assembly: InternalsVisibleTo("VaultAgent.Test")]


namespace VaultAgent.SecretEngines
{
	/// <summary>
	/// Represents a "Smart" Vault Secret (KV2Secret).  While all of the functionality exposed by this class can be done with a combination of the
	/// KV2SecretEngine and the KV2SecretBase objects, it puts that functionality into a single class, that makes for much less lines of code and a
	/// much easier to work with functionality when it comes to moving a KV2Secret's information to and from the Vault.
	/// <para>The main add is a set of VSE_ methods that enable the reading, saving, deleting, getting info on the secret you are working with</para>
	/// <para>There is also an adjustment to the path / name sequence for a secret.</para>
	/// <para>There are now 3 components to the path.  A full path now has these 3 components that together form a full path in the format of base/path/name</para>
	/// </summary>
	public abstract class VaultSecretEntryBase : IKV2Secret { //: KV2SecretBase<VaultSecretEntryNoCAS> {
		private KV2SecretEngine _kv2SecretEngine = null;
        // TODO change secret to private and use pass thru methods on this class to access required properties
		protected KV2Secret _secret;
		protected KV2SecretMetaDataInfo _info;
        

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
            SecretEngine = secretEngine;
		}



        /// <summary>
        /// Constructor accepting the Name and Path of Secret.  Caller will be responsible at a later time for specifying the SecretEngine that should be used to store this Secret In
        /// </summary>
        /// <param name="name">The Name of this secret</param>
        /// <param name="path">The Path of this secret</param>
        public VaultSecretEntryBase (string name, string path = "") {
            InitializeNew(name,path);
        }



		/// <summary>
		/// Constructor accepting the SecretEngine and Secret Name that this secret's Vault Operations (VSE) should be applied to.
		/// </summary>
		/// <param name="secretEngine">The KV2SecretEngine that this secret should operate with</param>
		/// <param name="fullPathAndName">The Name of this secret, including any parent paths.  This will be separated out into Name and Path Properties</param>
		/// <para>Note, the FullPath and name parameter does not specify the basePath</para>
		public VaultSecretEntryBase (KV2SecretEngine secretEngine, string fullPathAndName) {
            InitializeNew(fullPathAndName);
            // TODO -Work in this method - the name and path should use the namepath UtilityFX Tuple method

            SecretEngine = secretEngine;
        }


    
		/// <summary>
		/// Constructor accepting the SecretEngine that this secret's Vault Operations (VSE) should be applied to.
		/// </summary>
		/// <param name="secretEngine">The KV2SecretEngine that this secret should operate with</param>
		/// <param name="name">The Name of this secret</param>
		/// <param name="path">The Path of this secret</param>
		public VaultSecretEntryBase (KV2SecretEngine secretEngine ,string name, string path = "") {
			InitializeNew(name,path);
			SecretEngine = secretEngine;
		}

		
		/// <summary>
		/// Initializes this class' variables to initial values
		/// </summary>
		private void InitializeNew (string name = "", string pathRoot = "") {
            // We rely upon the KV2Secret constructor logic to interrogate and set the name and path properties.
            if (name != string.Empty)
                _secret = new KV2Secret(name, pathRoot);
            else
                _secret = new KV2Secret();

            _info = null;
		}


        /// <summary>
        /// This should be overwritten by descendant objects.  It will be called any time the secret is read from the Vault.
        /// <para>If you need to set any internal variables based upon the read, this is method you would use</para>
        /// </summary>
        protected virtual void OnVSE_Read () { }


        /// <summary>
        /// This is the first method called when a VSE_Save is executed, gives the object time to manipulate the backing object before the actual save is done.  Should return true to continue with save
        /// </summary>
        protected virtual bool OnVSE_SaveBefore () { return true; }


		/// <summary>
		/// Method called AFTER the VSE has been saved to the vault.  
		/// </summary>
		protected virtual void OnVSE_SaveAfter () { }



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
		/// The Name of this Secret.  
		/// </summary>
		public string Name {
			get { return _secret.Name; }
			set { _secret.Name = value; }
		}


		/// <summary>
		/// The Parent path of this secret.  Note, When setting this Path, the PathRoot property is set to the value the caller set, then the actual path is computed based upon the ComputePath method.
		/// So, the value you set, could be different than the value you read back.
		/// <para>It is preferred that you set the Path thru the PathRoot property, to ensure everything seems logical, end result is the same.</para>
		/// </summary>
		public string Path {
			get { return _secret.Path;}
            set {
                _secret.Path = value;
            }
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
		[JsonProperty]
		public Dictionary<string, string> Attributes {
			get { return _secret.Attributes;}
            internal set { _secret.Attributes = value; }
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
		/// <para>If the read is successful, then the onVSE_Read method is called, allowing descendants to further manipulate the data if necessary.</para>
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_Read() {
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }
			KV2Secret newSecret = await _kv2SecretEngine.ReadSecret<KV2Secret>(FullPath, 0);
			if (newSecret == null) return false;
			_secret = newSecret;
            

            // Call method that allows descendants to do additional processing after a read.
            OnVSE_Read();
			return true;
		}


		/// <summary>
		/// Reads the requested version of this VSE's Vault Secret data from the Vault.  Returns True on Success.  Note, this will overwrite any existing values that exist
		/// in this VSE's secret object that have not been saved to the Vault.
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_ReadVersion(int versionNumber) {
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }
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
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }
			OnVSE_SaveBefore();
			bool success = await _kv2SecretEngine.SaveSecret(_secret, KV2EnumSecretSaveOptions.AlwaysAllow);
			return success;
		}


		/// <summary>
		/// Saves this secret to the Vault.  It will succeed only if this is the First time this secret has ever been saved.
		/// <para>Only applies to secret that are stored in Engines using Check And Set</para>
		/// </summary>
		/// <returns></returns>
		protected async Task<bool> VSE_SaveNew () {
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }

            if ( !OnVSE_SaveBefore() ) return false;
			bool success = await _kv2SecretEngine.SaveSecret(_secret, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist);
			OnVSE_SaveAfter();

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
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }
			bool success = await _kv2SecretEngine.SaveSecret(_secret, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch,this.Version);
			return success;
		}


		/// <summary>
		/// Returns True if a VSE with this name and path, already exist in the Vault.  False if it does not Exist.
		/// <para>If you are going to end up reading the Vault Entry anyway, then it is more efficient to use VSE_Read instead.</para>
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_Exists () {
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }
			KV2Secret newSecret = await _kv2SecretEngine.ReadSecret<KV2Secret>(FullPath, 0);
			if (newSecret == null) return false;
			return true;
		}


		/// <summary>
		/// Deletes this secret's current version from the Vault
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_Delete () {
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }
			bool success = await _kv2SecretEngine.DeleteSecretVersion(_secret);
			return success;
		}


		/// <summary>
		/// Performs a read of the Vault Secret's MetaData Information which mostly provides version information about the secret, including
		/// Current Version, Max # of versions it keeps, the oldest version and timestamp information about each of the versions.
		/// </summary>
		/// <returns></returns>
		public async Task<bool> VSE_Info () {
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }
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
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }
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
            if (!IsEngineDefined)
            {
                string msg =
                    string.Format(
                        "The KV2 Secret Engine has not been set on this VSE Object [{0}].  Unable to perform any Engine steps",
                        FullPath);
                throw new ApplicationException(msg);
            }
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

        #region "Attribute Accessor Methods"


        /// <summary>
        /// Retrieves the attributeName from the Attributes List.  If it does not exist of if the value is not a number (including empty string) then null is returned.  Otherwise the integer is returned
        /// </summary>
        /// <param name="attributeName">Name of the attribute to retrieve</param>
        /// <returns></returns>
        protected internal int? GetIntAttributeNullable(string attributeName)
        {
            // Try and Get the value.
            bool result = _secret.Attributes.TryGetValue(attributeName, out string value);
            if (result)
            {
                if (value == "") return null;

                // Now try and convert to integer
                result = int.TryParse(value, out int number);
                if (result) return number;

                string errMsg =
                    string.Format(
                        "VSE Secret [{0}] had an issue converting one of it's attribute values from a string to an integer.  Attribute Name [{1}].  The value was [{2}]",
                        _secret.Name, attributeName, value);
                throw new ArgumentOutOfRangeException(errMsg);
            }

            return null;
        }



		/// <summary>
		/// Retrieves a Vault boolean value for the requested Secret Attribute.  String Representations are T for True, F for False.  If not found it false
		/// </summary>
		/// <param name="attributeName">Name of the attribute to get</param>
		/// <returns></returns>
        protected internal bool GetBoolAttributeDefault (string attributeName) {
            // Try and Get the value.
            bool result = _secret.Attributes.TryGetValue(attributeName, out string value);
            if ( result ) {
                if ( value == "T" )
                    return true;
                else if ( value == "F" )
                    return false;
                else {
                    string msg = string.Format(
                        "Secret [{0}] Attribute [{1}] has an invalid value stored in Vault.  Looking for a boolean string value of either T or F, but found [{2}]",
                        FullPath, attributeName, value);
                    throw new ArgumentException(msg);
                }
            }

            return true;
        }



		/// <summary>
		/// Stores a boolean value as a string with T for True and F for False
		/// </summary>
		/// <param name="attributeName">The name of the attribute to set</param>
		/// <param name="value">The boolean value to set the attribute to</param>
        protected internal void SetBoolAttribute (string attributeName, bool value) {
            if ( value )
                _secret.Attributes [attributeName] = "T";
            else
                _secret.Attributes [attributeName] = "F";
        }



        /// <summary>
		/// Retrieves the attributeName from the Attributes List.  If it does not exist or if the value is not a number (including empty string) then 0 is returned.  Otherwise the integer is returned.
		/// </summary>
		/// <param name="attributeName">Name of the attribute to retrieve</param>
		/// <returns></returns>
		protected internal int GetIntAttributeDefault (string attributeName)
        {
            int defaultValue = 0;

            // Try and Get the value.
            bool result = _secret.Attributes.TryGetValue(attributeName, out string value);
            if (result)
            {
                if (value == "") return defaultValue;

                // Now try and convert to integer
                result = int.TryParse(value, out int number);
                if (result) return number;

                string errMsg =
                    string.Format(
                        "VSE Secret [{0}] had an issue converting one of it's attribute values from a string to an integer.  Attribute Name [{1}].  The value was [{2}]",
                        _secret.Name, attributeName, value);
                throw new ArgumentOutOfRangeException(errMsg);
            }

            return defaultValue;
        }



        /// <summary>
        /// Saves the given integer value into the Attributes List under the provided AttributeName
        /// </summary>
        /// <param name="attributeName">Name of the Attribute to save the value under</param>
        /// <param name="value">The value to be stored</param>
        protected internal void SetIntAttribute(string attributeName, int value)
        {
            _secret.Attributes[attributeName] = value.ToString();
        }



        /// <summary>
        /// Saves the given DateTimeOffset value into the Attributes List under the provided AttributeName
        /// </summary>
        /// <param name="attributeName">Name of the Attribute to save the value under</param>
        /// <param name="value">The value to be stored</param>
        protected internal void SetDateTimeOffsetAttribute(string attributeName, DateTimeOffset value)
        {
            _secret.Attributes[attributeName] = value.ToUnixTimeSeconds().ToString();
        }



        /// <summary>
        /// Retrieves the attributeName from the Attributes List.  If it does not exist or if the value is not a number (including empty string) then DateTimeOffset.MinValue is returned.  Otherwise the integer is returned.
        /// </summary>
        /// <param name="attributeName">Name of the attribute to retrieve</param>
        /// <returns></returns>
        protected internal DateTimeOffset GetDateTimeOffsetAttributeDefault(string attributeName)
        {
            DateTimeOffset defaultValue = DateTimeOffset.MinValue;

            // Try and Get the value.
            bool result = _secret.Attributes.TryGetValue(attributeName, out string value);
            if (result)
            {
                if (value == "") return defaultValue;

                // Now try and convert to long
                result = long.TryParse(value, out long number);
                if (!result)
                {
                    string errMsg =
                        string.Format(
                            "VSE Secret [{0}] had an issue converting one of it's attribute values from a string to a DateTimeOffset.  Attribute Name [{1}].  The value was [{2}]",
                            _secret.Name, attributeName, value);
                    throw new ArgumentOutOfRangeException(errMsg);
                }
                DateTimeOffset returnDate = DateTimeOffset.FromUnixTimeSeconds(number);
                return returnDate;
            }

            return defaultValue;
        }



        /// <summary>
        /// Retrieves the attributeName from the Attributes List.  If it does not exist or if the value is not a number (including empty string) then null is returned.  Otherwise the integer is returned.
        /// </summary>
        /// <param name="attributeName">Name of the attribute to retrieve</param>
        /// <returns></returns>
        protected internal DateTimeOffset? GetDateTimeOffsetAttributeNullable(string attributeName)
        {
            // Try and Get the value.
            bool result = _secret.Attributes.TryGetValue(attributeName, out string value);
            if (result)
            {
                if (value == "") return null;

                // Now try and convert to long
                result = long.TryParse(value, out long number);
                if (!result)
                {
                    string errMsg =
                        string.Format(
                            "VSE Secret [{0}] had an issue converting one of it's attribute values from a string to a DateTimeOffset.  Attribute Name [{1}].  The value was [{2}]",
                            _secret.Name, attributeName, value);
                    throw new ArgumentOutOfRangeException(errMsg);
                }
                DateTimeOffset returnDate = DateTimeOffset.FromUnixTimeSeconds(number);
                return returnDate;
            }

            return null;
        }


		/// <summary>
		/// Returns the KV2Secret's ParentPath property.'
		/// </summary>
		/// <returns></returns>
		public string GetParentPath()
		{
			return ((IKV2Secret)_secret).GetParentPath();
		}




		#endregion
	}
}
