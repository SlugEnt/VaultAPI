using System;
using Newtonsoft.Json;
using System.Collections.Generic;



namespace VaultAgent.SecretEngines.KV2
{
	/// <summary>
	/// Represents a secret read from the Vault.  Secrets can have zero to many attributes which are just Key Value Pairs of a name and some data value.
	/// However, a secret without at least one attribute is not a secret, for the attributes are where the value for the secret is retrieved from.  
	/// Important is that when saving a secret, you must save it with all it's attributes or else any that are missing on the save will be removed from 
	/// the vault.  So, if upon reading a secret it has attributes of canDelete:True and connection:db1 and you save it, but the only attribute in the 
	/// list upon save is connection:db1 then canDelete will no longer exist after the save.  
	/// 
	/// Therefore it is best to read the secret, make changes to any existing attributes and then add any new ones, then save it.
	/// </summary>
	public class KV2Secret : IEquatable<KV2Secret>, ICloneable {
        // The path to the secret in the Vault Instance
	    private string _path;

        // The name of the secret object in the Vault Instance.
	    private string _name;



		/// <summary>
		/// Creates a new empty secret
		/// </summary>
		public KV2Secret() {
			Attributes = new Dictionary<string, string>();
		}



		/// <summary>
		/// Creates a new secret with the specified Name (Path)
		/// </summary>
		/// <param name="secretName">The name of the secret.</param>
		/// <param name="path">The path to the secret to be stored.  apps/appA/config   apps/appA is the path.</param>
		public KV2Secret(string secretName, string path = "") {
		    Name = secretName;
		    Path = path;
			Attributes = new Dictionary<string, string>();
		}



        /// <summary>
        /// The name of the secret.  In Vault terminology this is the very last part of the secret path.  So if a secret is stored at
        /// app/AppA/username  then the secret name would be username and the secret path would be app/AppA.  
        /// </summary>
        public string Name { get => _name;
            set { _name = value; }
        }


        /// <summary>
        /// The path where the secret should be stored.  So if a secret is stored at app/AppA/username then the secret path would be app/AppA.
        /// Note:  All leading and trailing slashes are removed from the passed in value.
        /// </summary>
        public string Path {
            get { return _path;}
            set {
                string temp;
                if (value == "/") { _path = ""; }
                else { _path = value.TrimEnd('/').TrimStart(('/')); }
            }
        }



        // Returns the entire path to the Vault Secret.  This is the Path + the Name.
        public string FullPath {
            get {
                if (_path == "") { return Name;}

                return (Path + "/" + Name);
            }
        }



		/// <summary>
		/// The actual values that should be saved in the secret. 
		/// </summary>
		[JsonProperty("data")]
		public Dictionary<string, string> Attributes { get; set; }

		

		/// <summary>
		/// MetaData associated with the secret.
		/// </summary>
		[JsonProperty("metadata")]
		public Dictionary<string,string> Metadata { get; set; }



		// Extended Attributes


		/// <summary>
		/// When the secret was actually saved to the Vault data store.  
		/// </summary>
		public DateTimeOffset CreatedTime { get; internal set; }


		/// <summary>
		/// When this particular secret version was deleted from the Vault data store.
		/// </summary>
		public string DeletionTime { get; internal set; }


		/// <summary>
		/// Boolean - Whether this particular secret version is soft deleted or destroyed.  True means this secret data cannot be undeleted.
		/// </summary>
		public bool Destroyed { get; internal set; }


		/// <summary>
		/// The version number of this particular secret.
		/// </summary>
		public int Version { get; internal set; }



        #region "EqualityComparers"

        /// <summary>
        /// Determines if 2 KV2Secrets are the same.  Same is defined as: same name, path, number of attributes, and same attribute names and values.
        /// Does not evaluate any metadata or Version attributes.
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public bool Equals (KV2Secret s) {
            // If S is null then !=
            if (ReferenceEquals (s, null)) { return false;}

            // Optimization for common success case where references are same.
            if (ReferenceEquals (this, s)) { return true;}

            // If not of the exact same class type.
            if (this.GetType() != s.GetType()) { return false;}

            // Ok now need to do field matching.
	        if (this.Attributes.Count != s.Attributes.Count) { return false; }

	        if (this.FullPath != s.FullPath) { return false; }

            // Now validate the Attributes are exactly the same.
	        foreach (KeyValuePair<string, string> a in this.Attributes) {
	            string val;
	            if (s.Attributes.TryGetValue (a.Key, out val)) {
	                if (a.Value != val) { return false; }
	            }
	            else { return false; }
	        }

	        return true;
	    }


	    public override bool Equals (object obj) { return this.Equals (obj as KV2Secret); }


	    public static bool operator == (KV2Secret left, KV2Secret right) {
	        if (ReferenceEquals (left, null)) {
                if (ReferenceEquals (right,null)) {
	                return true;
	            }
	            return false;
	        }
      
	        return left.Equals (right);
	    }


	    public static bool operator != (KV2Secret left, KV2Secret right) { return !(left == right); }


	    public override int GetHashCode() { return this.FullPath.GetHashCode(); }

        public object Clone()
        {
            // Perform a deep clone.
            KV2Secret copy = (KV2Secret) MemberwiseClone();

            // Copy the attributes
            if (Attributes != null) {
                copy.Attributes = new Dictionary<string, string>();
                foreach (KeyValuePair<string, string> attr in Attributes) { copy.Attributes.Add (attr.Key, attr.Value); }
            }

            // Copy the MetaData
            if (Metadata != null) {
                copy.Metadata = new Dictionary<string, string>();
                foreach (KeyValuePair<string, string> meta in Metadata) { copy.Metadata.Add (meta.Key, meta.Value); }
            }

            return copy;
        }

	

        #endregion

    }
}
