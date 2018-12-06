using System;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;


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
	public class KV2Secret {
	    private string _path;

		/// <summary>
		/// Creates a new empty secret
		/// </summary>
		public KV2Secret() {
			Attributes = new Dictionary<string, string>();
		}

//TODO Need to split namePath into Name and Path attributes.  Makes more sense and easier to use.

		/// <summary>
		/// Creates a new secret with the specified Name (Path)
		/// </summary>
		/// <param name="namePath">The secret's name or more precisely in Vault terms the path of the secret.</param>
		public KV2Secret(string secretName, string path = "") {
		    Name = secretName;
		    Path = path;
			Attributes = new Dictionary<string, string>();
		}



        /// <summary>
        /// The name of the secret.  In Vault terminology this is the very last part of the secret path.  So if a secret is stored at
        /// app/AppA/username  then the secret name would be username and the secret path would be app/AppA.  
        /// </summary>
        public string Name { get; set; }


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
	
	}
}
