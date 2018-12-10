//TODO - This only partially works for KV2 backends.  
// Need to figure out how we would do this for KV2.


using System;

namespace VaultAgent.Backends.System
{
	/// <summary>
	/// The VaultPolicyPathItem class is the C# object representation of a Vault Policy object.
	/// A Vault Policy consists of 2 main items:
	///   - The Name or Path which is the location in Vault that is to be protected.
	///   - A List of attributes that determine the rights that the policy conveys upon that path.
	/// There are 8 supported attributes that a Vault Policy can have.
	///   Create  - Allows creating data at the given path. Very few parts of Vault distinguish between create and update, so most operations require both
	///				create and update capabilities. Parts of Vault that provide such a distinction are noted in documentation.
	///   Read    - Allows reading the data.
	///   Update  - Allows changing the data at the given path. In most parts of Vault, this implicitly includes the ability to create the initial value at the path.
	///   Delete  - Allows deleting of the data.
	///   List (Only certain policies can have list capability) - Allows listing values at the given path. Note that the keys returned by a list operation are
	///				not filtered by policies. Do not encode sensitive information in key names. Not all backends support listing.
	///   Sudo    - Allows access to paths that are root-protected. Tokens are not permitted to interact with these paths unless they are have the sudo capability
	///				(in addition to the other necessary capabilities for performing an operation against that path, such as read or delete).
	///   Root    -  //TODO - seems to be gone...
	///   Deny    - Overrides all other attributes.  Prevents any access to the protected path.
	/// </summary>
	public class VaultPolicyPathItem
	{
		private bool _createAllowed = false;
		private bool _readAllowed = false;
		private bool _updateAllowed = false;
		private bool _deleteAllowed = false;
		private bool _listAllowed = false;
		private bool _sudoAllowed = false;
		private bool _rootAllowed = false;
		private bool _denied = true;
		private bool _isPrefixType = false;
		private string _path;
	    private string _backendMount;
	    private string _protectedPath;


	    public VaultPolicyPathItem (string backendMount, string protectedPath, bool isPrefixPolicyType) {
	        BackendMountName = backendMount;
	        ProtectedPath = protectedPath;
	        IsPrefixType = isPrefixPolicyType;
	    }



		/// <summary>
		/// Creates a VaultPolicyPathItem object that will protect the given path.  The very first "path item" (Everything up to the first slash) is marked as the backendMount.
		/// This is the legacy constructor for backward compatibility.  Preference should be given to using the new constructor whenever possible.
		/// </summary>
		/// <param name="path">The path in Vault that this policy applies to.</param>
		public VaultPolicyPathItem (string path) {
            SeparatePathIntoComponents(path);
		}



		/// <summary>
		/// Creates a Vault Policy object that will protect a given Prefix Path.  This is a path that ends with slash.
		/// The isPrefixPolicyType setting overrides the trailing slash on the path statement and is what determines if the Path is a PrefixType
		/// An IsPrefixPolicy contains a trailing slash.
		/// </summary>
		/// <param name="path"></param>
		/// <param name="isPrefixPolicyType"></param>
		public VaultPolicyPathItem(string path, bool isPrefixPolicyType) {
            SeparatePathIntoComponents(path);
			IsPrefixType = isPrefixPolicyType;
		}



        /// <summary>
        /// The backend mount name is always the first "folder" in the Vault Instance policy path.  It is a required item.  Cannot contain any slashes.  Leading and Trailing slashes are
        /// automatically removed.
        /// </summary>
        public string BackendMountName { get => _backendMount;
            set {
                // We remove any trailing or leading slashed.
                _backendMount = value.Trim('/');
                if (_backendMount.Contains("/")) { throw new ArgumentException("The backendMount cannot be a path.  You provided " + value + " as the value for the backendMount."); }
            }
        }



        /// <summary>
        /// The ProtectedPath is the Vault path (excluding the mount name) that the policy applies to.
        /// </summary>
        public string ProtectedPath {
            get => _protectedPath;
            set {
                // Remove any leading slash.
                string tempPath = value.TrimStart ('/');
                int length = tempPath.Length;

                // See if trailing slash.  Then it is a prefix type.
                if (value.EndsWith ("/")) {
                    IsPrefixType = true;
                    length = length - 1;
                    tempPath = tempPath.TrimEnd ('/');
                }

                _protectedPath = tempPath.Substring(0,length);
            }

            
        }



		/// <summary>
		/// The path to the object being protected by this policy.  If the path contains a trailing slash it is considered a Prefix Type.  This will automatically
		/// be determined by this method and the IsPrefixType property will be set accordingly.
		/// </summary>
		[Obsolete]
		public string Path {
			get => _protectedPath;
			set {
			    ProtectedPath = value;
			}
		}



        /// <summary>
        /// The IsPrefix property is used to determine if a Vault policy is a prefixed policy. This just means does it apply to just a 
        /// </summary>
		public bool IsPrefixType {
			get => _isPrefixType;
			set {
			    _isPrefixType = value;
			}
		}



        #region "Security Settings"


        /// <summary>
        /// Sets the Create allowed attribute.
        /// </summary>
        public bool CreateAllowed {
			get => _createAllowed; //{ return _createAllowed; }
			set {
				_denied = false;
				_createAllowed = value;
			}
		}



		/// <summary>
		/// Sets the Read allowed attribute.
		/// </summary>
		public bool ReadAllowed
		{
			get => _readAllowed;
			set {
				_denied = false;
				_readAllowed = value;
			}
		}



		/// <summary>
		/// Sets the Update allowed attribute.
		/// </summary>
		public bool UpdateAllowed
		{
			get { return _updateAllowed; }
			set {
				_denied = false;
				_updateAllowed = value;
			}
		}



		/// <summary>
		/// Sets the Delete allowed attribute.
		/// </summary>
		public bool DeleteAllowed
		{
			get { return _deleteAllowed; }
			set {
				_denied = false;
				_deleteAllowed = value;
			}
		}



		/// <summary>
		/// Sets the List allowed attribute - If the policy object is of a type that can be Listed.
		/// </summary>
		public bool ListAllowed
		{
			get { return _listAllowed; }
			set {
				_denied = false;
				_listAllowed = value;
			}
		}


		/// <summary>
		/// Sets the Sudo allowed attribute.  Sudo allows access to paths that are root-protected.  Tokens are not allowed to access these paths unless they have the sudo capability.
		/// </summary>
		public bool SudoAllowed
		{
			get { return _sudoAllowed; }
			set {
				_denied = false;
				_sudoAllowed = value;
			}
		}

		public bool RootAllowed
		{
			get { return _rootAllowed; }
			set {
				_denied = false;
				_rootAllowed = value;
			}
		}



	/// <summary>
	/// Either sets denied property or cancels it.  If setting Denied to True, then ALL other permissions are set to False.  
	/// If setting denied to false and it was True, then none of the other permissions are changed (they remain false), you must manually enable the ones you want.
	/// </summary>
	public bool Denied
		{
			get { return _denied; }
			set {
				if (value == true) {
					_createAllowed = false;
					_readAllowed = false;
					_updateAllowed = false;
					_deleteAllowed = false;
					_listAllowed = false;
					_sudoAllowed = false;
					_rootAllowed = false;
				}
			}
		}



		/// <summary>
		/// Shortcut method for setting or getting a CRUD value (Whether the policy path item has Create, Read, Update and Delete all set to true.  Returns True
		/// if all 4 are set to true, False otherwise.  During Set operations, it will automatically set all of the values to the value specified (true or false)
		/// </summary>
		public bool CRUDAllowed {
			get {
				if ((_createAllowed) && (_readAllowed) && (_updateAllowed) && (_deleteAllowed)) {
					return true;
				}
				else {
					return false;
				}
			}

			set {
				CreateAllowed = value;
				ReadAllowed = value;
				UpdateAllowed = value;
				DeleteAllowed = value;
			}
		}



        /// <summary>
        /// A Shortcut method to setting full control for a given path.  This sets Create, Read, Update, Delete AND List to the value specified.
        /// </summary>
	    public bool FullControl {
	        get {
	            if ((_createAllowed) && (_readAllowed) && (_updateAllowed) && (_deleteAllowed) && (_listAllowed))
	            {
	                return true;
	            }
	            else
	            {
	                return false;
	            }

            }
            set {
	            CRUDAllowed = value;
	            ListAllowed = value;
	        }
	    }
        #endregion 


        /// <summary>
        /// This routine is used to break out a single path item into its separate components - BackendMount and ProtectedPath as well as set the IsPrefixType flag.  
        /// </summary>
        /// <param name="path"></param>
        private void SeparatePathIntoComponents (string path) {
            string tempPath = path.TrimStart('/');

            // Now find first slash.  Everything up to it becomes the backendMount name.
            int pos = tempPath.IndexOf('/');
            _backendMount = tempPath.Substring(0, pos);


            // Everything after is the path.
            ProtectedPath = path.Substring (pos+1);
        }
    }
}
