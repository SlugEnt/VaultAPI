//TODO - This only partially works for KV2 backends.  
// Need to figure out how we would do this for KV2.


using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent.Backends.System
{

	/// <summary>
	/// The VaultPolicyPathItem class is the C# object representation of a Vault Policy object with some enhancements.
	/// A Vault Policy consists of several items:  Broadly speaking it is:
	///   - The Name or Path which is the location in Vault that is to be protected.
	///   - A List of attributes that determine the rights that the policy conveys upon that path.
	/// The path consists of:
	///   |part1|/|part2|/|part3|
	///   Part1 is mandatory and is a part of every Vault Policy object.  It is the backend mount name that is being protected.  For example secret.
	///   Part3 is also mandatory and is the actual data path the policy applies to.
	///   Part2 is optional/mandatory depending on whether the policy applies to a KeyValue Version 2 path or any other path.
	///     - If the path is not a KeyValue Version 2 path, then essentially part 2 does not exist.
	///     - If it does apply to a KeyValue Version 2 path then part 2 will be one of:
	///        : metadata
	///        : data
	///        : delete
	///        : undelete
	///        : destroy
	///
	/// The backendMount, ProtectedPath IsPrefixType and IsKV2Type properties can only be set during object construction since they are a part of the objects Key value.
	///
	/// The property setters and constructor on this class will automatically set the IsKV2Policy flag to true if it finds any of those keywords as the first 
	/// part of the path (after the backend mount name).  It is critical that users not use those prefixes AT ALL in ANY backend.
	/// Likewise it will insert these setters if the policy is flagged as KV2Policy type.
	///  
	/// However, with the advent of KeyValue2 paths some changes needed to be made.
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
	public class VaultPolicyPathItem {
	    private static string[] KV2Keywords = new string[]
	    {
	        "data",
	        "metadata",
	        "delete",
	        "undelete",
	        "destroy"
	    };

	    private string _key;
	    private string _path;
	    private string _backendMount;
	    private string _protectedPath;


	    private bool _isPrefixType = false;
	    private bool _isKV2Policy = false;


        private bool _createAllowed = false;
		private bool _readAllowed = false;
		private bool _updateAllowed = false;
		private bool _deleteAllowed = false;
		private bool _listAllowed = false;
		private bool _sudoAllowed = false;
		private bool _rootAllowed = false;
		private bool _denied = true;
		

        // Extended Property
	    private bool _extKV2_DeleteAnyKeyVersion = false;
	    private bool _extKV2_UnDelete = false;
	    private bool _extKV2_DestroyVersions = false;
	    private bool _extKV2_ViewMetadata = false;
	    private bool _extKV2_DeleteMetaData = false;


        #region "Constructors"

        /// <summary>
        /// Creates a Vault Policy Path Item object.  Note, that the protectedPath parameter will be interrogated to see if it indicates that
        /// this is an IsPrefix or IsKV2 policy AND if the Answer is Yes, it WILL OVERRIDE any False setting for isPrefix and isKV2 parameters
        /// passed in.
        /// </summary>
        /// <param name="backendMount">The name/path to the backend that this policy applies to.  Note, all leading/trailing slashes are removed.</param>
        /// <param name="protectedPath">The path that this policy is applicable to.  If the path ends with a trailing slash then it is considered
        /// a PrefixPolicyType (Meaning its permissions apply to subsecrets).  If the path starts with a KV2 prefix then it will be considered to be
        /// a KV2Policy type.  </param>
        /// <param name="isPrefixPolicyType">Set to true to indicate this policy object applies to the secret and ALL subsecrets (subfolders).
        /// This value will be overriden during the path interrogation IF it is determined that the path indicates this is a PrefixType.  Thus
        /// this parameter is used only in the case where the path does not indicate whether it is a prefix type AND this parameter value is true.</param>
        /// <param name="isKV2PolicyType">Set to true to indicate that this policy object applies to a KeyValue Version 2 secret store.  In this case
        /// the path parameter will have one of the KV2 prefixes applied to it.  </param>
        public VaultPolicyPathItem (string backendMount, string protectedPath, bool? isPrefixPolicyType = null, bool? isKV2PolicyType = null) {
            // If caller specified the type of KV2 policy type then we need to set it to the value they passed in.
            if (isKV2PolicyType != null) { _isKV2Policy = (bool)isKV2PolicyType; }

            if (isPrefixPolicyType != null) { _isPrefixType = (bool)isPrefixPolicyType; }


            // Note that the ProtectedPath setter WILL OVERRIDE either of the above 2 items IF it can definitively determine that it is a KV2 path 
            // or a prefix type policy.
            _backendMount = DeriveBackendName (backendMount);
            

            // Interrogate the path.
            bool isKV2 = false;
            bool isPrefix = false;

            (_protectedPath, isKV2, isPrefix) = DeriveProtectedPath(protectedPath);

            // We override the IsPrefix and IsKV2 settings if we determined during exploration of the path that either of these was true.  
            if (isKV2) { _isKV2Policy = true; }
            if (isPrefix) { _isPrefixType = true; }


            // Now build the key 
            _key = CalculateKeyValue (_backendMount, _protectedPath, _isKV2Policy, _isPrefixType);
        }



        /// <summary>
        /// Creates a Vault Policy Path Item object.  Note, that the protectedPath parameter will be interrogated to see if it indicates that
        /// this is an IsPrefix or IsKV2 policy AND if the Answer is Yes, it WILL OVERRIDE any False setting for isPrefix and isKV2 parameters
        /// passed in.
        /// </summary>
        /// <param name="protectedPath">The path that this policy is applicable to.  If the path ends with a trailing slash then it is considered
        /// a PrefixPolicyType (Meaning its permissions apply to subsecrets).  If the path starts with a KV2 prefix then it will be considered to be
        /// a KV2Policy type.  </param>
		public VaultPolicyPathItem (string protectedPath) {
		    (_backendMount, _protectedPath, _isKV2Policy, _isPrefixType) = SeparatePathIntoComponents(protectedPath);
		    _key = CalculateKeyValue(_backendMount, _protectedPath, _isKV2Policy, _isPrefixType);
        }



        /// <summary>
        /// Creates a Vault Policy Path Item object.  Note, that the protectedPath parameter will be interrogated to see if it indicates that
        /// this is an IsPrefix or IsKV2 policy AND if the Answer is Yes, it WILL OVERRIDE any False setting for isPrefix and isKV2 parameters
        /// passed in.
        /// </summary>
        /// <param name="protectedPath">The path that this policy is applicable to.  If the path ends with a trailing slash then it is considered
        /// a PrefixPolicyType (Meaning its permissions apply to subsecrets).  If the path starts with a KV2 prefix then it will be considered to be
        /// a KV2Policy type.  </param>
        /// <param name="isPrefixPolicyType">Set to true to indicate this policy object applies to the secret and ALL subsecrets (subfolders).
        /// This value will be overriden during the path interrogation IF it is determined that the path indicates this is a PrefixType.  Thus
        /// this parameter is used only in the case where the path does not indicate whether it is a prefix type AND this parameter value is true.</param>
        /// <param name="isKV2PolicyType">Set to true to indicate that this policy object applies to a KeyValue Version 2 secret store.  In this case
        /// the path parameter will have one of the KV2 prefixes applied to it.  </param>
		public VaultPolicyPathItem(string protectedPath, bool? isPrefixPolicyType = null, bool? isKV2PolicyType = null) {
		    // If caller specified the type of KV2 policy type then we need to set it to the value they passed in.
		    if (isKV2PolicyType != null) { _isKV2Policy = (bool)isKV2PolicyType; }

		    if (isPrefixPolicyType != null) { _isPrefixType = (bool)isPrefixPolicyType; }

		    bool isKV2 = false;
		    bool isPrefix = false;

            (_backendMount, _protectedPath, isKV2, isPrefix) = SeparatePathIntoComponents(protectedPath);


            // We override the IsPrefix and IsKV2 settings if we determined during exploration of the path that either of these was true.  
		    if (isKV2) { _isKV2Policy = true;}
		    if (isPrefix) { _isPrefixType = true;}

		    _key = CalculateKeyValue(_backendMount, _protectedPath, _isKV2Policy, _isPrefixType);		
		}

        #endregion


        #region "Normal Properties"



        /// <summary>
        /// The key is simply the backend name + the protectedPath .
        /// </summary>
        public string Key {
            get => _key;
            private set { _key = CalculateKeyValue(_backendMount,_protectedPath,_isKV2Policy,_isPrefixType); }
        }



        /// <summary>
        /// The backend mount name is always the first "folder" in the Vault Instance policy path.  It is a required item.  Cannot contain any slashes.  Leading and Trailing slashes are
        /// automatically removed.
        /// </summary>
        public string BackendMountName {
            get => _backendMount;
        }



        /// <summary>
        /// Derives the Backend Name from the provided value.
        /// </summary>
        /// <param name="backendName"></param>
        /// <returns></returns>
	    public static string DeriveBackendName (string backendName) {
	        // We remove any trailing or leading slashes.
            string tempName=  backendName.Trim('/');
	        if (tempName.Contains("/")) { throw new ArgumentException("The backendMount cannot be a path.  You provided " + backendName + " as the value for the backendMount."); }

	        return tempName;
	    }




        /// <summary>
        /// The ProtectedPath is the Vault path (excluding the mount name) that the policy applies to.
        /// There are some words of Caution:
        ///  1) You should never use any of the restricted KV2Policy prefixes as the start of any path in ANY backend.  Doing so will cause the policies to not work.
        ///     You have been warned.  These are:  metadata, data, destroy, delete, undelete.
        ///  2) Setting this property after initial construction will never override the IsPrefix and IsKV2 properties.  You must manually adjust those after object creation.
        /// Important Note:  If you provide a trailing slash then the IsPrefixType flag is set to true.  However, the opposite is not true.  If you do not specify
        /// a trailing slash then the IsPrefixType is not set to false, but rather remains unchanged.  You should use the IsPrefixType property to unset the value.
        /// </summary>
        public string ProtectedPath {
            get => _protectedPath;
        }



        /// <summary>
        /// Deconstructs the protected path part of the path
        /// </summary>
        /// <param name="pathValue"></param>
        /// <returns></returns>
	    public static (string protectedPath, bool isKV2Type, bool isPrefixType) DeriveProtectedPath (string pathValue) {
	        bool isKv2Type = false;
	        bool prefixType = false;

	        // Remove any leading slash.
	        string tempPath = pathValue.TrimStart('/');



	        // Now see if the string starts with any KV2 reserved words.  If it does we remove the reserved word and set the KV2 flag.
	        foreach (string s in KV2Keywords)
	        {
	            if (tempPath.StartsWith(s))
	            {
	                isKv2Type = true;
	                tempPath = tempPath.Substring(s.Length + 1);
	            }
	        }


	        int length = tempPath.Length;

	        // See if trailing slash.  Then it is a prefix type.
	        if (pathValue.EndsWith("/")) {
	            prefixType = true;
	            length--;
	            tempPath = tempPath.TrimEnd('/');
	        }

	        return (tempPath.Substring (0, length), isKv2Type, prefixType);
	    }



        /// <summary>
        /// Returns the normal full Vault policy path for this item.  This is what Vault expects to see as the path.  This will one of the following, but only one:
        ///   - For non-KV2 policies = The backendmount + the protectedPath + the trailing slash if IsPrefixType.
        ///   - For KV2-Policies = the backendmount + "/data/" + the ProtectedPath plus the trailing slash if IsPrefixType.
        /// It will never return the Extended KV2 properties path other than the /data/ one.
        /// </summary>
        public string FullPath {
	        get {
	            string trailer;

	            if (IsPrefixType) { trailer = "/"; }
	            else { trailer = "";}

	            if (_isKV2Policy) { return (_backendMount + "/data/" + _protectedPath + trailer);}
                else { return (_backendMount + "/" + _protectedPath + trailer); }
	            
	        }
	    }




        /// <summary>
        /// The IsPrefix property is used to determine if a Vault policy is a prefixed policy. This just means does it apply to just a 
        /// </summary>
		public bool IsPrefixType {
			get => _isPrefixType;
			//private set {
			//    _isPrefixType = value;
			//}
		}

    

        /// <summary>
        /// Sets/Gets whether a policy Item refers to a Vault KeyValue2 policy.  This is important because KV2 paths are different than all other backend type paths.
        /// Specifically all data is stored at backendMount/data/|rest of path|.  When this flag is set to true, it turns on the extended security settings that
        /// KV2 backends support.  In addition the fullPath that is returned is altered to include the KV2 security prefix inside of it.  The KV2 security prefix is
        /// the 2nd path from the left.  So backend1/data/path/pathb/pathc.  data is the KV2 security prefix.
        /// </summary>
	    public bool IsKV2Policy
	    {
	        get => _isKV2Policy;
	        //private set { _isKV2Policy = value; }
	    }

    #endregion
 

        #region "Security Settings"


        /// <summary>
        /// Sets the Create allowed attribute.
        /// </summary>
        public bool CreateAllowed {
			get => _createAllowed; 
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


        #region "Extended Properties"


	    /// <summary>
	    /// Only applies to KeyValue2 policy paths.  When true the permission to delete any version of a secret is enabled.
	    /// </summary>
	    public bool ExtKV2_DeleteAnyKeyVersion {
	        get => _extKV2_DeleteAnyKeyVersion;
	        set {
	            _extKV2_DeleteAnyKeyVersion = value;
	            _isKV2Policy = true;
	        }
	    }



	    /// <summary>
	    /// Only applies to KeyValue2 policy paths.  When true the permission to undelete a secret is enabled.
	    /// </summary>
        public bool ExtKV2_UndeleteSecret {
	        get => _extKV2_UnDelete;
	        set { _extKV2_UnDelete = value;
	            _isKV2Policy = true;
	        }
	    }



	    /// <summary>
	    /// Only applies to KeyValue2 policy paths.  When true the permission to destroy the versions of a secret is enabled.
	    /// </summary>
        public bool ExtKV2_DestroySecret {
	        get => _extKV2_DestroyVersions;
	        set { _extKV2_DestroyVersions = value;
	            _isKV2Policy = true;
	        }
	    }



	    /// <summary>
	    /// Only applies to KeyValue2 policy paths.  When true the permission to view the metadata for a given secret is enabled.
	    /// </summary>
        public bool ExtKV2_ViewMetaData {
	        get => _extKV2_ViewMetadata;
	        set { _extKV2_ViewMetadata = value;
	            _isKV2Policy = true;
	        }
	    }




	    /// <summary>
	    /// Only applies to KeyValue2 policy paths.  When true the permission to delete the metadata for a given secret is enabled.
	    /// </summary>
	    public bool ExtKV2_DeleteMetaData {
            get => _extKV2_DeleteMetaData;
	        set { _extKV2_DeleteMetaData = value;
	            _isKV2Policy = true;
	        }
	    }
        #endregion




        /// <summary>
        /// Takes a path string and decomposes it into its backend, protectedPath components and determines if the path indicates whether this is
        /// a prefix type path or KV2 policy path.
        /// </summary>
        /// <param name="path">The path object to be analyzed and decomposed.</param>
        /// <returns>Tuple:  (Backend, protectedPath, isKV2Policy, isPrefixType</returns>
	    private static (string backend, string protectedPath, bool isKV2Policy, bool isPrefixType) SeparatePathIntoComponents (string path) {
	        // Now find first slash.  Everything up to it becomes the backendMount name.
	        int pos = path.IndexOf('/', 1);

	        string backendMount = DeriveBackendName(path.Substring(0, pos));

	        // Everything after is the path.

	        (string protectedPath,  bool isKV2Policy,  bool isPrefixType) = DeriveProtectedPath(path.Substring(pos + 1));
	        return (backendMount, protectedPath, isKV2Policy, isPrefixType);
	    }


        

        /// <summary>
        /// Returns the key value given the provided path.  This version is used by external entities who wish to know what the key value is given a particular
        /// path object.  Internal routines should use the multiple parameter version.
        /// </summary>
        /// <param name="path">The path to calculate a key value for.</param>
        /// <returns>String:  What the key is given the path.</returns>
	    public static string CalculateKeyValue (string path) {
	        string backend;
	        string protectedPath;
	        bool isKV2Policy;
	        bool isPrefixType;

	        (backend, protectedPath, isKV2Policy, isPrefixType) = SeparatePathIntoComponents (path);

            return CalculateKeyValue (backend, protectedPath, isKV2Policy, isPrefixType);
	    }



	    /// <summary>
	    /// Returns the VaultPolicyPathItem Key value based upon the passed in values.  Should be used by internal routines.
	    /// </summary>
	    /// <param name="backend">The Backend Mount component of the object.</param>
	    /// <param name="protectedPath">The path that the policy is protecting.</param>
	    /// <param name="isKV2">True if the path object represents a KeyValue version 2 ACL property.</param>
	    /// <param name="isPrefix">True if the path object represents sub items of the current path.</param>
	    /// <returns></returns>
	    private static string CalculateKeyValue (string backend, string protectedPath, bool isKV2, bool isPrefix) {
	        string iKV2 = isKV2 ? "1" : "0";
	        string iPrefix = isPrefix ? "/" : "";

	        return backend + "/" + protectedPath + iPrefix + "::" + iKV2;
	    }




        /// <summary>
        /// Returns the Vault HCL policy text for this object.  This can then be inserted into the overall Policy object and sent to Vault.  This may result in the
        /// output of multiple path statements.
        /// </summary>
        /// <returns></returns>
	    public string ToVaultHCLPolicyFormat() {
            StringBuilder policyHCLFormat = new StringBuilder();
            List<string> permissions = new List<string>(20);
            
            

            // Build the normal permissions path object
            if (_denied) { permissions.Add ("deny"); }
            else {
                if (_createAllowed) { permissions.Add ("create"); }

                if (_readAllowed) { permissions.Add ("read"); }

                if (_deleteAllowed) { permissions.Add ("delete"); }

                if (_updateAllowed) { permissions.Add ("update"); }

                if (_sudoAllowed) { permissions.Add ("sudo"); }

                if (_rootAllowed) { permissions.Add ("root"); }

                if (_listAllowed) { permissions.Add ("list"); }
            }

            // Now build path statement if permissions list contains at least 1 entry for the normal permissions.
            // This will build either a /backend/patha/pathb path or a /backend/data/patha/pathb object.
            if (permissions.Count > 0) {
                policyHCLFormat =  BuildHCLPolicyPathStatement(this.FullPath, permissions);
                if (!_isKV2Policy) { return policyHCLFormat.ToString(); }

                // Now check for extended properties in KV2 and return them.
                permissions.Clear();

                // Check MetaData Permissions.  These will be assigned to the MetaData path.
                if (_extKV2_ViewMetadata) { permissions.Add("read");}

                if (_extKV2_DeleteMetaData) { permissions.Add ("delete"); }

                if (_listAllowed) { permissions.Add("list");}

                if (permissions.Count > 0) { policyHCLFormat.Append (BuildHCLPolicyPathStatement (_backendMount + "/metadata/" + _protectedPath + "/*",permissions)); }

                permissions.Clear();


                // Now check the other extended permissions.  Each has its own call.
                if (_extKV2_DeleteAnyKeyVersion) {
                    policyHCLFormat.Append (BuildHCLPolicyPathStatement (_backendMount + "/delete/" + _protectedPath + "/*", new List<string> (){"update"}));
                }
                if (_extKV2_UnDelete)
                {
                    policyHCLFormat.Append(BuildHCLPolicyPathStatement(_backendMount + "/undelete/" + _protectedPath + "/*", new List<string>() { "update" }));
                }
                if (_extKV2_DestroyVersions)
                {
                    policyHCLFormat.Append(BuildHCLPolicyPathStatement(_backendMount + "/destroy/" + _protectedPath + "/*", new List<string>() { "update" }));
                }
            }

            if (policyHCLFormat.Length > 0) { return policyHCLFormat.ToString(); }

            return "";


        }



        /// <summary>
        /// Builds a single Vault HCL formatted JSON Policy Path statement.
        /// </summary>
        /// <param name="path">The vault path that the policy applies to.</param>
        /// <param name="permissions">A List of permissions that apply to this path.</param>
        /// <returns></returns>
	    private StringBuilder BuildHCLPolicyPathStatement (string path, List<string> permissions ) {
	        StringBuilder jsonSB = new StringBuilder();

            // Path header statement
	        jsonSB.Append(" path \\\"" + path);
	        jsonSB.Append("\\\" { capabilities = [");


            // Now build fields
	        foreach (string field in permissions) {
	            jsonSB.Append ("\\\"" + field + "\\\",");
            }


	        // Remove last comma.
	        if (permissions.Count > 0)
	        {
	            char val = jsonSB[jsonSB.Length - 1];
	            if (val.ToString() == ",") { jsonSB.Length -= 1; }
	        }


            // Close out this path entry.
            jsonSB.Append("]} ");

	        return jsonSB;
        }
    }
}
