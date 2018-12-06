
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

		/// <summary>
		/// Createa a VaultPolicyPathItem object that will protect the given path.
		/// </summary>
		/// <param name="path">The path in Vault that this policy applies to.</param>
		public VaultPolicyPathItem (string path) {
			Path = path;
			//_isPrefixType = path.EndsWith("/") ? true : false;
		}


		/// <summary>
		/// Creates a Vault Policy object that will protect a given Prefix Path.  This is a path that ends with slash.
		/// The isPrefixPolicyType setting overrides the trailing slash on the path statement and is what determines if the Path is a PrefixType
		/// </summary>
		/// <param name="path"></param>
		/// <param name="isPrefixPolicyType"></param>
		public VaultPolicyPathItem(string path, bool isPrefixPolicyType) {
				Path = path;
				IsPrefixType = isPrefixPolicyType;
		}



		/// <summary>
		/// The path to the object being protected by this policy.  If the path contains a trailing slash it is considered a Prefix Type.  This will automatically
		/// be determined by this method and the IsPrefixType property will be set accordingly.
		/// </summary>
		public string Path {
			get => _path ;
			set {
				_path = value;

				// If object contains a trailing slash then set IsPrefixType
				_isPrefixType = value.EndsWith("/") ? true : false;
			}
		}



		public bool IsPrefixType {
			get => _isPrefixType;
			set {
				if (value) {
					// Make sure the path contains a single trailing slash.
					if (Path.EndsWith("/")) { return; }

					Path = Path + "/";
				}

				// Not a Prefix type - remove any trailing slash.
				else {
					Path = Path.TrimEnd('/');
					_isPrefixType = false;
				}
			}
		}



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





	}
}
