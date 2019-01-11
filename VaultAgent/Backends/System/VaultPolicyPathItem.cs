//TODO - This only partially works for KV2 backends.  
// Need to figure out how we would do this for KV2.


using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace VaultAgent.Backends.System {
    /// <summary>
    /// The VaultPolicyPathItem class is the C# object representation of a Vault Policy object with some enhancements.
    /// A Vault Policy consists of several items:  Broadly speaking it is:
    ///   <para>  - The Name or Path which is the location in Vault that is to be protected.</para>
    ///   <para>  - A List of attributes that determine the rights that the policy conveys upon that path.</para>
    /// <para>The path consists of:    |part1|/|part2|/|part3|</para>
    /// <para>  Part1 is mandatory and is a part of every Vault Policy object.  It is the backend mount name that is being protected.  For example secret.</para>  
    /// <para>  Part3 is also mandatory and is the actual data path the policy applies to.</para>
    /// <para>  Part2 is optional/mandatory depending on whether the policy applies to a KeyValue Version 2 path or any other path.</para>
    /// <para>   - If the path is not a KeyValue Version 2 path, then essentially part 2 does not exist.</para> 
    /// <para>   - If it does apply to a KeyValue Version 2 path then part 2 will be one of:</para>
    /// <para>       : metadata</para>
    /// <para>       : data</para>
    /// <para>       : delete</para>
    /// <para>       : undelete</para>
    /// <para>       : destroy</para>
    ///
    /// The backendMount and ProtectedPath properties can only be set during object construction since they are a part of the objects Key value.
    ///
    /// The property setters and constructor on this class will automatically set the IsKV2Policy flag to true if it finds any of those keywords as the first 
    /// part of the path (after the backend mount name).  It is critical that users not use those SubFolders AT ALL in ANY backend.
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
    ///
    ///
    /// <para>
    /// Vault Inner workings.  Vault can store the permissions for a GIVEN path in one of 3 manners and in some instances requires that a given object be split
    /// across several paths in order to assign permissions and in fact with KV2 permissions this gets assigned as many as 6 different paths.
    /// </para>
    /// <para>In essence there are 3 path endings that determine how a particular set of permissions applies: </para>
    /// <para>  - backend/secretA/*  /* pattern = Means the permission applies to all SubSecrets of secretA, but NOT secretA itself.
    /// List can also be specified with this pattern.</para>
    /// <para>  - backend/secretA/   /  pattern = This is only valid when setting the list permission.  Note /* pattern also works for List permission.</para>
    /// <para>  - backend/secretA    secret pattern = This means the permissions only apply directly to secretA and NOT ANY subsecrets.</para>
    /// <para></para>
    /// <para> With the above knowledge.  We are making the following rules:</para>
    /// <para>   - We will always save List permissions with the /* pattern as it applies to other permissions as well.</para>
    /// <para>   - We will never save List permission with the / pattern.</para>
    /// <para>   - When saving attributes of a secret we always use the secret pattern (no trailing anything).</para>
    /// <para>   - When saving subsecrets we always use /* pattern.</para>
    /// <para>   - We will interpret policies read from Vault with the / or /* pattern and  list permission, but always store the path as the /* upon a save.</para>
    /// </summary>
    public class VaultPolicyPathItem {
        private static string [] KV2Keywords = new string [] {"data", "metadata", "delete", "undelete", "destroy"};

        private string _key;
        private string _path;
        private string _backendMount;
        private string _protectedPath;
        private string _KV2_PathID = ""; // The KeyValue2 Path SubFolder that this object had upon creation.  See Property for details.

        private bool _isSubFolderType = false;
        private bool _isKV2Policy = false;


        private bool _createAllowed = false;
        private bool _readAllowed = false;
        private bool _updateAllowed = false;
        private bool _deleteAllowed = false;
        private bool _listAllowed = false;
        private bool _sudoAllowed = false;
        private bool _rootAllowed = false;
        private bool? _denied = null;


        // Extended Property
        private bool _extKV2_DeleteAnyKeyVersion = false;
        private bool _extKV2_UnDelete = false;
        private bool _extKV2_DestroyVersions = false;
        private bool _extKV2_ViewMetadata = false;
        private bool _extKV2_DeleteMetaData = false;
        private bool _extKV2_ListMetaData = false;


        #region "Constructors"


        /// <summary>
        /// Creates a Vault Policy Path Item object.  Note, that the protectedPath parameter will be interrogated to see if it indicates that
        /// this is an IsSubFolder or IsKV2 policy AND if the Answer is Yes, it WILL OVERRIDE any False setting for isSubFolder and isKV2 parameters
        /// passed in.
        /// </summary>
        /// <param name="backendMount">The name/path to the backend that this policy applies to.  Note, all leading/trailing slashes are removed.</param>
        /// <param name="protectedPath">The path that this policy is applicable to.  If the path ends with a trailing slash or a trailing /* then it is considered
        /// a SubFolderPolicyType (Meaning its permissions apply to subsecrets only).
        /// If the path starts with a KV2 prefix then it will be considered to be a KV2Policy type.  </param>
        public VaultPolicyPathItem (string backendMount, string protectedPath) {
            _backendMount = DeriveBackendName (backendMount);


            // Interrogate the path.
            bool isKV2 = false;
            bool isSubFolder = false;

            (_protectedPath, isKV2, isSubFolder, _KV2_PathID) = DeriveProtectedPath (protectedPath);

            // We override the IsSubFolder and IsKV2 settings if we determined during exploration of the path that either of these was true.  
            if ( isKV2 ) { _isKV2Policy = true; }

            if ( isSubFolder ) { _isSubFolderType = true; }


            // Now build the key 
            _key = CalculateKeyValue (_backendMount, _protectedPath);
        }



        /// <summary>
        /// Creates a Vault Policy Path Item object.  Note, that the protectedPath parameter will be interrogated to see if it indicates that
        /// this is an IsSubFolder or IsKV2 policy AND if the Answer is Yes, it WILL OVERRIDE any False setting for isSubFolder and isKV2 parameters
        /// passed in.
        /// </summary>
        /// <param name="protectedPath">The path that this policy is applicable to and it must include the backend as the first part of the path in this method call.
        /// The following reserved words immediately following the backend mount name mean something special to KeyValue V2 backends and thus should never be used to identify
        /// the start of the path in ANY backend.  This class treats those as Extended Attribute Identifiers and the paths will not protect what you think:
        /// <para>    You have been warned.  These are:  metadata, data, destroy, delete, undelete.</para>
        /// 
        /// If the path ends with a trailing slash or /* then it is considered a SubSecretPolicyType (Meaning its permissions apply to subsecrets).
        /// If the path starts with a KV2 SubFolder then it will be considered to be a KV2Policy type.  </param>
        public VaultPolicyPathItem (string protectedPath) {
            (_backendMount, _protectedPath, _isKV2Policy, _isSubFolderType, _KV2_PathID) = SeparatePathIntoComponents (protectedPath);
            _key = CalculateKeyValue (_backendMount, _protectedPath);
        }



        /// <summary>
        /// Constructor for creating a KeyValue2 (KV2) type of policy object.  True must be the first parameter or else an exception will be thrown.  In addition the
        /// protectedPath parameter MUST NOT contain the KV2 path prefix (data, metadata, etc).  If it does you will end up with a true protected path of /backend/data/data/pathA/pathB/secret
        /// </summary>
        /// <param name="KeyValue2Type">MUST BE TRUE.  If set to false it will throw an error.</param>
        /// <param name="backendMount">The name/path to the backend that this policy applies to.  Note, all leading/trailing slashes are removed.</param>
        /// <param name="protectedPath">The path that this policy is applicable to.  If the path ends with a trailing slash or a trailing /* then it is considered
        /// a SubFolderPolicyType (Meaning its permissions apply to subsecrets only). 
        public VaultPolicyPathItem (bool KeyValue2Type, string backendMount, string protectedPath) {
            bool isKV2;
            bool isSubFolder = false;


            if ( KeyValue2Type == false ) {
                throw new ArgumentException (
                    "The KeyValue2Type parameter MUST be set to TRUE when calling this variant of the VaultPolicyPathItem constructor.");
            }

            // Set KV2 Policy setting to true.
            _isKV2Policy = true;

            _backendMount = DeriveBackendName (backendMount);


            // We strip out any KV2 prefixes from the path (so we do not duplicate) 
            (_protectedPath, isKV2, isSubFolder, _KV2_PathID) = DeriveProtectedPath (protectedPath);

            // We override the IsSubFolder setting if we determined during exploration of the path that either of these was true.  
            if ( isSubFolder ) { _isSubFolderType = true; }


            // Now build the key 
            _key = CalculateKeyValue (_backendMount, _protectedPath);
        }


        #endregion


        #region "Normal Properties"


        /// <summary>
        /// The key is simply the backend name + the protectedPath .
        /// </summary>
        public string Key {
            get => _key;
            private set { _key = CalculateKeyValue (_backendMount, _protectedPath); }
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
            string tempName = backendName.Trim ('/');
            if ( tempName.Contains ("/") ) {
                throw new ArgumentException ("The backendMount cannot be a path.  You provided " + backendName + " as the value for the backendMount.");
            }

            return tempName;
        }



        /// <summary>
        /// The ProtectedPath is the Vault path (excluding the mount name) that the policy applies to. There are some words of Caution:
        /// <para> -  You should never use any of the restricted KV2Policy SubFolders as the start of any path in ANY backend.  Doing so will cause the policies to not work.</para>
        /// <para>    You have been warned.  These are:  metadata, data, destroy, delete, undelete.</para>
        /// </summary>
        public string ProtectedPath {
            get => _protectedPath;
        }



        /// <summary>
        /// Deconstructs the protected path part of the path
        /// </summary>
        /// <param name="pathValue">The path to be deconstructed.</param>
        /// <returns></returns>
        public static (string protectedPath, bool isKV2Type, bool isSubFolderType, string KV2_PathSubFolder) DeriveProtectedPath (string pathValue) {
            bool isKv2Type = false;
            bool SubFolderType = false;

            // Remove any leading slash.
            string tempPath = pathValue.TrimStart ('/');
            string KV2_PathSubFolder = "";


            // Now see if the string starts with any KV2 reserved words.  If it does we remove the reserved word and set the KV2 flag.
            foreach ( string s in KV2Keywords ) {
                if ( tempPath.StartsWith (s) ) {
                    isKv2Type = true;
                    tempPath = tempPath.Substring (s.Length + 1);
                    KV2_PathSubFolder = s;
                }
            }


            // See if trailing slash.  Then it is a SubFolder type.
            if ( pathValue.EndsWith ("/*") ) { SubFolderType = true; }

            // If it ends with a slash we automatically add the * for consistency.
            else if ( pathValue.EndsWith ("/") ) {
                SubFolderType = true;
                return ((tempPath + "*"), isKv2Type, SubFolderType, KV2_PathSubFolder);
            }

            return (tempPath, isKv2Type, SubFolderType, KV2_PathSubFolder);
        }



        /// <summary>
        /// Returns the full Vault secret DATA path this policy applies too.
        /// <para>  - For non-KV2 policies = The backendmount + the protectedPath</para>
        /// <para>  - For KV2-Policies = the backendmount + "/data/" + the ProtectedPath</para>
        /// <para>It will never return the Extended KV2 properties path other than the /data/ one.  Thus it will never return metadata, undelete, delete and others.</para>
        /// </summary>
        public string SecretPath {
            get {
                if ( _isKV2Policy ) { return (_backendMount + "/data/" + _protectedPath); }
                else { return (_backendMount + "/" + _protectedPath); }
            }
        }



        /// <summary>
        /// Returns true if this object protects SubSecrets or is only relevant to the specific secret path identified.
        /// </summary>
        public bool IsSubFolderType {
            get => _isSubFolderType;
        }



        /// <summary>
        /// Gets whether a policy Item refers to a Vault KeyValue2 policy.  This is important because KV2 paths are different than all other backend type paths.
        /// Specifically all data is stored at backendMount/data/|rest of path|.  When this flag is set to true, it turns on the extended security settings that
        /// KV2 backends support.  In addition the fullPath that is returned is altered to include the KV2 security SubFolder inside of it.  The KV2 security SubFolder is
        /// the 2nd path from the left.  So backend1/data/path/pathb/pathc.  data is the KV2 security SubFolder.
        /// </summary>
        public bool IsKV2Policy {
            get => _isKV2Policy;
        }



        /// <summary>
        /// The KV2_PathID is the value of the path SubFolder on a KeyValue Version 2 ACL policy path.  For example given the below Vault KV2 ACL Policy path:
        /// backendA/metadata/path1/pathB.
        /// The KV2_PathID would be metadata.
        /// This is necessary to know when reading policies from the Vault Instance and trying to convert them into VaultPolicyPathItem objects.  Since this C#
        /// class combines multiple Vault paths into a single path, when creating the objects from Vault, we must know what the original KV2 SubFolder was so we
        /// can set the appropriate permission.  For example, the Update permission is stored both on the /data/ path as well as the /delete/ path.  We must be
        /// able to identify which is which.  This property allows us to tell that.
        /// </summary>
        public string KV2_PathID {
            get => _KV2_PathID;
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
        public bool ReadAllowed {
            get => _readAllowed;
            set {
                _denied = false;
                _readAllowed = value;
            }
        }



        /// <summary>
        /// Sets the Update allowed attribute.
        /// </summary>
        public bool UpdateAllowed {
            get { return _updateAllowed; }
            set {
                _denied = false;
                _updateAllowed = value;
            }
        }



        /// <summary>
        /// Sets the Delete allowed attribute.
        /// </summary>
        public bool DeleteAllowed {
            get { return _deleteAllowed; }
            set {
                _denied = false;
                _deleteAllowed = value;
            }
        }



        /// <summary>
        /// Sets the List allowed attribute - If the policy object is of a type that can be Listed.
        /// </summary>
        public bool ListAllowed {
            get { return _listAllowed; }
            set {
                _denied = false;
                _listAllowed = value;
            }
        }


        /// <summary>
        /// Sets the Sudo allowed attribute.  Sudo allows access to paths that are root-protected.  Tokens are not allowed to access these paths unless they have the sudo capability.
        /// </summary>
        public bool SudoAllowed {
            get { return _sudoAllowed; }
            set {
                _denied = false;
                _sudoAllowed = value;
            }
        }


        public bool RootAllowed {
            get { return _rootAllowed; }
            set {
                _denied = false;
                _rootAllowed = value;
            }
        }



        /// <summary>
        /// Sets or Gets the Denied property.  This property will have one of 3 values:
        /// <para> - Null - Upon initial object creation this value is undefined.</para>
        /// <para> - True - Was explicitly set to denied by caller.</para>
        /// <para> - False - Was explicity set to not denied by caller or by another property calling it.</para>
        /// <para>If setting Denied to True, then ALL other permissions are set to False, including all the extKV2 properties.  </para>
        /// <para>If setting denied to false and it was True, then none of the other permissions are changed (they remain false), you must manually enable the ones you want.</para>
        /// </summary>
        public bool? Denied {
            get { return _denied; }
            set {
                if ( value == true ) {
                    _createAllowed = false;
                    _readAllowed = false;
                    _updateAllowed = false;
                    _deleteAllowed = false;
                    _listAllowed = false;
                    _sudoAllowed = false;
                    _rootAllowed = false;

                    if ( IsKV2Policy ) {
                        _extKV2_DeleteAnyKeyVersion = false;
                        _extKV2_DeleteMetaData = false;
                        _extKV2_DestroyVersions = false;
                        _extKV2_ListMetaData = false;
                        _extKV2_UnDelete = false;
                        _extKV2_ViewMetadata = false;
                    }
                }

                _denied = value;
            }
        }



        /// <summary>
        /// Shortcut method for setting or getting a CRUD value (Whether the policy path item has Create, Read, Update and Delete all set to true.  Returns True
        /// if all 4 are set to true, False otherwise.  During Set operations, it will automatically set all of the values to the value specified (true or false)
        /// <para>Note:  Create,Read,Update and Allowed only means the "data" part of the Secret.  So it does not set any of the _extKV2 attributes that might
        /// use the create attribute to set a _extKV2 property value.  Those attributes are only set thru the _extKV2 properties directly.</para>
        /// </summary>
        public bool CRUDAllowed {
            get {
                if ( (_createAllowed) && (_readAllowed) && (_updateAllowed) && (_deleteAllowed) ) { return true; }
                else { return false; }
            }

            set {
                CreateAllowed = value;
                ReadAllowed = value;
                UpdateAllowed = value;
                DeleteAllowed = value;
            }
        }



        /// <summary>
        /// A Shortcut method to setting full control for a given path.  This sets Create, Read, Update, Delete AND List to the value specified.  On a KV2 type policy
        /// object it will also set all the _extKV2 attributes to true as well.
        /// </summary>
        public bool FullControl {
            get {
                if ( (_createAllowed) && (_readAllowed) && (_updateAllowed) && (_deleteAllowed) && (_listAllowed) ) {
                    if ( IsKV2Policy ) {
                        if ( (_extKV2_DeleteMetaData) &&
                             (_extKV2_DeleteAnyKeyVersion) &&
                             (_extKV2_DestroyVersions) &&
                             (_extKV2_ListMetaData) &&
                             (_extKV2_UnDelete) &&
                             (_extKV2_ViewMetadata) ) { return true; }

                        return false;
                    }

                    return true;
                }
                else { return false; }
            }
            set {
                CRUDAllowed = value;
                ListAllowed = value;

                if ( IsKV2Policy ) {
                    _extKV2_DeleteMetaData = true;
                    _extKV2_DeleteAnyKeyVersion = true;
                    _extKV2_DestroyVersions = true;
                    _extKV2_ListMetaData = true;
                    _extKV2_UnDelete = true;
                    _extKV2_ViewMetadata = true;
                }
            }
        }


        #endregion


        #region "Extended Properties"


        /// <summary>
        /// When true the permission to delete any version of a secret is enabled.  Throws InvalidOperationException if the policy is not a KV2 type policy.
        /// </summary>
        public bool ExtKV2_DeleteAnyKeyVersion {
            get => _extKV2_DeleteAnyKeyVersion;
            set {
                if ( _isKV2Policy ) { _extKV2_DeleteAnyKeyVersion = value; }
                else
                    throw new InvalidOperationException (
                        "Vault Policy Path Item is not a KeyValue Version 2 Policy Type.  Extended attributes only apply to KV2 type policies.");
            }
        }



        /// <summary>
        /// When true the permission to undelete a secret is enabled.  Throws InvalidOperationException if the policy is not a KV2 type policy.
        /// </summary>
        public bool ExtKV2_UndeleteSecret {
            get => _extKV2_UnDelete;
            set {
                if ( _isKV2Policy ) { _extKV2_UnDelete = value; }
                else
                    throw new InvalidOperationException (
                        "Vault Policy Path Item is not a KeyValue Version 2 Policy Type.  Extended attributes only apply to KV2 type policies.");
            }
        }



        /// <summary>
        /// Only applies to KeyValue2 policy paths.  When true the permission to destroy the versions of a secret is enabled.  Throws InvalidOperationException if the policy is not a KV2 type policy.
        /// </summary>
        public bool ExtKV2_DestroySecret {
            get => _extKV2_DestroyVersions;
            set {
                if ( _isKV2Policy ) { _extKV2_DestroyVersions = value; }
                else
                    throw new InvalidOperationException (
                        "Vault Policy Path Item is not a KeyValue Version 2 Policy Type.  Extended attributes only apply to KV2 type policies.");
            }
        }



        /// <summary>
        /// Only applies to KeyValue2 policy paths.  When true the permission to view the metadata for a given secret is enabled.  Throws InvalidOperationException if the policy is not a KV2 type policy.
        /// </summary>
        public bool ExtKV2_ViewMetaData {
            get => _extKV2_ViewMetadata;
            set {
                if ( _isKV2Policy ) { _extKV2_ViewMetadata = value; }
                else
                    throw new InvalidOperationException (
                        "Vault Policy Path Item is not a KeyValue Version 2 Policy Type.  Extended attributes only apply to KV2 type policies.");
            }
        }



        /// <summary>
        /// Only applies to KeyValue2 policy paths.  When true the permission to delete the metadata for a given secret is enabled.  Throws InvalidOperationException if the policy is not a KV2 type policy.
        /// </summary>
        public bool ExtKV2_DeleteMetaData {
            get => _extKV2_DeleteMetaData;
            set {
                if ( _isKV2Policy ) { _extKV2_DeleteMetaData = value; }
                else
                    throw new InvalidOperationException (
                        "Vault Policy Path Item is not a KeyValue Version 2 Policy Type.  Extended attributes only apply to KV2 type policies.");
            }
        }


        /// <summary>
        /// Ability to List KeyValue2 Versions.  Throws InvalidOperationException if the policy is not a KV2 type policy.
        /// </summary>
        public bool ExtKV2_ListMetaData {
            get => _extKV2_ListMetaData;
            set {
                if ( _isKV2Policy ) { _extKV2_ListMetaData = value; }
                else
                    throw new InvalidOperationException (
                        "Vault Policy Path Item is not a KeyValue Version 2 Policy Type.  Extended attributes only apply to KV2 type policies.");
            }
        }


        #endregion



        /// <summary>
        /// Takes a path string and decomposes it into its backend, protectedPath components and determines if the path indicates whether this is
        /// a SubFolder type path or KV2 policy path.
        /// </summary>
        /// <param name="path">The path object to be analyzed and decomposed.</param>
        /// <returns>Tuple:  (Backend, protectedPath, isKV2Policy, isSubFolderType</returns>
        private static (string backend, string protectedPath, bool isKV2Policy, bool isSubFolderType, string KV2Path) SeparatePathIntoComponents (string path) {
            // Now find first slash.  Everything up to it becomes the backendMount name.
            int pos = path.IndexOf ('/', 1);

            if ( pos == -1 ) {
                throw new VaultInvalidDataException ("Invalid value specified for the Vault Path.  Path must consist of a backend/path/path...");
            }

            string backendMount = DeriveBackendName (path.Substring (0, pos));

            // Everything after is the path.
            (string protectedPath, bool isKV2Policy, bool isSubFolderType, string KV2Path) = DeriveProtectedPath (path.Substring (pos + 1));
            return (backendMount, protectedPath, isKV2Policy, isSubFolderType, KV2Path);
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
            bool isSubFolderType;
            string KV2Path;

            (backend, protectedPath, isKV2Policy, isSubFolderType, KV2Path) = SeparatePathIntoComponents (path);

            return CalculateKeyValue (backend, protectedPath);
        }



        /// <summary>
        /// Returns the VaultPolicyPathItem Key value based upon the passed in values.  Should be used by internal routines.
        /// </summary>
        /// <param name="backend">The Backend Mount component of the object.</param>
        /// <param name="protectedPath">The path that the policy is protecting.</param>
        /// <param name="isKV2">True if the path object represents a KeyValue version 2 ACL property.</param>
        /// <param name="isSubFolder">True if the path object represents sub items of the current path.</param>
        /// <returns></returns>
        private static string CalculateKeyValue (string backend, string protectedPath) { return (backend + "/" + protectedPath); }



        /// <summary>
        /// Returns the Vault HCL policy text for this object.  This can then be inserted into the overall Policy object and sent to Vault.
        /// This may (and likely will) result in the output of multiple path statements for KeyValue V2 path statements.
        /// </summary>
        /// <returns></returns>
        public string ToVaultHCLPolicyFormat () {
            StringBuilder policyHCLFormat = new StringBuilder();
            List<string> permissions = new List<string> (20);


            // Build the normal permissions path object
            if ( _denied == true ) { permissions.Add ("deny"); }
            else {
                if ( _createAllowed ) { permissions.Add ("create"); }

                if ( _readAllowed ) { permissions.Add ("read"); }

                if ( _deleteAllowed ) { permissions.Add ("delete"); }

                if ( _updateAllowed ) { permissions.Add ("update"); }

                if ( _sudoAllowed ) { permissions.Add ("sudo"); }

                if ( _rootAllowed ) { permissions.Add ("root"); }

                //TODO - List now needs to know if it is KV2 policy type or not.
                if ( _listAllowed ) { permissions.Add ("list"); }
            }

            // Now build path statement if permissions list contains at least 1 entry for the normal permissions.
            // This will build either a /backend/patha/pathb path or a /backend/data/patha/pathb object.
            if ( permissions.Count > 0 ) { policyHCLFormat = BuildHCLPolicyPathStatement (this.SecretPath, permissions); }


            // If this is a KV2 versioned policy, then check the Extended Policy Fields.
            if ( _isKV2Policy ) {
                string kv2Path;

                // These KeyValue V2 paths must always end in /*
                if ( _protectedPath.EndsWith ("/*") ) { kv2Path = _protectedPath; }
                else if ( _protectedPath == "*" ) { kv2Path = "*"; }
                else { kv2Path = _protectedPath + "/*"; }

                // Now check for extended properties in KV2 and return them.
                permissions.Clear();

                // Check MetaData Permissions.  These will be assigned to the MetaData path.
                if ( _extKV2_ViewMetadata ) { permissions.Add ("read"); }

                if ( _extKV2_DeleteMetaData ) { permissions.Add ("delete"); }

                if ( _listAllowed || _extKV2_ListMetaData ) { permissions.Add ("list"); }

                if ( permissions.Count > 0 ) { policyHCLFormat.Append (BuildHCLPolicyPathStatement (_backendMount + "/metadata/" + kv2Path, permissions)); }

                permissions.Clear();


                // Now check the other extended permissions.  Each has its own call.
                if ( _extKV2_DeleteAnyKeyVersion ) {
                    policyHCLFormat.Append (BuildHCLPolicyPathStatement (_backendMount + "/delete/" + kv2Path, new List<string>() {"update"}));
                }

                if ( _extKV2_UnDelete ) {
                    policyHCLFormat.Append (BuildHCLPolicyPathStatement (_backendMount + "/undelete/" + kv2Path, new List<string>() {"update"}));
                }

                if ( _extKV2_DestroyVersions ) {
                    policyHCLFormat.Append (BuildHCLPolicyPathStatement (_backendMount + "/destroy/" + kv2Path, new List<string>() {"update"}));
                }
            }

            if ( policyHCLFormat.Length > 0 ) { return policyHCLFormat.ToString(); }

            return "";
        }



        /// <summary>
        /// Builds a single Vault HCL formatted JSON Policy Path statement.
        /// </summary>
        /// <param name="path">The vault path that the policy applies to.</param>
        /// <param name="permissions">A List of permissions that apply to this path.</param>
        /// <returns></returns>
        private StringBuilder BuildHCLPolicyPathStatement (string path, List<string> permissions) {
            StringBuilder jsonSB = new StringBuilder();

            // Path header statement
            jsonSB.Append (" path \\\"" + path);
            jsonSB.Append ("\\\" { capabilities = [");


            // Now build fields
            foreach ( string field in permissions ) { jsonSB.Append ("\\\"" + field + "\\\","); }


            // Remove last comma.
            if ( permissions.Count > 0 ) {
                char val = jsonSB [jsonSB.Length - 1];
                if ( val.ToString() == "," ) { jsonSB.Length -= 1; }
            }


            // Close out this path entry.
            jsonSB.Append ("]} ");

            return jsonSB;
        }



        /// <summary>
        /// This method will clear the KV2_PathID value.  This is a necessary routine in order to properly convert Vault Policies into these C# objects when
        /// reading from the Vault Instance.
        /// </summary>
        public void Clear_KV2Path () { _KV2_PathID = ""; }
    }
}