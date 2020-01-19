using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.System {
    /// <summary>
    /// The VaultPolicyContainer is a class that represents all the permissions associated with a given Vault policy.
    /// A Vault policy consists of one or more Vault paths and the associated permissions to be granted on that path.
    /// </summary>
    public class VaultPolicyContainer {
        private string _name;


        /// <summary>
        /// Creates a Vault Policy Container with the given name.  The name is stored in lower case in the Vault Instance.
        /// </summary>
        /// <param name="name"></param>
        public VaultPolicyContainer (string name) {
            Name = name;
            PolicyPaths = new Dictionary<string, VaultPolicyPathItem>();
        }



        /// <summary>
        /// The name of this policy.  Vault stores all policies as lower case values and so it is converted to all lower case when setting the value. 
        /// </summary>
        public string Name
		{
			get => _name;
	        set => _name = value.ToLower();
		}



		/// <summary>
		/// Provides access to the set of policy paths that make up this overall security policy.
		/// Callers should typicall only use this to loop thru list.  They should call AddPolicyPathItem and GetPolicyPathItem to add/retrieve a specific policy path item.
		/// </summary>
		public Dictionary<string, VaultPolicyPathItem> PolicyPaths { get; private set; }



        /// <summary>
        /// Will add a new VaultPolicyPathItem based upon the provided path parameter OR return a reference to an already existing VaultPolicyPathItem if the path is already
        /// in the PolicyPaths dictionary.  This is necessary to handle the KV2 ACL policies which have different path prefixes, but which we want to handle as a single object.
        /// The VaultPolicyPathItem class now handles for this situation.  When reading policies from a Vault Instance this should be the method used to create the
        /// VaultPolicyPathItem objects.
        /// <para>
        /// Returns: True if the item DID NOT exist and it was added.  Returns the new object in the out parameter.
        /// </para>
        /// <para>
        /// Returns: False if the item DID exist.  Will return the EXISTING VaultPolicyPathItem in the out parameter.
        /// </para>
        /// </summary>
        /// <param name="path">The path to add to this policies permission list.  If the path already exists in the list then the existing object is returned.
        /// Otherwise a new defaulted object is returned.</param>
        /// <param name="vaultPolicyPathItem">The VaultPolicyPathItem that was addeed or if it already existed, the existing one</param>
        /// <returns></returns>
        public bool TryAddPath (string path, out VaultPolicyPathItem vaultPolicyPathItem) {
            string key = VaultPolicyPathItem.CalculateKeyValue (path);
            VaultPolicyPathItem vppi;

            if ( PolicyPaths.TryGetValue (key, out vppi) ) {
                vaultPolicyPathItem = vppi;
                return false;
            }

            vppi = new VaultPolicyPathItem (path);
            PolicyPaths.Add (vppi.Key, vppi);
            vaultPolicyPathItem = vppi;
            return true;
        }



        /// <summary>
        /// Adds the given VaultPolicyPathItem object to the protected paths List for this policy container.  Note:  The object must not already exist.
        /// </summary>
        /// <param name="vaultPolicyPathItem">The VaultPolicyPathItem to be added to this policies permission list.</param>
        /// <returns>True on success.</returns>
        public bool AddPolicyPathObject (VaultPolicyPathItem vaultPolicyPathItem) {
            PolicyPaths.Add (vaultPolicyPathItem.Key, vaultPolicyPathItem);
            return true;
        }
    }
}