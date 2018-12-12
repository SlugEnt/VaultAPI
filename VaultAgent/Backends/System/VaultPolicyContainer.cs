using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.System
{
	public class VaultPolicyContainer {
	    private string _name;

		public VaultPolicyContainer(string name) {
            
			Name = name;
			PolicyPaths = new Dictionary<string,VaultPolicyPathItem>();

            //new List<VaultPolicyPathItem>();
		}


	    // The name of this policy.  Vault stores all policies as lower case values and so it is converted to all lower case when setting the value.
        public string Name {
	        get { return _name; }
	        set { _name = value.ToLower(); }
	    }



        //public List<VaultPolicyPathItem> PolicyPaths { get; private set; }
        /// <summary>
	    /// Provides access to the set of policy paths that make up this overall security policy.
	    /// Callers should typicall only use this to loop thru list.  They should call AddPolicyPathItem and GetPolicyPathItem to add/retrieve a specific policy path item.
        /// </summary>
	    public Dictionary<string,VaultPolicyPathItem> PolicyPaths { get; private set; }



        /// <summary>
        /// Will add a new VaultPolicyPathItem based upon the provided path parameter OR return a reference to an already existing VaultPolicyPathItem if the path is already
        /// in the PolicyPaths dictionary.  This is necessary to handle the KV2 ACL policies which have different path prefixes, but which we want to handle as a single object.
        /// The VaultPolicyPathItem class now handles for this situation.  When reading policies from a Vault Instance this should be the method used to create the
        /// VaultPolicyPathItem objects.
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        public VaultPolicyPathItem TryAddPath (string path) {
            string key = VaultPolicyPathItem.CalculateKeyValue (path);
            VaultPolicyPathItem vppi;

            if (PolicyPaths.TryGetValue(key, out vppi)) { return vppi; }
            vppi = new VaultPolicyPathItem(path);
            PolicyPaths.Add(vppi.Key,vppi);
            return vppi;
        }



        /// <summary>
        /// Adds the given VaultPolicyPathItem object to the protected paths List for this policy container.  Note:  The object must not already exist.
        /// </summary>
        /// <param name="vaultPolicyPathItem"></param>
        /// <returns></returns>
	    public bool AddPolicyPathObject (VaultPolicyPathItem vaultPolicyPathItem) {
            PolicyPaths.Add(vaultPolicyPathItem.Key,vaultPolicyPathItem);
            return true;
        }

	}
}
