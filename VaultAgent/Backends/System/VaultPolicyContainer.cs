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
			PolicyPaths = new List<VaultPolicyPathItem>();
		}


	    // The name of this policy.  Vault stores all policies as lower case values and so it is converted to all lower case when setting the value.
        public string Name {
	        get { return _name; }
	        set { _name = value.ToLower(); }
	    }

	    public List<VaultPolicyPathItem> PolicyPaths { get; private set; }
	}
}
