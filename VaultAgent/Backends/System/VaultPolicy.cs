using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.System
{
	public class VaultPolicy
	{
		public VaultPolicy(string name) {
			Name = name;
			PolicyPaths = new List<VaultPolicyPath>();
		}

		public string Name { get; set; }

		public List<VaultPolicyPath> PolicyPaths { get; private set; }
	}
}
