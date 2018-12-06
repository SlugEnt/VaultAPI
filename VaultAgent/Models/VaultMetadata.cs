using System;
using System.Collections.Generic;
using System.Text;

namespace VaultAgent.Models
{
    // TODO - Vaults MetaData tags are not arrays, but rather just an entire string made up of KeyValue pairs.  JSONConverter is unable to convert to Dictionaries.  Will need to write a custom converter.
	/// <summary>
	/// Used to represent the Vault Metadata object that is found as a property on many Vault internal objects. It is simply
	/// a List of KeyValuePairs in which the Key is a string and the Value is a string.
	/// </summary>
	
    public class VaultMetadata : Dictionary<string,string>
    {
/*		public Dictionary<string,string> Data;

		// Constructor
	    public VaultMetadata() {
		    Data = new Dictionary<string, string>();
	    }
*/
    }
}
