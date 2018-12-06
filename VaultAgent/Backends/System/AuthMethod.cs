using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VaultAgent.Backends.System
{
	public class AuthMethod
	{
		// _typeEnum is always considered the key identifier for this object.
		private EnumAuthMethods _typeEnum;
		private string _type;
		private string _name;
		private string _path;



		/// <summary>
		/// Constructor for AuthMethod.  This is the only method that accepts the actual Vault String value.  The path value can be
		/// either the Name or Path.  It's a path if it has the trailing slash.
		/// </summary>
		/// <param name="path">String - Either the path or the name of the method.  Constructor determines which by the last character.
		/// If the last character is a trailing slash then it is a path.  If not it is a name.
		/// </param>
		/// <param name="type">String - Type of authentication method to create, specified as the backend Vault name.</param>
		[JsonConstructor]
		public AuthMethod (string path, string type) {
			// We do not call the actual property setters here, because of an endless loop situation.
			_type = type;
			_typeEnum = AuthMethodEnumConverters.EnumAuthMethodsFromString(type);
			Config = new AuthConfig();

			// We also accept a null path value.  We have to allow this because Vault does not return the path as part of the JSON object, but 
			// rather as a dictionary key element.  We are assuming that if the value is null then the caller will eventually get around to 
			// setting the path or name....
			if (path != null) { SetPathAndName(path); }
		}



		/// <summary>
		/// Constructor that accepts our EnumAuthMethod argument for constructing the method.
		/// </summary>
		/// <param name="authenticationMethod">EnumAuthMethod - Type of authentication method object to create</param>
		public AuthMethod (string path, EnumAuthMethods authenticationMethod) {
			_typeEnum = authenticationMethod;
			_type = AuthMethodEnumConverters.EnumAuthMethodsToString(_typeEnum);
			Config = new AuthConfig();

			if (path == null) {
				throw new ArgumentException("The path value cannot be null.");
			}
			if (path == "") {
				throw new ArgumentException("The path value cannot be an empty string.");
			}

			SetPathAndName(path);
		}




		/// <summary>
		/// Since vault backend accepts paths with a trailing slash and without, but usually returns with a slash it can be difficult to compare
		/// values created with values returned.  We therefore break them into name and path.  Name is without the slash, path is with the slash.
		/// </summary>
		/// <param name="value"></param>
		private void SetPathAndName(string value) {
			// Determine if value or name.
			if (value[value.Length - 1] == '/') {
				_path = value;
				_name= value.Substring(0, value.Length - 1);
			}
			else {
				_name = value;
				_path = value + '/';
			}

		}




		/// <summary>
		/// The name or path of the object to create.
		/// </summary>
		public string Path
		{
			get { return _path; }
			set {
				SetPathAndName(value);
			}
		}


		/// <summary>
		/// Name of this authentication backend.
		/// </summary>
		public string Name
		{
			get { return _name; }
			set {
				SetPathAndName(value);
			}
		}


		/// <summary>
		/// General description of the authentication method.
		/// </summary>
		public string Description { get; set; }



		
		/// <summary>
		/// The Vault authentication method type as enum.
		/// </summary>
		public EnumAuthMethods Type
		{
			get { return _typeEnum; }
			set {
				_typeEnum = value;
				_type = AuthMethodEnumConverters.EnumAuthMethodsToString(value);
			}
		}



		
		/// <summary>
		/// The Vault Proper string name for the Authentication Method this object represents.
		/// </summary>
		public string TypeAsString {
			get { return _type; }		
		}




		/// <summary>
		/// A Vault Authentication Method configuration object that provides additional details about the Authentication Method.
		/// </summary>
		[JsonProperty("config", NullValueHandling = NullValueHandling.Ignore)]
		public AuthConfig Config { get; private set; }


		[JsonProperty("accessor")]
		/// <summary>
		/// Returned by Vault.
		/// </summary>
		public string Accessor { get; private set; }

		
		/// <summary>
		/// Returned by Vault.  Not sure of purpose.
		/// </summary>
		public bool Local { get; private set; }


		/// <summary>
		/// /// Returned by Vault.  Not sure of purpose.
		/// </summary>
		public bool SealWrap { get; private set; }

	}
}
