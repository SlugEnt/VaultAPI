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
		

		[JsonConstructor]
		/// <summary>
		/// Constructor for AuthMethod.  This is the only method that accepts 
		/// </summary>
		/// <param name="type"></param>
		public AuthMethod (string type) {
			// we do not call the actual property setters here, because of an endless loop situation.
			_type = type;
			_typeEnum = AuthMethodEnumConverters.EnumAuthMethodsFromString(type);
		}


		public AuthMethod (EnumAuthMethods authenticationMethod) {
			_typeEnum = authenticationMethod;
			_type = AuthMethodEnumConverters.EnumAuthMethodsToString(_typeEnum);
		}


		[JsonProperty("path")]
		public string Path { get; set; }

		//[JsonProperty("description")]
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



		[JsonProperty("config", NullValueHandling = NullValueHandling.Ignore)]
		public AuthConfig Config { get; set; }


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
