using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.System
{
	public enum EnumAuthMethods
	{
		[Description("approle")]
		AppRole = 0,
		AWS = 1,
		GoogleCloud = 2,
		Kubernetes = 3,
		GitHub = 4,
		LDAP = 5,
		Okta = 6,
		Radius = 7,
		TLSCertificates = 8,
		UsernamePassword = 9,
		Token = 10 //,
		//Azure = 10
	}


	public static class AuthMethodEnumConverters
	{

		/// <summary>
		/// This function takes the EnumAuthMethods value and converts it to the Vault proper string name.
		/// </summary>
		/// <param name="method">The EnumAuthMethods value that corresponds to a proper Vault Authentication Method string name.</param>
		/// <returns>String value of the method.</returns>
		public static string EnumAuthMethodsToString(EnumAuthMethods method) {
			// Never change these values unless the Vault backend changes them.  Serialization / Deserialization will cease
			// to function if they do not match.

			switch (method) {
				case EnumAuthMethods.AppRole:
					return "approle";
				case EnumAuthMethods.AWS:
					return "aws";
				case EnumAuthMethods.GoogleCloud:
					return "gcp";
				case EnumAuthMethods.Kubernetes:
					return "kubernetes";
				case EnumAuthMethods.GitHub:
					return "github";
				case EnumAuthMethods.LDAP:
					return "ldap";
				case EnumAuthMethods.Okta:
					return "okta";
				case EnumAuthMethods.Radius:
					return "radius";
				case EnumAuthMethods.TLSCertificates:
					return "cert";
				case EnumAuthMethods.UsernamePassword:
					return "userpass";
				case EnumAuthMethods.Token:
					return "token";
				// Vault .1		case EnumAuthMethods.Azure:
				// Vault .1			sAuthType = "azure"; break;
				//				case EnumAuthMethods.Tokens:
				//					sAuthType = "auth"; break;
				default:
					string msg = "The EnumAuthMethod value of " + method + "is invalid.";
					throw new ArgumentException(msg);
			}
		}




		/// <summary>
		/// Converts the Vault proper EnumAuthMethod for the given Vault proper name for the method.
		/// </summary>
		/// <param name="authMethod">Vault proper string name for the authentication method.</param>
		/// <returns>EnumAuthMethod value for the given string name.</returns>
		public static EnumAuthMethods EnumAuthMethodsFromString (string authMethod) {
			switch (authMethod) {
				case "approle":
					return EnumAuthMethods.AppRole;
				case "token":
					return EnumAuthMethods.Token;
				case "aws":
					return EnumAuthMethods.AWS;
				case "gcp":
					return EnumAuthMethods.GoogleCloud;
				case "kubernetes":
					return EnumAuthMethods.Kubernetes;
				case "github":
					return EnumAuthMethods.GitHub;
				case "ldap":
					return EnumAuthMethods.LDAP;
				case "okta":
					return EnumAuthMethods.Okta;
				case "radius":
					return EnumAuthMethods.Radius;
				case "cert":
					return EnumAuthMethods.TLSCertificates;
				case "userpass":
					return EnumAuthMethods.UsernamePassword;
				default:
					string msg = "Unknown Authentication Method given: " + authMethod;
					throw new ArgumentException(msg);
			}
		}
	}

}
