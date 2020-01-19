using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.System {
    /// <summary>
    /// The types of Authentication Methods that Vault Supports.  Note, many of these are not implemented in this library but are listed here for completeness.
    /// </summary>
    public enum EnumAuthMethods {
        /// <summary>
        /// An Application Role Authentication Method
        /// </summary>
        [Description ("approle")] AppRole = 0,


        /// <summary>
        /// An Amazon Web Services Authentication Method
        /// </summary>
        AWS = 1,

        /// <summary>
        /// A Google Cloud Authentication Method
        /// </summary>
        GoogleCloud = 2,

        /// <summary>
        /// A Kurbernetes Authentication Method
        /// </summary>
        Kubernetes = 3,

        /// <summary>
        /// A GitHub Authentication Method
        /// </summary>
        GitHub = 4,


        /// <summary>
        /// An LDAP Authentication Method
        /// </summary>
        LDAP = 5,

        /// <summary>
        /// A Okta Authentication Method
        /// </summary>
        Okta = 6,


        /// <summary>
        /// A TLSCertificate Authentication Method
        /// </summary>
        TLSCertificates = 7,

        /// <summary>
        /// A UserNamePassword Authentication Method
        /// </summary>
        UsernamePassword = 8,

        /// <summary>
        /// An Azure Authentication Method
        /// </summary>
        Token = 9
    }



    /// <summary>
    /// Utility Class to convert Enum values of AuthMethods into strings
    /// </summary>
    public static class AuthMethodEnumConverters {
        /// <summary>
        /// This function takes the EnumAuthMethods value and converts it to the Vault proper string name.
        /// </summary>
        /// <param name="method">The EnumAuthMethods value that corresponds to a proper Vault Authentication Method string name.</param>
        /// <returns>String value of the method.</returns>
        public static string EnumAuthMethodsToString (EnumAuthMethods method) {
            // Never change these values unless the Vault backend changes them.  Serialization / Deserialization will cease
            // to function if they do not match.

            switch ( method ) {
                case EnumAuthMethods.AppRole: return "approle";
                case EnumAuthMethods.Token: return "token";
                case EnumAuthMethods.AWS: return "aws";
                case EnumAuthMethods.GoogleCloud: return "gcp";
                case EnumAuthMethods.Kubernetes: return "kubernetes";
                case EnumAuthMethods.GitHub: return "github";
                case EnumAuthMethods.LDAP: return "ldap";
                case EnumAuthMethods.Okta: return "okta";

//				case EnumAuthMethods.Radius:
                //				return "radius";
                case EnumAuthMethods.TLSCertificates: return "cert";
                case EnumAuthMethods.UsernamePassword: return "userpass";

                // Vault .1		case EnumAuthMethods.Azure:
                // Vault .1			sAuthType = "azure"; break;
                //				case EnumAuthMethods.Tokens:
                //					sAuthType = "auth"; break;
                default:
                    string msg = "The EnumAuthMethod value of " + method + "is invalid.";
                    throw new ArgumentException (msg);
            }
        }



        /// <summary>
        /// Converts the Vault proper EnumAuthMethod for the given Vault proper name for the method.
        /// </summary>
        /// <param name="authMethod">Vault proper string name for the authentication method.</param>
        /// <returns>EnumAuthMethod value for the given string name.</returns>
        public static EnumAuthMethods EnumAuthMethodsFromString (string authMethod) {
            switch ( authMethod ) {
                case "approle": return EnumAuthMethods.AppRole;
                case "token": return EnumAuthMethods.Token;
                case "aws": return EnumAuthMethods.AWS;
                case "gcp": return EnumAuthMethods.GoogleCloud;
                case "kubernetes": return EnumAuthMethods.Kubernetes;
                case "github": return EnumAuthMethods.GitHub;
                case "ldap": return EnumAuthMethods.LDAP;
                case "okta": return EnumAuthMethods.Okta;

//				case "radius":
                //				return EnumAuthMethods.Radius;
                case "cert": return EnumAuthMethods.TLSCertificates;
                case "userpass": return EnumAuthMethods.UsernamePassword;
                default:
                    string msg = "Unknown Authentication Method given: " + authMethod;
                    throw new ArgumentException (msg);
            }
        }
    }
}