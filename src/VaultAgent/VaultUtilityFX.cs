using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent {
    /// <summary>
    /// Various Utility Functions Needed by the Library
    /// </summary>
    public static class VaultUtilityFX {
        /// <summary>
        /// Converts a time from Unix Timestamp into .Net Datetime
        /// </summary>
        /// <param name="unixTimeStamp"></param>
        /// <returns></returns>
        public static DateTime ConvertUnixTimeStamp (string unixTimeStamp) {
            return new DateTime (1970, 1, 1, 0, 0, 0).AddSeconds (Convert.ToDouble (unixTimeStamp));
        }


        /// <summary>
        /// Converts a DateTime into a Unix TimeStamp
        /// </summary>
        /// <param name="unixTimeStamp"></param>
        /// <returns></returns>
        public static DateTime ConvertUnixTimeStamp (long unixTimeStamp) {
            return new DateTime (1970, 1, 1, 0, 0, 0).AddSeconds (Convert.ToDouble (unixTimeStamp));
        }


        /// <summary>
        /// Encodes an Ascii value into Base64
        /// </summary>
        /// <param name="textToEncode">Ascii text to be encoded</param>
        /// <returns></returns>
        public static string Base64EncodeAscii (string textToEncode) {
            byte [] rawBytes = ASCIIEncoding.ASCII.GetBytes (textToEncode);
            return Convert.ToBase64String (rawBytes);
        }


        /// <summary>
        /// Decodes a Base64 value into an Ascii string
        /// </summary>
        /// <param name="textToDecode">The Base64 text to decode into Ascii</param>
        /// <returns></returns>
        public static string Base64DecodeAscii (string textToDecode) {
            byte [] decoded = Convert.FromBase64String (textToDecode);
            return ASCIIEncoding.ASCII.GetString (decoded);
        }



        // TODO - Not SURE We NEED THIS ANYMORE - Can be replaced with VaultSerializationHelper.FromJSON method.
        /// <summary>
        /// This function accepts a JSON string and will convert it into a strongly typed C# class object.  
        /// Especially useful for converting JSON objects that are sub arrays or sub lists into C# Lists or Dictionaries.
        /// Example:  JSON:  { Keys: {"1": 144, "2": 54, "3": 98}
        /// </summary>
        /// <typeparam name="T">The C# class type to convert the JSON into. </typeparam>
        /// <param name="json">The JSON string that should be converted.</param>
        /// <returns>The C# class type to be returned filled with the JSON values.</returns>
        public static T ConvertJSON<T> (string json) { return JsonConvert.DeserializeObject<T> (json); }


        /// <summary>
        /// In a Vault url string the verty last part of a URL that is a path is the name
        /// </summary>
        /// <param name="path">The Path to Interrogate</param>
        /// <returns></returns>
        public static string GetNameFromVaultPath (string path) {
	        string s = path.TrimStart('/').TrimEnd('/');
            int length = s.Length;
	        for ( int i = length; --i >= 0; ) {
		        char ch = s [i];
		        if ( ch == '/' ) return s.Substring(i + 1, length - i - 1);
	        }

	        return s;
        }


        /// <summary>
        /// Returns the full path part of a Vault URL path.  Strips leading and trailing slashes.
        /// </summary>
        /// <param name="path">The Path to interrogate</param>
        /// <returns></returns>
        public static string GetPathFromVaultPath (string path) {
	        string s = path.TrimStart('/').TrimEnd('/');
	        int length = s.Length;
	        for (int i = length; --i >= 0;)
	        {
		        char ch = s[i];
                if (ch == '/')
                    // If at start of string, then there is no path.

					return s.Substring(0, i);
	        }

	        return string.Empty;

        }


        /// <summary>
        /// Returns the Path and Name parts of  Vault Path
        /// </summary>
        /// <param name="value">The Vault string / path that you wish to separate into Name and Path parameters</param>
        /// <returns></returns>
        public static(string path, string name) GetNameAndPathTuple (string value) {
            // 1st get the name
            string nameElement = "";
            int pathEnd = 0;
            string s = value.TrimStart('/').TrimEnd('/');
            int length = s.Length;
            for ( int i = length; --i >= 0; ) {
                char ch = s [i];
                if ( ch == '/' ) {
                    nameElement = s.Substring(i + 1, length - i - 1);
                    pathEnd = i;
                    break;
                }
            }

            if ( nameElement == string.Empty ) nameElement = s;


            // The rest is the path
            string pathElement;
            if ( pathEnd != 0 ) {
                pathElement = s.Substring(0, pathEnd + 1).TrimEnd('/');
            }
            else
                pathElement = "";

            return (pathElement, nameElement);
        }



        /// <summary>
        /// Returns the name and path parts of the provided 2 arguments.  IF the path is empty AND the name
        /// is a path plus the name, then they are separated out, otherwise the parameters are returned, minus
        /// leading and trailing slashes.
        /// </summary>
        /// <param name="name">The name parameter</param>
        /// <param name="path">The path parameter</param>
        /// <returns></returns>
        public static(string path, string name) GetNameAndPathFromValuesTuple (string name, string path = "") {
            string tempName = name.Trim('/');
            if (tempName.Contains("/"))
            {
                if (path != string.Empty) throw new ArgumentException("The Name parameter must not contain any path arguments, if the path parameter has a value");
                return VaultUtilityFX.GetNameAndPathTuple(name);
            }
            else {
                return (path.Trim('/'), tempName);
            }
        }
    }
}