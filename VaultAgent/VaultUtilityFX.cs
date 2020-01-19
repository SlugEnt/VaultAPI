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
    }
}