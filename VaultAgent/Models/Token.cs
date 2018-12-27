using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommonFunctions;
using Newtonsoft.Json;
using VaultAgent;

namespace VaultAgent.Models
{
	/// <summary>
	/// Represents a Vault token.  
	/// 
	/// Note:  An Accessor Token does not have an ID value.
	/// </summary>
	public class Token {
		// The Time To Live value for this token in seconds.
		private long _ttl;

		/// <summary>
		/// The ID or unique identifier of the token.  This is usually set to a random value by the Vault backend upon token creation.
		/// </summary>
		[JsonProperty("id")]
		public string ID { get; set; }


		/// <summary>
		/// A name or description for the token for informational purposes only.
		/// </summary>
		[JsonProperty("display_name")]
		public string DisplayName { get; set; }


		/// <summary>
		/// Readonly field.  The path where the token was created at.
		/// </summary>
		[JsonProperty("path")]
		public string APIPath { get; private set; }



		//TODO figure out what type of value this is, long, DateTimeOffset?
		//   "expire_time": "2017-04-30T11:18:11.228946708-08:00",
		[JsonProperty("expire_time")]
		public string ExpireTimeStr { get; private set; }



		/// <summary>
		/// Returns the ExpireTime as a valid C# DateTime object.
		/// </summary>
		/// <returns></returns>
		public DateTime ExpireTimeAsDateTime()
		{
			DateTime d = DateTime.Now;
			bool success = DateTime.TryParse(ExpireTimeStr, out d);
			if (success)
			{
				return d;
			}
			else
			{
				throw new InvalidDataException("ExpireTime could not be decoded into a valid DateTime:  ExpireTimeStr = " + ExpireTimeStr);
			}
		}



		/// <summary>
		/// An Explicit maximum lifetime for the token.  This value is a hard limit and cannot be exceeded.  
		/// </summary>
		[JsonProperty("explicit_max_ttl")]
		public long MaxTTL { get; set; }


		//TODO - Convert to a List<string>
		/// <summary>
		/// Metadata is used to attach arbitrary string-type metadata to the token.  This data is displayed in the audit log.
		/// </summary>
		[JsonProperty("meta")]
		public object Meta { get; set; }


		/// <summary>
		/// A maximum number of times that this token can be used.  After the last use the token is automatically revoked by the Vault Instance.  Zero is unlimited.
		/// </summary>
		[JsonProperty("num_uses")]
		public long NumberOfUses { get; set; }


		/// <summary>
		/// Whether the token has a parent token or is without parent.
		/// </summary>
		[JsonProperty("orphan")]
		public bool IsOrphan { get; set; }



		/// <summary>
		/// Indicates that the token should never expire. It should be renewed before the end of the period and it will be renewed for the value specified.
		/// </summary>
		[JsonProperty("period")]
		public string Period { get; set; }


		/// <summary>
		/// A list of policies that this token is associated with.
		/// </summary>
		[JsonProperty("policies")]
		public List<string> Policies { get; set; }


		/// <summary>
		/// Indicates if this token is renewable.
		/// </summary>
		[JsonProperty("renewable")]
		public bool IsRenewable { get; set; }


		// Comes from Vault as a long, but should be set as 1h or 5m... Need to figure out.
		[JsonProperty("ttl")]
		public long TTL
		{
			get { return _ttl; }
			set { _ttl = value; }
		}


		// Alternative method of getting/setting the TTL of the token in a more readable TimeUnit Class.
		public TimeUnit TTLasTimeUnit {
			get { return new TimeUnit(_ttl); }
			set { _ttl = value.InSecondsLong; }
		}


		// The following properties can only be set during Token Reading from Vault.	


		/// <summary>
		/// The accessor token ID that can be used to access this root token without knowing the root token ID.
		/// </summary>
		[JsonProperty("accessor")]
		public string AccessorTokenID { get; private set; }


		#region "CreateTime and TTL"
		/// <summary>
		/// The time in seconds since 1/1/1970 that the token was created.  Read Only.
		/// </summary>
		[JsonProperty("creation_time")]
		public long CreationTime { get; private set; }



		/// <summary>
		/// Returns the CreationTime of the token as a DateTime Object
		/// </summary>
		public DateTime CreationTime_AsDateTime {
			get {
				return VaultUtilityFX.ConvertUnixTimeStamp(CreationTime);
			}
		}


		/// <summary>
		/// The TTL time period the token originally had upon creation.  This value does not change.  Not sure this has an real use?
		/// </summary>
		[JsonProperty("creation_ttl")]
		public long CreationTTL { get; private set; }

		#endregion



		// Believe this is for associating a user account across different auth methods (for instance bsmith in LDAP and bob in GIT).?
		[JsonProperty("entity_id")]
		public string EntityId { get; private set; }


		/// <summary>
		/// The Date and Time the token was originally issued.
		/// </summary>
		[JsonProperty("issue_time")]
		public DateTimeOffset IssueTime { get; private set; }


		/// <summary>
		/// True if this token information was retrieved from the Vault Instance.  Used internally for a few items.
		/// </summary>
		public bool ReadFromVault { get; private set; }


		/// <summary>
		/// This value should never be set by a caller.  Only read.
		/// </summary>
		public EnumTokenType TokenType { get; set; }


		/// <summary>
		/// Default JSON Constructor
		/// </summary>
		[JsonConstructor]
		public Token (string id, string accessor, long creation_time, long creation_ttl, string entity_id, DateTimeOffset issue_time) {
			ID = id;
			AccessorTokenID = accessor;
			CreationTime = creation_time;
			CreationTTL = creation_ttl;
			EntityId = entity_id;
			IssueTime = issue_time;
			ReadFromVault = true;
		}



		// Default empty constructor
		public Token() {
			ReadFromVault = false;
		}


		/// <summary>
		/// Constructor that accepts the token ID value
		/// </summary>
		/// <param name="tokenValue"></param>
		public Token (string tokenID) {
			ID = tokenID;
			ReadFromVault = false;
		}


		/// <summary>
		/// Returns True if this token has a parent token.
		/// </summary>
		public bool HasParent {
			get { return !IsOrphan; }
			set { IsOrphan = !value; }
		}
	}
}
