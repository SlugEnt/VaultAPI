using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommonFunctions;
using Newtonsoft.Json;

namespace VaultAgent.Models
{
	public class Token {
		// The Time To Live value for this token in seconds.
		private long _ttl;	


		[JsonProperty("id")]
		public string Id { get; set; }

		[JsonProperty("display_name")]
		public string DisplayName { get; set; }

		[JsonProperty("path")]
		public string APIPath { get; set; }



		//TODO figure out what type of value this is, long, DateTimeOffset?
		[JsonProperty("expire_time")]
		public string ExpireTimeStr { get; set; }

		[JsonProperty("explicit_max_ttl")]
		public long MaxTTL { get; set; }


		[JsonProperty("meta")]
		public object Meta { get; set; }

		[JsonProperty("num_uses")]
		public long NumberOfUses { get; set; }

		[JsonProperty("orphan")]
		public bool IsOrphan { get; set; }

		[JsonProperty("period")]
		public string Period { get; set; }

		[JsonProperty("policies")]
		public List<string> Policies { get; set; }

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
		public TimeUnit TTL_TimeUnit {
			get { return new TimeUnit(_ttl); }
			set { _ttl = value.InSecondsLong; }
		}


		// The following properties can only be set during via Token Reading from Vault.	
		
		
		// JSON Set Only
		[JsonProperty("accessor")]
		public string AccessorTokenID { get; private set; }

		// JSON Set Only
		[JsonProperty("creation_time")]
		public long CreationTime { get; private set; }

		// JSON Set Only
		[JsonProperty("creation_ttl")]
		public long CreationTTL { get; private set; }

		// JSON Set Only
		[JsonProperty("entity_id")]
		public string EntityId { get; private set; }

		// JSON Set Only
		[JsonProperty("issue_time")]
		public DateTimeOffset IssueTime { get; private set; }


		/// <summary>
		/// True if this token information was retrieved from the Vault Instance.  Used internally for a few items.
		/// </summary>
		public bool ReadFromVault { get; private set; }



		/// <summary>
		/// Default JSON Constructor
		/// </summary>
		[JsonConstructor]
		public Token (string id, string accessor, long creation_time, long creation_ttl, string entity_id, DateTimeOffset issue_time) {
			Id = id;
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
			Id = tokenID;
			ReadFromVault = false;
		}


		/// <summary>
		/// Returns True if this token has a parent token.
		/// </summary>
		public bool HasParent {
			get { return !IsOrphan; }
			set { IsOrphan = !value; }
		}


		/// <summary>
		/// Returns Creation Time of Token as a DateTime value
		/// </summary>
		public DateTime CreationTime_AsDateTime {
			get {
				return VaultUtilityFX.ConvertUnixTimeStamp(CreationTime);
			}
		}
	}
}
