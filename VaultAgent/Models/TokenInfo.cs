using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VaultAgent.Models
{
	public class TokenInfo {
		[JsonProperty("id")]
		public string Id { get; set; }

		[JsonProperty("display_name")]
		public string DisplayName { get; set; }

		[JsonProperty("path")]
		public string APIPath { get; set; }

		[JsonProperty("accessor")]
		public string AccessorTokenID { get; set; }

		[JsonProperty("creation_time")]
		public long CreationTime { get; set; }

		[JsonProperty("creation_ttl")]
		public long CreationTTL { get; set; }

		[JsonProperty("entity_id")]
		public string EntityId { get; set; }

		//TODO figure out what type of value this is, long, DateTimeOffset?
		[JsonProperty("expire_time")]
		public string ExpireTimeStr { get; set; }

		[JsonProperty("explicit_max_ttl")]
		public long TokenExplicitMaxTTL { get; set; }

		[JsonProperty("issue_time")]
		public DateTimeOffset IssueTime { get; set; }

		[JsonProperty("meta")]
		public object Meta { get; set; }

		[JsonProperty("num_uses")]
		public long NumberOfUses { get; set; }

		[JsonProperty("orphan")]
		public bool IsOrphan { get; set; }
/* Deprecated
		[JsonProperty("period")]
		public string Period { get; set; }
*/
		[JsonProperty("policies")]
		public List<string> Policies { get; set; }

		[JsonProperty("renewable")]
		public bool IsRenewable { get; set; }

		[JsonProperty("ttl")]
		public long TTL { get; set; }



		/// <summary>
		/// Default JSON Constructor
		/// </summary>
		[JsonConstructor]
		public TokenInfo() { }


		/// <summary>
		/// Constructor that accepts the token ID value
		/// </summary>
		/// <param name="tokenValue"></param>
		public TokenInfo (string tokenID) { Id = tokenID; }


		/// <summary>
		/// Returns True if this token has a parent token.
		/// </summary>
		public bool HasParent { get { return !IsOrphan; } }


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
