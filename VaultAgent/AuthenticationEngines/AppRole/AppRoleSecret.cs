using Newtonsoft.Json;

namespace VaultAgent.AuthenticationEngines
{
	public class AppRoleSecret
	{
		[JsonProperty("secret_id")]
		public string ID { get; set; }

		[JsonProperty("secret_id_accessor")]
		public string Accessor { get; set; }
	}
}
