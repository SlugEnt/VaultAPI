using Newtonsoft.Json;

namespace VaultAgent.Backends.Transit.Models
{
	public class TransitBackupRestoreItem
	{
		[JsonProperty("backup")]
		public string KeyBackup { get; set; }

		[JsonIgnore]
		public bool Success { get; set; }

		[JsonIgnore]
		public string ErrorMsg { get; set; }
	}
}