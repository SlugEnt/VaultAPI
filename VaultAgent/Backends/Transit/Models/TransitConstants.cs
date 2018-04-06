using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent.Backends.Transit.Models
{
	public static class TransitConstants
	{
		public static readonly string KeyConfig_MinDecryptVers = "min_decryption_version";
		public static readonly string KeyConfig_MinEncryptVers = "min_encryption_version";
		public static readonly string KeyConfig_DeleteAllowed = "deletion_allowed";
		public static readonly string KeyConfig_Exportable = "exportable";
		public static readonly string KeyConfig_Allow_Backup = "allow_plaintext_backup";
	}
}
