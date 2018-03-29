using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VaultAgent
{
	public static class VaultUtilityFX
	{
		public static DateTime ConvertUnixTimeStamp(string unixTimeStamp) {
			return new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(Convert.ToDouble(unixTimeStamp));
		}
		public static DateTime ConvertUnixTimeStamp(long unixTimeStamp) {
			return new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(Convert.ToDouble(unixTimeStamp));
		}

	}
}
