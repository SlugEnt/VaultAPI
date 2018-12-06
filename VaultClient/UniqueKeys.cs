using System;
using System.Collections.Generic;
using System.Text;

namespace VaultClient
{   // Used to generate Unique Keys for Vault Tests.  Especially useful when using a single Vault instance that continuously runs.
	public class UniqueKeys
	{
		private int _keyIncrementer = 0;
		private object _keyIncrLock = new object();
		private string _stGuid;

		public UniqueKeys() {
			DateTime d = DateTime.Now;
			_stGuid = TimeGuid.ConvertTimeToChar(d);
		}


		/// <summary>
		/// Creates a small random key based upon the current time (H:M:S).
		/// </summary>
		/// <param name="prefix"></param>
		/// <returns></returns>
		public string GetKey(string prefix = "Key") {
			string val = prefix + _stGuid + IncrementKey();
			return val;
		}


		public string RefreshKey(string prefix = "Key") {
			DateTime d = DateTime.Now;
			_stGuid = TimeGuid.ConvertTimeToChar(d);
			return GetKey();
		}


		private string IncrementKey() {
			string val;
			lock (_keyIncrLock) {
				_keyIncrementer++;
				val = _keyIncrementer.ToString();
			}
			return val;
		}
	}
}
