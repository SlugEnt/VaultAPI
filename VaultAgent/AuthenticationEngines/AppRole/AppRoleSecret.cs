using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VaultAgent.Backends.AppRole
{
	public class AppRoleSecret
	{
		[JsonProperty("secret_id")]
		public string ID { get; set; }

		[JsonProperty("secret_id_accessor")]
		public string Accessor { get; set; }
	}
}
