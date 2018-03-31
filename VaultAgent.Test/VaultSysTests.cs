using NUnit.Framework;
using System.Net.Http;
using System.Collections.Generic;
using VaultAgent;
using VaultAgent.Models;
using System;
using System.Threading.Tasks;


namespace VaultAgentTests
{
    public class VaultSysTests
    {

        [SetUp]
        public async Task Setup()
        {

		}



        [Test]
        public async Task VaultSetupTest()
        {
			// Make sure we have a root token and an ip address.
			Assert.AreNotEqual(VaultServerRef.rootToken, "");
			Assert.AreNotEqual(VaultServerRef.ipAddress, "");
        }

		[Test]
		public async Task ConnectTest() {

			HttpClient client = new HttpClient();

			// Update port # in the following line.
			client.BaseAddress = VaultServerRef.vaultURI;
			client.DefaultRequestHeaders.Accept.Clear();
			client.DefaultRequestHeaders.Add("X-Vault-Token", VaultServerRef.rootToken);


			string path = "v1/auth/token/lookup";
			var stringTask = client.GetStringAsync(path);
			var msg = await stringTask;

			var data = msg;
		}


		[Test]
		public async Task TokenInfoTest () {
			// This is temporary until we have the ability to send input parameters
			string path = "v1/auth/token/lookup";

			// JSON the input variables
			Dictionary<string, string> content = new Dictionary<string, string>();
			content.Add("token", VaultServerRef.rootToken);

			try {
				VaultAPI_Http VH = new VaultAPI_Http(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

				VaultDataResponseObject vdr = await VH.PostAsync(path, "TokenInfoTest" ,content);

				string sJSON = vdr.GetResponsePackageAsJSON();

				Assert.IsNotEmpty(sJSON);
			}
			catch (Exception e) { }

			//Console.WriteLine("JSON = {0}", vdr.GetDataPackageAsJSON());

		}
	}
}