using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using NUnit.Framework;

namespace VaultAgent.Test
{
    [TestFixture]
    public class Test_VaultAPI_HTTP {
        private VaultAPI_Http _vaultHTTP;

        [OneTimeSetUp]
        public void SetupOneTime () {
            _vaultHTTP = new VaultAPI_Http("http://localhost",16100);
        }


        [Test]
        [TestCase("just a string")]
        [TestCase("must be https/n")]
        public void ConvertJSONArrayToList_knownErrors (string json) {
            Assert.Throws<JsonReaderException>(() => _vaultHTTP.ConvertJSONArrayToList(json, "nothing"), "A10:  Did not throw correct error");
        }
    }
}
