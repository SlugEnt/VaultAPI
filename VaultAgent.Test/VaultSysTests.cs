using NUnit.Framework;

namespace VaultAgentTests
{
    public class VaultSysTests
    {

        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void VaultSetupTest()
        {
			// Make sure we have a root token and an ip address.
			Assert.AreNotEqual(VaultServerRef.rootToken, "");
			Assert.AreNotEqual(VaultServerRef.ipAddress, "");
        }
    }
}