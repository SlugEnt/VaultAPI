using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.VisualStudio.TestPlatform.Common.Telemetry;
using NUnit.Framework;

namespace VaultAgent.Test
{
	[TestFixture, Order(1)]
	[Parallelizable]
	public class VaultUtilityFX_Test
	{
		[TestCase("/root/path1/path2/name", "name")]
		[TestCase("name", "name")]
		[TestCase("name/", "name")]
		[TestCase("/root/name", "name")]
		[TestCase("root/path1/path2/name", "name")]
		[TestCase("/name", "name")]
		[Test]
		public void GetNameFromPath (string fullPathName, string expected) {
			string result = VaultUtilityFX.GetNameFromVaultPath(fullPathName);
			Assert.AreEqual(expected,result);
		}


		[TestCase("/root/path1/path2/name", "root/path1/path2")]
		[TestCase("name", "")]
		[TestCase("/root/name", "root")]
		[TestCase("root/path1/path2/name", "root/path1/path2")]
		[TestCase("/name", "")]
		[Test]
		public void GetPathFromPath(string fullPathName, string expected)
		{
			string result = VaultUtilityFX.GetPathFromVaultPath(fullPathName);
			Assert.AreEqual(expected, result);
		}


        [TestCase("/nameonly", "nameonly", "")]
        [TestCase("/nameonly/", "nameonly", "")]
        [TestCase("rootpath/namepart", "namepart", "rootpath")]
        [TestCase("rootpath/part2/namepart", "namepart", "rootpath/part2")]
        [TestCase("rootpath/namepart/", "namepart", "rootpath")]
        [TestCase("/a", "a", "")]
        [TestCase("/a/", "a", "")]
        [TestCase("a", "a", "")]
        [TestCase("a", "a", "")]
		[Test]
        public void GetPathNameTuple (string value, string name, string path) {
            (string pathResult, string nameResult) = VaultUtilityFX.GetNameAndPathTuple(value);
			Assert.AreEqual(name,nameResult,"A10:  Name is not correct value");
			Assert.AreEqual(path, pathResult,"A20:  Path is not expected value");
        }


		[TestCase("A", "namePart", "","namePart", "")]
        [TestCase("B", "/namePart", "", "namePart", "")]
        [TestCase("C", "/namePart/", "", "namePart", "")]
        [TestCase("D", "namePart", "root", "namePart", "root")]
        [TestCase("E", "/namePart", "root", "namePart", "root")]
        [TestCase("F", "/namePart/", "root", "namePart", "root")]
        [TestCase("G", "namePart", "/root", "namePart", "root")]
        [TestCase("H", "namePart", "/root/", "namePart", "root")]
        [TestCase("I", "namePart", "root/patha", "namePart", "root/patha")]
        [TestCase("J", "root/namePart", "", "namePart", "root")]
        [TestCase("K", "/root/namePart", "", "namePart", "root")]
        [TestCase("L", "/root/namePart/", "", "namePart", "root")]
        [TestCase("M", "root/patha/namePart", "", "namePart", "root/patha")]
		[Test]
        public void GetPathAndNameValuesTuple (string scenario, string name, string path, string expName, string expPath) {
            (string pathResult, string nameResult) = VaultUtilityFX.GetNameAndPathFromValuesTuple(name, path);
            Assert.AreEqual(expName, nameResult, "A10:  Name is not correct value");
            Assert.AreEqual(expPath, pathResult, "A20:  Path is not expected value");
        }


        [Test]
        [TestCase("A", "root/namePart", "root", "namePart", "")]
        [TestCase("B", "path2/path3/namePart", "root/path4", "namePart", "")]
        public void GetPathAndNameValuesTupleThrows(string scenario, string name, string path, string expName, string expPath) {
            Assert.Throws<ArgumentException>(() => VaultUtilityFX.GetNameAndPathFromValuesTuple(name, path));
        }
    }

}
