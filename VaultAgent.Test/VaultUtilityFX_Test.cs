using System;
using System.Collections.Generic;
using System.Text;
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
	}
}
