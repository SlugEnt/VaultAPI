using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using VaultAgent.SecretEngines.KV2;

namespace VaultAgent.Test.ModelTests
{
    [TestFixture]
    [Parallelizable]
    class KV2Secret_Tests
    {

        // Validate that 2 secrets with the same name, path, number of attributes, same attribute keys and keys have the same values are equal.
        [Test]
        public void TwoSecrets_EvaluateToEquals_Success()
        {
            string name = "ABC/xyz";
            string attrA = "attribA";
            string attrB = "attribB";
            string valA = "valueA";
            string valB = "valueB";

            KV2Secret a = new KV2Secret(name);
            KV2Secret b = new KV2Secret(name);

            a.Attributes.Add(attrA, valA);
            b.Attributes.Add(attrA, valA);
            a.Attributes.Add(attrB, valB);
            b.Attributes.Add(attrB, valB);

            Assert.IsTrue(a.Equals(b));
        }



        // Validate that 2 secrets with different names are not equal.
        [Test]
        public void TwoSecretsWithDifferentNames_NotEqual()
        {
            string nameA = "nameA";
            string nameB = "nameB";

            KV2Secret a = new KV2Secret(nameA);
            KV2Secret b = new KV2Secret(nameB);

            Assert.IsFalse(a.Equals(b));
        }



        // Validate that 2 secrets with different paths are not equal.
        [Test]
        public void TwoSecretsWithDifferentPaths_NotEqual()
        {
            string name = "nameA";
            string pathA = "patha/pathc/pathxyz";
            string pathB = "pathb/pathc/pathxyz";

            KV2Secret a = new KV2Secret(name, pathA);
            KV2Secret b = new KV2Secret(name, pathB);

            Assert.IsFalse(a.Equals(b));
        }



        // Validate that 2 secrets with different number of attributes are not equal.
        [Test]
        public void TwoSecretsWithDifferentAttributeCounts_NotEqual()
        {
            string name = "nameA";
            string path = "patha/pathc/pathxyz";

            KV2Secret a = new KV2Secret(name, path);
            KV2Secret b = new KV2Secret(name, path);

            a.Attributes.Add("attrA", "valueA");

            Assert.IsFalse(a.Equals(b));
        }



        // Validate that 2 secrets with different attribute keys are not equal.
        [Test]
        public void TwoSecretsWithDifferentAttributeKeys_NotEqual()
        {
            string name = "nameA";
            string path = "patha/pathc/pathxyz";

            KV2Secret a = new KV2Secret(name, path);
            KV2Secret b = new KV2Secret(name, path);

            a.Attributes.Add("attrA", "valueA");
            b.Attributes.Add("attrB", "valueA");

            Assert.IsFalse(a.Equals(b));
        }



        // Validate that 2 secrets with different values for the same attribute key are not equal.
        [Test]
        public void TwoSecretsWithDifferentAttributeValues_NotEqual()
        {
            string name = "nameA";
            string path = "patha/pathc/pathxyz";

            KV2Secret a = new KV2Secret(name, path);
            KV2Secret b = new KV2Secret(name, path);

            a.Attributes.Add("attrA", "valueA");
            b.Attributes.Add("attrA", "valueB");

            Assert.IsFalse(a.Equals(b));
        }



        // Validate the FullPath property of a KV2 secret works.
        [Test]
        [TestCase("secretA", "/", "secretA")]
        [TestCase("secretB", "/App1", "App1/secretB")]
        [TestCase("secretC", "/App1/secretB", "App1/secretB/secretC")]
        [TestCase("secretD", "", "secretD")]
        [TestCase("secretE", "/App2/", "App2/secretE")]
        [TestCase("secretF", "//App2/", "App2/secretF")]
        [TestCase("secretG", "/App2//", "App2/secretG")]
        public void SecretFullPath_ProducesCorrectValues(string name, string path, string result)
        {
            KV2Secret secret = new KV2Secret(name, path);
            Assert.AreEqual(result, secret.FullPath);
        }



        [Test]
        // Validate that we do not need to specify the path parameter.
        public void SecretFullPath_ProducesCorrectValues()
        {
            string name = "ABCxyz";
            KV2Secret secret = new KV2Secret(name);
            Assert.AreEqual(name, secret.Name);
        }



		// When a secret is initially created its version should be 0 and WasReadFromVault should be false.
	    [Test]
	    public void WasReadFromVault_InitiallyReturnsFalse() {
		    string name = "ttt";
			KV2Secret secret = new KV2Secret(name);
			Assert.IsFalse(secret.WasReadFromVault,"A10:   Expected WasReadFromVault to be false.");
			Assert.AreEqual(0,secret.Version,"A20:  Secret Version should initially be zero.");
	    }



        [Test]
        // Test that Secret shortcut access the actual backing value correctly.  Vault pushes
        public void SecretVersion()
        {
            KV2SecretWrapper secretA = new KV2SecretWrapper
            {
                Secret = new KV2Secret("test", "/"),
                Version = 2
            };
            Assert.AreEqual(2, secretA.Version);
            Assert.AreEqual(2, secretA.Data.Metadata.Version);
        }



        // Test for Reflexive Equality property (One of the 5 required tests for Referential Object Equality)
        [Test]
        public void RefObjEqual_SecretEqualsSelf_True() {
            KV2Secret x = new KV2Secret("ABC","temp/temp2");
            Assert.True(x.Equals(x));
        }




        // Test for Symmetric Equality property (One of the 5 required tests for Referential Object Equality)
        [Test]
        public void RefObjEqual_SymmetricEquality_Validates()
        {
            // Test inequality.
            KV2Secret x = new KV2Secret("ABC", "temp/temp2");
            KV2Secret y = new KV2Secret("xyz","temp4/temp5");

            bool answerA = x.Equals (y);
            Assert.False(answerA, "A10:  The 2 secrets are different, expected this to be false.");

            bool answerB = y.Equals (x);          
            Assert.False(answerB, "A20:  The 2 secrets are different, expected this to be false.");

            Assert.AreEqual(answerA,answerB,"A30:  Expected the 2 comparison tests to both report the same result. They instead gave different answers.");


            // Now lets test an equal set of objects.
            KV2Secret xx = new KV2Secret("ABC", "temp/temp2");
            KV2Secret yy = new KV2Secret("ABC", "temp/temp2");

            bool answerAA = xx.Equals(yy);
            Assert.True(answerAA, "A100:  The 2 secrets are different, expected this to be false.");

            bool answerBB = yy.Equals(xx);
            Assert.True(answerBB, "A120:  The 2 secrets are different, expected this to be false.");

            Assert.AreEqual(answerAA, answerBB, "A130:  Expected the 2 comparison tests to both report the same result. They instead gave different answers.");

        }


        [Test]
        public void RefObjEqual_TransitiveProperty_Validates() {
            // Test inequality.
            KV2Secret xx = new KV2Secret("ABC", "temp/temp2");
            KV2Secret yy = new KV2Secret("ABC", "temp/temp2");
            KV2Secret zz = new KV2Secret("ABC", "temp/temp2");

            bool answerAA = xx.Equals(yy);
            bool answerBB = yy.Equals(zz);
            bool answerCC = xx.Equals(zz);

            Assert.True(answerAA, "A10:  The 2 secrets are the same, but the result is false.");
            Assert.True(answerBB, "A20:  The 2 secrets are the same, but the result is false.");
            Assert.True(answerCC, "A30:  The 2 secrets are the same, but the result is false.");
        }


        [Test]
        public void RefObjEqual_SecretEqualsNull_ReturnsFalse() {
            KV2Secret xx = new KV2Secret("ABC", "temp/temp2");
            Assert.False(xx.Equals(null));
        }


        [Test]
        public void RefObjEqual_NullEqualsNull_ReturnsTrue()
        {
            KV2Secret xx = null;
            Assert.Throws<NullReferenceException> (()=> xx.Equals(null));
        }



        // Validated we can clone a Secret object successfully.
        [Test]
        public void CloneWorks() {
            KV2Secret a = new KV2Secret("abc","xyz");
            a.Attributes.Add("attra","vala");
            a.Attributes.Add("attrb", "valb");
            a.Attributes.Add("attrc", "valc");

            // Set extended attribute values.
            a.CreatedTime = DateTimeOffset.Now;
            a.DeletionTime = "abc";
            a.Destroyed = true;
            a.Version = 19;

            // Now clone
            KV2Secret b = (KV2Secret) a.Clone();

            Assert.AreEqual(a.Name,b.Name,"A10:  Names are not equal.");
            Assert.AreEqual(a.Path, b.Path, "A20:  Paths are not equal.");
            Assert.AreEqual(a.FullPath, b.FullPath, "A30:  FullPaths are not equal.");
            Assert.AreEqual(a.Attributes.Count,b.Attributes.Count,"A40: Attribute counts are different");
            Assert.AreEqual(a.Destroyed,b.Destroyed,"A50:  Destroyed booleans are not same");
            Assert.AreEqual(a.CreatedTime,b.CreatedTime,"A60:   Created Times are different");
            Assert.AreEqual(a.Version,b.Version,"A70:  Version numbers are different.");
            Assert.AreEqual(a.DeletionTime,b.DeletionTime,"A80:  Deletion times are different");
            foreach (KeyValuePair<string,string> attr in a.Attributes) {
                CollectionAssert.Contains(b.Attributes,attr,"A100:  Attribute Key: " + attr.Key + " with value: " + attr.Value + " was not found.");               
            }
        }
    }
}
