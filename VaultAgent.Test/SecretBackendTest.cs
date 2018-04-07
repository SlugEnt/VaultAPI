using System;
using System.Collections.Generic;
using NUnit.Framework;
using VaultAgent.Backends.Secret;
using VaultAgentTests;
using VaultAgent.Backends.System;
using System.Threading.Tasks;

namespace VaultAgentTests
{
    public class SecretBackendTest
    {
		// The Vault Transit Backend we will be using throughout our testing.
		SecretBackend SB;

		// For system related calls we will use this Backend.
		VaultSystemBackend VSB;

	
		/// <summary>
		/// Secret Backend database name. 
		/// </summary>
		string secretBE_A = "secretA";


		// Used to ensure we have a random key.
		int randomSecretNum = 0;
		string secretPrefix = "Test/ZYAB";



		public async Task Secret_Init() {
			if (SB != null) {
				return;
			}


			// Create a Transit Backend Mount for this series of tests.
			VSB = new VaultSystemBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

			// Create a custom Secret Backend.
			string secretName = secretBE_A;
			string desc = "Secret DB: " + secretName + " backend.";
			bool rc = await VSB.SysMountEnable(secretName, desc, EnumBackendTypes.Secret);
			Assert.AreEqual(true, rc);

			SB = new SecretBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, secretName);
			return;
		}




		public async Task<string> Secret_Init_Create(Secret val) {
			await Secret_Init();

			randomSecretNum++;
			string secretName = secretPrefix + randomSecretNum.ToString();

			val.Path = secretName;
			Assert.True(await SB.CreateSecretAndReturn(val));

			return secretName;
		}

		



		[Test, Order(1)]
		public async Task Secret_CreateAndMountCustomSecretBackend() {
			await Secret_Init();
		}




		// Simple Secret Creation Test.
		[Test, Order(100)]
		public async Task Secret_CreateSecret () {
			await Secret_Init();

			Secret A = new Secret();

			string secretName = "Test/A/mysecret";
			A.Path = secretName;
			A.Attributes.Add("conn", "db1-Myconn");
			A.Attributes.Add("user", "dbuserAdmin");

			Assert.True(await SB.CreateSecretAndReturn(A));
		}



		// Create an Empty Secret, from a Secret object.  Has no attributes
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromSecretObject_ReturnsTrue() {
			await Secret_Init();

			Secret A = new Secret();

			string secretName = "Test/B/mysecret";
			A.Path = secretName;

			Assert.True(await SB.CreateSecretAndReturn(A));
		}



		// Create an Empty Secret from just a secret name.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromJustSecretName_ReturnsTrue() {
			await Secret_Init();		
			string secretName = "Test/C/mysecret";
			Assert.True(await SB.CreateSecretAndReturn(secretName));
		}



		// Create an empty secret with just the secret name.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromJustSecretName_ReturnsSecretObject () {
			await Secret_Init();

			String secretName = "Test/D/myothersec";
			Secret B = await SB.CreateSecret(secretName);
			Assert.NotNull(B);
			Assert.AreEqual(secretName, B.Path);
		}




		// Create an empty secret from a Secret Object, returning a secret.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromSecretObject_ReturnsSecretObject() {
			await Secret_Init();

			String secretName = "Test/E/myothersec";
			Secret A = new Secret(secretName);
			Secret B = await SB.CreateSecret(A);
			Assert.NotNull(B);
			Assert.AreEqual(secretName, B.Path);
		}






		// Read a secret, passing a secret name only.
		[Test, Order(200)]
		public async Task Secret_ReadSecret_PassingSecretPath() {
			// Create a Secret.
			Secret A = new Secret();
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test", "testValue");
			A.Attributes.Add(kv1.Key,kv1.Value);
			A.Path = await Secret_Init_Create(A);


			// Now read the secret.
			Secret B = await SB.ReadSecret(A.Path);
			Assert.NotNull(B);
			Assert.Contains(kv1.Key, B.Attributes.Keys);
			Assert.AreEqual(kv1.Value, B.Attributes.GetValueOrDefault(kv1.Key));
			Assert.AreEqual(A.Path, B.Path);
		}



		// Read a secret, by passing an existing secret object.
		[Test, Order(200)]
		public async Task Secret_ReadSecret_PassingSecretObject () {
			// Create a Secret.
			Secret A = new Secret();
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test", "testValue");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Path = await Secret_Init_Create(A);

			// Now read the secrt.
			Secret B = await (SB.ReadSecret(A));
			Assert.NotNull(B);
			Assert.Contains(kv1.Key, B.Attributes.Keys);
			Assert.AreEqual(kv1.Value, B.Attributes.GetValueOrDefault(kv1.Key));
			Assert.AreEqual(A.Path, B.Path);
		}


		[Test, Order(300)]
		public async Task Secret_ListKeys_DeepList_ListsAllKeys() {
			// Create a generic seceret object.
			Secret z = new Secret();
			z.Path = "Test/Level";
			for (int i=1;i < 5;i++) {
				z.Path = z.Path + "/Level" + i.ToString();
				Assert.True(await SB.CreateSecretAndReturn(z));
			}

			
		}
	}


}
