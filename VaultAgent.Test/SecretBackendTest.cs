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
		SysBackend VSB;

	
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
			VSB = new SysBackend(VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken);

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
			Assert.True(await SB.CreateOrUpdateSecretAndReturn(val));

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

			Assert.True(await SB.CreateOrUpdateSecretAndReturn(A));
		}



		// Create an Empty Secret, from a Secret object.  Has no attributes
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromSecretObject_ReturnsTrue() {
			await Secret_Init();

			Secret A = new Secret();

			string secretName = "Test/B/mysecret";
			A.Path = secretName;

			Assert.True(await SB.CreateOrUpdateSecretAndReturn(A));
		}



		// Create an Empty Secret from just a secret name.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromJustSecretName_ReturnsTrue() {
			await Secret_Init();		
			string secretName = "Test/C/mysecret";
			Assert.True(await SB.CreateOrUpdateSecretAndReturn(secretName));
		}



		// Create an empty secret with just the secret name.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromJustSecretName_ReturnsSecretObject () {
			await Secret_Init();

			String secretName = "Test/D/myothersec";
			Secret B = await SB.CreateOrUpdateSecret(secretName);
			Assert.NotNull(B);
			Assert.AreEqual(secretName, B.Path);
		}




		// Create an empty secret from a Secret Object, returning a secret.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromSecretObject_ReturnsSecretObject() {
			await Secret_Init();

			String secretName = "Test/E/myothersec";
			Secret A = new Secret(secretName);
			Secret B = await SB.CreateOrUpdateSecret(A);
			Assert.NotNull(B);
			Assert.AreEqual(secretName, B.Path);
		}




		[Test, Order (100)]
		public async Task Secret_CreateSecret_Success () {
			await Secret_Init();

			String secretName = "Test/F/bkbk";
			Secret A = new Secret(secretName);

			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("user", "FredFlinstone");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("house", "rubbles");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Attributes.Add(kv2.Key, kv2.Value);

			Secret secret = await SB.CreateSecret(A);
			Assert.NotNull(secret);

			// 3 because all secrets saved to Vault have a TTL value that is added as an attribute.
			Assert.AreEqual(3, secret.Attributes.Count);
		}



		// Tests if Create Secret returns null if the secret already exists.  Prevents overwriting it.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_ExistingSecret_ReturnsNull () {
			await Secret_Init();

			String secretName = "Test/F/hhyhyk";
			Secret A = new Secret(secretName);

			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("user", "FredFlinstone");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("house", "rubbles");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Attributes.Add(kv2.Key, kv2.Value);

			Secret secret = await SB.CreateSecret(A);
			Assert.NotNull(secret);

			// Now try to create it again.  Should fail.
			Secret secret2 = await SB.CreateSecret(A);
			Assert.Null(secret2);
		}




		// Read a secret that does not exist.  Should return null.
		[Test,Order(200)]
		public async Task Secret_ReadSecret_SecretDoesNotExist_ReturnsNull () {
			await Secret_Init();

			Assert.Null(await SB.ReadSecret(Guid.NewGuid().ToString()));
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



		// IfExists should return false when no secret exists.
		[Test, Order(250)]
		public async Task Secret_IfExists_IfNoSecret_ShouldReturnFalse () {
			await Secret_Init();

			string secret = Guid.NewGuid().ToString();
			Secret A = new Secret(secret);

			Assert.False(await SB.IfExists(A));
		}




		// IfExists should return true when a secret exists.
		[Test, Order(250)]
		public async Task Secret_IfExists_SecretExists_ShouldReturnTrue() {
			// Create a Secret.
			Secret A = new Secret();
			A.Path = await Secret_Init_Create(A);

			Assert.True(await SB.IfExists(A));
		}





		// IfExists should return false when no secret exists.
		[Test, Order(250)]
		public async Task Secret_IfExists_IfNoSecretSecretPath_ShouldReturnFalse() {
			await Secret_Init();

			string secret = Guid.NewGuid().ToString();

			Assert.False(await SB.IfExists(secret));
		}




		// IfExists should return true when a secret exists.
		[Test, Order(250)]
		public async Task Secret_IfExists_SecretExistsSecretPath_ShouldReturnTrue() {
			// Create a Secret.
			Secret A = new Secret();
			A.Path = await Secret_Init_Create(A);

			Assert.True(await SB.IfExists(A.Path));
		}





		[Test, Order(300)]
		public async Task Secret_ListSecrets_NoSubSecrets_Success () {
			Secret A = new Secret();
			A.Path = await Secret_Init_Create(A);

			List<string> secrets = await SB.ListSecrets(A.Path);
			Assert.AreEqual(0, secrets.Count);
		}




		// List sub secrets.
		[Test, Order(300)]
		public async Task Secret_ListSecrets_WithSubSecrets_Success() {
			await Secret_Init();

			// Create a generic seceret object.
			Secret z = new Secret();
			try {


				// Create 2 secrets each with 2 sub secrets.
				string startPath = "Test/Level";
				z.Path = startPath;
				for (int i = 1; i < 3; i++) {
					z.Path = startPath + "/Level" + i.ToString();
					Assert.True(await SB.CreateOrUpdateSecretAndReturn(z));
					}
			
				// Now list those secrets
				List<string> secrets = await SB.ListSecrets(startPath);
				Assert.AreEqual(2, secrets.Count);
			}
			catch (Exception e) { Console.WriteLine("Error - {0}", e.Message); }
		}




		// Same as prior test.  Only we pass a Secret object instead of a secret Path.
		[Test, Order(300)]
		public async Task Secret_ListSecrets_WithSubSecretsPassingSecretObject_Success() {
			await Secret_Init();

			// Create a generic seceret object.
			Secret z = new Secret();
			try {


				// Create 2 secrets each with 2 sub secrets.
				string startPath = "Test/Level";
				z.Path = startPath;
				for (int i = 1; i < 3; i++) {
					z.Path = startPath + "/Level" + i.ToString();
					Assert.True(await SB.CreateOrUpdateSecretAndReturn(z));
				}

				// Now list those secrets
				z.Path = startPath;
				List<string> secrets = await SB.ListSecrets(z);
				Assert.AreEqual(2, secrets.Count);
			}
			catch (Exception e) { Console.WriteLine("Error - {0}", e.Message); }
		}



		// List secrets that have multiple sub secrets.
		[Test, Order(300)]
		public async Task Secret_ListSecrets_WithSubSubSecrets_Success () {
			await Secret_Init();

			// Create a generic seceret object.
			Secret z = new Secret();
			Secret y = new Secret();
			try {


				// Create 2 secrets each with 2 sub secrets.
				string startPath = "Test/Level";
				z.Path = startPath;
				for (int i = 1; i < 3; i++) {
					z.Path = startPath + "/Level" + i.ToString();
					Assert.True(await SB.CreateOrUpdateSecretAndReturn(z));
					for (int j = 1; j < 3; j++) {
						y.Path = z.Path + "/SubLevel" + j.ToString();
						Assert.True(await SB.CreateOrUpdateSecretAndReturn(y));
					}
				}

				// Now list those secrets
				List<string> secrets = await SB.ListSecrets(startPath);
				Assert.AreEqual(4, secrets.Count);
			}
			catch (Exception e) { Console.WriteLine("Error - {0}", e.Message); }
		}




		[Test, Order(400)]
		public async Task Secret_UpdateSecret_Success () {
			Secret A = new Secret();
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test", "testValue");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("abc", "123e");
			KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("ZYX", "88g8g9dfkj df");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Attributes.Add(kv2.Key, kv2.Value);
			A.Attributes.Add(kv3.Key, kv3.Value);
			A.Path = await Secret_Init_Create(A);

			Secret A2 = await SB.ReadSecret(A);
			Assert.AreEqual(A.Path, A2.Path);
			Assert.AreEqual(A.Attributes.Count + 1, A2.Attributes.Count);

			// Now lets change some values.
			A2.Attributes[kv1.Key] = kv1.Key;
			A2.Attributes[kv2.Key] = kv2.Key;
			A2.Attributes[kv3.Key] = kv3.Key;

			Secret B = await SB.UpdateSecret(A2);
			Assert.NotNull(B);
			Assert.AreEqual(A2.Attributes.Count, B.Attributes.Count);
			Assert.AreEqual(kv1.Key, B.Attributes[kv1.Key]);
			Assert.AreEqual(kv2.Key, B.Attributes[kv2.Key]);
			Assert.AreEqual(kv3.Key, B.Attributes[kv3.Key]);
		}



		[Test, Order(800)]
		public async Task Secret_DeleteSecret_SpecifyingPath_Success() {
			// Create a Secret that has attributes.
			Secret A = new Secret();
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test", "testValue");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("abc", "123e");
			KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("ZYX", "88g8g9dfkj df");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Attributes.Add(kv2.Key, kv2.Value);
			A.Attributes.Add(kv3.Key, kv3.Value);
			A.Path = await Secret_Init_Create(A);

			Assert.True(await SB.DeleteSecret(A.Path));

			// Try to read the secret.
			Assert.Null(await SB.ReadSecret(A));
		}




		// Should delete the secret from Vault AND the secret object.
		[Test, Order(800)]
		public async Task Secret_DeleteSecret_FromSecretObject_Success() {
			// Create a Secret that has attributes.
			Secret A = new Secret();
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test", "testValue");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("abc", "123e");
			KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("ZYX", "88g8g9dfkj df");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Attributes.Add(kv2.Key, kv2.Value);
			A.Attributes.Add(kv3.Key, kv3.Value);
			A.Path = await Secret_Init_Create(A);

			// Store path for later use.
			string thePath = A.Path;

			// Now delete secret.  Should return True AND set secret to NULL.
			Assert.True(await SB.DeleteSecret(A));
			Assert.AreEqual("", A.Path);
			Assert.AreEqual(0, A.Attributes.Count);


			// Try to read the secret.
			Assert.Null(await SB.ReadSecret(thePath));
		}



		[Test,Order(800)]
		public bool Secret_DeleteSecret_ShouldFailIfNoPermission () {
			throw new NotImplementedException();
		}


	}


}
