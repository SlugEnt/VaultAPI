using System;
using System.Collections.Generic;
using NUnit.Framework;
using VaultAgent.SecretEngines;
using VaultAgent.Backends.System;
using System.Threading.Tasks;
using VaultAgent;

namespace VaultAgentTests
{


	[Parallelizable]
    public class SecretBackendTest
    {
		private VaultAgentAPI _vaultAgentAPI;
		private readonly UniqueKeys _uniqueKeys = new UniqueKeys();       // Unique Key generator

		// The KeyValue Secret  Backend we will be using throughout our testing.
		KeyValueSecretEngine _keyValueSecretEngine;



		[OneTimeSetUp]
		public async Task Secret_Init() {
			if (_vaultAgentAPI != null) {
				return;
			}

			// Build Connection to Vault.
			_vaultAgentAPI = new VaultAgentAPI("testa", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);
			string mountName = _uniqueKeys.GetKey("SEC");

			// Create a secret Backend Mount for this series of tests.
			_keyValueSecretEngine = (KeyValueSecretEngine)await _vaultAgentAPI.CreateSecretBackendMount(EnumSecretBackendTypes.Secret, mountName, mountName, "Secret V1 Backend");

			Assert.NotNull(_keyValueSecretEngine);
			return;
		}




		private async Task<string> Secret_Init_Create(KeyValueSecret val) {
			string sec = _uniqueKeys.GetKey("SEC");

			val.Path = sec;
			Assert.True(await _keyValueSecretEngine.CreateOrUpdateSecretAndReturn(val));

			return sec;
		}

		


		// Simple Secret Creation Test.
		[Test, Order(100)]
		public async Task Secret_CreateSecret () {
			KeyValueSecret A = new KeyValueSecret();

			string secretName = "Test/A/mysecret";
			A.Path = secretName;
			A.Attributes.Add("conn", "db1-Myconn");
			A.Attributes.Add("user", "dbuserAdmin");

			Assert.True(await _keyValueSecretEngine.CreateOrUpdateSecretAndReturn(A));
		}



		// Create an Empty Secret, from a Secret object.  Has no attributes
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromSecretObject_ReturnsTrue() {
			KeyValueSecret A = new KeyValueSecret();

			string secretName = "Test/B/mysecret";
			A.Path = secretName;

			Assert.True(await _keyValueSecretEngine.CreateOrUpdateSecretAndReturn(A));
		}



		// Create an Empty Secret from just a secret name.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromJustSecretName_ReturnsTrue() {
			string secretName = "Test/C/mysecret";
			Assert.True(await _keyValueSecretEngine.CreateOrUpdateSecretAndReturn(secretName));
		}



		// Create an empty secret with just the secret name.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromJustSecretName_ReturnsSecretObject () {
			String secretName = "Test/D/myothersec";
			KeyValueSecret B = await _keyValueSecretEngine.CreateOrUpdateSecret(secretName);
			Assert.NotNull(B);
			Assert.AreEqual(secretName, B.Path);
		}




		// Create an empty secret from a Secret Object, returning a secret.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_FromSecretObject_ReturnsSecretObject() {
			String secretName = "Test/E/myothersec";
			KeyValueSecret A = new KeyValueSecret(secretName);
			KeyValueSecret B = await _keyValueSecretEngine.CreateOrUpdateSecret(A);
			Assert.NotNull(B);
			Assert.AreEqual(secretName, B.Path);
		}




		[Test, Order (100)]
		public async Task Secret_CreateSecret_Success () {
			String secretName = "Test/F/bkbk";
			KeyValueSecret A = new KeyValueSecret(secretName);

			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("user", "FredFlinstone");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("house", "rubbles");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Attributes.Add(kv2.Key, kv2.Value);

			KeyValueSecret secret = await _keyValueSecretEngine.CreateSecret(A);
			Assert.NotNull(secret);

			// 3 because all secrets saved to Vault have a TTL value that is added as an attribute.
			Assert.AreEqual(3, secret.Attributes.Count);
		}



		// Tests if Create Secret returns null if the secret already exists.  Prevents overwriting it.
		[Test, Order(100)]
		public async Task Secret_CreateSecret_ExistingSecret_ReturnsNull () {
			String secretName = "Test/F/hhyhyk";
			KeyValueSecret A = new KeyValueSecret(secretName);

			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("user", "FredFlinstone");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("house", "rubbles");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Attributes.Add(kv2.Key, kv2.Value);

			KeyValueSecret secret = await _keyValueSecretEngine.CreateSecret(A);
			Assert.NotNull(secret);

			// Now try to create it again.  Should fail.
			KeyValueSecret secret2 = await _keyValueSecretEngine.CreateSecret(A);
			Assert.Null(secret2);
		}




		// Read a secret that does not exist.  Should return null.
		[Test,Order(200)]
		public async Task Secret_ReadSecret_SecretDoesNotExist_ReturnsNull () {
			Assert.Null(await _keyValueSecretEngine.ReadSecret(Guid.NewGuid().ToString()));
		}




		// Read a secret, passing a secret name only.
		[Test, Order(200)]
		public async Task Secret_ReadSecret_PassingSecretPath() {
			// Create a Secret.
			KeyValueSecret A = new KeyValueSecret();
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test", "testValue");
			A.Attributes.Add(kv1.Key,kv1.Value);
			A.Path = await Secret_Init_Create(A);


			// Now read the secret.
			KeyValueSecret B = await _keyValueSecretEngine.ReadSecret(A.Path);
			Assert.NotNull(B);
			Assert.Contains(kv1.Key, B.Attributes.Keys);
			Assert.AreEqual(kv1.Value, B.Attributes.GetValueOrDefault(kv1.Key));
			Assert.AreEqual(A.Path, B.Path);
		}



		// Read a secret, by passing an existing secret object.
		[Test, Order(200)]
		public async Task Secret_ReadSecret_PassingSecretObject () {
			// Create a Secret.
			KeyValueSecret A = new KeyValueSecret();
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test", "testValue");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Path = await Secret_Init_Create(A);

			// Now read the secrt.
			KeyValueSecret B = await (_keyValueSecretEngine.ReadSecret(A));
			Assert.NotNull(B);
			Assert.Contains(kv1.Key, B.Attributes.Keys);
			Assert.AreEqual(kv1.Value, B.Attributes.GetValueOrDefault(kv1.Key));
			Assert.AreEqual(A.Path, B.Path);
		}



		// IfExists should return false when no secret exists.
		[Test, Order(250)]
		public async Task Secret_IfExists_IfNoSecret_ShouldReturnFalse () {
			string secret = Guid.NewGuid().ToString();
			KeyValueSecret A = new KeyValueSecret(secret);

			Assert.False(await _keyValueSecretEngine.IfExists(A));
		}




		// IfExists should return true when a secret exists.
		[Test, Order(250)]
		public async Task Secret_IfExists_SecretExists_ShouldReturnTrue() {
			// Create a Secret.
			KeyValueSecret A = new KeyValueSecret();
			A.Path = await Secret_Init_Create(A);

			Assert.True(await _keyValueSecretEngine.IfExists(A));
		}





		// IfExists should return false when no secret exists.
		[Test, Order(250)]
		public async Task Secret_IfExists_IfNoSecretSecretPath_ShouldReturnFalse() {
			string secret = Guid.NewGuid().ToString();
			Assert.False(await _keyValueSecretEngine.IfExists(secret));
		}




		// IfExists should return true when a secret exists.
		[Test, Order(250)]
		public async Task Secret_IfExists_SecretExistsSecretPath_ShouldReturnTrue() {
			// Create a Secret.
			KeyValueSecret A = new KeyValueSecret();
			A.Path = await Secret_Init_Create(A);

			Assert.True(await _keyValueSecretEngine.IfExists(A.Path));
		}





		[Test, Order(300)]
		public async Task Secret_ListSecrets_NoSubSecrets_Success () {
			KeyValueSecret A = new KeyValueSecret();
			A.Path = await Secret_Init_Create(A);

			List<string> secrets = await _keyValueSecretEngine.ListSecrets(A.Path);
			Assert.AreEqual(0, secrets.Count);
		}




		// List sub secrets.
		[Test, Order(300)]
		public async Task Secret_ListSecrets_WithSubSecrets_Success() {
			// Create a generic seceret object.
			KeyValueSecret z = new KeyValueSecret();
			try {


				// Create 2 secrets each with 2 sub secrets.
				string startPath = "Test/Level";
				z.Path = startPath;
				for (int i = 1; i < 3; i++) {
					z.Path = startPath + "/Level" + i.ToString();
					Assert.True(await _keyValueSecretEngine.CreateOrUpdateSecretAndReturn(z));
					}
			
				// Now list those secrets
				List<string> secrets = await _keyValueSecretEngine.ListSecrets(startPath);
				Assert.AreEqual(2, secrets.Count);
			}
			catch (Exception e) { Console.WriteLine("Error - {0}", e.Message); }
		}




		// Same as prior test.  Only we pass a Secret object instead of a secret Path.
		[Test, Order(300)]
		public async Task Secret_ListSecrets_WithSubSecretsPassingSecretObject_Success() {
			// Create a generic seceret object.
			KeyValueSecret z = new KeyValueSecret();
			try {


				// Create 2 secrets each with 2 sub secrets.
				string startPath = "Test/Level";
				z.Path = startPath;
				for (int i = 1; i < 3; i++) {
					z.Path = startPath + "/Level" + i.ToString();
					Assert.True(await _keyValueSecretEngine.CreateOrUpdateSecretAndReturn(z));
				}

				// Now list those secrets
				z.Path = startPath;
				List<string> secrets = await _keyValueSecretEngine.ListSecrets(z);
				Assert.AreEqual(2, secrets.Count);
			}
			catch (Exception e) { Console.WriteLine("Error - {0}", e.Message); }
		}



		// List secrets that have multiple sub secrets.
		[Test, Order(300)]
		public async Task Secret_ListSecrets_WithSubSubSecrets_Success () {
			// Create a generic seceret object.
			KeyValueSecret z = new KeyValueSecret();
			KeyValueSecret y = new KeyValueSecret();
			try {


				// Create 2 secrets each with 2 sub secrets.
				string startPath = "Test/Level";
				z.Path = startPath;
				for (int i = 1; i < 3; i++) {
					z.Path = startPath + "/Level" + i.ToString();
					Assert.True(await _keyValueSecretEngine.CreateOrUpdateSecretAndReturn(z));
					for (int j = 1; j < 3; j++) {
						y.Path = z.Path + "/SubLevel" + j.ToString();
						Assert.True(await _keyValueSecretEngine.CreateOrUpdateSecretAndReturn(y));
					}
				}

				// Now list those secrets
				List<string> secrets = await _keyValueSecretEngine.ListSecrets(startPath);
				Assert.AreEqual(4, secrets.Count);
			}
			catch (Exception e) { Console.WriteLine("Error - {0}", e.Message); }
		}




		[Test]
		public async Task Secret_UpdateSecret_Success () {
			KeyValueSecret A = new KeyValueSecret();
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test", "testValue");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("abc", "123e");
			KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("ZYX", "88g8g9dfkj df");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Attributes.Add(kv2.Key, kv2.Value);
			A.Attributes.Add(kv3.Key, kv3.Value);
			A.Path = await Secret_Init_Create(A);

			KeyValueSecret A2 = await _keyValueSecretEngine.ReadSecret(A);
			Assert.AreEqual(A.Path, A2.Path);
			Assert.AreEqual(A.Attributes.Count + 1, A2.Attributes.Count);

			// Now lets change some values.
			A2.Attributes[kv1.Key] = kv1.Key;
			A2.Attributes[kv2.Key] = kv2.Key;
			A2.Attributes[kv3.Key] = kv3.Key;

			KeyValueSecret B = await _keyValueSecretEngine.UpdateSecret(A2);
			Assert.NotNull(B);
			Assert.AreEqual(A2.Attributes.Count, B.Attributes.Count);
			Assert.AreEqual(kv1.Key, B.Attributes[kv1.Key]);
			Assert.AreEqual(kv2.Key, B.Attributes[kv2.Key]);
			Assert.AreEqual(kv3.Key, B.Attributes[kv3.Key]);
		}



		[Test]
		public async Task Secret_DeleteSecret_SpecifyingPath_Success() {
			// Create a Secret that has attributes.
			KeyValueSecret A = new KeyValueSecret();
			KeyValuePair<string, string> kv1 = new KeyValuePair<string, string>("test", "testValue");
			KeyValuePair<string, string> kv2 = new KeyValuePair<string, string>("abc", "123e");
			KeyValuePair<string, string> kv3 = new KeyValuePair<string, string>("ZYX", "88g8g9dfkj df");
			A.Attributes.Add(kv1.Key, kv1.Value);
			A.Attributes.Add(kv2.Key, kv2.Value);
			A.Attributes.Add(kv3.Key, kv3.Value);
			A.Path = await Secret_Init_Create(A);

			Assert.True(await _keyValueSecretEngine.DeleteSecret(A.Path));

			// Try to read the secret.
			Assert.Null(await _keyValueSecretEngine.ReadSecret(A));
		}




		// Should delete the secret from Vault AND the secret object.
		[Test, Order(800)]
		public async Task Secret_DeleteSecret_FromSecretObject_Success() {
			// Create a Secret that has attributes.
			KeyValueSecret A = new KeyValueSecret();
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
			Assert.True(await _keyValueSecretEngine.DeleteSecret(A));
			Assert.AreEqual("", A.Path);
			Assert.AreEqual(0, A.Attributes.Count);


			// Try to read the secret.
			Assert.Null(await _keyValueSecretEngine.ReadSecret(thePath));
		}



		[Test,Order(800)]
		public bool Secret_DeleteSecret_ShouldFailIfNoPermission () {
			throw new NotImplementedException();
			return false;
		}


	}


}
