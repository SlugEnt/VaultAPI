using System.Collections.Generic;
using System.ComponentModel;
using System.Threading;
using NUnit.Framework;
using VaultAgent.Backends.System;
using VaultAgent.SecretEngines;
using System.Threading.Tasks;
using VaultAgent.Backends;
using VaultAgentTests;
using VaultAgent;
using System;
using VaultAgent.AuthenticationEngines;
using SlugEnt;


namespace VaultAgentTests
{

    /// <summary>
    /// Tests the Identity Secret Engine
    /// </summary>
	[TestFixture]
	[Parallelizable]
	class IdentitySecretEngine_Test {
		private VaultAgentAPI _vaultAgentAPI;
		private IdentitySecretEngine _idEngine;
		private readonly UniqueKeys _uniqueKey = new UniqueKeys("_","__"); // Unique Key generator

		// Used in the Entity Alias tests.
		private string _appRoleAccessor = "";

		private AppRoleAuthEngine _appRoleAuthEngine;

		// Used to get around thread locking /await issues.
		private bool bLocking = false;
		private Object locking = new Object();



		/// <summary>
		/// One Time Setup - Run once per a single Test run exection.
		/// </summary>
		/// <returns></returns>
		[OneTimeSetUp]
		public void Identity_Init() {
			if ( _vaultAgentAPI != null ) { return; }

			// Build Connection to Vault.
			_vaultAgentAPI = new VaultAgentAPI("IdentityTest", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);
			_idEngine = (IdentitySecretEngine) _vaultAgentAPI.ConnectToSecretBackend(EnumSecretBackendTypes.Identity);

			}



		public async Task SetupAliasTestConditions() {

			lock (locking) {
				while (bLocking == true) {
					Thread.Sleep(100);
				}

				// Set lock to true.
				bLocking = true;
			}

			string AppRoleEngine = "appRoleTST";

			try {


				// If already done this during this test run, then no need to do again.
				if ( _appRoleAccessor != "" ) { return; }

				// We need A role based Auth engine so we can test the Alias functionality.  This is a constant value.  If we can't find it then we create it.

				AuthMethod authMethod = null;
				while ( authMethod == null ) {
					Dictionary<string, AuthMethod> authMethods = await _vaultAgentAPI.System.AuthListAll();

					// See if the AppRole Backend exists.  We need to add a trailing slash because vault returns the key with a trailing slash.  Swallow exception not found.
					try { authMethod = authMethods[AppRoleEngine + "/"]; }
					catch ( KeyNotFoundException ) { }

					if ( authMethod == null ) {
						AuthMethod am = new AuthMethod(AppRoleEngine, EnumAuthMethods.AppRole);
						bool rc = await _vaultAgentAPI.System.AuthEnable(am);
						Thread.Sleep(60);
					}
				}

				// Connect the AppRole Authentication engine.
				_appRoleAuthEngine =
					(AppRoleAuthEngine) _vaultAgentAPI.ConnectAuthenticationBackend(EnumBackendTypes.A_AppRole, AppRoleEngine, AppRoleEngine);

				// Store the accessor for use in entity-alias tests and to alert that we completed this setup task.
				_appRoleAccessor = authMethod.Accessor;
			}

			catch ( Exception ) { Assert.False(true, "[SetupAliasTestConditions]  Try block errored"); }
			finally {

				lock (locking) { bLocking = false; }
			}


			//TestContext.WriteLine("Role Name:     {0}", _theRole.Name);
			//TestContext.WriteLine("Role ID:       {0}", _theRole.RoleID);
			TestContext.WriteLine("Role Backend:  {0}", AppRoleEngine);
			TestContext.WriteLine("Role Accessor: {0}", _appRoleAccessor);
		}


		#region EntityTests




		// Validates we can save a new entity.
		[Test]
		public async Task Create_Entity_Success() {
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest1");
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company","ACME");
			entity.Metadata.Add("Products","Dynamite");

			// Now save entity
			Entity rc = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(rc, "A10:  Expected to receive an Entity object");
			Guid gID = new Guid();
			Assert.AreNotEqual(gID,rc.Id, "A20:  The SaveEntity method should have returned an Entity object with a GUID value.  Instead it is at default - 0.");
			TestContext.WriteLine("Entity Name:   {0}", entity.Name);
			TestContext.WriteLine("Entity ID:     {0}", entity.Id);
		}



		// Validates that we can read an already existing entity.
		[Test]
		public async Task Read_Entity_Success() {
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest1");
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Now save entity
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity,"A10:  Expected an Entity object to be returned.  Received nothing");


			// Now read the Entity.
			Entity readEntity = await _idEngine.ReadEntity(savedEntity.Id);


			// Validate they are the same:
			Assert.IsNotNull(readEntity, "A20:  Expected an updated Entity object to be returned.  Received nothing.");
			Assert.AreEqual(savedEntity.Id, readEntity.Id, "A25:  The entity ID's were not the same.  Big Problem!");

			CollectionAssert.AreEquivalent(entity.Policies,savedEntity.Policies,"A30:  Policies Lists are not the same.");
			CollectionAssert.AreEquivalent(entity.Metadata,savedEntity.Metadata,"A40:  MetaData objects were expected to be equivalent, but they are not.");
		}



		// Validates that we can read an already existing entity.
		[Test]
		public async Task Read_EntityByName_Success() {
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest1");
			entity.Metadata.Add("Company", "ACME");

			// Now save entity
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected an Entity object to be returned.  Received nothing");


			// Now read the Entity.
			Entity readEntity = await _idEngine.ReadEntity(savedEntity.Name);


			// Validate they are the same:
			Assert.IsNotNull(readEntity, "A20:  Expected an updated Entity object to be returned.  Received nothing.");
			Assert.AreEqual(savedEntity.Id, readEntity.Id, "A25:  The entity ID's were not the same.  Big Problem!");

			CollectionAssert.AreEquivalent(entity.Policies, savedEntity.Policies, "A30:  Policies Lists are not the same.");
			CollectionAssert.AreEquivalent(entity.Metadata, savedEntity.Metadata, "A40:  MetaData objects were expected to be equivalent, but they are not.");
		}




		// Validates we can update an existing entity
		[Test]
		public async Task Update_ExistingEntity_Success() {
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest1");
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Save Entity and retrieve the saved Entity object.
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected an Entity object to be returned.  Received nothing");

			// Now update.  Lets add 2 more policies and one more MetaData attributes.
			savedEntity.Policies.Add("polTest3");
			savedEntity.Policies.Add("polTest4");
			savedEntity.Metadata.Add("Animals","Coyotes");

			// Now update and retrieve the new object.
			Entity updatedEntity = await _idEngine.SaveEntity(savedEntity);
			Assert.IsNotNull(updatedEntity, "A20:  Expected an updated Entity object to be returned.  Received nothing.");
			Assert.AreEqual(savedEntity.Id,updatedEntity.Id, "A25:  The entity ID's were not the same.  Big Problem!");

			// Validate MetaData and Policies collections are equivalent
			CollectionAssert.AreEquivalent(savedEntity.Policies, updatedEntity.Policies, "A30:  Policies Lists are not the same.");
			CollectionAssert.AreEquivalent(savedEntity.Metadata, updatedEntity.Metadata, "A40:  MetaData objects were expected to be equivalent, but they are not.");
		}



		// Validate that we can delete an Entity by ID.
		[Test]
		public async Task Delete_ExistingEntity_Success() {
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest1");
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Save Entity and retrieve the saved Entity object.
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected an Entity object to be returned.  Received nothing");

			Assert.True(await _idEngine.DeleteEntity(savedEntity.Id));
		}



		// Validate that we can delete an Entity by Name
		[Test]
		public async Task Delete_ExistingEntityByName_Success() {
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest1");
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Save Entity and retrieve the saved Entity object.
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected an Entity object to be returned.  Received nothing");

			Assert.True(await _idEngine.DeleteEntity(savedEntity.Name));
		}



		[Test]
		public async Task ListEntitiesByName_Success() {
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Products", "Dynamite");

			// Save Entity and retrieve the saved Entity object.
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected an Entity object to be returned.  Received nothing");

			// Now list the entities. It should be more than 0.  We are not sure how many due to the other tests.  But it will be > 0 for sure.
			List<string> entities = await _idEngine.ListEntitiesByName();
			Assert.GreaterOrEqual(entities.Count,1,"A20:  Expected to receive a list of entities with at least 1 entry.");
			CollectionAssert.Contains(entities, entity.Name, "A30:  Was looking for the entity we created.  But did not find it.");
		}



		[Test]
		public async Task ListEntitiesByID_Success() {
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Products", "Dynamite");

			// Save Entity and retrieve the saved Entity object.
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected an Entity object to be returned.  Received nothing");

			// Now list the entities. It should be more than 0.  We are not sure how many due to the other tests.  But it will be > 0 for sure.
			List<Guid> entities = await _idEngine.ListEntitiesByID();
			Assert.GreaterOrEqual(entities.Count, 1, "A20:  Expected to receive a list of entities with at least 1 entry.");
			CollectionAssert.Contains(entities,savedEntity.Id,"A30:  Was looking for the entity we created.  But did not find it.");
		}



		// Validate that trying to delete a nonExistentEntity Throws an error.
		[Test]
		public async Task Delete_NonExistentEntity_ReturnsTrue() {
			Guid guid = Guid.NewGuid();

			Assert.True(await _idEngine.DeleteEntity(guid),"A10:  Expected that the return code was True.");
		}


#pragma warning disable CS1998
        // Validates that trying to read an entity that does not exist throws the correct error.
        [Test]
		public async Task Read_NonExistentEntity_ThrowsError() {
			Guid guid = Guid.NewGuid();

			Assert.ThrowsAsync<VaultInvalidPathException>(async () => await _idEngine.ReadEntity(guid),"A10:  Expected to receive the VaultInvalidPathException error when trying to read a nonexistent Entity.");
		}
#pragma warning restore CS1998

        #endregion


        #region EntityAliasTests

        [Test]
		public async Task SaveEntityAlias_Success() {
			// Ensure Alias Pre-Conditions are defined.
			await SetupAliasTestConditions();

			// Now create an entity.
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Now save entity
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected to receive an Entity object");

			// Write out some values 
			TestContext.WriteLine("Entity Name:      {0}", savedEntity.Name);
			TestContext.WriteLine("Entity ID:        {0}", savedEntity.Id);


			// Now we need to create an AppRole and store it off.
			string roleName = _uniqueKey.GetKey("aRoleT");
			AppRole theRole = new AppRole(roleName);
			theRole = await _appRoleAuthEngine.SaveRoleAndReturnRoleObject(theRole);
			Assert.IsNotNull(theRole, "The application role must be a valid role object in order for the Entity-Alias tests to work.");


			// Now lets create an alias.
			Guid aliasGuid = await _idEngine.SaveAlias(savedEntity.Id, _appRoleAccessor, theRole.Name);
			Assert.AreNotEqual(aliasGuid.ToString(),Guid.Empty.ToString());

			TestContext.WriteLine("Alias ID:         {0}", aliasGuid);
			TestContext.WriteLine("Alias Name:       {0}", theRole.Name);
		}


		[Test]
		public async Task EntityAlias_Read_Success() {
			// Ensure Alias Pre-Conditions are defined.
			await SetupAliasTestConditions();

			// Now create an entity.
			string name = _uniqueKey.GetKey("Entity");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Now save entity
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected to receive an Entity object");

			// Write out some values 
			TestContext.WriteLine("Entity Name:      {0}", savedEntity.Name);
			TestContext.WriteLine("Entity ID:        {0}", savedEntity.Id);

			// Now we need to create an AppRole and store it off.
			string roleName = _uniqueKey.GetKey("aRoleT");
			AppRole theRole = new AppRole(roleName);
			theRole = await _appRoleAuthEngine.SaveRoleAndReturnRoleObject(theRole);
			Assert.IsNotNull(theRole, "The application role must be a valid role object in order for the Entity-Alias tests to work.");

			// Now lets create an alias.
			Guid aliasGuid = await _idEngine.SaveAlias(savedEntity.Id, _appRoleAccessor, theRole.Name);
			Assert.AreNotEqual(aliasGuid.ToString(), Guid.Empty.ToString());

			TestContext.WriteLine("Alias ID:         {0}", aliasGuid);
			TestContext.WriteLine("Alias Name:       {0}", theRole.Name);

			// Now lets read the alias back.
			EntityAlias alias = await _idEngine.ReadAlias(aliasGuid);
			Assert.AreEqual(theRole.Name, alias.Name, "A30:  Alias Name was incorrect.");
			Assert.AreEqual(_appRoleAccessor, alias.MountAccessor, "A40:  Mount Accessors were not the same.");
			Assert.AreEqual(savedEntity.Id, alias.CanonicalId, "A50:  Auth backend ID's were not the same.");
		}



		// Validates that creating an alias to a remote authentication backend user that does not exist works. 
		// Yeah - sounds backward, but it is what it is.  
		// This just serves as a test to ensure that future changes to Vault are detected.
		[Test]
		public async Task EntityAlias_SaveInvalidAuthUserName_Success() {
			// Ensure Alias Pre-Conditions are defined.
			await SetupAliasTestConditions();

			// Now create an entity.
			string name = _uniqueKey.GetKey("EntityR");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Now save entity
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected to receive an Entity object");

			// Write out some values 
			TestContext.WriteLine("Entity Name:      {0}", savedEntity.Name);
			TestContext.WriteLine("Entity ID:        {0}", savedEntity.Id);

			// Create a bogus role name "user"
			string roleName = _uniqueKey.GetKey("aRoleTEE");

			// Now lets create an alias to that role.
			Guid aliasGuid = await _idEngine.SaveAlias(savedEntity.Id, _appRoleAccessor, roleName);
			Assert.AreNotEqual(Guid.Empty, aliasGuid, "A20:  Expected an error.");
		}




		[Test]
		public void EntityAlias_Update_Success() {
			throw new NotImplementedException();
			// It is not working correctly.
			/*
			// Ensure Alias Pre-Conditions are defined.
			await SetupAliasTestConditions();

			// Now create an entity.
			string name = _uniqueKey.GetKey("EntityU");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Now save entity
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected to receive an Entity object");

			// Write out some values 
			TestContext.WriteLine("Entity Name:      {0}", savedEntity.Name);
			TestContext.WriteLine("Entity ID:        {0}", savedEntity.Id);

			// Now we need to create an AppRole and store it off.
			string roleName = _uniqueKey.GetKey("aRoleTU");
			AppRole theRole = new AppRole(roleName);
			theRole = await _appRoleAuthEngine.SaveRoleAndReturnRoleObject(theRole);
			Assert.IsNotNull(theRole, "The application role must be a valid role object in order for the Entity-Alias tests to work.");

			// Now lets create an alias.
			Guid aliasGuid = await _idEngine.SaveAlias(savedEntity.Id, _appRoleAccessor, theRole.Name);
			Assert.AreNotEqual(aliasGuid.ToString(), Guid.Empty.ToString());

			TestContext.WriteLine("Alias ID:         {0}", aliasGuid);
			TestContext.WriteLine("Alias Name:       {0}", theRole.Name);

			// Now lets read the alias back.
			EntityAlias alias = await _idEngine.ReadAlias(aliasGuid);
			Assert.AreEqual(theRole.Name, alias.Name,"A30:  Alias Name was incorrect.");
			Assert.AreEqual(_appRoleAccessor,alias.MountAccessor,"A40:  Mount Accessors were not the same.");
			Assert.AreEqual(savedEntity.Id,alias.CanonicalId,"A50:  Auth backend ID's were not the same.");


			// Now lets update the alias. 
			string newName = "ZXY";
			alias.Name = newName;
			Guid guid = await _idEngine.UpdateAlias(alias.Id, alias.CanonicalId, alias.MountAccessor, alias.Name);

			EntityAlias newAlias = await _idEngine.ReadAlias(guid);
			Assert.AreEqual(newName,newAlias.Name,"Alias name does not appear to have been updated.");
            */
		}


		[Test]
		public async Task EntityAlias_Delete_Success() {
			// Ensure Alias Pre-Conditions are defined.
			await SetupAliasTestConditions();

			// Now create an entity.
			string name = _uniqueKey.GetKey("EntityD");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Now save entity
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected to receive an Entity object");

			// Write out some values 
			TestContext.WriteLine("Entity Name:      {0}", savedEntity.Name);
			TestContext.WriteLine("Entity ID:        {0}", savedEntity.Id);

			// Now we need to create an AppRole and store it off.
			string roleName = _uniqueKey.GetKey("aRoleD");	
			AppRole theRole = new AppRole(roleName);
			theRole = await _appRoleAuthEngine.SaveRoleAndReturnRoleObject(theRole);
			Assert.IsNotNull(theRole, "The application role must be a valid role object in order for the Entity-Alias tests to work.");

			// Now lets create an alias.
			Guid aliasGuid = await _idEngine.SaveAlias(savedEntity.Id, _appRoleAccessor, theRole.Name);
			Assert.AreNotEqual(aliasGuid.ToString(), Guid.Empty.ToString());

			TestContext.WriteLine("Alias ID:         {0}", aliasGuid);
			TestContext.WriteLine("Alias Name:       {0}", theRole.Name);

			// Now lets read the alias back.
			EntityAlias alias = await _idEngine.ReadAlias(aliasGuid);
			Assert.AreEqual(theRole.Name, alias.Name, "A30:  Alias Name was incorrect.");
			Assert.AreEqual(_appRoleAccessor, alias.MountAccessor, "A40:  Mount Accessors were not the same.");
			Assert.AreEqual(savedEntity.Id, alias.CanonicalId, "A50:  Auth backend ID's were not the same.");

			// Now Delete it.
			Assert.True(await _idEngine.DeleteAlias(alias.Id));

			// Validate it is gone.
			Assert.ThrowsAsync<VaultInvalidPathException>(async () => await _idEngine.ReadAlias(aliasGuid));
		}


		// Validates that List Alias works.
		[Test]
		public async Task EntityAlias_List_Works() {
			// Ensure Alias Pre-Conditions are defined.
			await SetupAliasTestConditions();

			// Now create an entity.
			string name = _uniqueKey.GetKey("EntityD");
			Entity entity = new Entity(name);
			entity.Policies.Add("polTest2");
			entity.Metadata.Add("Company", "ACME");
			entity.Metadata.Add("Products", "Dynamite");

			// Now save entity
			Entity savedEntity = await _idEngine.SaveEntity(entity);
			Assert.IsNotNull(savedEntity, "A10:  Expected to receive an Entity object");
			Thread.Sleep(60);

			List<Guid> aliases = await _idEngine.ListAliases();
			Assert.GreaterOrEqual(aliases.Count,1,"A20:  Expected the list of aliases to contain 1 or more items.");
		}

		#endregion

	} // End Class
}
