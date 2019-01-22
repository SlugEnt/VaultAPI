using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using VaultAgent.Backends;
using VaultAgent.SecretEngines;

namespace VaultAgent.SecretEngines {
    public class IdentitySecretEngine : VaultSecretBackend {
        // ==============================================================================================================================================
        /// <summary>
        /// Constructor.  Initializes the connection to Vault Identity Store.  Store has a fixed mounting location and name.
        /// </summary>
        /// <param name="httpConnector">The VaultAPI_http Http Connection object</param>
        public IdentitySecretEngine (VaultAgentAPI vaultAgentAPI) : base ("Identity", "identity", vaultAgentAPI) {
            Type = EnumBackendTypes.Identity;
            IsSecretBackend = true;
        }


        /*
         * Methods to be implemented:
         *  - Create Entity					 - Implemented (SaveEntity)
         *  - Read Entity by ID				 - Implemented (ReadEntity)
         *  - Update Entity by ID			 - Implemented (SaveEntity)
         *  - Delete Entity by ID			 - Implemented (DeleteEntity)
         *  - List Entities by ID			 - Implemented (ListEntitiesByID)
         *  - Create / Update Entity by Name - Not Implemented
         *  - Read Entity by Name			 - Implemented
         *  - Delete Entity by Name			 - Implemented
         *  - List Entities by Name			 - Implemented
         *  - Merge Entities				 - Not Implemented
         */


        #region "Core Entity Methods"


        /// <summary>
        /// Saves the given entity to the Database.  If an Entity ID is provided it will update the entry.  Otherwise a new entity will be
        /// created.  It returns Null if the save failed for some reason.  Otherwise returns an Entity object.
        /// </summary>
        /// <param name="entity"></param>
        /// <returns></returns>
        public async Task<Entity> SaveEntity (Entity entity) {
            string path = MountPointPath + "entity";

            string json = JsonConvert.SerializeObject (entity);

            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "IdentityEngine: SaveEntity", json);
            if ( vdro.Success ) {
                Guid guid;

                // If this was an update (Non empty Guid) then Vault for some reason does not return anything.  So we need to get the GUID from the 
                // passed in Entity object.  Otherwise it is in the response body.
                if ( entity.Id != Guid.Empty ) { guid = entity.Id; }
                else {
	                string id = await vdro.GetDotNetObject<string>("data.id");
                    //string id = vdro.GetDataPackageFieldAsJSON ("id");
                    guid = new Guid (id);
                }

                Entity entityNew = await ReadEntity (guid);

                // TODO - Read the Entity back from the DB and return to user.
                return entityNew;
            }


            return null;
        }



        /// <summary>
        /// Reads the requested Entity from the Vault.  Returns Entity object on success.
        /// <para>Throws [VaultInvalidPathException] if the entity was not found.</para>
        /// </summary>
        /// <param name="id">The GUID ID value of the entity to retrieve.</param>
        /// <returns></returns>
        public async Task<Entity> ReadEntity (Guid id) {
            string path = MountPointPath + "entity/id/" + id;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "IdentityEngine: ReadEntity", null);
            if ( vdro.Success ) {
	            return await vdro.GetDotNetObject<Entity>();
                //Entity entity = vdro.GetVaultTypedObjectV2<Entity>();
                //return entity;
            }

            return null;
        }



        /// <summary>
        /// Reads the requested Entity from the Vault.  Returns Entity object on success.
        /// <para>Throws [VaultInvalidPathException] if the entity was not found.</para>
        /// </summary>
        /// <param name="entityName">The name of the entity to read.</param>
        /// <returns>Entity object</returns>
        public async Task<Entity> ReadEntity (string entityName) {
            string path = MountPointPath + "entity/name/" + entityName;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "IdentityEngine: ReadEntity (EntityName)", null);
            if ( vdro.Success ) {
	            return await vdro.GetDotNetObject<Entity>();
                //Entity entity = vdro.GetVaultTypedObjectV2<Entity>();
                //return entity;
            }

            return null;
        }



        /// <summary>
        /// Deletes an Entity and all of it's associated aliases.  Returns True if successful.  Will also return True if the ID passed in does not
        /// exist in the Vault Database.
        /// </summary>
        /// <param name="id">The Id of the entity to be deleted.</param>
        /// <returns></returns>
        public async Task<bool> DeleteEntity (Guid id) {
            string path = MountPointPath + "entity/id/" + id;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.DeleteAsync (path, "DeleteEntity");
            return vdro.Success ? true : false;
        }



        /// <summary>
        /// Deletes an Entity and all of it's associated aliases.  Returns True if successful.  Will also return True if the name passed in does not
        /// exist in the Vault Database.
        /// </summary>
        /// <param name="id">The Id of the entity to be deleted.</param>
        /// <returns></returns>
        public async Task<bool> DeleteEntity (string entityName) {
            string path = MountPointPath + "entity/name/" + entityName;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.DeleteAsync (path, "DeleteEntity (EntityName)");
            return vdro.Success ? true : false;
        }



        /// <summary>
        /// Lists all the entities by name.
        /// </summary>	
        /// <returns></returns>
        public async Task<List<string>> ListEntitiesByName () {
            string path = MountPointPath + "entity/name";

            try {
                // Setup List Parameter
                Dictionary<string, string> contentParams = new Dictionary<string, string>() {{"list", "true"}};


                VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "ListEntitesByName", contentParams);
                if ( vdro.Success ) {
	                return await vdro.GetDotNetObject<List<string>>("data.keys");
//	                string js = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "keys");
  //                  List<string> keys = VaultUtilityFX.ConvertJSON<List<string>> (js);
    //                return keys;
                }

                throw new ApplicationException ("IdentitySecretEngine:ListEntitiesByName -> Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no entities.  We just return an empty list.
            catch ( VaultInvalidPathException) {
                return new List<string>();
            }
        }



        public async Task<List<Guid>> ListEntitiesByID () {
            string path = MountPointPath + "entity/id";

            try {
                // Setup List Parameter
                Dictionary<string, string> contentParams = new Dictionary<string, string>() {{"list", "true"}};


                VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "ListEntitesByID", contentParams);
                if ( vdro.Success ) {
	                return await vdro.GetDotNetObject<List<Guid>>("data.keys");
                    //string js = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "keys");
//                    List<Guid> keys = VaultUtilityFX.ConvertJSON<List<Guid>> (js);
  //                  return keys;
                }

                throw new ApplicationException ("IdentitySecretEngine:ListEntitiesByID -> Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no entities.  We just return an empty list.
            catch ( VaultInvalidPathException) {
                return new List<Guid>();
            }
        }



        public void MergeEntities (string idToMergeTo, string [] entityIDsToMerge) { throw new NotImplementedException(); }


        #endregion


        #region EntityAlias


        /// <summary>
        /// Creates a new alias for an Entity object.
        /// </summary>
        /// <returns></returns>
        public async Task<Guid> SaveAlias (Guid entityID, string mountAccessor, string aliasName) {
            string path = MountPointPath + "entity-alias";

            Dictionary<string, string> contentParams = new Dictionary<string, string>()
            {
                {"name", aliasName},
                {"canonical_id", entityID.ToString()},
                {"mount_accessor", mountAccessor}
            };


            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "IdentityEngine: SaveAlias", contentParams);
            if ( vdro.Success ) {
	            string id = await vdro.GetDotNetObject<string>("data.id");
//                string id = vdro.GetDataPackageFieldAsJSON ("id");
                Guid guid = new Guid (id);
                return guid;
            }
            else { return Guid.Empty; }
        }



        /// <summary>
        /// Reads the alias with the associated ID from the Identity store.  Returns an EntityAlias of the read object.
        /// <para>[VaultInvalidDataPath] - returns this exception if it could not find the requested value.</para>
        /// </summary>
        /// <param name="aliasID"></param>
        /// <returns></returns>
        public async Task<EntityAlias> ReadAlias (Guid aliasID) {
            string path = MountPointPath + "entity-alias/id/" + aliasID;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "IdentityEngine: ReadAlias (AliasID)", null);
            if ( vdro.Success ) {
	            return await vdro.GetDotNetObject<EntityAlias>();
//                string json = vdro.GetDataPackageAsJSON();

                //return true;
  //              EntityAlias entityAlias = vdro.GetVaultTypedObject<EntityAlias>();
    //            return entityAlias;
            }

            return null;
        }



        /// <summary>
        /// Updates the given Alias (ID) with the specified mountAccessor and aliasName.
        /// </summary>
        /// <param name="aliasID">The alias ID to be updated with new values.</param>
        /// <param name="entityID">The ID of the entity to which this Alias belongs.</param>
        /// <param name="mountAccessor">The authentication backend mount accessor the alias belongs to.</param>
        /// <param name="aliasName">Name of the authentication backend user to associate with this alias.</param>
        /// <returns></returns>
        public async Task<Guid> UpdateAlias (Guid aliasID, Guid entityID, string mountAccessor, string aliasName) {
            string path = MountPointPath + "entity-alias/id/" + aliasID;

            Dictionary<string, string> contentParams = new Dictionary<string, string>()
            {
                {"name", aliasName},
                {"canonical_id", entityID.ToString()},
                {"mount_accessor", mountAccessor}
            };


            VaultDataResponseObjectB vdro = await _parent._httpConnector.PostAsync_B (path, "IdentityEngine: UpdateAlias", contentParams);
            if ( vdro.Success ) {
	            string id = await vdro.GetDotNetObject<string>("data.id");  //vdro.GetDataPackageFieldAsJSON ("id");
                Guid guid = new Guid (id);
                return guid;
            }
            else { return Guid.Empty; }
        }



        /// <summary>
        /// Deletes an EntityAlias.  Returns true on success.
        /// </summary>
        /// <param name="id">The Id of the entityAlias to be deleted.</param>
        /// <returns></returns>
        public async Task<bool> DeleteAlias (Guid id) {
            string path = MountPointPath + "entity-alias/id/" + id;

            VaultDataResponseObjectB vdro = await _parent._httpConnector.DeleteAsync (path, "DeleteEntityAlias");
            return vdro.Success ? true : false;
        }



        public async Task<List<Guid>> ListAliases () {
            string path = MountPointPath + "entity-alias/id";

            try {
                // Setup List Parameter
                Dictionary<string, string> contentParams = new Dictionary<string, string>() {{"list", "true"}};


                VaultDataResponseObjectB vdro = await _parent._httpConnector.GetAsync_B (path, "ListAliases", contentParams);
                if ( vdro.Success ) {
	                return await vdro.GetDotNetObject<List<Guid>>("data.keys");
//                    string js = vdro.GetJSONPropertyValue (vdro.GetDataPackageAsJSON(), "keys");
  //                  List<Guid> keys = VaultUtilityFX.ConvertJSON<List<Guid>> (js);
    //                return keys;
                }

                throw new ApplicationException ("IdentitySecretEngine:ListAliases -> Arrived at unexpected code block.");
            }

            // 404 Errors mean there were no entities.  We just return an empty list.
            catch ( VaultInvalidPathException ) {
                return new List<Guid>();
            }
        }


        #endregion
    }
}