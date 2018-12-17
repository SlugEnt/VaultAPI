using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using System.Threading.Tasks;
using VaultAgentTests;
using VaultAgent.Backends.System;
using VaultAgent;
using VaultAgent.Backends;
using VaultAgent.AuthenticationEngines;
using VaultAgent.Models;
using VaultAgent.SecretEngines;
using VaultAgent.SecretEngines.KV2;

namespace VaultAgentTests {


    [TestFixture]
    [Parallelizable]
    public class PolicyTests {
        private VaultAgentAPI _vaultAgentAPI;
        private VaultSystemBackend _vaultSystemBackend;
        private UniqueKeys _uniqueKeys = new UniqueKeys();       // Unique Key generator


        [OneTimeSetUp]
        public async Task Backend_Init() {
            if (_vaultSystemBackend != null)
            {
                return;
            }

            // Build Connection to Vault.
            _vaultAgentAPI = new VaultAgentAPI("PolicyBE", VaultServerRef.ipAddress, VaultServerRef.ipPort, VaultServerRef.rootToken, true);

            // Create a new system Backend Mount for this series of tests.
            _vaultSystemBackend = _vaultAgentAPI.System;

        }


        #region VaultPolicyPathItem_Tests
        [Test]
        public void VPPI_InitialFields_AreCorrect()
        {
            string polName = _uniqueKeys.GetKey("Pol/");
            VaultPolicyPathItem vpp = new VaultPolicyPathItem(polName);

            Assert.False(vpp.CreateAllowed, "Create Not False");
            Assert.False(vpp.DeleteAllowed, "Delete Not False");
            Assert.False(vpp.ListAllowed, "List Not False");
            Assert.False(vpp.ReadAllowed, "Read Not False");
            Assert.False(vpp.RootAllowed, "Root Not False");
            Assert.False(vpp.SudoAllowed, "Sudo Not False");
            Assert.False(vpp.UpdateAllowed, "Update Not False");

            // Denied is undefined initially.
            Assert.IsNull(vpp.Denied, "Denied property was not initially set to null.");
        }



        // Validates that the VPPI single constructor is able to break the path down into backend and protected path values as well as set the IsSubFolders type parameter
        [Test]
        [TestCase(1,"secret/path1", "secret","path1",false)]
        [TestCase(2,"secret2/path1/path2/path3","secret2","path1/path2/path3",false)]
        [TestCase(3,"/secret3/path1/path2/path3", "secret3", "path1/path2/path3",false)]
        [TestCase(4,"/secret4/path1/path2/path3/", "secret4", "path1/path2/path3/*",true)]
        [TestCase(5,"secret5/path1/path2/path3/", "secret5", "path1/path2/path3/*",true)]
        [TestCase(6,"sA/metadata/pathA/path2","sA","pathA/path2",false)]
        [TestCase(7, "sA/undelete/pathA/path2", "sA", "pathA/path2", false)]
        [TestCase(8, "sA/delete/pathA/path2", "sA", "pathA/path2", false)]
        [TestCase(9, "sA/destroy/pathA/path2", "sA", "pathA/path2", false)]
        [TestCase(10, "sA/data/pathA/path2", "sA", "pathA/path2", false)]
        public void VPPI_PathSeparatedCorrectlyIntoComponentParts (int id, string path, string expectedBE, string expectedPath, bool expectedSubFolder) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
            Assert.AreEqual(expectedBE,vppi.BackendMountName,"A10: Backend Mount Name is not expected value.");
            Assert.AreEqual(expectedPath,vppi.ProtectedPath,"A20:  Protected Path is not expected value.");
            Assert.AreEqual(expectedSubFolder, vppi.IsSubFolderType, "A30:  IsSubFolder property is not expected value.");
        }



		// Validates that the VPPI constructor that takes backend name and path parameters works correctly.
        [Test]
        [TestCase(1,"secret","path1","secret","path1",false)]
        [TestCase(2,"secret2", "path1", "secret2", "path1",false)]
        [TestCase(3,"/secret3", "/path1", "secret3", "path1",false)]
        [TestCase(4,"secret4/", "path1/", "secret4", "path1/*",true)]
        [TestCase(5,"secret5", "path1/path2/path3/", "secret5", "path1/path2/path3/*",true)]
        public void VPPI_DefaultConstructor_BackendPathIsPrefix_Works (int id,string backend, string path, string expectedBE, string expectedPath, bool expectedSubFolderType) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(backend,path);
            Assert.AreEqual(expectedBE, vppi.BackendMountName, "A10: Backend Mount Name is not expected value.");
            Assert.AreEqual(expectedPath, vppi.ProtectedPath, "A20:  Protected Path is not expected value.");
            Assert.AreEqual(expectedSubFolderType, vppi.IsSubFolderType, "A30:  IsPrefixType is not expected value.");
        }


        
		// Validates that the Secret Path property returns the proper path value.
        [Test]
        [TestCase(1,"secret", "path1",  false, "secret/path1","")]
        [TestCase(2,"secret2", "path1",  false, "secret2/path1","")]
        [TestCase(3,"/secret3", "/path1", false, "secret3/path1","")]
        [TestCase(4,"secret4/", "path1/", false,"secret4/path1/*","")]
        [TestCase(5,"secret5", "path1/path2/path3/", true, "secret5/path1/path2/path3/*","")]
        [TestCase(6,"secret6", "data/path1", false, "secret6/data/path1","data")]
        [TestCase(7, "secret7", "metadata/path1", false, "secret7/data/path1","metadata")]
        [TestCase(8, "secret8", "destroy/path1", false, "secret8/data/path1", "destroy")]
        [TestCase(9, "secret8", "delete/path1", false, "secret8/data/path1", "delete")]
        [TestCase(10, "secret8", "undelete/path1", false, "secret8/data/path1", "undelete")]
        public void VPPI_FullPath_ReturnsCorrectValues(int ID, string backend, string path, bool notUsed, string expectedPath, string expectedKVPath)
        {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(backend, path);
            Assert.AreEqual(expectedPath, vppi.SecretPath, "A10: Full path is not expected value.");
            Assert.AreEqual(expectedKVPath,vppi.KV2_PathID, "A20:  The KeyValue Version 2 path prefix was not expected value.");
        }



        // Validates that the key for a VaultPolicyPathItem object is generated correctly.
        [Test]
        [TestCase(1, "secret/path1", "secret","path1")]
        [TestCase(2, "secret2/path1/path2/path3", "secret2","path1/path2/path3")]
        [TestCase(3, "/secret3/path1/path2/path3", "secret3","path1/path2/path3")]
        [TestCase(4, "/secret4/path1/path2/path3/", "secret4","path1/path2/path3/*")]
        [TestCase(5, "secret5/path1/path2/path3/", "secret5","path1/path2/path3/*")]
        [TestCase(6, "sA/metadata/pathA/path2", "sA","pathA/path2")]
        [TestCase(7, "sA/undelete/pathA/path2", "sA","pathA/path2")]
        [TestCase(8, "sA/delete/pathA/path2", "sA","pathA/path2")]
        [TestCase(9, "sA/destroy/pathA/path2", "sA","pathA/path2")]
        [TestCase(10, "sA/data/pathA/path2", "sA","pathA/path2")]
        [TestCase(11, "sA/metadata/pathA/path2/*", "sA","pathA/path2/*")]
        [TestCase(12, "sA/undelete/pathA/path2/*", "sA","pathA/path2/*")]
        [TestCase(13, "sA/delete/pathA/path2/*", "sA","pathA/path2/*")]
        [TestCase(14, "sA/destroy/pathA/path2/*", "sA","pathA/path2/*")]
        [TestCase(15, "sA/data/pathA/path2/*", "sA","pathA/path2/*")]
        public void VPPI_Key_ProducedCorrectly(int id, string path, string expectedBE, string expectedPath)

        {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
            Assert.AreEqual(expectedBE, vppi.BackendMountName, "A10: Backend Mount Name is not expected value.");
            Assert.AreEqual(expectedPath, vppi.ProtectedPath, "A20:  Protected Path is not expected value.");
        }




        [Test]
        [TestCase("C", "Create")]
        [TestCase("R", "Read")]
        [TestCase("U", "Update")]
        [TestCase("D", "Delete")]
        [TestCase("L", "List")]
        [TestCase("T", "Root")]
        [TestCase("S", "Sudo")]
		// Test that setting capabilities to true works and removes the denied setting if set.01
		public void VPPI_SettingTrueToFields_Success(string type, string value)
        {
            string polName = _uniqueKeys.GetKey("Pol/");
            VaultPolicyPathItem vpp = new VaultPolicyPathItem(polName);
            vpp.Denied = true;

            switch (type)
            {
                case "C":
                    vpp.CreateAllowed = true;
                    Assert.True(vpp.CreateAllowed, value + " Allowed was not True");
                    break;
                case "R":
                    vpp.ReadAllowed = true;
                    Assert.True(vpp.ReadAllowed, value + " Allowed was not True");
                    break;
                case "U":
                    vpp.UpdateAllowed = true;
                    Assert.True(vpp.UpdateAllowed, value + " Allowed was not True");
                    break;
                case "D":
                    vpp.DeleteAllowed = true;
                    Assert.True(vpp.DeleteAllowed, value + " Allowed was not True");
                    break;
                case "L":
                    vpp.ListAllowed = true;
                    Assert.True(vpp.ListAllowed, value + " Allowed was not True");
                    break;
                case "T":
                    vpp.RootAllowed = true;
                    Assert.True(vpp.RootAllowed, value + " Allowed was not True");
                    break;
                case "S":
                    vpp.SudoAllowed = true;
                    Assert.True(vpp.SudoAllowed, value + " Allowed was not True");
                    break;
			}
            Assert.False(vpp.Denied, "Denied should have been set to false.");
        }



        // Denied on a policy must set everything else to false.
        [Test]
        public void VPPI_SetDenied_SetsEverythingElseTo_False()
        {
            string polName = _uniqueKeys.GetKey("Pol/");
            VaultPolicyPathItem vpp = new VaultPolicyPathItem(polName);

            vpp.CreateAllowed = true;
            vpp.ReadAllowed = true;
            vpp.UpdateAllowed = true;
            vpp.DeleteAllowed = true;
            vpp.ListAllowed = true;
            vpp.RootAllowed = true;
            vpp.SudoAllowed = true;

            Assert.True(vpp.CreateAllowed, "Create Allowed was not True");
            Assert.True(vpp.ReadAllowed, "Read Allowed was not True");
            Assert.True(vpp.UpdateAllowed, "Update Allowed was not True");
            Assert.True(vpp.DeleteAllowed, "Delete Allowed was not True");
            Assert.True(vpp.ListAllowed, "List Allowed was not True");
            Assert.True(vpp.RootAllowed, "Root Allowed was not True");
            Assert.True(vpp.SudoAllowed, "Sudo Allowed was not True");


            // Now set Denied.  Make sure the above are false.
            vpp.Denied = true;
            Assert.False(vpp.CreateAllowed, "Create Allowed was not set to False");
            Assert.False(vpp.ReadAllowed, "Read Allowed was not set to False");
            Assert.False(vpp.UpdateAllowed, "Update Allowed was not set to False");
            Assert.False(vpp.DeleteAllowed, "Delete Allowed was not set to False");
            Assert.False(vpp.ListAllowed, "List Allowed was not set to False");
            Assert.False(vpp.RootAllowed, "Root Allowed was not set to False");
            Assert.False(vpp.SudoAllowed, "Sudo Allowed was not set to False");
        }



        // Validate that we can get a permission string back from the ToVaultHCL Policy Method.
        [Test]
        public void VPPI_CanBuildVaultPermissionString() {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem("ABC","pathA/pathB");
            vppi.CreateAllowed = true;
            string permission = vppi.ToVaultHCLPolicyFormat();
            Assert.IsNotEmpty(permission,"A10:  Expected a permission string to be returned.");
        }



		// Validate that calling a KeyValue V2 Extended Attribute property setter throws error if the policy is not KV2 type of policy.
	    [Test]
	    public void VPPI_CallingKV2Attribute_OnNonKV2PolicyItem_ThrowsError() {
			VaultPolicyPathItem vppi = new VaultPolicyPathItem("/be/test/path1");
			
		    //vppi.ExtKV2_DeleteAnyKeyVersion = true;
		    InvalidOperationException e = Assert.Throws<InvalidOperationException>( () => vppi.ExtKV2_DeleteAnyKeyVersion = true);
		    InvalidOperationException e2 = Assert.Throws<InvalidOperationException>(() => vppi.ExtKV2_DeleteMetaData = true);
		    InvalidOperationException e3 = Assert.Throws<InvalidOperationException>(() => vppi.ExtKV2_DestroySecret = true);
		    InvalidOperationException e4 = Assert.Throws<InvalidOperationException>(() => vppi.ExtKV2_ListMetaData = true);
		    InvalidOperationException e5 = Assert.Throws<InvalidOperationException>(() => vppi.ExtKV2_UndeleteSecret= true);
		    InvalidOperationException e6 = Assert.Throws<InvalidOperationException>(() => vppi.ExtKV2_ViewMetaData = true);
		}



        // Validates that the CRUD property sets the Create, Read, Update and Delete properties as expected.
        [Test]
        public void VPPI_CRUDSetOperation_Works()
        {
            VaultPolicyPathItem vaultPolicyPathItem = new VaultPolicyPathItem("secret/itemA");

            // Validate initial CRUD items are all false.
            Assert.False(vaultPolicyPathItem.CreateAllowed);
            Assert.False(vaultPolicyPathItem.ReadAllowed);
            Assert.False(vaultPolicyPathItem.UpdateAllowed);
            Assert.False(vaultPolicyPathItem.DeleteAllowed);

            // Now Set CRUD
            vaultPolicyPathItem.CRUDAllowed = true;

            // Validate CRUD items are now true
            Assert.True(vaultPolicyPathItem.CreateAllowed);
            Assert.True(vaultPolicyPathItem.ReadAllowed);
            Assert.True(vaultPolicyPathItem.UpdateAllowed);
            Assert.True(vaultPolicyPathItem.DeleteAllowed);

            // Now Set CRUD to False.
            vaultPolicyPathItem.CRUDAllowed = false;

            // Validate CRUD items are all false.
            Assert.False(vaultPolicyPathItem.CreateAllowed);
            Assert.False(vaultPolicyPathItem.ReadAllowed);
            Assert.False(vaultPolicyPathItem.UpdateAllowed);
            Assert.False(vaultPolicyPathItem.DeleteAllowed);

        }


        // Validates that the FullControl property sets the Create, Read, Update, Delete and List properties as expected.
        [Test]
        public void VPPI_FullControlSetOperation_Works()
        {
            VaultPolicyPathItem vaultPolicyPathItem = new VaultPolicyPathItem("secret/itemB");

            // Validate initial FullControl items are all false.
            Assert.False(vaultPolicyPathItem.CreateAllowed);
            Assert.False(vaultPolicyPathItem.ReadAllowed);
            Assert.False(vaultPolicyPathItem.UpdateAllowed);
            Assert.False(vaultPolicyPathItem.DeleteAllowed);
            Assert.False(vaultPolicyPathItem.ListAllowed);

            // Now Set Full Control
            vaultPolicyPathItem.FullControl = true;

            // Validate FullControl items are now true
            Assert.True(vaultPolicyPathItem.CreateAllowed);
            Assert.True(vaultPolicyPathItem.ReadAllowed);
            Assert.True(vaultPolicyPathItem.UpdateAllowed);
            Assert.True(vaultPolicyPathItem.DeleteAllowed);
            Assert.True(vaultPolicyPathItem.ListAllowed);

            // Now Set FullControl to False.
            vaultPolicyPathItem.FullControl = false;

            // Validate final FullControl items are all false.
            Assert.False(vaultPolicyPathItem.CreateAllowed);
            Assert.False(vaultPolicyPathItem.ReadAllowed);
            Assert.False(vaultPolicyPathItem.UpdateAllowed);
            Assert.False(vaultPolicyPathItem.DeleteAllowed);
            Assert.False(vaultPolicyPathItem.ListAllowed);

        }



        // Validates that the key for a Vault Policy Path Item is generated correctly.
        [Test]
        [TestCase(1,"/backend1/pathA/pathB/pathC","backend1/pathA/pathB/pathC", "Normal Path test with KV2:False and IsPrefix:False")]
        [TestCase(2, "/backend1/pathA", "backend1/pathA","Normal Path test with KV2:False and IsPrefix:False")]
        [TestCase(3, "/backend1/pathA/", "backend1/pathA/*","Normal Path test with KV2:False and IsPrefix:True")]
        [TestCase(4, "/backend1/pathA/pathB", "backend1/pathA/pathB", "Normal Path test with KV2:False and IsPrefix:True")]
        [TestCase(5, "/backend2/data/pathA", "backend2/pathA", "KV2 Path test with IsPrefix:False")]
        [TestCase(6, "/backend2/metadata/pathA", "backend2/pathA", "KV2 Path test with IsPrefix:False")]
        [TestCase(7, "/backend2/destroy/pathA", "backend2/pathA", "KV2 Path test with IsPrefix:False")]
        [TestCase(8, "/backend2/delete/pathA", "backend2/pathA", "KV2 Path test with IsPrefix:False")]
        [TestCase(9, "/backend2/undelete/pathA", "backend2/pathA", "KV2 Path test with IsPrefix:False")]
        [TestCase(10, "/backend3/a/data/pathA", "backend3/a/data/pathA", "Test Similar path to KV2 Path test with IsPrefix:False")]
        [TestCase(11, "/backend3/a/metadata/pathA", "backend3/a/metadata/pathA", "Test Similar path to KV2 Path test with IsPrefix:False")]
        [TestCase(12, "/backend3/a/destroy/pathA", "backend3/a/destroy/pathA", "Test Similar path to KV2 Path test with IsPrefix:False")]
        [TestCase(13, "/backend3/a/delete/pathA", "backend3/a/delete/pathA", "Test Similar path to KV2 Path test with IsPrefix:False")]
        [TestCase(14, "/backend3/a/undelete/pathA", "backend3/a/undelete/pathA", "Test Similar path to KV2 Path test with IsPrefix:False")]
        public void VPPI_KeyGenerated_CorrectlyFromPath (int id, string path, string expectedKey,string desc) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
            Assert.AreEqual(expectedKey,vppi.Key,desc);
        }
        #endregion


        #region "Other Policy Tests"
        //TODO this needs some finishing work.../
        [Test]
        public async Task VaultInstance_CanCreatePolicy_WithSingleVaultPolicyItem()
        {

            // Create a Vault Policy Path Item
            string polName = _uniqueKeys.GetKey("secret/Pol");
            VaultPolicyPathItem vpi = new VaultPolicyPathItem(polName);
            vpi.DeleteAllowed = true;

            // Create a Vault Policy Item
            VaultPolicyContainer VP = new VaultPolicyContainer("TestingABC");
            VP.AddPolicyPathObject (vpi);
            bool rc = await _vaultSystemBackend.SysPoliciesACLCreate(VP);
        }



        // Validates we can create a policy container object with multiple PolicyPathItems and they are all saved to Vault Instance
        [Test]
        public async Task VaultInstance_CanCreateAPolicy_WithMultipleVaultPolicyItems()
        {
            // Create multiple Vault Policy Path Items
            string polName = _uniqueKeys.GetKey("secret/Pol");
            VaultPolicyPathItem vpi1 = new VaultPolicyPathItem(polName);
            vpi1.DeleteAllowed = true;
            vpi1.ReadAllowed = true;
            vpi1.CreateAllowed = true;

            string pol2Name = _uniqueKeys.GetKey("secret/Pol");
            VaultPolicyPathItem vpi2 = new VaultPolicyPathItem(pol2Name);
            vpi2.ListAllowed = true;

            string pol3Name = _uniqueKeys.GetKey("secret/Pol");
            VaultPolicyPathItem vpi3 = new VaultPolicyPathItem(pol3Name);
            vpi3.ListAllowed = true;
            vpi3.DeleteAllowed = true;
            vpi3.ReadAllowed = true;
            vpi3.SudoAllowed = true;

            string pol4Name = _uniqueKeys.GetKey("secret/Pol");
            VaultPolicyPathItem vpi4 = new VaultPolicyPathItem(pol4Name);
            vpi4.DeleteAllowed = true;


            // Create a Vault Policy Item and add the policy paths.
            VaultPolicyContainer VP = new VaultPolicyContainer("TestingABCD");
            VP.AddPolicyPathObject (vpi1);
            VP.AddPolicyPathObject(vpi2);
            VP.AddPolicyPathObject(vpi3);
            VP.AddPolicyPathObject(vpi4);

            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP));


            //TODO - Read the policies back and compare.
        }



        // Validates that we can read a Policy object from Vault that contains just a single path permission object.
        [Test]
        public async Task Vault_CanReadSinglePathPolicy()
        {
            VaultPolicyContainer VP = new VaultPolicyContainer("Test2000A");

            VaultPolicyPathItem vpi3 = new VaultPolicyPathItem("secret/Test2000A");
            vpi3.ListAllowed = true;
            vpi3.DeleteAllowed = true;
            vpi3.ReadAllowed = true;
            vpi3.SudoAllowed = true;
            VP.AddPolicyPathObject (vpi3);

            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP));


            // Now lets read it back. 
            VaultPolicyContainer vpNew = await _vaultSystemBackend.SysPoliciesACLRead("Test2000A");

            Assert.AreEqual(1, vpNew.PolicyPaths.Count);

            VaultPolicyPathItem vppiFound;

            Assert.True (vpNew.PolicyPaths.TryGetValue (vpi3.Key, out vppiFound),"A10:  Did not find the VaultPolicyPathItem in the internal dictionary.");

            Assert.AreEqual(vpi3.ListAllowed, vppiFound.ListAllowed);
            Assert.AreEqual(vpi3.DeleteAllowed, vppiFound.DeleteAllowed);
            Assert.AreEqual(vpi3.ReadAllowed, vppiFound.ReadAllowed);
            Assert.AreEqual(vpi3.SudoAllowed, vppiFound.SudoAllowed);
        }



        [Test]
        // Can read a policy that has multiple paths attached to it.
        public async Task Vault_CanReadMultiplePathPolicy()
        {
            // Create a Vault Policy Item and add the policy paths.
            string name = _uniqueKeys.GetKey ("POL");
            VaultPolicyContainer VP = new VaultPolicyContainer(name);


            string path1 = "secret/Test2000B1";
            VaultPolicyPathItem vpi1 = new VaultPolicyPathItem(path1);
            vpi1.ListAllowed = true;
            vpi1.DeleteAllowed = true;
            vpi1.ReadAllowed = true;
            vpi1.SudoAllowed = true;
            VP.AddPolicyPathObject(vpi1);

            // 2nd policy path
            string path2 = "secret/Test2000B2";
            VaultPolicyPathItem vpi2 = new VaultPolicyPathItem(path2);
            vpi2.Denied = true;
            VP.AddPolicyPathObject(vpi2);

            // 3rd policy path
            string path3 = "secret/Test2000B3";
            VaultPolicyPathItem vpi3 = new VaultPolicyPathItem(path3);
            vpi3.ListAllowed = true;
            vpi3.ReadAllowed = true;
            vpi3.UpdateAllowed = true;
            VP.AddPolicyPathObject(vpi3);


            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP),"A10:  Unable to create policy in the Vault instance successfully.");


            // Now lets read it back. 
            VaultPolicyContainer vpNew = await _vaultSystemBackend.SysPoliciesACLRead(name);

            Assert.AreEqual(3, vpNew.PolicyPaths.Count,"A20:  PolicyPaths count was not expected value.");
            foreach (VaultPolicyPathItem item in vpNew.PolicyPaths.Values)
            {
                if (item.SecretPath == path1)
                {
                    Assert.AreEqual(vpi1.ListAllowed, item.ListAllowed,"a30:  Listallowed property not expected value.");
                    Assert.AreEqual(vpi1.DeleteAllowed, item.DeleteAllowed,"a31:  DeleteAllowed property not expected value.");
                    Assert.AreEqual(vpi1.ReadAllowed, item.ReadAllowed, "a32:  ReadAllowed property not expected value.");
                    Assert.AreEqual(vpi1.SudoAllowed, item.SudoAllowed, "a33:  SudoAllowed property not expected value.");
                }
                else if (item.SecretPath == path2)
                {
                    Assert.AreEqual(vpi2.Denied, item.Denied, "a40:  Denied property not expected value.");
                }
                else if (item.SecretPath == path3)
                {
                    Assert.AreEqual(vpi3.ListAllowed, item.ListAllowed, "a50:  Listallowed property not expected value.");
                    Assert.AreEqual(vpi3.ReadAllowed, item.ReadAllowed, "a51:  ReadAllowed property not expected value.");
                    Assert.AreEqual(vpi3.UpdateAllowed, item.UpdateAllowed, "a52:  UpdateAllowed property not expected value.");
                    Assert.AreEqual(vpi3.CreateAllowed, false);
                    Assert.AreEqual(vpi3.DeleteAllowed, false);
                    Assert.AreEqual(vpi3.SudoAllowed, false);
                    Assert.AreEqual(vpi3.Denied, false);
                }
                // If here, something is wrong.
                else { Assert.True(false, "invalid path returned of {0}", item.SecretPath,"A60:  Invalid SecretPath specified"); }
            }
        }



        // Validate that a KeyValue2 permission of destroy is properly saved in the Vault Instance and can be read back in successfully.
        [Test]
        public async Task Vault_KV2_Confirm_DestroyPermission_CreatedCorrectly() {
            string polName = _uniqueKeys.GetKey ("Destroy");
            VaultPolicyContainer policyContainer = new VaultPolicyContainer(polName);

            // Create the policy Path Permission Object
            string backend = "kv2Back";
            string path = "data/asecret";
            VaultPolicyPathItem polItem = new VaultPolicyPathItem(backend,path);
            polItem.ExtKV2_DestroySecret = true;
            policyContainer.AddPolicyPathObject (polItem);

            // Create policy.
            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(policyContainer),"A10: Unable to save the policy : " + policyContainer);

            // Now read policy back.
            VaultPolicyContainer policyContainer2 = await _vaultSystemBackend.SysPoliciesACLRead(polName);
            Assert.IsNotNull(policyContainer2,"A20:  Policy was not retrieved.");

            // Validate it.
            VaultPolicyPathItem polItem2 = policyContainer2.PolicyPaths.First().Value;
            Assert.AreEqual(polItem.ExtKV2_DestroySecret, polItem2.ExtKV2_DestroySecret,"A30:  Policy Items retrieved was not same as saved.");
        }



        [Test]
        // Validates that we can correctly create and read back a Vault KeyValue2 policy.
        public async Task Vault_Validate_Complex_KV2PolicyTest()
        {
            throw new NotImplementedException();

            // Create a Vault Policy Item and add the policy paths.
            string name = _uniqueKeys.GetKey("POL");
            VaultPolicyContainer VP = new VaultPolicyContainer(name);


            string path1 = "secret/Test2000B1";
            VaultPolicyPathItem vpi1 = new VaultPolicyPathItem(path1);
            vpi1.ListAllowed = true;
            vpi1.DeleteAllowed = true;
            vpi1.ReadAllowed = true;
            vpi1.SudoAllowed = true;
            VP.AddPolicyPathObject(vpi1);

            // 2nd policy path
            string path2 = "secret/Test2000B2";
            VaultPolicyPathItem vpi2 = new VaultPolicyPathItem(path2);
            vpi2.Denied = true;
            VP.AddPolicyPathObject(vpi2);

            // 3rd policy path
            string path3 = "secret/Test2000B3";
            VaultPolicyPathItem vpi3 = new VaultPolicyPathItem(path3);
            vpi3.ListAllowed = true;
            vpi3.ReadAllowed = true;
            vpi3.UpdateAllowed = true;
            VP.AddPolicyPathObject(vpi3);


            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP));


            // Now lets read it back. 
            VaultPolicyContainer vpNew = await _vaultSystemBackend.SysPoliciesACLRead(name);

            Assert.AreEqual(3, vpNew.PolicyPaths.Count);
            foreach (VaultPolicyPathItem item in vpNew.PolicyPaths.Values)
            {
                if (item.SecretPath == path1)
                {
                    Assert.AreEqual(vpi1.ListAllowed, item.ListAllowed);
                    Assert.AreEqual(vpi1.DeleteAllowed, item.DeleteAllowed);
                    Assert.AreEqual(vpi1.ReadAllowed, item.ReadAllowed);
                    Assert.AreEqual(vpi1.SudoAllowed, item.SudoAllowed);
                }
                else if (item.SecretPath == path2)
                {
                    Assert.AreEqual(vpi2.Denied, item.Denied);
                }
                else if (item.SecretPath == path3)
                {
                    Assert.AreEqual(vpi3.ListAllowed, item.ListAllowed);
                    Assert.AreEqual(vpi3.ReadAllowed, item.ReadAllowed);
                    Assert.AreEqual(vpi3.UpdateAllowed, item.UpdateAllowed);
                    Assert.AreEqual(vpi3.CreateAllowed, false);
                    Assert.AreEqual(vpi3.DeleteAllowed, false);
                    Assert.AreEqual(vpi3.SudoAllowed, false);
                    Assert.AreEqual(vpi3.Denied, false);
                }
                // If here, something is wrong.
                else { Assert.True(false, "invalid path returned of {0}", item.SecretPath); }
            }
        }



        // Validates that Attempting to read a non-existent policy returns the expected VaultException and the SpecificErrorCode value is set to ObjectDoesNotExist.
        [Test]
        public void Vault_ReadOfNonExistentPolicy_ResultsInExpectedError()
        {
            VaultInvalidPathException e = Assert.ThrowsAsync<VaultInvalidPathException>(async () => await _vaultSystemBackend.SysPoliciesACLRead("NonExistentPolicy"));
            Assert.AreEqual(EnumVaultExceptionCodes.ObjectDoesNotExist, e.SpecificErrorCode);
        }



        [Test]
        public async Task Policy_ListReturnsPolicies()
        {
            // Ensure there is at least one policy saved.
            VaultPolicyContainer VP = new VaultPolicyContainer("listPolicyA");
            VaultPolicyPathItem vpi = new VaultPolicyPathItem("secret/listpol2000A");
            vpi.ListAllowed = true;
            VP.AddPolicyPathObject(vpi);

            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP));

            // Now get a list of policies.
            List<string> polList = await _vaultSystemBackend.SysPoliciesACLList();
            Assert.True(polList.Count > 0);
        }




        [Test]
        // Providing a valid policy name results in returning true.
        public async Task Policy_CanDelete_ValidPolicyName()
        {
            // Create a policy to delete
            VaultPolicyContainer VP = new VaultPolicyContainer("deletePolicyA");
            VaultPolicyPathItem vpi = new VaultPolicyPathItem("secret/Test2000A");
            vpi.ListAllowed = true;
            VP.AddPolicyPathObject(vpi);
            

            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP));

            // Now delete it.
            Assert.True(await _vaultSystemBackend.SysPoliciesACLDelete(VP.Name));
        }




        [Test]
        // Providing an invalid policy name returns false.
        public async Task Policy_Delete_InvalidPolicyName_ReturnsTrue()
        {
            Assert.True(await _vaultSystemBackend.SysPoliciesACLDelete("invalidName"));
        }


        #endregion


        #region "KV2 Policies"

        [Test]
        [TestCase("secret/metadata/path1/path2")]
        [TestCase("secret/data/path1/path2")]
        [TestCase("secret/data/path3/path2")]
        [TestCase("secret/destroy/path1/path2")]
        [TestCase("secret/delete/path1/path2")]
        [TestCase("secret/undelete/path1/path2")]
        public void VPPI_KV2_SinglePathConstructor_Sets_IsKV2Property (string path) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
            Assert.IsTrue(vppi.IsKV2Policy,"A10:  Expected the IsKV2Policy property to be true.");
        }




		// Validate that we can build a proper VaultInstance permission string.
		[Test]
		public void VPPI_KV2_CanBuildKV2PermissionString() {
			VaultPolicyPathItem vppi = new VaultPolicyPathItem("ABC", "pathA/pathB");
			vppi.CreateAllowed = true;
			Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("create"), "A10:  Did not find the create permission in the Vault policy string.");
			Assert.AreEqual("ABC/pathA/pathB", vppi.SecretPath);

			// Create a KV2 policy item
			VaultPolicyPathItem vppi2 = new VaultPolicyPathItem("ABC", "data/pathA/pathB");
			vppi2.CreateAllowed = true;
			vppi2.DeleteAllowed = true;
			vppi2.ExtKV2_DeleteAnyKeyVersion = true;

			Assert.True(vppi2.ToVaultHCLPolicyFormat().Contains("create"), "A20:  Did not find the create permission in the Vault policy string.");
			Assert.True(vppi2.ToVaultHCLPolicyFormat().Contains("delete"), "A30:  Did not find the delete permission in the Vault policy string.");
			Assert.True(vppi2.ToVaultHCLPolicyFormat().Contains("/data/"), "A40:  Did not find the /data/ subpath in the Vault policy string.");
			Assert.AreEqual("ABC/data/pathA/pathB", vppi2.SecretPath, "A50:  The secretPath property did not return the expected value.");
		}




		// Validate that the proper path prefixes are generated for KeyValue2 policies
		[Test]
		[TestCase(2)]
		[TestCase(3)]
		[TestCase(4)]
		[TestCase(5)]
		[TestCase(6)]
		public void VPPI_KV2_PoliciesProduce_ProperPathPrefixes(int id) {
			string be = "ZZ";
			string pa = "pathA/pathB";
			string policyString;
			string expVal;


			VaultPolicyPathItem vppi = new VaultPolicyPathItem(be, "data/" + pa);
			switch (id) {
				case 2:
					vppi.ExtKV2_DeleteAnyKeyVersion = true;
					policyString = vppi.ToVaultHCLPolicyFormat();
					expVal = be + "/delete/" + pa + "/*";
					Assert.That(policyString.Contains(expVal), "A10:  Policy String was not expected value.");
					Assert.That(policyString.Contains("update"), "A11:  Policy string did not contain expected permission.");
					break;
				case 3:
					vppi.ExtKV2_DeleteMetaData = true;
					policyString = vppi.ToVaultHCLPolicyFormat();
					expVal = be + "/metadata/" + pa + "/*";
					Assert.That(policyString.Contains(expVal), "A30:  Policy String was not expected value.");
					Assert.That(policyString.Contains("delete"), "A31:  Policy string did not contain expected permission.");
					break;
				case 4:
					vppi.ExtKV2_DestroySecret = true;
					policyString = vppi.ToVaultHCLPolicyFormat();
					expVal = be + "/destroy/" + pa + "/*";
					Assert.That(policyString.Contains(expVal), "A40:  Policy String was not expected value.");
					Assert.That(policyString.Contains("update"), "A41:  Policy string did not contain expected permission.");
					break;
				case 5:
					vppi.ExtKV2_UndeleteSecret = true;
					policyString = vppi.ToVaultHCLPolicyFormat();
					expVal = be + "/undelete/" + pa + "/*";
					Assert.That(policyString.Contains(expVal), "A50:  Policy String was not expected value.");
					Assert.That(policyString.Contains("update"), "A51:  Policy string did not contain expected permission.");
					break;
				case 6:
					vppi.ExtKV2_ViewMetaData = true;
					policyString = vppi.ToVaultHCLPolicyFormat();
					expVal = be + "/metadata/" + pa + "/*";
					Assert.That(policyString.Contains(expVal), "A60:  Policy String was not expected value.");
					Assert.That(policyString.Contains("read"), "A61:  Policy string did not contain expected permission.");
					break;
			}
		}




		// Validates that the SecretPath property will return the proper KV2 type policy secret path.
		[Test]
		[TestCase(1,"A/data/path1","A/data/path1")]
		[TestCase(2, "A/data/path1/", "A/data/path1/*")]
		[TestCase(3, "A/data/path1/*", "A/data/path1/*")]
		[TestCase(4, "A/metadata/path1", "A/data/path1")]
		[TestCase(5, "A/metadata/path1/", "A/data/path1/*")]
		[TestCase(6, "A/metadata/path1/*", "A/data/path1/*")]
		[TestCase(7, "A/delete/path1", "A/data/path1")]
		[TestCase(8, "A/delete/path1/", "A/data/path1/*")]
		[TestCase(9, "A/delete/path1/*", "A/data/path1/*")]
		[TestCase(10, "A/undelete/path1", "A/data/path1")]
		[TestCase(11, "A/undelete/path1/", "A/data/path1/*")]
		[TestCase(12, "A/undelete/path1/*", "A/data/path1/*")]
		[TestCase(13, "A/destroy/path1", "A/data/path1")]
		[TestCase(14, "A/destroy/path1/", "A/data/path1/*")]
		[TestCase(15, "A/destroy/path1/*", "A/data/path1/*")]
		public void VPPI_KV2_SecretPathReturnsProperPath(int id, string path, string expSecPath) {
			// Create a KV2 policy item
			VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);

			vppi.CreateAllowed = true;
			Assert.AreEqual(expSecPath,vppi.SecretPath, "A10:  The SecretPath property did not return the expected value");
		}



		// Validates combinations of KeyValue2 permissions and a secret object and how many path statements they generate.
	    [Test]
		[TestCase("A",1,"Test just a KV2 secret save.  Should be 1 path.")]
	    [TestCase("B", 2, "Test just a KV2 secret save AND a KV2 Delete.  Should be 2 paths.")]
	    [TestCase("C", 2, "Test just a KV2 secret save AND a KV2 Destroy.  Should be 2 paths.")]
	    [TestCase("D", 2, "Test just a KV2 secret save AND a KV2 Undelete.  Should be 2 paths.")]
	    [TestCase("E", 2, "Test just a KV2 secret save AND a KV2 MetaData Delete, List and View.  Should be 2 paths.")]
	    [TestCase("F", 3, "Test just a KV2 secret save, a KV2 MetaData and a KV2 Delete.  Should be 3 paths.")]
	    [TestCase("G", 5, "Test all KV2 Attributes set.  Should be 5 paths.")]
		[TestCase("H", 1, "DestroySecret only Attribute set.  Should be 1 path.")]
		public void VPPI_KV2_SubFolderPath_GeneratesSinglePolicyPath(string scenario, int expNumberOfPaths, string testScenario) {
		    string path = "BE/data/path1/*";
			VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);

		    switch (scenario) {
				case "A":
					vppi.ReadAllowed = true;
					break;
				case "B":
					vppi.ReadAllowed = true;
					vppi.ExtKV2_DeleteAnyKeyVersion = true;
					break;
				case "C":
					vppi.ReadAllowed = true;
					vppi.ExtKV2_DestroySecret = true;
					break;
				case "D":
					vppi.ReadAllowed = true;
					vppi.ExtKV2_UndeleteSecret = true;
					break;
			    case "E":
				    vppi.ReadAllowed = true;
				    vppi.ExtKV2_ViewMetaData = true;
				    vppi.ExtKV2_ListMetaData = true;
					vppi.ExtKV2_DeleteMetaData = true;
				    break;
				case "F":
					vppi.ReadAllowed = true;
					vppi.ExtKV2_ViewMetaData = true;
					vppi.ExtKV2_DeleteAnyKeyVersion = true;
					break;
			    case "G":
				    vppi.ReadAllowed = true;
				    vppi.ExtKV2_ViewMetaData = true;
				    vppi.ExtKV2_ListMetaData = true;
				    vppi.ExtKV2_DeleteMetaData = true;
				    vppi.ExtKV2_DeleteAnyKeyVersion = true;
				    vppi.ExtKV2_DestroySecret = true;
				    vppi.ExtKV2_UndeleteSecret = true;
				    break;
				case "H":
					vppi.ExtKV2_DestroySecret = true;
					break;
			}


			string vaultPolicyStatement = vppi.ToVaultHCLPolicyFormat();
		    int found = 0;
		    bool bExit = false;
		    string temp = vaultPolicyStatement;
		    int pos = -1;
		    while (!bExit) {
			    pos = temp.IndexOf("path ");

			    if (pos > -1) {
				    found++;
				    temp = temp.Substring(pos + 1);
			    }
			    else { bExit = true; }
		    }
			
			Assert.AreEqual(expNumberOfPaths,found,"A10:  Did not find the number of paths we were expecting to find.");
	    }




	    // Validate the KV2 Destroy permission generates proper Vault Instance policy statement.
	    [Test]
	    public void VPPI_KV2_DestroyAttr_PolicyPath_Correct() {
		    string path = "ABC/destroy/pathA";

		    VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
		    vppi.ExtKV2_DestroySecret = true;

		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("update"), "A10:  Did not find the update permission in the Vault policy string.");
		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("destroy"), "A20:  Did not find the destroy permission in the Vault policy string.");
	    }


	    // Validate the KV2 Undelete permission generates proper Vault Instance policy statement.
	    [Test]
	    public void VPPI_KV2_UndeleteAttr_PolicyPath_Correct() {
		    string path = "ABC/undelete/pathA";

		    VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
		    vppi.ExtKV2_UndeleteSecret = true;

		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("update"), "A10:  Did not find the update permission in the Vault policy string.");
		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("undelete"), "A20:  Did not find the undelete permission in the Vault policy string.");
	    }



	    // Validate the KV2 Delete permission generates proper Vault Instance policy statement.
	    [Test]
	    public void VPPI_KV2_DeleteAttr_PolicyPath_Correct() {
		    string path = "ABC/delete/pathA";

		    VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
		    vppi.ExtKV2_DeleteAnyKeyVersion = true;

		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("update"), "A10:  Did not find the update permission in the Vault policy string.");
		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("delete"), "A20:  Did not find the delete permission in the Vault policy string.");
	    }



	    // Validate the KV2 Metadata permission generates proper Vault Instance policy statement.
	    [Test]
	    public void VPPI_KV2_MetadataAttr_PolicyPath_Correct() {
		    string path = "ABC/metadata/pathA";

		    VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
		    vppi.ExtKV2_DeleteMetaData = true;
		    vppi.ExtKV2_ListMetaData = true;
		    vppi.ExtKV2_ViewMetaData = true;

		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("list"), "A10:  Did not find the list permission in the Vault policy string.");
		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("read"), "A11:  Did not find the read permission in the Vault policy string.");
		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("delete"), "A12:  Did not find the delete permission in the Vault policy string.");
			Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("metadata"), "A20:  Did not find the metadata permission in the Vault policy string.");
	    }



	    // Validate that the normal List Attribute will generate the proper KV2 policy permission statement
	    [Test]
	    public void VPPI_KV2_ListAttribute_MetadataAttr_PolicyPath_Correct() {
		    string path = "ABC/metadata/pathA";

		    VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
		    vppi.ListAllowed = true;

		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("list"), "A10:  Did not find the list permission in the Vault policy string.");
		    Assert.True(vppi.ToVaultHCLPolicyFormat().Contains("metadata"), "A20:  Did not find the metadata permission in the Vault policy string.");
	    }
		#endregion


		#region "FullCycle Policy Tests"
		// This section does complex tests on each of the Permissions to make sure they actually work in the Vault environment.

	    [Test]
	    public async Task Test1() {
		    string beName = _uniqueKeys.GetKey("backEnd");
		    string pathNameRoot = _uniqueKeys.GetKey("rootPth");
		    string secretPath;
		    KV2Secret readSecret;
		    KV2SecretWrapper secretReadWrapper;


		    // Create the backend.
		    VaultSysMountConfig testBE = new VaultSysMountConfig();
		    Assert.True(await _vaultSystemBackend.SysMountCreate(beName, "test Backend", EnumSecretBackendTypes.KeyValueV2),
			    "A10:  Enabling backend " + beName + " failed.");

		    // Lets create a policy for root path.
		    VaultPolicyPathItem vppi = new VaultPolicyPathItem(beName, "data/" + pathNameRoot);
		    vppi.CRUDAllowed = true;

		    // Create the Actual Policy container
		    VaultPolicyContainer polCon1 = new VaultPolicyContainer("polCon1");
		    polCon1.AddPolicyPathObject(vppi);

		    // Save Policy to Vault Instance.
		    Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(polCon1), "A20:  Saving the policy to Vault Instance failed.");

		    // Now create a token that will have this policy applied to it.
		    TokenAuthEngine tokenEng = (TokenAuthEngine) _vaultAgentAPI.ConnectAuthenticationBackend(EnumBackendTypes.A_Token);

		    TokenNewSettings tokenASettings = new TokenNewSettings();
		    tokenASettings.Policies = new List<string>();
		    tokenASettings.Policies.Add(polCon1.Name);
		    Token tokenA = await tokenEng.CreateToken(tokenASettings);

		    // Now we will use that token to try and test the secret out.  We need to create a new instance of Vault to test the token out.
		    VaultAgentAPI vaultAgent2 = new VaultAgentAPI("TestComplexPolicies", _vaultAgentAPI.IP, _vaultAgentAPI.Port, _vaultAgentAPI.Token.ID);
		    KV2SecretEngine secEng = (KV2SecretEngine) vaultAgent2.ConnectToSecretBackend(EnumSecretBackendTypes.KeyValueV2, beName, beName);


		    // Now lets test our permissions. The first thing we need to do is create the secret path, but as our root token.  The new token
			// we just created does not have access to the parent folder to do anything.  Create on the secret folder does not actually allow you 
			// to create a secret.

		    // 1. Save Secret
		    KV2Secret secret = new KV2Secret(pathNameRoot);
		    secret.Attributes.Add("attrA", "valueA");
		    secret.Attributes.Add("attrB", "valueB");
		    Assert.True(await secEng.SaveSecret(secret, KV2EnumSecretSaveOptions.OnlyIfKeyDoesNotExist), "A30:  Unable to save the secret.");


			// Now we can switch to our reduced permission token for testing. 
		    vaultAgent2.Token = tokenA;


			// 2. Read Secret.
			secretReadWrapper = await secEng.ReadSecret(pathNameRoot);
		    readSecret = secretReadWrapper.Secret;
		    Assert.AreEqual(secret.Attributes.Count, readSecret.Attributes.Count, "A40:  The secret read back was not the same as the one we saved.  Huh?");

		    // 3. Validate the secret attributes.
		    string attrValue;
		    foreach (KeyValuePair<string, string> kv in secret.Attributes) {
			    // Confirm it exists in the Read back version and the value is the same.
			    Assert.True(readSecret.Attributes.TryGetValue(kv.Key, out attrValue), "A50:  Unable to find the secret attribute: " + kv.Key);
			    Assert.AreEqual(kv.Value, attrValue, "A51:  Attribute was found, but its value was different.");
		    }

		    // 4. Update the secret.  
		    secret.Attributes.Add("attrC", "valueC");
		    secret.Attributes["attrB"] = "ValueB2";
		    Assert.True(await secEng.SaveSecret(secret, KV2EnumSecretSaveOptions.OnlyOnExistingVersionMatch, secretReadWrapper.Version),
			    "A60:  Updating the secret failed.");

		    // 5 Read the secret back and confirm.
		    secretReadWrapper = await secEng.ReadSecret(pathNameRoot);
		    readSecret = secretReadWrapper.Secret;
		    Assert.AreEqual(secret.Attributes.Count, readSecret.Attributes.Count, "A61:  The secret read back was not the same as the one we saved.  Huh?");

		    // 6. Validate the secret attributes.
		    foreach (KeyValuePair<string, string> kv in secret.Attributes) {
			    // Confirm it exists in the Read back version and the value is the same.
			    Assert.True(readSecret.Attributes.TryGetValue(kv.Key, out attrValue), "A64:  Unable to find the secret attribute: " + kv.Key);
			    Assert.AreEqual(kv.Value, attrValue, "A66:  Attribute was found, but its value was different.");
		    }

		    // 7. Delete the secret.
		    Assert.True(await secEng.DeleteSecretVersion(secret), "A70:  Unable to delete the secret.");
	    }


	    #endregion

		}
	}
