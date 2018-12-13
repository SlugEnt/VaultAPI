using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using System.Threading.Tasks;
using VaultAgentTests;
using VaultAgent.Backends.System;
using VaultAgent;

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

            // Denied is true initially.
            Assert.True(vpp.Denied, "Denied Not True");
        }



        // Validates that the new Policy Constructors is able to break the path down into backend and protected path values as well as set the IsPrefixType
        [Test]
        [TestCase(1,"secret/path1", "secret","path1",false)]
        [TestCase(2,"secret2/path1/path2/path3","secret2","path1/path2/path3",false)]
        [TestCase(3,"/secret3/path1/path2/path3", "secret3", "path1/path2/path3",false)]
        [TestCase(4,"/secret4/path1/path2/path3/", "secret4", "path1/path2/path3",true)]
        [TestCase(5,"secret5/path1/path2/path3/", "secret5", "path1/path2/path3",true)]
        [TestCase(6,"sA/metadata/pathA/path2","sA","pathA/path2",false)]
        [TestCase(7, "sA/undelete/pathA/path2", "sA", "pathA/path2", false)]
        [TestCase(8, "sA/delete/pathA/path2", "sA", "pathA/path2", false)]
        [TestCase(9, "sA/destroy/pathA/path2", "sA", "pathA/path2", false)]
        [TestCase(10, "sA/data/pathA/path2", "sA", "pathA/path2", false)]
        public void VPPI_PathSeparatedCorrectlyIntoComponentParts (int id, string path, string expectedBE, string expectedPath, bool expectedPrefix) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
            Assert.AreEqual(expectedBE,vppi.BackendMountName,"A10: Backend Mount Name is not expected value.");
            Assert.AreEqual(expectedPath,vppi.ProtectedPath,"A20:  Protected Path is not expected value.");
            Assert.AreEqual(expectedPrefix, vppi.IsPrefixType, "A30:  IsPrefixType is not expected value.");
        }




        [Test]
        [TestCase(1,"secret","path1",true,"secret","path1",true)]
        [TestCase(2,"secret2", "path1", false, "secret2", "path1",false)]
        [TestCase(3,"/secret3", "/path1", true, "secret3", "path1",true)]
        [TestCase(4,"secret4/", "path1/", false, "secret4", "path1",true)]
        [TestCase(5,"secret5", "path1/path2/path3/", true, "secret5", "path1/path2/path3",true)]
        public void VPPI_DefaultConstructor_BackendPathIsPrefix_Works (int id,string backend, string path, bool IsPrefix, string expectedBE, string expectedPath, bool expectedPrefix) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(backend,path,IsPrefix);
            Assert.AreEqual(expectedBE, vppi.BackendMountName, "A10: Backend Mount Name is not expected value.");
            Assert.AreEqual(expectedPath, vppi.ProtectedPath, "A20:  Protected Path is not expected value.");
            Assert.AreEqual(expectedPrefix, vppi.IsPrefixType, "A30:  IsPrefixType is not expected value.");
        }


        

        [Test]
        [TestCase(1,"secret", "path1", true, "secret/path1/","")]
        [TestCase(2,"secret2", "path1", false, "secret2/path1","")]
        [TestCase(3,"/secret3", "/path1", true, "secret3/path1/","")]
        [TestCase(4,"secret4/", "path1/", false,"secret4/path1/","")]
        [TestCase(5,"secret5", "path1/path2/path3/", true, "secret5/path1/path2/path3/","")]
        [TestCase(6,"secret6", "data/path1", false, "secret6/data/path1","data")]
        [TestCase(7, "secret7", "metadata/path1", false, "secret7/data/path1","Metadata")]
        [TestCase(8, "secret8", "destroy/path1", false, "secret8/data/path1", "destroy")]
        [TestCase(9, "secret8", "delete/path1", false, "secret8/data/path1", "delete")]
        [TestCase(10, "secret8", "undelete/path1", false, "secret8/data/path1", "undelete")]
        public void VPPI_FullPath_ReturnsCorrectValues(int ID, string backend, string path, bool IsPrefix, string expectedPath, string expectedKVPath)
        {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(backend, path, IsPrefix);
            Assert.AreEqual(expectedPath, vppi.FullPath, "A10: Full path is not expected value.");
            Assert.AreEqual(expectedKVPath,vppi.KV2_PathID, "A20:  The KeyValue Version 2 path prefix was not expected value.");
        }



        // Validates that the key for a VaultPolicyPathItem object is generated correctly.
        [Test]
        [TestCase(1, "secret/path1", "secret/path1")]
        [TestCase(2, "secret2/path1/path2/path3", "secret2/path1/path2/path3")]
        [TestCase(3, "/secret3/path1/path2/path3", "secret3/path1/path2/path3")]
        [TestCase(4, "/secret4/path1/path2/path3/", "secret4/path1/path2/path3/*")]
        [TestCase(5, "secret5/path1/path2/path3/", "secret5/path1/path2/path3/*")]
        [TestCase(6, "sA/metadata/pathA/path2", "sA/pathA/path2/*")]
        [TestCase(7, "sA/undelete/pathA/path2", "sA/pathA/path2/*")]
        [TestCase(8, "sA/delete/pathA/path2", "sA/pathA/path2/*")]
        [TestCase(9, "sA/destroy/pathA/path2", "sA/pathA/path2/*")]
        [TestCase(10, "sA/data/pathA/path2", "sA/pathA/path2/*")]
        [TestCase(11, "sA/metadata/pathA/path2/*", "sA/pathA/path2/*")]
        [TestCase(12, "sA/undelete/pathA/path2/*", "sA/pathA/path2/*")]
        [TestCase(13, "sA/delete/pathA/path2/*", "sA/pathA/path2/*")]
        [TestCase(14, "sA/destroy/pathA/path2/*", "sA/pathA/path2/*")]
        [TestCase(15, "sA/data/pathA/path2/*", "sA/pathA/path2/*")]

        public void VPPI_Key_ProducedCorrectly(int id, string path, string expectedBE, string expectedPath, bool expectedPrefix)

        {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
            Assert.AreEqual(expectedBE, vppi.BackendMountName, "A10: Backend Mount Name is not expected value.");
            Assert.AreEqual(expectedPath, vppi.ProtectedPath, "A20:  Protected Path is not expected value.");
            Assert.AreEqual(expectedPrefix, vppi.IsPrefixType, "A30:  IsPrefixType is not expected value.");
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



        // Validate that we can get a permission string back.
        [Test]
        public void VPPI_CanBuildVaultPermissionString() {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem("ABC","pathA/pathB",false);
            vppi.CreateAllowed = true;
            string permission = vppi.ToVaultHCLPolicyFormat();
            Assert.IsNotEmpty(permission,"A10:  Expected a permission string to be returned.");
        }



        // Validate that we can build a proper permission string.
        [Test]
        public void VPPIKV2_CanBuildKV2PermissionString() {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem("ABC", "pathA/pathB", false);
            vppi.CreateAllowed = true;
            Assert.True (vppi.ToVaultHCLPolicyFormat().Contains("create"),"A10:  Did not find the create permission in the Vault policy string.");
            Assert.AreEqual("ABC/pathA/pathB",vppi.FullPath);

            // Create a KV2 policy item
            VaultPolicyPathItem vppi2 = new VaultPolicyPathItem("ABC", "pathA/pathB", false,true);
            vppi2.CreateAllowed = true;
            vppi2.DeleteAllowed = true;
            vppi2.ExtKV2_DeleteAnyKeyVersion = true;

            Assert.True(vppi2.ToVaultHCLPolicyFormat().Contains("create"), "A20:  Did not find the create permission in the Vault policy string.");
            Assert.True(vppi2.ToVaultHCLPolicyFormat().Contains("delete"), "A30:  Did not find the delete permission in the Vault policy string.");
            Assert.True(vppi2.ToVaultHCLPolicyFormat().Contains("/data/"), "A40:  Did not find the /data/ subpath in the Vault policy string.");
            Assert.AreEqual("ABC/data/pathA/pathB",vppi2.FullPath, "A50:  The fullpath property did not return the expected value.");
        }




        // Validate that the proper path prefixes are generated for KeyValue2 policies
        [Test]
        [TestCase(2)]
        [TestCase(3)]
        [TestCase(4)]
        [TestCase(5)]
        [TestCase(6)]
        public void VPPIKV2_PoliciesProduce_ProperPathPrefixes (int id) {
            string be = "ZZ";
            string pa = "pathA/pathB";
            string policyString;

            
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(be, pa, false);
            switch (id) {
                case 2: 
                    vppi.ExtKV2_DeleteAnyKeyVersion = true;
                    policyString = vppi.ToVaultHCLPolicyFormat();
                    Assert.That (policyString.Contains (be + "/delete/" + pa + "/*"), "A10:  Policy String was not expected value.");
                    Assert.That(policyString.Contains("update"), "A10:  Policy string did not contain expected permission.");
                    break;
                case 3: vppi.ExtKV2_DeleteMetaData = true;
                    vppi.ExtKV2_DeleteMetaData = true;
                    policyString = vppi.ToVaultHCLPolicyFormat();
                    Assert.That(policyString.Contains(be + "/metadata/" + pa + "/*"), "A30:  Policy String was not expected value.");
                    Assert.That(policyString.Contains("delete"), "A31:  Policy string did not contain expected permission.");
                    break;
                case 4: vppi.ExtKV2_DestroySecret = true;
                    vppi.ExtKV2_DestroySecret = true;
                    policyString = vppi.ToVaultHCLPolicyFormat();
                    Assert.That(policyString.Contains(be + "/destroy/" + pa + "/*"), "A40:  Policy String was not expected value.");
                    Assert.That(policyString.Contains("update"), "A41:  Policy string did not contain expected permission.");
                    break;
                case 5: vppi.ExtKV2_UndeleteSecret = true;
                    vppi.ExtKV2_UndeleteSecret = true;
                    policyString = vppi.ToVaultHCLPolicyFormat();
                    Assert.That(policyString.Contains(be + "/undelete/" + pa + "/*"), "A50:  Policy String was not expected value.");
                    Assert.That(policyString.Contains("update"), "A51:  Policy string did not contain expected permission.");
                    break;
                case 6: vppi.ExtKV2_ViewMetaData = true;
                    vppi.ExtKV2_ViewMetaData = true;
                    policyString = vppi.ToVaultHCLPolicyFormat();
                    Assert.That(policyString.Contains(be + "/metadata/" + pa + "/*"), "A60:  Policy String was not expected value.");
                    Assert.That(policyString.Contains("read"), "A61:  Policy string did not contain expected permission.");
                    break;
            }



        }




        // Validates that the FullPath property will return the proper KV2 type policy data path.
        [Test]
        public void VPPI_FullPathReturns_KV2DataPath() {
            // Create a KV2 policy item
            VaultPolicyPathItem vppi1 = new VaultPolicyPathItem("ABC", "pathA/pathB", false,true);
            
            vppi1.CreateAllowed = true;
            Assert.AreEqual("ABC/data/pathA/pathB", vppi1.FullPath, "A10:  The fullpath property did not return the expected value of : " + "ABC/data/pathA/pathB");
        }



        [Test]
        [TestCase(1, "secret/appA/", true, "secret/appA/", true)]
        [TestCase(2, "secret/appA", true, "secret/appA/", true)]
        [TestCase(3, "secret/appA/", false, "secret/appA/", true)]
        [TestCase(4, "secret/appA", false, "secret/appA", false)]
        [TestCase(5, "secret/appA/settingB", false, "secret/appA/settingB", false)]
        [TestCase(6, "secret/appA/settingB", true, "secret/appA/settingB/", true)]
        [TestCase(7, "secret/appA/settingB/", false, "secret/appA/settingB/", true)]
        [TestCase(8, "secret/appA/settingB/", true, "secret/appA/settingB/", true)]
        // Validates the Prefix Constructor works correctly by removing/adding trailing path slash depending on IsPrefix setting.
        public void VPPI_IsPrefixConstructor_WorksCorrectly(int id, string pathParam, bool prefixParam, string expPathValue, bool expPrefixValue)
        {
            VaultPolicyPathItem vaultPolicyPathItem = new VaultPolicyPathItem(pathParam, prefixParam);
            Assert.AreEqual(expPathValue, vaultPolicyPathItem.FullPath, "A10:  The protected path value was not equal to expected value.");
            Assert.AreEqual(expPrefixValue, vaultPolicyPathItem.IsPrefixType, "A20:  The expected Prefix Value was not set.");
        }



        /*  No longer valid test as the Protected Path cannot be changed after object construction.
        [Test]
        [TestCase(1,"secret/appA", true, "appA/", true)]
        [TestCase(2,"secret/appA/", true, "appA", true)]
        [TestCase(3,"secret/appA", false, "appA/", true)]
        [TestCase(4,"secret/appA/", false, "appA", false)]
        [TestCase(5,"secret/appA/settingB", true, "appA/settingC", true)]
        [TestCase(6,"secret/appA/SettingB/", true, "appA/settingC", true)]
        [TestCase(7,"secret/appA/settingB", false, "appA/settingC", false)]
        [TestCase(8,"secret/appA/settingB", false, "appA/settingC/", true)]
        public void PathWithPrefix_Sets_IsPrefixType_Correctly(int id, string pathParam, bool prefixParam, string newPath, bool isPrefixValue)
        {
            VaultPolicyPathItem vaultPolicyPathItem = new VaultPolicyPathItem(pathParam, prefixParam);


            // Since we called constructor with the prefix parameter, no matter what the path has (trailing slash or not) the prefix parameter 
            // determines the type of path object and the IsPrefix setting.
            Assert.AreEqual(prefixParam, vaultPolicyPathItem.IsPrefixType, "A1: policy IsPrefixType setting is not expected value.");


            // Now change the path to be something different.  Confirm IsPrefix setting changes appropriately
            vaultPolicyPathItem.ProtectedPath = newPath;

            Assert.AreEqual(isPrefixValue, vaultPolicyPathItem.IsPrefixType, "A2: New policy IsPrefix property is not expected value.");
            
        }
        */



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
        [TestCase(1,"/backend1/pathA/pathB/pathC","backend1/pathA/pathB/pathC::0", "Normal Path test with KV2:False and IsPrefix:False")]
        [TestCase(2, "/backend1/pathA", "backend1/pathA::0","Normal Path test with KV2:False and IsPrefix:False")]
        [TestCase(3, "/backend1/pathA/", "backend1/pathA/::0","Normal Path test with KV2:False and IsPrefix:True")]
        [TestCase(4, "/backend1/pathA/pathB", "backend1/pathA/pathB::0", "Normal Path test with KV2:False and IsPrefix:True")]
        [TestCase(5, "/backend2/data/pathA", "backend2/pathA::1", "KV2 Path test with IsPrefix:False")]
        [TestCase(6, "/backend2/metadata/pathA", "backend2/pathA::1", "KV2 Path test with IsPrefix:False")]
        [TestCase(7, "/backend2/destroy/pathA", "backend2/pathA::1", "KV2 Path test with IsPrefix:False")]
        [TestCase(8, "/backend2/delete/pathA", "backend2/pathA::1", "KV2 Path test with IsPrefix:False")]
        [TestCase(9, "/backend2/undelete/pathA", "backend2/pathA::1", "KV2 Path test with IsPrefix:False")]
        [TestCase(10, "/backend3/a/data/pathA", "backend3/a/data/pathA::0", "Test Similar path to KV2 Path test with IsPrefix:False")]
        [TestCase(11, "/backend3/a/metadata/pathA", "backend3/a/metadata/pathA::0", "Test Similar path to KV2 Path test with IsPrefix:False")]
        [TestCase(12, "/backend3/a/destroy/pathA", "backend3/a/destroy/pathA::0", "Test Similar path to KV2 Path test with IsPrefix:False")]
        [TestCase(13, "/backend3/a/delete/pathA", "backend3/a/delete/pathA::0", "Test Similar path to KV2 Path test with IsPrefix:False")]
        [TestCase(14, "/backend3/a/undelete/pathA", "backend3/a/undelete/pathA::0", "Test Similar path to KV2 Path test with IsPrefix:False")]
        public void VPPI_KeyGenerated_CorrectlyFromPath (int id, string path, string expectedKey,string desc) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
            Assert.AreEqual(expectedKey,vppi.Key,desc);
        }
        #endregion


        #region "Other Policy Tests"
        //TODO this needs some finishing work.../
        [Test]
        public async Task Policy_CanCreatePolicy_WithSingleVaultPolicyItem()
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
        public async Task Policy_CanCreateAPolicy_WithMultipleVaultPolicyItems()
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


            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP));


            // Now lets read it back. 
            VaultPolicyContainer vpNew = await _vaultSystemBackend.SysPoliciesACLRead(name);

            Assert.AreEqual(3, vpNew.PolicyPaths.Count);
            foreach (VaultPolicyPathItem item in vpNew.PolicyPaths.Values)
            {
                if (item.FullPath == path1)
                {
                    Assert.AreEqual(vpi1.ListAllowed, item.ListAllowed);
                    Assert.AreEqual(vpi1.DeleteAllowed, item.DeleteAllowed);
                    Assert.AreEqual(vpi1.ReadAllowed, item.ReadAllowed);
                    Assert.AreEqual(vpi1.SudoAllowed, item.SudoAllowed);
                }
                else if (item.FullPath == path2)
                {
                    Assert.AreEqual(vpi2.Denied, item.Denied);
                }
                else if (item.FullPath == path3)
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
                else { Assert.True(false, "invalid path returned of {0}", item.FullPath); }
            }
        }



        // Validate that a KeyValue2 permission of destroy is properly saved in the Vault Instance and can be read back in successfully.
        [Test]
        public async Task Vault_KV2_Confirm_DestroyPermission_CreatedCorrectly() {
            string polName = _uniqueKeys.GetKey ("Destroy");
            VaultPolicyContainer policyContainer = new VaultPolicyContainer(polName);

            // Create the policy Path Permission Object
            string backend = "kv2Back";
            string path = "asecret";
            VaultPolicyPathItem polItem = new VaultPolicyPathItem(backend,path,null,true);
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
                if (item.FullPath == path1)
                {
                    Assert.AreEqual(vpi1.ListAllowed, item.ListAllowed);
                    Assert.AreEqual(vpi1.DeleteAllowed, item.DeleteAllowed);
                    Assert.AreEqual(vpi1.ReadAllowed, item.ReadAllowed);
                    Assert.AreEqual(vpi1.SudoAllowed, item.SudoAllowed);
                }
                else if (item.FullPath == path2)
                {
                    Assert.AreEqual(vpi2.Denied, item.Denied);
                }
                else if (item.FullPath == path3)
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
                else { Assert.True(false, "invalid path returned of {0}", item.FullPath); }
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
        public void KV2_SinglePathConstructor_IsKV2Property_IsSet (string path) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
            Assert.IsTrue(vppi.IsKV2Policy,"A10:  Expected the IsKV2Policy property to be true.");
        }
        #endregion
    }
}
