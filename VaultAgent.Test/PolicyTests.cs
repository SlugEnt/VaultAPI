using System;
using System.Collections.Generic;
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


        #region Policy_Tests
        [Test]
        public void Policy_VaultPolicyPath_InitialFields_AreCorrect()
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
        [TestCase("secret/path1", "secret","path1",false)]
        [TestCase("secret2/path1/path2/path3","secret2","path1/path2/path3",false)]
        [TestCase("/secret3/path1/path2/path3", "secret3", "path1/path2/path3",false)]
        [TestCase("/secret4/path1/path2/path3/", "secret4", "path1/path2/path3",true)]
        [TestCase("secret5/path1/path2/path3/", "secret5", "path1/path2/path3",true)]

        public void PathSeparatedCorrectlyIntoComponentParts (string path, string expectedBE, string expectedPath, bool expectedPrefix) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(path);
            Assert.AreEqual(expectedBE,vppi.BackendMountName,"A10: Backend Mount Name is not expected value.");
            Assert.AreEqual(expectedPath,vppi.ProtectedPath,"A20:  Protected Path is not expected value.");
            Assert.AreEqual(expectedPrefix, vppi.IsPrefixType, "A30:  IsPrefixType is not expected value.");
        }


        [Test]
        [TestCase("secret","path1",true,"secret","path1")]
        [TestCase("secret2", "path1", false, "secret2", "path1")]
        [TestCase("/secret3", "/path1", true, "secret3", "path1")]
        [TestCase("secret4/", "path1/", false, "secret4", "path1")]
        [TestCase("secret5", "path1/path2/path3/", true, "secret5", "path1/path2/path3")]
        public void DefaultConstructor_BackendPathIsPrefix_Works (string backend, string path, bool IsPrefix, string expectedBE, string expectedPath) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(backend,path,IsPrefix);
            Assert.AreEqual(expectedBE, vppi.BackendMountName, "A10: Backend Mount Name is not expected value.");
            Assert.AreEqual(expectedPath, vppi.ProtectedPath, "A20:  Protected Path is not expected value.");
            Assert.AreEqual(IsPrefix, vppi.IsPrefixType, "A30:  IsPrefixType is not expected value.");
        }



        // Validate we can change the backend mount name.
        [Test]
        [TestCase("old","new","new")]
        [TestCase("old", "/new", "new")]
        [TestCase("old", "new/", "new")]
        public void ChangingBackendName_Success(string oldValue, string newValue, string expectedValue) {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(oldValue, "path1", true);
            Assert.AreEqual(oldValue,vppi.BackendMountName,"A10:  Initial BackendMount name did not get set correctly.");
            vppi.BackendMountName = newValue;
            Assert.AreEqual(expectedValue, vppi.BackendMountName, "A20:  Backend Mount name did not change to expected value.");
        }




        // Validate we can change the protected path.
        [Test]
        [TestCase("old", "new", "new",false)]
        [TestCase("old", "/new", "new",false)]
        [TestCase("old", "new/", "new", true)]
        [TestCase("old", "new/path2/", "new/path2",true)]
        [TestCase("old", "/new/path2/path3", "new/path2/path3", false)]
        public void ChangingProtectedPath_Success(string oldValue, string newValue, string expectedValue, bool expectedPrefix)
        {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem("backend", oldValue, false);
            Assert.AreEqual(oldValue, vppi.ProtectedPath, "A10:  Initial ProtectedPath did not get set correctly.");
            vppi.ProtectedPath = newValue;
            Assert.AreEqual(expectedValue, vppi.ProtectedPath, "A20:  ProtectedPath did not change to expected value.");
            Assert.AreEqual(expectedPrefix, vppi.IsPrefixType, "A30:  IsPrefixType is not expected value.");
        }




        [Test]
        [TestCase("secret", "path1", true, "secret/path1/")]
        [TestCase("secret2", "path1", false, "secret2/path1")]
        [TestCase("/secret3", "/path1", true, "secret3/path1/")]
        [TestCase("secret4/", "path1/", false,"secret4/path1")]
        [TestCase("secret5", "path1/path2/path3/", true, "secret5/path1/path2/path3/")]
        public void FullPath_ReturnsCorrectValues(string backend, string path, bool IsPrefix, string expectedPath)
        {
            VaultPolicyPathItem vppi = new VaultPolicyPathItem(backend, path, IsPrefix);
            Assert.AreEqual(expectedPath, vppi.FullPath, "A10: Full path is not expected value.");
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
        public void SettingTrueToFields_Success(string type, string value)
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
        public void SetDenied_SetsEverythingElseTo_False()
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
            VP.PolicyPaths.Add(vpi);
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
            VaultPolicyPathItem vpi4 = new VaultPolicyPathItem(pol3Name);
            vpi4.DeleteAllowed = true;


            // Create a Vault Policy Item and add the policy paths.
            VaultPolicyContainer VP = new VaultPolicyContainer("TestingABCD");
            VP.PolicyPaths.Add(vpi1);
            VP.PolicyPaths.Add(vpi2);
            VP.PolicyPaths.Add(vpi3);
            VP.PolicyPaths.Add(vpi4);

            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP));
        }



        // Validates that we can read a Policy object from Vault that contains just a single path permission object.
        [Test]
        public async Task Policy_CanReadSinglePathPolicy()
        {
            VaultPolicyContainer VP = new VaultPolicyContainer("Test2000A");

            VaultPolicyPathItem vpi3 = new VaultPolicyPathItem("secret/Test2000A");
            vpi3.ListAllowed = true;
            vpi3.DeleteAllowed = true;
            vpi3.ReadAllowed = true;
            vpi3.SudoAllowed = true;
            VP.PolicyPaths.Add(vpi3);

            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP));


            // Now lets read it back. 
            VaultPolicyContainer vpNew = await _vaultSystemBackend.SysPoliciesACLRead("Test2000A");

            Assert.AreEqual(1, vpNew.PolicyPaths.Count);
            Assert.AreEqual(vpi3.ListAllowed, vpNew.PolicyPaths[0].ListAllowed);
            Assert.AreEqual(vpi3.DeleteAllowed, vpNew.PolicyPaths[0].DeleteAllowed);
            Assert.AreEqual(vpi3.ReadAllowed, vpNew.PolicyPaths[0].ReadAllowed);
            Assert.AreEqual(vpi3.SudoAllowed, vpNew.PolicyPaths[0].SudoAllowed);
        }



        [Test]
        // Can read a policy that has multiple paths attached to it.
        public async Task Policy_CanReadMultiplePathPolicy()
        {
            // Create a Vault Policy Item and add the policy paths.
            VaultPolicyContainer VP = new VaultPolicyContainer("Test2000B");


            string path1 = "secret/Test2000B1";
            VaultPolicyPathItem vpi1 = new VaultPolicyPathItem(path1);
            vpi1.ListAllowed = true;
            vpi1.DeleteAllowed = true;
            vpi1.ReadAllowed = true;
            vpi1.SudoAllowed = true;
            VP.PolicyPaths.Add(vpi1);

            // 2nd policy path
            string path2 = "secret/Test2000B2";
            VaultPolicyPathItem vpi2 = new VaultPolicyPathItem(path2);
            vpi2.Denied = true;
            VP.PolicyPaths.Add(vpi2);


            // 3rd policy path
            string path3 = "secret/Test2000B3";
            VaultPolicyPathItem vpi3 = new VaultPolicyPathItem(path3);
            vpi3.ListAllowed = true;
            vpi3.ReadAllowed = true;
            vpi3.UpdateAllowed = true;
            VP.PolicyPaths.Add(vpi3);

            Assert.True(await _vaultSystemBackend.SysPoliciesACLCreate(VP));


            // Now lets read it back. 
            VaultPolicyContainer vpNew = await _vaultSystemBackend.SysPoliciesACLRead("Test2000B");

            Assert.AreEqual(3, vpNew.PolicyPaths.Count);
            foreach (VaultPolicyPathItem item in vpNew.PolicyPaths)
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
        public void Policy_ReadOfNonExistentPolicy_ResultsInExpectedError()
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
            VP.PolicyPaths.Add(vpi);

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
            VP.PolicyPaths.Add(vpi);

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



        [Test]
        [TestCase("secret/appA/", true, "secret/appA/", true)]
        [TestCase("secret/appA", true, "secret/appA/", true)]
        [TestCase("secret/appA/", false, "secret/appA", false)]
        [TestCase("secret/appA", false, "secret/appA", false)]
        [TestCase("secret/appA/settingB", false, "secret/appA/settingB", false)]
        [TestCase("secret/appA/settingB", true, "secret/appA/settingB/", true)]
        [TestCase("secret/appA/settingB/", false, "secret/appA/settingB", false)]
        [TestCase("secret/appA/settingB/", true, "secret/appA/settingB/", true)]
        // Validates the Prefix Constructor works correctly by removing/adding trailing path slash depending on IsPrefix setting.
        public void IsPrefixConstructor_WorksCorrectly(string pathParam, bool prefixParam, string pathValue, bool prefixValue)
        {
            VaultPolicyPathItem vaultPolicyPathItem = new VaultPolicyPathItem(pathParam, prefixParam);
            Assert.AreEqual(vaultPolicyPathItem.FullPath, pathValue);
            Assert.AreEqual(vaultPolicyPathItem.IsPrefixType, prefixValue);
        }




        [Test]
        [TestCase("secret/appA", true, "appA/", true)]
        [TestCase("secret/appA/", true, "appA", true)]
        [TestCase("secret/appA", false, "appA/", true)]
        [TestCase("secret/appA/", false, "appA", false)]
        [TestCase("secret/appA/settingB", true, "appA/settingC", true)]
        [TestCase("secret/appA/SettingB/", true, "appA/settingC", true)]
        [TestCase("secret/appA/settingB", false, "appA/settingC", false)]
        [TestCase("secret/appA/settingB", false, "appA/settingC/", true)]
        public void PathWithPrefix_Sets_IsPrefixType_Correctly(string pathParam, bool prefixParam, string newPath, bool isPrefixValue)
        {
            VaultPolicyPathItem vaultPolicyPathItem = new VaultPolicyPathItem(pathParam, prefixParam);


            // Since we called constructor with the prefix parameter, no matter what the path has (trailing slash or not) the prefix parameter 
            // determines the type of path object and the IsPrefix setting.
            Assert.AreEqual(prefixParam, vaultPolicyPathItem.IsPrefixType, "A1: policy IsPrefixType setting is not expected value.");


            // Now change the path to be something different.  Confirm IsPrefix setting changes appropriately
            vaultPolicyPathItem.ProtectedPath = newPath;

            Assert.AreEqual(isPrefixValue, vaultPolicyPathItem.IsPrefixType, "A2: New policy IsPrefix property is not expected value.");
            
        }



        // Validates that the CRUD property sets the Create, Read, Update and Delete properties as expected.
        [Test]
        public void Policy_CRUDSetOperation_Works()
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
        public void Policy_FullControlSetOperation_Works()
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
        #endregion


    }
}
