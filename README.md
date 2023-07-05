# VaultAgent

VaultAgent is a C# library that provides an opinionated access to the HashiCorp Vault API Interface.  It has extensive unit tests for each of the implemented
API methods and backends as well as robust error handling and plenty of documentation.  C# classes that map to JSON objects are always used to return information
to the caller.  


It has been Unit tested against Vault version 1.11.1 (Latest as of July 2022).

# Release Notes
## Version 1.2
   - ListSecrets methods replaced with a single method --> ListSecrets
   - ListSecrets functionality is now controled by a KV2ListSecretSettings object
   - ListSecrets has ability to return an entire tree hierarchy of secrets, full path names, Just parent secrets or just child secrets and more
   - DeleteSecrets now will fully traverse the requested secrets tree and delete all child secrets.  This is the only way in vault to ensure a secret with children is deleted.

## Implemented Functionality
This library implements several key parts of vault

* System Backend
  - Mounts - Fully Implemented
  - Auth  - Fully Implemented
  - Audit - (Partial - no hash)
  - Capabilities (Partial)
  - Policy / Policies - Fully Implemented

* App Role Backend (95% implemented, just a couple of the accessor and other minor functions not implemented.)

* LDAP Auth Backend (85%) 
  - Login - Implemented
  - Group To Policy Mapping - Implemented
  - Save / Read LDAP Engine Config - Implemented
  - Some user methods implemented
  Mainly missing delete group method

* Token Auth Backend (95%)
  - All important methods and most informational methods implemented.

* Identity Secret Engine (60%)
  - All Entity and Entity Alias methods implemented
  - Missing Group information.

* KeyValue V2 (100%)
  - Fully implemented.

* KeyValue V1 (90%)

* Transit (90%)

### Next Steps
* Finish the LDAP and Identity backends.



### Usage
To test the library you will need to have a local instance of the Vault binary installed somewhere.  In the Solution Folder there is a RunVaultDev.bat script that you can use as a sample for starting your own Vault instance up.  Both the Unit Test and the VaultClient sample require a Vault Instance with the following configuration.

* IP Address:   127.0.0.1
* Port:         16100
* Root Token:   tokenA

The RunVaultDev.bat file will automatically start a development instance of Vault up with the above settings.
These Vault Settings are hardcoded in 2 places in the test/sample projects:
* VaultClient - VaultClient_Main  
* VaultAgent.Test - VaultServerSetup.cs:InitTestingSetup 


### VaultClient
At the moment this pretty much needs to be re-written with some real samples.  At the present it is wired
for an Active Directory Login and thus nothing will work without this.  

This needs to be replaced.

The Transit samples work


```
#!CSharp
// The following are all examples of use

```

