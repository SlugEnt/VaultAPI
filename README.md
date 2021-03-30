# VaultAgent

VaultAgent is a C# library that provides an opinionated access to the HashiCorp Vault API Interface.  It has extensive unit tests for each of the implemented
API methods and backends as well as robust error handling and plenty of documentation.  C# classes that map to JSON objects are always used to return information
to the caller.  

## Beta Product
This is still very much a beta product and only implements a subset of the full Vault backend functionality, but probably the backends that most users would
initially be looking for.  

It has been Unit tested against Vault version 1.3.1 (Latest as of January 2020).

## Implemented Functionality
This library is very much a Work In Process.  The core modules that we needed to use have been implemented.  Following is the status of the backends

* System Backend
  - Mounts - Fully Implemented
  - Auth  - Fully Implemented
  - Audit - (Partial - no hash)
  - Capabilities (Partial)
  - Policy / Policies - Fully Implemented

* App Role Backend (95% implemented, just a couple of the accessor and other minor functions not implemented.)
* LDAP Auth Backend (75%) 
  - Login - Implemented
  - Group To Policy Mapping - Implemented
  - Save / Read LDAP Engine Config - Implemented
  Mainly missing the User methods and delete group method

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

