# VaultAgent

VaultAgent is a C# library that provides an opinionated access to the HashiCorp Vault API Interface.  While there are several other libraries that exist
I feel this one provides a much more robust interface to the Vault API than some of the others.  It has extensive unit tests for each of the implemented
API methods and backends as well as robust error handling and plenty of documentation.  C# classes that map to JSON objects are always used to return information
to the caller.

## Beta Product
This is still very much a beta product and only implements a subset of the full Vault backend functionality, but probably the backends that most users would
initially be looking for.  

It has been Unit tested against Vault version 1.0.1 (Latest as of January 2019).

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
* Some Performance enhancements on the HTTP calls.


### Usage
See the Unit Tests or the Test Console App for some guidance on how to use.

```
#!CSharp
// The following are all examples of use

```

