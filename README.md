# malswitch

Lets try to code a malware collection platform. 

## Goals

Learn by trying a software system that allow to easily manage a collection of malwares.

## Requirements

* Each binary has associated meta informations in the form of a list of tags.
* Tags are of the form Name/Value/Parameter and allow for multiple values for the same tag.
* Some tags are required: basic hashes, submission date, submiter identity
* Each instance has an identity that is a private key
* Changes are historized in the meta-informations and signed with the private key
* A change is a diff of the Yaml file
* This collection is shared by a P2P protocol to allow distributed storage with its meta-informations.
* It has to be very simple to install: run it for the first time and it creates the necessary configurations, directories...
* Database storage for the catalog shall not require system configuration.

## Technical choices

* Go as programming language
* SQLite as database backend as it allows for installation-less run
* IPFS as P2P protocol as it is mature and has binding for Go
* Collection is stored in a hierarchy of directories
* Meta-informations are stored in a YAML text file in the same directory as the binary
* Binaries are to be stored, renamed to their sha256 encoded in hex in a non executable file
* Identities shall be Ed25519 private keys
* Signatures shall be Ed25519 signatures
* User interface is not included: every interface is REST calls
-----

* [Architecture](doc/Architecture.md) - General program architecture and file organization 
* [Community](doc/Community.md)       - Community and file sharing management
* [File formats](doc/Fileformats.md)  - File formats of catalogued entries


