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
  
## Architecture

```
       <user>                        <user>                                           <user>                                       <user>
          |                            ^                                                ^                                             ^
          |                            |                                                |                                             |
    (submit malware)             (check status)                                         V                                             |
          |                            |                                        [catalog browser]                                     |
[ submission gateway ]                 |                                                |                                             |
          |                            |                             (read and update catalog, and collection)  (select samples to share and sharing circles)
          V                            |                                                |                                             |
  <submission queue>                   |                                                |                                             |
          |                            V                                                |                                             |
          +---(process bin)--->[submission analyzer]--(reference)--<storage catalog>----+                                             |
                                       |                                                |                                             V
                         (package binary and meta infos)                                +-----( update collection and catalog)---[Exchanger]---<P2P Network>
                                       |                                                |                                             ^
                             <collection storage>---------------------------------------+                                             |
                                                                                                                                      V
                                                                                                                              <community database>
```  

-----

## Directories

```
           <WORKROOT>
               |
               +---data---submissions---<UUID(code1)
               |      |            |       \---History.yaml
               |      |            |        \--Manifest.yaml
               |      |            |         \-<hex(SHA256)>.bin
               |      |            \
               |      |             \---<UUID(code2)>--...
               |      |              \--<UUID(code3)>--...
               |      +---temp               
               |      |
               |      \-collection----<sha256(code1)>
               |             \          \---History.yaml
               |              \          \--Manifest.yaml
               |               \          \-<hex(SHA256)>.bin
               |                \
               |                 \-----<sha256(code2)>--...
               |                  \----<sha256(code3)>--...
               |
               +---databases--catalog.db
               |     \-------community.db
               |
               +---logs
                \    \-----subgateway--<YYYY>-<MM>.log
                 \    \----subanalyzer-<YYYY>-<MM>.log
                  \    \---catbrowser-<YYYY>-<MM>.log
                   \    \--exchanger-<YYYY>-<MM>.log
                    \
                     \--share--<TODO>          
```

-----

## Components

### Submission gateway

It is a REST API which receives users binaries with optional tags specified.
Upon reception:
1. user acceptable tags are written into the manifest
2. the sha256 of the file is computed
3. the sha256 tag is added to the manifest
4. compute manifest signature and add it to history

#### Exposed API

* `submission-queue/POST(binary,tag,value)->UUID` - submit an entry to queue and return the malware submission UUID
* `submission-queue/*` - return HTTP 400 error

#### Files

* configuration `$CONFIGDIR/malwswitch/subgateway.ini`
* clé de signature `$CONFIGDIR/malwswitch/malswitch-id.ed25519` 

---

### Submission analyzer

Submission analyzer jobs is to process new files:
1. compute hashes (md5, sha1, sha256, sha512)
2. reads the Manifest for user defined tags
5. check if a directory already exists for the sha256 of the sample in the collection
6. if a directory exists,
    1. merge user defined tags into the existing Manifest
    2. add the user tags to the catalog database
    3. compute the updated manifest signature
    4. add the operation to the history
    5. delete the submission queue entry
7. if a directory does not exist
    1. copy the initial Manifest to the collection
    2. compute the signature of the Manifest
    3. add it to the history
    4. create informations in the catalog
    5. delete the submission queue entry

#### Exposed API

* `submission-analyzer/GET` return the list of the entries in the queue
* `submission-analyzer/GET(uuid)` return the information of an entry in the queue

#### Files

* configuration `$CONFIGDIR/malwswitch/subanalyzer.ini`
* clé de signature `$CONFIGDIR/malwswitch/malswitch-id.ed25519` 
* base de donnée de catalogue `$WORKDIR/databases/catalog.db`

---

### Exchanger

Allows share on a P2P network selected samples for selected identities.


#### Exposed API

* `exchanger/*` TODO

#### Files

* configuration `$CONFIGDIR/malwswitch/exchanger.ini`
* clé de signature `$CONFIGDIR/malwswitch/malswitch-id.ed25519` 
* base de donnée de communauté `$WORKDIR/databases/community.db`
* base de donnée de catalogue `$WORKDIR/databases/catalog.db`

-----

## Manifest file format

Manifest is a YAML file.

### Required tags

* `LastChangeTime`
* `SHA256`
* `TLP`
* `Path(submission)`

### Optionnal tags

* `SHA512`
* `SHA384`
* `SHA1`
* `MD5`
* `FirstBytes`
* `AssociatedGroups`
* `Techniques`
* `Names`
  
### Signature

1. Sort the tags
2. TODO


