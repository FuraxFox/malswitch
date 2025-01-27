# Architecture

```
       <user>                        <user>                                           <user>                                       <user>
          |                            ^                                                ^                                             ^
          |                            |                                                |                                             |
    (submit malware)             (check status)                                         V                                             |
          |                            |                                        [catalog browser]                                     |
[ submission gateway ]<----------------+                                                |                                             |
          |                                                          (read and update catalog, and collection)  (select samples to share and sharing circles)
          V                                                                             |                                             |
  <submission queue>                                                                    |                                             |
          |                                                                             |                                             |
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
               |      |            |        \--Submission.yaml
               |      |            |         \-<hex(SHA256)>.bin
               |      |            \
               |      |             \---<UUID(code2)>--...
               |      |              \--<UUID(code3)>--...
               |      +---temp               
               |      |
               |      \-collection----<sha256(code1)>
               |             \          \----History.yaml
               |              \          \---Manifest.yaml
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
* `submission-queue/GET` return the list of the entries in the queue
* `submission-queue/GET(uuid)` return the information of an entry in the queue
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

None

### Files

* configuration `$CONFIGDIR/malwswitch/subanalyzer.ini`
* signature key `$CONFIGDIR/malwswitch/malswitch-id.ed25519` 
* catalog database `$WORKDIR/databases/catalog.db`


### Exchanger

Allows share on a P2P network selected samples for selected identities.


#### Exposed API

* `exchanger/*` TODO

#### Files

* configuration `$CONFIGDIR/malwswitch/exchanger.ini`
* clé de signature `$CONFIGDIR/malwswitch/malswitch-id.ed25519` 
* community database `$WORKDIR/databases/community.db`
* catalog database  `$WORKDIR/databases/catalog.db`



# Assocation between samples

An association bewteen samples defines any link between an unlimited number of samples.
Links have history and status. 
To keep that history links are never removed but "deprecated".

Links status are:
- `active` link is up to date
- `reviewed` link needs confirmation
- `deprecated` link is to be considered as obsolete


An  association is a vector of:
- `association_date` 
- `association_type`
- `association_entries` 
- `association_description`

Possible association types are:
- `shared TTP`
- `shared campaign`
- `shared incident`
- `variants`
- `known_malware_versions`

