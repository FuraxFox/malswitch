# Communities and file sharing

## Concepts

Malswitch allows to share information on peer to peer basis with community.

A community is characterized by a UUID identifier, a couple private/public key and a description

Each sharing host exposes a "community catalog" to a community.

This catalog contains the subset of the global catalog exposed to a particular community.

There are 3 modes of sharing :

* `existence` - share the fact that the file exists in the catalog and its hashes (Manifest)
* `file`      - share the hashes and the actual file (Manifest and binary)
* `full`      - share the hashes, the file, and the complete history and analysis (Manifest, binary, History)


## Data organisation

```

     Communities
         \
          \---------< community-id1, pub-key1, priv-key1, description1 >
           \                            \
            \                        < catalog-entry-id1, tlp, sharing-mode, hashes >
             \                       < catalog-entry-id3, tlp, sharing-mode, hashes >
              \                      < catalog-entry-id4, tlp, sharing-mode, hashes >
               \
                \----< community-id2, pub-key2, priv-key2, description2 >
                 \                       \
                  \                    < catalog-entry-id1, tlp, sharing-mode, hashes >
                   \                   < catalog-entry-id2, tlp, sharing-mode, hashes >
                    \                  < catalog-entry-id4, tlp, sharing-mode, hashes >
                     \---- ...

```

* communities are stored in the table `communities` in the catalog database
* community catalogs are stored in the table `communities_catalog` in the catalog database
* entries sharing is stored in 

## Communities table

* `< community-id, pub-key, priv-key, description >`

where

* `<community-id>`
* `<pub-key>`
* `<priv-key>`
* `<description>`

## Communities catalog table

* `< catalog-entry-id, TLP, sharing-mode, hashes >`

where :

* *`<community-id> is a valid identifier for a community existing in the database
* `<TLP>` is the TLP with which the binary can be shared
* `<sharing-mode>` is either `existence`, `file` or `full`


