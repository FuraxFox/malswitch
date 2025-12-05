# Adversary Intelligence Query protocol description

## Description

Adversary Intelligence Query(AIQ) protocol is a simple protocol to search on CTI repositories within a community.
It aims to be minimal: it only manages search and search results, it does not describe how the identified IOCs are to be transfered between peers.

## AIQ message protocole descriptin

AIQ messages are signed encrypted and signed messages.

## AIQ message structure

```go
type EncryptedMessage struct {
	Version     int
	Data        string   
	Signature   string   
	WrappedKeys []string 
	Sender      MessageContact
}
```

Where

* `Version` is an int defining protocol version. Current version is 1.
* `Data` is base 64 encoded ciphertext + nonce
* `Signature` is base64 encoded ed25519 signature of the normalized message
* `WrappedKeys`is a list of base64 encoded wrapped symmetric keys (one per recipient)
* `Sender` is a public key pair of the message sender

## AIQ Wrapper message

```go
type Request struct {
    Community uuid
    Type      string
    Payload {}

}
```

Where Type can be 
* `SubmitSearch`, 
* `SearchAccepted`, 
* `ResultPull`,` , 
* `SearchResult`, 
* `Error`, 
* `CommunityRefresh`, 
* `CommunityResign`, 
* `CommunityReplace`, 
* `CommunityChangeAccepted`

## Community management sub-protocol description

### Community refresh

A community refresh is the 

```
Commnity Owner                                      CommunityMembers
---------------------                               ----------------- 
<generate request>    =======(CommunityRefresh)====> <accept update>
<enqueue ref>         <======(SearchAccepted)====== <enqueue search>
```

## Search sub-protocol description

All requests are serialized as JSON.
The request JSON is transported in a aiq-message.

A client submit a `SubmitSearch` request to a *SearchHead*.
The *SearchHead* answers with a `SearchAccepted` message containing a `search_uuid` 
if the search was accepted, or an `Error` message otherwise.

The client can then pull the *SearchHead* by sending a `ResultPull` containin the `search_uuid` to get the result status.
It get a `SearchResult` answer that contains: the `search_uuid`, a `search_status` and optionnaly a `search_result_content` fields.
`search_status` can be : `waiting`, `running`, `dead`, `finished` or `unknown`.
`search_result_content` is only present if `search_status` is set to `finished`.

`search_result_content` is defined as follow:
```go 
type SearchMatch struct {
    UUID        string `json:match_uuid`
    Reference   string `json:reference`
    ContentURL  string `json:"content_uri,omitempty"`
    ContenType  string `json:"content_type,omitempty"`
}

type SearchResult struct {
    SearchUUID   string        `json:search_uuid`
    Status       string        `json:"status"`
    MatchesCount int           `json:"matches_count", omitempty"`
    Matches      []SearchMatch `json:"matches,omitempty"`
}
```

### Search request submission

```
Client                                              SearchHead
---------------------                               ----------------- 
<generate request>    =======(SubmitSearch)=======> <accept search>
<enqueue ref>         <======(SearchAccepted)====== <enqueue search>
```

### Search result interrogation

```
Client                                              Searchhead
---------------------                               ----------------- 
<check result>        ========(ResultPull)========> <check queue>
<process result>      <==(SearchResult)============ <generate result>
```


### Error
```
Client                                              Searchhead
---------------------                               ----------------- 
<generate request>    =======(SubmitSearch)=======> <accept search>
<error processing>    <=========(Error)============ <generate error>
```


