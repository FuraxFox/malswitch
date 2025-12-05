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
* `Error`, 
* `SearchSubmit`, 
* `SearchAccepted`, 
* `SearchResultPull`, 
* `SearchResult`, 
* `CommunityRefresh`, 
* `CommunityResign`, 
* `CommunityUpdate`, 
* `CommunityChangeResult`

## Community management sub-protocol description

Communities are group of users characterized by a key pair (signing and 
encrypting).
A community is signed by a community owner.
It is characterized by a UUID which acts as the community name.
It contains a `thresold`  that defines the maximum level of IOC acceptable 
to share on the community.

### Community refresh

A community refresh happens when the Community Owner send a community to a member.
The member then anwser with a `CommunityUpdateResult`.

```
Commnity Owner                                     Community Members
-------------------                                ----------------- 
<generate request>  =======(CommunityRefresh)====> <accept update>
<process result>    <==(CommunityUpdateResult)==== <enqueue search>
```

### Community resignation

A community resignation happens when a community member ask for his keys to be 
removed from the community.
A member can only resign himself.

```
Commnity member                                          Community Owner
--------------------                                     ----------------- 
<generate request>   =======(CommunityResignMember)====> <process resignation>
<process result>     <======(CommunityUpdateResult)===== <enqueue search>
```


### Community resignation

A community update happens when a community member ask for his keys to be
replaced by new keys in the community.
A member can only update himself.

```
Commnity member                                     Community Owner
---------------------                               ----------------- 
<generate request>    =======(CommunityUpdate)====> <process resignation>
<enqueue ref>         <==(CommunityUpdateResult)=== <enqueue search>
```


## Search sub-protocol description

All requests are serialized as JSON.
The request JSON is transported in a aiq-message.

A client submit a `SubmitSearch` request to a *SearchHead*.
The *SearchHead* answers with a `SearchAccepted` message if the search 
was accepted, or an `Error` message otherwise.

`SearchReference` is defined as follow:
```go
type SearchReference struct {
    SearchUUID string `json:"search_uuid"`
    Action     string `json:"search_action"`
}
```
where `search_action` must be `accepted`.

The client can then pull the *SearchHead* by sending a `SearchReference` 
with `search_action` set to `pull` to get the result status.

The *SearchHead returns a `SearchResult` answer that contains a status.

The status can be : `waiting`, `running`, `dead`, `finished` or `unknown`.

Two other fields `matches` and `match_count` are only present if the status 
is set to `finished`.

`SearchResult` is defined as follow:
```go 
type SearchMatch struct {
    MatchUUID   string `json:"match_uuid"`
    Reference   string `json:"reference"`
    ContentURL  string `json:"content_uri,omitempty"`
    ContenType  string `json:"content_type,omitempty"`
}

type SearchResult struct {
    SearchUUID   string        `json:"search_uuid"`
    Status       string        `json:"status"`
    MatchesCount int           `json:"matches_count", omitempty"`
    Matches      []SearchMatch `json:"matches,omitempty"`
}
```

### Search request submission

```
Client                                             SearchHead
--------------------                               ----------------- 
<generate request>  =========(SearchSubmit)=======> <accept search>
<enqueue ref>       <=(SearchReference(accepted))== <enqueue search>
```

### Search result interrogation

```
Client                                               Searchhead
---------------------                                ----------------- 
<check result>        ===(SearchReference(pull))===> <check queue>
<process result>      <=======(SearchResult)======== <generate result>
```




