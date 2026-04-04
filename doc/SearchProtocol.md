# Adversary Intelligence Query protocol description

## Description

Adversary Intelligence Query(AIQ) protocol is a simple protocol to search on CTI repositories within a community.
It aims to be minimal: it only manages search and search results, it does not describe how the identified IOCs are to be transfered between peers.

## AIQ message protocole descriptin

AIQ messages are signed encrypted and signed messages.

## AIQ message structure

```go
type EncryptedMessage struct {
	Version       int
	Data          string   // Base64 encoded ciphertext + nonce
	Signature     string   // Base64 encoded ed25519 signature of the normalized message
	WrappedKeys   []string // List of Base64 encoded wrapped symmetric keys (one per recipient)
	RecipientKeys []string // List of Base64 encoded Ed25519 public signature keys of recipients
	Sender        MessageContact
}
```

Where

* `Version` is an int defining protocol version. Current version is 1.
* `Data` is base 64 encoded ciphertext + nonce
* `Signature` is base64 encoded ed25519 signature of the normalized message
* `WrappedKeys`is a list of base64 encoded wrapped symmetric keys (one per recipient)
* `Sender` is a public key pair of the message sender

## AIQ Request Envelope message

```go
type RequestEnveloppe struct {
	CommunityUUID      string                     `json:"community_uuid"`
	Type               RequestType                `json:"request_type"`
	Error              *ErrorRequest              `json:"error,omitempty"`
	SubmitRequest      *SearchSubmitRequest       `json:"submit_request,omitempty"`
	ResultRequest      *SearchResultRequest       `json:"result_request,omitempty"`
	SearchReference    *SearchReferenceRequest    `json:"search_reference_request,omitempty"`
	CommunityUpdate    *CommunityUpdateRequest    `json:"community_update_request,omitempty"`
	CommunitySubscribe *CommunitySubscribeRequest `json:"community_subscribe_request,omitempty"`
	GetMessages        *GetMessagesRequest        `json:"get_messages_request,omitempty"`
	GetMessagesResp    *GetMessagesResponse       `json:"get_messages_response,omitempty"`
	PostMessageResp    *PostMessageResponse       `json:"post_message_response,omitempty"`
}
```

Where `RequestType` can be:
* `error-request`
* `search-submit-request`
* `search-accepted-request`
* `search-pull-request`
* `search-result-request`
* `community-refresh-request`
* `community-resign-request`
* `community-update-request`
* `community-update-accepted`
* `community-subscribe-request`
* `community-subscription-queued`
* `community-change-request`
* `get-messages-request`
* `get-messages-response`
* `post-message-response`

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

A client submit a `SubmitSearchRequest` request to a *SearchHead*.
The *SearchHead* answers with a `SearchAccepted` message if the search 
was accepted, or an `Error` message otherwise.

```go

type HashEntry struct {
	Value string `json:"value"` // The hash string (e.g., a0eebc99da0)
	Type  string `json:"type"`  // e.g., "MD5", "SHA256"
}


type SearchSubmitRequest struct {
	Type     string      `json:"type"`                // e.g., "IP_LIST", "HASH_LIST", "YARA_RULE", "GENERIC_STRING"
	IPs      []string    `json:"ips,omitempty"`       // Used for IP_LIST
	Hashes   []HashEntry `json:"hashes,omitempty"`    // Used for HASH_LIST
	YaraRule string      `json:"yara_rule,omitempty"` // Used for YARA_RULE
	Text     string      `json:"text,omitempty"`      // Used for IOC_TYPE_TEXT (or for simple text searches)
}
```


`SearchReferenceRequest` is defined as follow:
```go
type SearchReferenceRequest struct {
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

type SearchResultRequest struct {
    SearchUUID   string        `json:"search_uuid"`
    Status       string        `json:"status"`
    MatchesCount int           `json:"matches_count", omitempty"`
    Matches      []SearchMatch `json:"matches,omitempty"`
}
```

### Search request submission

```
Client                                                     SearchHead
--------------------                                       ----------------- 
<generate request>  =========(SearchSubmitRequest)=======> <accept search>
<enqueue ref>       <=(SearchReferenceRequest(accepted))== <enqueue search>
```

### Search result interrogation

```
Client                                                       Searchhead
---------------------                                        ----------------- 
<check result>        ===(SearchReferenceRequest(pull))===> <check queue>
<process result>      <=======(SearchResultRequest)======== <generate result>
```

## Community Broker: Asynchronous message exchange

A community broker acts as a central mailbox for community messages. Members can post messages for others and retrieve messages intended for them.

### Posting a message to the broker

Any member can post an `EncryptedMessage` to the broker. The broker stores it and notifies the recipient(s) when they poll for messages.

```
Sender                                                     Broker
--------------------                                       -----------------
<generate message>   =========(AIQ Message)==============> <verify signature>
<process result>     <======(PostMessageResponse)========= <store message>
```

### Retrieving messages from the broker

Members periodically poll the broker to retrieve messages intended for them.

```
Recipient                                                  Broker
--------------------                                       -----------------
<generate poll req>  =========(GetMessagesRequest)========> <verify signature>
<decrypt messages>   <========(GetMessagesResponse)======== <fetch messages>
```

### Search via Broker

The *SearchHead* can poll the broker for `SearchSubmitRequest` and post results back to the broker.

```
Client               Broker              SearchHead
-----------------    --------------      -----------------
<post search>  ===>  <store search>
                     <wait poll>   <===  <poll broker>
                     <deliver search>==> <process search>
<poll broker>  <===  <store result>  <===  <post result>
<get result>
```



