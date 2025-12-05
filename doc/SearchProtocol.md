# Adversary Intelligence Query protocol description

## Description

Adversary Intelligence Query(AIQ) protocol is a simple protocol to search on CTI repositories within a community.
It aims to be minimal: it only manages search and search results, it does not describe how the identified IOCs are to be transfered between peers.

## AIQ message protocole descriptin

AIQ messages are signed encrypted and signed messages.

## AIQ message structure

```
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


## Search sub protocol description

All request are serialized as JSON.
The request JSON is transported in a aiq-message.

### Search with result

```
Client                                              Server
---------------------                               ----------------- 
<generate request>    =======(SubmitSearch)=======> <accept search>
<enqueue ref>         <======(SearchAccepted)====== <enqueue search>
<check result>        ========(ResultPull)========> <check queue>
<process result>      <==(SearchResult)============ <generate result>
```

### Search with no result

```
Client                                              Server
---------------------                               ----------------- 
<generate request>    =======(SubmitSearch)=======> <accept search>
<enqueue ref>         <======(SearchAccepted)====== <enqueue search>
<check result>        ========(ResultPull)========> <check queue>
<process result>      <=(SearchResultUnavailable)== <generate answer>
```

### Error
```
Client                                              Server
---------------------                               ----------------- 
<generate request>    =======(SubmitSearch)=======> <accept search>
<error processing>    <=========(Error)============ <generate error>
```


