# Malswitch

Malswitch implements a community system that allows to share search in a closed community identified by public keys.

Malswitch is implemented as a golang project with different binaries implementing different roles.
Each tools is in a `cmd` subdirectory.


## AIQ protocol

AIQ is a protocol to exchange between members of the community.
AIQ community system is aimed at submitting searches on IOCs remotly between pairs (eventually only known by a public key).

There are various services in AIQ:
- search head: that receive a search from a community member and execute the search
- community manager: approves and removes community members and dispatch the community updates
- search client: a community member who submits a search
- community broker: that acts as a mailbox for the community messages allowing members not to be connected directly

AIQ message structure allows for both targeted (one member) and broadcast(whole community) search. 

## Search head

The search head can be interrogated in two ways:
- by direct HTTP interrogation by a valid member of the community
- asynchronously by messages sent to a community broker

It posts search results to a search broker.

# Search filtering

The search_head implements a policy Engine: A component that determines what can be searched. For example, a Search Head might refuse to search for certain sensitive internal IP ranges even if requested by a valid Community Member.

Policy on search is separated from the transport level: TLP, classification, labelling, sharing level (boolean or IOC sharing) which are in a search message and data storage attributes from the transport protocol(AIQ).

Information attributes are stored as a list of label_name,label_value.

## Community broker

I Community broker acts as a central hub and the single central point.
There is a single community broker per community.
The community broker address, port is a configuration setting for the clients and can be changed without changing the community.

It works in double bind, verifying the validity of community members signature of messages but unable to decrypt the messages content.

## Search client

The search client connects either:
- to the community broker
- or the search head

And submit a search message.




