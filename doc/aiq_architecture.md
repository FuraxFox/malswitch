# **AIQ: Asynchronous Intelligence Query Architecture**

## **1\. Overview**

AIQ is a decentralized, policy-driven threat intelligence sharing protocol purpose-built for high-security, closed communities. It facilitates the near real-time exchange of Indicators of Compromise (IOCs) across disparate organizational boundaries. By utilizing high-trust membership models, the protocol ensures that identity is cryptographically verified via Ed25519 signatures, while sensitive investigation content is shielded from intermediaries through end-to-end X25519 encryption.

## **2\. Core Components and Roles**

### **2.1 Community Manager (Administrative Client)**

* **Responsibility**: Serves as the ultimate root of trust for a specific community instance, defining and maintaining the cryptographic boundary.  
* **Actions**: Conducts the lifecycle management of participants, including approving new members, revoking compromised or departing keys, and generating the authoritative Community manifest. This manifest is digitally signed by the Manager to prevent tampering.  
* **Flux**: Acts as the control plane by pushing the full, signed member list to the Broker whenever the membership state changes. This ensures the Broker has an up-to-date "allow-list" for immediate enforcement.

### **2.2 Community Broker (Edge Service)**

* **Responsibility**: The primary architectural pivot point and the only component exposed as a public-facing web service. It functions as a "Double-Blind" asynchronous message exchange.  
* **Logic**:  
  * **Authentication**: Validates that every incoming request carries a valid signature from a key currently recognized in the Manager's Community manifest.  
  * **Routing**: Manages logical mailboxes, routing encrypted payloads to specific recipients based on their SignatureKey or unique UID.  
  * **Double-Blind Privacy**: Operates on a "need-to-know" basis. It lacks access to the X25519 private keys of members, meaning it can verify *who* is talking to *whom* and observe high-level policy tags, but it cannot inspect the actual IOCs being queried.  
* **Storage**: Provides temporary, stateful persistence for messages, holding them in an encrypted buffer until they are successfully fetched by the intended recipient or hit a pre-defined expiration threshold.

### **2.3 Search Client (Consumer)**

* **Responsibility**: Represents the investigative side of the protocol, initiating live queries for threat intelligence.  
* **Actions**: Constructs a PolicySearchRequest that wraps the IOC content. It performs end-to-end encryption of the search parameters targeted at specific peers and submits the resulting package to the Broker.  
* **Flux**: Operates asynchronously; after submission, it periodically polls the Broker for results associated with its unique RequestUUID, allowing for long-running searches to complete without maintaining a persistent connection.

### **2.4 Search Head (Producer/Worker)**

* **Responsibility**: The "Workhorse" that executes the actual search logic against localized, sensitive security datasets (e.g., SIEM, EDR, or proprietary malware repositories).  
* **Actions**:  
  * **Outbound Connectivity**: Designed for restricted environments, it initiates all connections outward to the Broker using Long-Polling or WebSockets. It never listens for inbound traffic, making it invisible to external scanners.  
  * **Policy Enforcement**: Acts as a gatekeeper by evaluating the PolicyTags (such as TLP or PAP) attached to a request. It decides if the local environment’s sensitivity allows for the execution of the search or the sharing of the resulting data.  
  * **Response Generation**: Signs and encrypts the search results (hits, misses, or metadata) before returning them to the Broker for the original Client to retrieve.

## **3\. Trust & Security Model**

### **3.1 Membership is Trust**

In AIQ, trust is binary and derived from membership. Being included in the Community manifest signed by the Manager is the fundamental prerequisite for any interaction. To handle varying degrees of sensitivity, the protocol favors "Trust Segmentation": if a lower-trust tier is required, a completely separate community is instantiated with its own Broker and Manager. This prevents metadata leakage and ensures that high-trust keys are never exposed to low-trust participants.

### **3.2 Cryptographic Layer**

* **Identity & Attribution**: Ed25519 Public Keys (SignatureKey) provide non-repudiable attribution for every message. Every action, from membership updates to search responses, is signed to ensure authenticity.  
* **Confidentiality**: X25519 Elliptic Curve Diffie-Hellman (EncryptionKey) enables end-to-end privacy. The investigators and respondents establish a shared secret that excludes the Broker, ensuring that even a compromised Broker cannot leak the IOCs under investigation.  
* **Infrastructure Integrity**: The Broker acts as a mandatory validation checkpoint. It rejects any packet not signed by a recognized member, effectively neutralizing unauthorized scanning or spoofing attempts at the edge of the network.

## **4\. Data & Policy Handling**

### **4.1 Generic Policy Tagging**

AIQ utilizes a highly extensible labeling system rather than a rigid schema. By using an array of label\_name and label\_value pairs, the protocol can adapt to diverse international and organizational standards without requiring code changes to the transport layer.

* **Standardized Metadata**: Common tags include TLP (Red, Amber, Green, Clear) for sharing speed and scope, PAP for protocol access, NATO\_CLASSIFICATION for formal government requirements, and RESTRICTIONS for data handling instructions.  
* **Policy Enforcement Point (PEP)**: Search Heads implement a PEP logic block that parses these tags. For example, a search tagged TLP:RED might trigger a "volatile-memory-only" search that is never written to disk, or it might prevent the result from being shared with any other community members (Relay: False).

## **5\. Flux Matrix (Broker-Centric)**

The following matrix describes the flow of data where the Broker acts as the central synchronization point, enabling firewalled members to participate fully.

| Source | Destination | Action | Protocol | Implications |
| :---- | :---- | :---- | :---- | :---- |
| **Manager** | **Broker** | POST /admin/community | HTTPS | Broker updates its local auth-cache. |
| **Client** | **Broker** | POST /mailbox/submit | HTTPS | Search is queued; Broker notifies of acceptance. |
| **Head** | **Broker** | GET /mailbox/fetch | HTTPS | Long-poll; connection held until task is ready. |
| **Head** | **Broker** | POST /mailbox/respond | HTTPS | Signed result is placed in Client’s mailbox. |
| **Client** | **Broker** | GET /mailbox/results | HTTPS | Client retrieves results via RequestUUID. |

## **6\. Implementation Principles (Go)**

1. **Unidirectional Exposure**: Security is enhanced by ensuring only the Broker requires a public inbound listener. This drastically reduces the attack surface of the internal participants.  
2. **Resilient Communication**: All components utilize graceful shutdown procedures and context-aware timeouts, ensuring that no messages are lost or partially processed during service restarts.  
3. **Edge Defense**: The Broker is the primary line of defense against DoS, implementing strict MaxRequestBodySize checks and per-key rate limiting to ensure community availability.  
4. **Logic Decoupling**: The AIQ transport layer is entirely agnostic of the search content. By using a SearchRequest interface, the system can easily expand to support new IOC types (YARA rules, SIGMA signatures, or PCAP snippets) without modifying the core messaging logic.

