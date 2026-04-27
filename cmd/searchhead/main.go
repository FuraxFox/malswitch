package main

import (
	"flag"
	"os"
	"time"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"

	"fmt"
	"log"
	"net/http"

	"crypto/ed25519"
)

const DEFAULT_LISTEN_ADDRESS = ":8080"

var (
	// Server's X25519 private key for incoming message decryption
	ServerDecryptionKey []byte
	// Server's Ed25519 private key for signing outgoing responses
	ServerSigningKey ed25519.PrivateKey
	// The list of contacts the server trusts (used for signature verification and authorization)
	Correspondents = []aiq_message.MessageContact{}
	brokerContact  *aiq_message.MessageContact
	communityUUID  string
)

func main() {
	serverPrivFile := flag.String("priv", "", "Path to the server's private key file (required)")
	brokerURL := flag.String("broker", "", "URL of the community broker (e.g., http://localhost:8080)")
	brokerPubKeyFile := flag.String("broker-pub", "", "Path to the broker's public key file")
	communityFile := flag.String("community", "", "Path to the community JSON file")
	pollInterval := flag.Int("interval", 30, "Polling interval in seconds")
	listenAddr := flag.String("listen", DEFAULT_LISTEN_ADDRESS, "Address for the search head to listen on")

	flag.Parse()

	if *serverPrivFile == "" {
		fmt.Println("Error: -priv flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// Load Server's Private Keys
	privKeys, err := aiq_message.LoadPrivateKeys(*serverPrivFile)
	if err != nil {
		log.Fatalf("Error loading server private key: %v", err)
	}
	ServerDecryptionKey = privKeys.DecryptionKey
	ServerSigningKey = privKeys.SigningKey
	log.Printf("Server initialized with keys from: %s", *serverPrivFile)

	// Load Community if provided
	if *communityFile != "" {
		comm, err := aiq.LoadCommunity(*communityFile)
		if err != nil {
			log.Fatalf("Error loading community from %s: %v", *communityFile, err)
		}
		communityUUID = comm.UUID
		for _, member := range comm.Members {
			Correspondents = append(Correspondents, member)
		}
		log.Printf("Loaded community %s with %d members.", communityUUID, len(comm.Members))
	}

	// Load Broker Public Key if provided
	if *brokerPubKeyFile != "" {
		contact, err := aiq_message.LoadContactFromFile(*brokerPubKeyFile)
		if err != nil {
			log.Fatalf("Error loading broker public key from %s: %v", *brokerPubKeyFile, err)
		}
		brokerContact = &contact
		Correspondents = append(Correspondents, contact)
		log.Printf("Broker public key loaded from: %s", *brokerPubKeyFile)
	}

	// Load additional client public keys from remaining arguments
	for _, clientPubKeyFile := range flag.Args() {
		clientContact, err := aiq_message.LoadContactFromFile(clientPubKeyFile)
		if err != nil {
			log.Fatalf("Error loading client public key from %s: %v", clientPubKeyFile, err)
		}

		// Populate Correspondents list
		Correspondents = append(Correspondents, clientContact)
		log.Printf("   -> Trusting client public key from: %s", clientPubKeyFile)
	}
	log.Printf("Trusting %d contact(s) for communication.", len(Correspondents))

	// Background broker polling
	if *brokerURL != "" {
		if brokerContact == nil {
			log.Fatalf("Error: -broker-pub is required when -broker is used")
		}
		go pollBroker(*brokerURL, privKeys, time.Duration(*pollInterval)*time.Second)
	}

	http.HandleFunc("/decrypt", DecryptHandler)

	log.Printf("\nStarting minimal decryption server on %s...", *listenAddr)
	log.Printf("POST JSON payload to http://localhost%s/decrypt", *listenAddr)

	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
