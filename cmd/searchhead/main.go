package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"os"
	"time"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"

	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"crypto/ed25519"
)

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

// DecryptHandler handles incoming JSON messages, decrypts, and sends an encrypted response.
func DecryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Decrypt the message (includes recipient verificaiton and cryptographic signature verification)
	clearText, sender, err := aiq_message.ReceiveMessage(body, ServerDecryptionKey, Correspondents)
	if err != nil {
		log.Printf("Decryption failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "Decryption Failed",
			"error":  err.Error(),
		})
		return
	}

	// Success
	log.Println("Decryption succeded ---")
	log.Printf("Decrypted Message: %s\n", clearText)

	responseText := handleAIQRequest(clearText)

	// The recipient for the response is the original sender (client)

	RespondRequest(w, r, sender, responseText)
}

func handleAIQRequest(decryptedPayload []byte) string {
	var responseText string
	request, err := aiq.DeserializeRequest(decryptedPayload)
	if err != nil {
		responseText = fmt.Sprintf("INVALID REQUEST: %v", err)
	} else {
		responseText = "REQUEST ACCEPTED"
		// TODO submit search
		log.Printf("Request: [%s]", request.String())
	}
	return responseText
}

func pollBroker(brokerURL string, privKeys aiq_message.PrivateKeySet, interval time.Duration) {
	ticker := time.NewTicker(interval)
	client := aiq.CreateHTTPClient(&privKeys, brokerURL+"/deliver-message")

	for range ticker.C {
		log.Printf("Polling broker at %s...", brokerURL)

		// 1. Create GetMessagesRequest
		req, err := aiq.NewGetMessagesRequest(communityUUID)
		if err != nil {
			log.Printf("Failed to create GetMessagesRequest: %v", err)
			continue
		}

		payload, _ := req.Serialize()

		// 2. Send to broker
		ack, err := client.SendMessage(brokerContact, string(payload))
		if err != nil {
			log.Printf("Failed to poll broker: %v", err)
			continue
		}

		// 3. Deserialize response
		respEnv, err := aiq.DeserializeRequest([]byte(ack))
		if err != nil {
			log.Printf("Failed to deserialize broker response: %v", err)
			continue
		}

		if respEnv.GetMessagesResp == nil {
			continue
		}

		// 4. Process messages
		for _, msg := range respEnv.GetMessagesResp.Messages {
			msgJSON, _ := json.Marshal(msg)
			clearText, sender, err := aiq_message.ReceiveMessage(msgJSON, ServerDecryptionKey, Correspondents)
			if err != nil {
				log.Printf("Failed to decrypt message from broker: %v", err)
				continue
			}

			log.Printf("Processing message from %s via broker", base64.StdEncoding.EncodeToString(sender.SignatureKey))
			responseText := handleAIQRequest(clearText)

			// 5. Post response back to broker
			if responseText != "" {
				respMsg, err := aiq_message.GenerateMessage([]byte(responseText), ServerSigningKey, []aiq_message.MessageContact{sender})
				if err != nil {
					log.Printf("Failed to generate response message: %v", err)
					continue
				}

				resp, err := http.Post(brokerURL+"/post-message", "application/json", bytes.NewReader(respMsg))
				if err != nil {
					log.Printf("Failed to post response to broker: %v", err)
					continue
				}
				resp.Body.Close()
				log.Printf("Posted response to %s via broker", base64.StdEncoding.EncodeToString(sender.SignatureKey))
			}
		}
	}
}

func main() {
	serverPrivFile := flag.String("priv", "", "Path to the server's private key file (required)")
	brokerURL := flag.String("broker", "", "URL of the community broker (e.g., http://localhost:8080)")
	brokerPubKeyFile := flag.String("broker-pub", "", "Path to the broker's public key file")
	communityFile := flag.String("community", "", "Path to the community JSON file")
	pollInterval := flag.Int("interval", 30, "Polling interval in seconds")
	listenAddr := flag.String("listen", ":8080", "Address for the search head to listen on")

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
