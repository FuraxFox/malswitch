package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"
	"github.com/sirupsen/logrus"
)

var (
	log       = logrus.New()
	database  *Database
	community aiq.Community
	brokerKey aiq_message.PrivateKeySet
	maxAge    = 3600
)

const (
	brokerKeyFile = "commbroker.priv"
	dbFile        = "commbroker.db"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <community_file> [max_age]\n", os.Args[0])
		os.Exit(1)
	}

	commFile := os.Args[1]
	if len(os.Args) >= 3 {
		if val, err := strconv.Atoi(os.Args[2]); err == nil {
			maxAge = val
		}
	}

	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	// Load community
	c, err := aiq.LoadCommunity(commFile)
	if err != nil {
		log.Fatalf("Failed to load community: %v", err)
	}
	community = c

	// Load or generate broker keys
	if _, err := os.Stat(brokerKeyFile); os.IsNotExist(err) {
		log.Infof("Broker key file not found, generating new keys...")
		pub, priv, err := aiq_message.GenerateKeySets()
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		brokerKey = priv

		// Save them
		keyJSON := aiq_message.PrivateKeySetJSON{
			DecryptionKey: base64.StdEncoding.EncodeToString(priv.DecryptionKey),
			SigningKey:    base64.StdEncoding.EncodeToString(priv.SigningKey),
		}
		data, _ := json.MarshalIndent(keyJSON, "", "  ")
		os.WriteFile(brokerKeyFile, data, 0600)
		log.Infof("Broker keys saved to %s", brokerKeyFile)
		log.Infof("Broker Public Signature Key: %s", pub.SignatureKey)
	} else {
		priv, err := aiq_message.LoadPrivateKeys(brokerKeyFile)
		if err != nil {
			log.Fatalf("Failed to load broker keys: %v", err)
		}
		brokerKey = priv
		log.Infof("Broker keys loaded from %s", brokerKeyFile)
	}

	// Init database
	db, err := InitDB(dbFile)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	database = db
	defer db.Close()

	// Background cleanup
	go cleanupLoop()

	// HTTP handlers
	http.HandleFunc("/post-message", postMessageHandler)
	http.HandleFunc("/deliver-message", deliverMessageHandler)

	log.Infof("Community Broker starting on :8080 (max_age: %ds)", maxAge)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		deleted, err := database.CleanupMessages(maxAge)
		if err != nil {
			log.Errorf("Cleanup error: %v", err)
		} else if deleted > 0 {
			log.Infof("Cleanup: removed %d expired or fully delivered messages", deleted)
		}
	}
}

func postMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Failed to read body: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 1. Verify if it's an AIQ message
	msg, err := aiq_message.VerifyAIQMessageSignature(body)
	if err != nil {
		log.Warnf("Invalid AIQ message from %s: %v", r.RemoteAddr, err)
		http.Error(w, "Invalid AIQ message", http.StatusBadRequest)
		return
	}

	// 2. Verify community membership
	if !aiq_message.CheckSenderAuthorization(&msg, community.Members) {
		log.Warnf("Unauthorized sender %s trying to post message", base64.StdEncoding.EncodeToString(msg.Sender.SignatureKey))
		respondError(w, "unauthorized community member", msg.Sender)
		return
	}

	// 3. Store message
	if err := database.SaveMessage(body); err != nil {
		log.Errorf("Failed to save message: %v", err)
		respondError(w, "failed to store message", msg.Sender)
		return
	}

	log.Infof("Message from %s accepted and stored", base64.StdEncoding.EncodeToString(msg.Sender.SignatureKey))

	// 4. Respond with success AIQ message
	respondSuccess(w, "message accepted", msg.Sender)
}

func deliverMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Failed to read body: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 1. Receive and Decrypt AIQ message
	// Since we need to know who is asking, we must decrypt it to see the GetMessagesRequest
	// Actually, VerifyAIQMessageSignature gives us the sender. Let's see if we can do better.
	// The issue says: "The request is a dedicated 'get-messages' aiq message"

	payload, sender, err := aiq_message.ReceiveMessage(body, brokerKey.DecryptionKey, community.Members)
	if err != nil {
		// Check if it's because it's not in the community
		// We need to distinguish between "not an AIQ message" and "not in community"
		var msg aiq_message.EncryptedMessage
		if unmarshalErr := json.Unmarshal(body, &msg); unmarshalErr != nil {
			log.Warnf("Invalid AIQ message from %s: %v", r.RemoteAddr, unmarshalErr)
			http.Error(w, "Invalid AIQ message", http.StatusBadRequest)
			return
		}

		// If it's a valid AIQ message but sender not in community
		if !aiq_message.CheckSenderAuthorization(&msg, community.Members) {
			log.Warnf("Forbidden: requester %s not in community", base64.StdEncoding.EncodeToString(msg.Sender.SignatureKey))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		log.Warnf("ReceiveMessage failed for %s: %v", r.RemoteAddr, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	envelope, err := aiq.DeserializeRequest(payload)
	if err != nil || envelope.Type != aiq.GetMessagesRequestType {
		log.Warnf("Invalid request type from %s", base64.StdEncoding.EncodeToString(sender.SignatureKey))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 2. Fetch undelivered messages
	recipientPubKey := base64.StdEncoding.EncodeToString(sender.SignatureKey)
	messages, ids, err := database.GetUndeliveredMessages(recipientPubKey)
	if err != nil {
		log.Errorf("Database error fetching messages for %s: %v", recipientPubKey, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Mark as delivered
	if err := database.MarkAsDelivered(recipientPubKey, ids); err != nil {
		log.Errorf("Failed to mark messages as delivered for %s: %v", recipientPubKey, err)
		// We still return the messages, the worst that can happen is duplicate delivery
	}

	// 4. Respond
	respEnv, _ := aiq.NewGetMessagesResponse(community.UUID, messages)
	respPayload, _ := respEnv.Serialize()
	respMsg, err := aiq_message.GenerateMessage(respPayload, brokerKey.SigningKey, []aiq_message.MessageContact{sender})
	if err != nil {
		log.Errorf("Failed to generate response for %s: %v", recipientPubKey, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Infof("Delivered %d messages to %s", len(messages), recipientPubKey)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respMsg)
}

func respondError(w http.ResponseWriter, message string, recipient aiq_message.MessageContact) {
	env, _ := aiq.NewErrorRequest(community.UUID, message)
	payload, _ := env.Serialize()
	resp, err := aiq_message.GenerateMessage(payload, brokerKey.SigningKey, []aiq_message.MessageContact{recipient})
	if err != nil {
		log.Errorf("Failed to generate AIQ error message: %v", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // AIQ level error, HTTP level OK
	w.Write(resp)
}

func respondSuccess(w http.ResponseWriter, status string, recipient aiq_message.MessageContact) {
	env, _ := aiq.NewPostMessageResponse(community.UUID, status)
	payload, _ := env.Serialize()
	resp, err := aiq_message.GenerateMessage(payload, brokerKey.SigningKey, []aiq_message.MessageContact{recipient})
	if err != nil {
		log.Errorf("Failed to generate AIQ success message: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}
