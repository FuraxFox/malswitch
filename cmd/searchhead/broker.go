package main

import (
	"bytes"
	"encoding/base64"
	"time"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"

	"encoding/json"
	"log"
	"net/http"
)

func pollBroker(brokerURL string, privKeys aiq_message.PrivateKeySet, interval time.Duration) {
	ticker := time.NewTicker(interval)
	client := aiq.CreateHTTPClient(&privKeys, brokerURL+"/deliver-message")

	for range ticker.C {
		log.Printf("Polling broker at %s...", brokerURL)

		// Create GetMessagesRequest
		req, err := aiq.NewGetMessagesRequest(communityUUID)
		if err != nil {
			log.Printf("Failed to create GetMessagesRequest: %v", err)
			continue
		}

		payload, _ := req.Serialize()

		// Send to broker
		ack, err := client.SendMessage(brokerContact, string(payload))
		if err != nil {
			log.Printf("Failed to poll broker: %v", err)
			continue
		}

		// Deserialize response
		respEnv, err := aiq.DeserializeRequest([]byte(ack))
		if err != nil {
			log.Printf("Failed to deserialize broker response: %v", err)
			continue
		}

		if respEnv.GetMessagesResp == nil {
			continue
		}

		// Process messages
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
