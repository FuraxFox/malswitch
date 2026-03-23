package aiq

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

type AIQHTTPClient struct {
	httpClient *http.Client
	targetURL  string
	clientKeys *aiq_message.PrivateKeySet
}

func CreateHTTPClient(clientK *aiq_message.PrivateKeySet, serverURL string) *AIQHTTPClient {
	client := AIQHTTPClient{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		targetURL:  serverURL,
		clientKeys: clientK,
	}
	return &client
}

// senddMessage encrypts the clear text (the signed JSON payload) to a specific recipient and post it
func (cli *AIQHTTPClient) SendMessage(serverContact *aiq_message.MessageContact, clearText string) (string, error) {
	return cli.SendMessageTo([]aiq_message.MessageContact{*serverContact}, clearText)
}

// senddMessage encrypts the clear text (the signed JSON payload) to a recipient list and post it
func (cli *AIQHTTPClient) SendMessageTo(correspondents []aiq_message.MessageContact, clearText string) (string, error) {

	jsonPayload, err := aiq_message.GenerateMessage([]byte(clearText), cli.clientKeys.SigningKey, correspondents)
	if err != nil {
		return "", fmt.Errorf("message generation failed: %w", err)
	}

	// Sending...
	resp, err := cli.httpClient.Post(cli.targetURL, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read server response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned error status %d: %s", resp.StatusCode, string(responseBody))
	}

	// Decode, verify and decrypt response (since only the server is accepted we do not check the sender)
	ack, _, err := aiq_message.ReceiveMessage(responseBody, cli.clientKeys.DecryptionKey, correspondents)
	if err != nil {
		return "", fmt.Errorf("error on acknowleded: %v", err)
	}

	// Success is implied by the lack of error from DecryptMessage and the OK status.
	log.Printf("Acknowledge received: %v", ack)
	return string(ack), nil
}
