/*
 * Minimal client to a secure search server
 */
package main

import (
	"bytes"
	"crypto/ed25519"

	"flag"
	"fmt"
	"log"
	"os"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// --- Global Client Configuration ---
type model struct {
	lstSearchTypes list.Model
	input          textinput.Model
	height         int
	width          int

	stage int

	searchType string
	loadingMsg string
	resultMsg  string
	errorMsg   string

	communityUUID string
	ServerURL     string
	ClientKeys    aiq_message.PrivateKeySet
	ServerContact aiq_message.MessageContact // Server's public key info
	Client        *aiq.AIQHTTPClient

	// Community management
	community         *aiq.Community
	communityFile     string
	subscriptionQueue []aiq_message.MessageContact
}

const DefaultServerURL = "http://localhost:8080/com-manager"

func main() {
	log.SetFlags(log.Ltime)

	// Define flags
	// Usage: ./app -client-priv=path -server-pub=path [-url=url] [-community=path]
	clientPrivFile := flag.String("client-priv", "", "Path to the client private key file (Required)")
	serverPubKeyFile := flag.String("server-pub", "", "Path to the server public key file (Required)")
	communityFile := flag.String("community", "", "Path to the community JSON file")
	serverURL := flag.String("url", DefaultServerURL, "The URL that the manager listens on")

	// Custom Usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// Validation for required flags
	if *clientPrivFile == "" || *serverPubKeyFile == "" {
		fmt.Println("Error: client-priv and server-pub are required.")
		flag.Usage()
		os.Exit(1)
	}

	var comm *aiq.Community
	communityUUID := "UNDEFINED"

	// Logic for Community File
	if *communityFile != "" {
		c, err := aiq.LoadCommunity(*communityFile)
		if err != nil {
			log.Fatalf("Failed to load community file: %v", err)
		}
		comm = &c
		communityUUID = comm.UUID
	}

	// TUI Execution
	fmt.Println("Starting Secure Message Community Manager...")

	// Note: We dereference the pointers (*flagName) to get the string values
	m := initialModel(*serverURL, communityUUID, *clientPrivFile, *serverPubKeyFile, *communityFile, comm)
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Owner logic
	if comm != nil && m.ClientKeys.SigningKey != nil {
		log.Printf("Community loaded: %s", comm.UUID)
		myPubKey := m.ClientKeys.SigningKey.Public().(ed25519.PublicKey)
		if bytes.Equal(myPubKey, comm.Owner.SignatureKey) {
			log.Printf("We are the owner of the community, starting listener...")
			go startSubscriptionServer(p, m.ClientKeys, comm)
		} else {
			log.Printf("We are NOT the owner. My key: %x, Owner key: %x", myPubKey, comm.Owner.SignatureKey)
		}
	}

	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}
}
