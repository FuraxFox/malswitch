/*
 * Minimal client to a secure search server
 */
package main

import (
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

const DefaultServerURL = "http://localhost:8080/decrypt"

func main() {
	log.SetFlags(log.Ltime) // Use original log settings

	// Parse Arguments (Original CLI structure)
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <client_priv_file> <server_pub_file> [server_url] [community_file]\n", os.Args[0])
		os.Exit(1)
	}

	clientPrivFile := os.Args[1]
	serverPubKeyFile := os.Args[2]
	serverURL := DefaultServerURL
	if len(os.Args) >= 4 {
		serverURL = os.Args[3]
	}

	var communityFile string
	var comm *aiq.Community
	communityUUID := "UNDEFINED"

	if len(os.Args) >= 5 {
		communityFile = os.Args[4]
		c, err := aiq.LoadCommunity(communityFile)
		if err != nil {
			log.Fatalf("Failed to load community file: %v", err)
		}
		comm = &c
		communityUUID = comm.UUID
	}

	// TUI Execution
	fmt.Println("Starting Secure Message Client TUI...")
	m := initialModel(serverURL, communityUUID, clientPrivFile, serverPubKeyFile, communityFile, comm)
	p := tea.NewProgram(m, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}

}
