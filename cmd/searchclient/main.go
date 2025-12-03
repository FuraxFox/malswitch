/*
 * Minimal client to a secure search server
 */
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/FuraxFox/malswitch/internal/message"
	"github.com/FuraxFox/malswitch/internal/search"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// --- Global Client Configuration ---
type model struct {
	stage         int
	cursor        int // For selection stage
	input         textinput.Model
	searchType    string
	loadingMsg    string
	resultMsg     string
	errorMsg      string
	communityUUID string
	ClientKeys    message.PrivateKeySet
	ServerContact message.MessageContact // Server's public key info
	ServerURL     string
}

var (

	// HTTP client
	httpClient = &http.Client{Timeout: 15 * time.Second}
)

// submitSearch builds the SearchRequest, transitions to loading, and sends the request.
func (m *model) submitSearch() (tea.Model, tea.Cmd) {
	inputValue := m.input.Value()
	if inputValue == "" {
		m.errorMsg = "Input cannot be empty."
		return m, nil
	}

	// Build the IOCPayload based on the selected type
	payload := search.IOCPayload{
		Type: m.searchType,
	}

	// In a real app, this logic would involve input validation (e.g., checking if IP is valid)
	switch m.searchType {
	case search.IOC_TYPE_IP_LIST, search.IOC_TYPE_HASH_LIST:
		// Split comma-separated string into a slice
		items := strings.Split(inputValue, ",")
		for i, item := range items {
			items[i] = strings.TrimSpace(item)
		}
		if m.searchType == search.IOC_TYPE_IP_LIST {
			payload.IPs = items
		} else {
			payload.Hashes = items
		}
	case search.IOC_TYPE_YARA_RULE, search.IOC_TYPE_TEXT:
		payload.Text = inputValue
	}

	// Wrap payload in SearchRequest
	request := search.SearchRequest{
		CommunityUUID: m.communityUUID,
		Content:       payload,
	}

	// Transition to loading state and start the network operation
	m.stage = stageLoading
	m.loadingMsg = fmt.Sprintf("Sending %s request to server...", m.searchType)
	m.errorMsg = ""
	m.resultMsg = ""
	m.input.Blur() // unfocus input field

	return m, m.sendRequestCmd(request)
}

func main() {
	log.SetFlags(log.Ltime) // Use original log settings

	// Parse Arguments (Original CLI structure)
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Printf("Usage: %s <client_priv_file> <server_pub_file> [server_url]\n", os.Args[0])
		os.Exit(1)
	}

	clientPrivFile := os.Args[1]
	serverPubKeyFile := os.Args[2]
	serverURL := "http://localhost:8080/decrypt"
	if len(os.Args) == 4 {
		serverURL = os.Args[3]
	}

	// This is a placeholder UUID.
	const communityUUID = "102a4868-74b9-41c3-b2de-694f02def520"

	// TUI Execution
	fmt.Println("Starting Secure Message Client TUI...")
	p := tea.NewProgram(initialModel(serverURL, communityUUID, clientPrivFile, serverPubKeyFile))
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}

}
