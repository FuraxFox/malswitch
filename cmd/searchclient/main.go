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

	// build SearchRequest
	request := aiq.RequestEnveloppe{
		CommunityUUID: m.communityUUID,
	}
	request.SubmitRequest.Type = m.searchType

	// In a real app, this logic would involve input validation (e.g., checking if IP is valid)
	switch m.searchType {
	case aiq.IOC_TYPE_IP_LIST:
		// Split comma-separated string into a slice
		items := strings.Split(inputValue, ",")
		for i, item := range items {
			items[i] = strings.TrimSpace(item)
		}
		if m.searchType == aiq.IOC_TYPE_IP_LIST {

			request.SubmitRequest.IPs = items
		}
	case aiq.IOC_TYPE_HASH_LIST:
		// Split comma-separated string into a slice
		items := strings.Split(inputValue, ",")
		for i, item := range items {
			items[i] = strings.TrimSpace(item)
		}
		for _, hval := range items {
			htype := "undefined"
			switch len(hval) {
			case 40:
				htype = "md5"
			case 64:
				htype = "sha1"
			case 128:
				htype = "sha256"
			default:
				htype = "unknown"
			}
			request.SubmitRequest.Hashes = append(request.SubmitRequest.Hashes, aiq.HashEntry{Type: htype, Value: hval})
		}
	case aiq.IOC_TYPE_YARA_RULE, aiq.IOC_TYPE_TEXT:
		request.SubmitRequest.Text = inputValue
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
	p := tea.NewProgram(
		initialModel(serverURL, communityUUID, clientPrivFile, serverPubKeyFile),
		tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}

}
