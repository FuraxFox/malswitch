/*
 * Minimal client to a secure search server
 */
package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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

	// Community management
	community         *aiq.Community
	communityFile     string
	subscriptionQueue []aiq_message.MessageContact
}

var (

	// HTTP client
	httpClient = &http.Client{Timeout: 15 * time.Second}
)

type subscriptionMsg struct {
	member *aiq_message.MessageContact
}

func startSubscriptionServer(p *tea.Program, keys aiq_message.PrivateKeySet, comm *aiq.Community) {
	// Extract port from owner endpoint
	u, err := url.Parse(comm.Owner.Endpoint)
	if err != nil {
		log.Printf("Invalid owner endpoint: %v", err)
		return
	}
	addr := u.Host
	if !strings.Contains(addr, ":") {
		// Use default port if not specified, but usually we need a port to listen
		log.Printf("Owner endpoint does not specify a port: %s", addr)
		return
	}
	// Extract just the port part if it's localhost or an IP, but ListenAndServe takes host:port
	// If it's something like "http://example.com:9000/sub", u.Host is "example.com:9000"
	// We might want to listen on all interfaces if it's not localhost
	listenAddr := addr
	if strings.HasPrefix(addr, "localhost:") || strings.HasPrefix(addr, "127.0.0.1:") {
		// keep as is
	} else {
		// Replace hostname with empty to listen on all interfaces
		if i := strings.LastIndex(addr, ":"); i != -1 {
			listenAddr = addr[i:]
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusInternalServerError)
			return
		}

		member, ack, err := aiq.HandleCommunitySubscribe(body, keys.DecryptionKey, keys.SigningKey, comm.Members)
		if err != nil {
			log.Printf("Subscription failed: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		p.Send(subscriptionMsg{member: member})
		w.Header().Set("Content-Type", "application/json")
		w.Write(ack)
	})

	log.Printf("Starting subscription server on %s%s", listenAddr, u.Path)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Printf("Subscription server failed: %v", err)
	}
}

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
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <client_priv_file> <server_pub_file> [server_url] [community_file]\n", os.Args[0])
		os.Exit(1)
	}

	clientPrivFile := os.Args[1]
	serverPubKeyFile := os.Args[2]
	serverURL := "http://localhost:8080/decrypt"
	if len(os.Args) >= 4 {
		serverURL = os.Args[3]
	}

	var communityFile string
	var comm *aiq.Community
	communityUUID := "102a4868-74b9-41c3-b2de-694f02def520"

	if len(os.Args) >= 5 {
		communityFile = os.Args[4]
		c, err := aiq.LoadCommunity(communityFile)
		if err != nil {
			log.Fatalf("Failed to load community file: %v", err)
		}
		comm = &c
		communityUUID = comm.UID
	}

	// TUI Execution
	fmt.Println("Starting Secure Message Client TUI...")
	m := initialModel(serverURL, communityUUID, clientPrivFile, serverPubKeyFile, communityFile, comm)
	p := tea.NewProgram(m, tea.WithAltScreen())

	// If we are the owner, start the subscription listener
	if comm != nil && m.ClientKeys.SigningKey != nil {
		log.Printf("Community loaded: %s", comm.UID)
		// Verify if we are the owner
		myPubKey := m.ClientKeys.SigningKey.Public().(ed25519.PublicKey)
		if bytes.Equal(myPubKey, comm.Owner.SignatureKey) {
			log.Printf("We are the owner of the community, starting listener...")
			go startSubscriptionServer(p, m.ClientKeys, comm)
		} else {
			log.Printf("We are NOT the owner of the community. My key: %x, Owner key: %x", myPubKey, comm.Owner.SignatureKey)
		}
	}

	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}

}
