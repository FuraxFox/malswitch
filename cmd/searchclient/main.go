package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/FuraxFox/malswitch/internal/message"
	"github.com/FuraxFox/malswitch/internal/search"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Global Client Configuration ---

var (
	// Client's keys (populated by initKeysFromMocks)
	ClientSigningKey    []byte                 // Placeholder for ed25519.PrivateKey
	ClientDecryptionKey []byte                 // Placeholder for X25519 Decryption Key
	ServerContact       message.MessageContact // Server's public key info
	ServerURL           string

	// HTTP client
	httpClient = &http.Client{Timeout: 15 * time.Second}
)

// --- TUI Constants and Styling ---

const (
	stageSelect = iota
	stageInput
	stageLoading
	stageResult
)

var (
	appStyle = lipgloss.NewStyle().Padding(1, 2)

	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#25A0F5"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000"))

	promptStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#EBCB8B"))

	selectedStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(0, 1)
)

// Search options available to the user
var searchOptions = []string{
	search.IOC_TYPE_IP_LIST,
	search.IOC_TYPE_HASH_LIST,
	search.IOC_TYPE_YARA_RULE,
	search.IOC_TYPE_TEXT,
}

// Map from option type to the prompt text
var searchPrompts = map[string]string{
	search.IOC_TYPE_IP_LIST:   "Enter IP addresses (comma-separated):",
	search.IOC_TYPE_HASH_LIST: "Enter Hashes (MD5/SHA, comma-separated):",
	search.IOC_TYPE_YARA_RULE: "Enter Yara Rule:",
	search.IOC_TYPE_TEXT:      "Enter Full Text Search String:",
}

// --- TUI Model and Messages ---

type model struct {
	stage         int
	cursor        int // For selection stage
	input         textinput.Model
	searchType    string
	loadingMsg    string
	resultMsg     string
	errorMsg      string
	communityUUID string
}

func initialModel(uuid string) model {
	ti := textinput.New()
	ti.Placeholder = "IOCs or Rule..."
	ti.Focus()
	ti.CharLimit = 200
	ti.Width = 80

	return model{
		stage:         stageSelect,
		input:         ti,
		communityUUID: uuid,
	}
}

// initKeysFromFile loads keys from the provided file paths, simulating the original logic.
func initKeysFromFile(clientPrivFile, serverPubKeyFile string) error {
	var err error

	// 1. Load Client's Full Private Key Set (S2)
	privKeys, err := message.LoadPrivateKeys(clientPrivFile)
	if err != nil {
		return fmt.Errorf("error loading client private key from %s: %w", clientPrivFile, err)
	}
	ClientSigningKey = privKeys.SigningKey
	ClientDecryptionKey = privKeys.DecryptionKey

	// 2. Load Server's Public Keys (R1)
	ServerContact, err = message.LoadContactFromFile(serverPubKeyFile)
	if err != nil {
		return fmt.Errorf("error loading server public key from %s: %w", serverPubKeyFile, err)
	}

	log.Printf("Client S2 initialized with full key pair from: %s", clientPrivFile)
	log.Printf("Client S2 configured to communicate with server R1 public key from: %s", serverPubKeyFile)
	return nil
}

// Msg to handle the result of the asynchronous network operation
type sendResultMsg struct {
	err    error
	result string // Decrypted response from server
}

// Command to start the asynchronous network operation
func sendRequestCmd(request search.SearchRequest) tea.Cmd {
	return func() tea.Msg {

		data, err := request.Serialize()
		if err != nil {
			return sendResultMsg{err: fmt.Errorf("could not build signed message: %w", err)}
		}

		// Encrypt the *signed* JSON payload as clearText
		err = sendEncryptedMessage(ServerURL, string(data))

		if err != nil {
			return sendResultMsg{err: err}
		}

		// Mock success acknowledgement (The server would usually send an ACK)
		return sendResultMsg{result: "Request sent and acknowledged by server."}
	}
}

// --- Bubble Tea Core Functions ---

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "esc":
			// Go back to selection stage if not already there or loading
			if m.stage == stageInput || m.stage == stageResult {
				m.stage = stageSelect
				m.errorMsg = ""
				m.resultMsg = ""
				m.input.SetValue("")
				m.input.Blur()
			}
			return m, nil
		}

		switch m.stage {
		case stageSelect:
			return m.handleSelectStage(msg)
		case stageInput:
			return m.handleInputStage(msg)
		}

	case sendResultMsg:
		m.stage = stageResult
		if msg.err != nil {
			m.errorMsg = msg.err.Error()
			m.resultMsg = ""
		} else {
			m.resultMsg = msg.result
			m.errorMsg = ""
		}
		return m, nil

	case tea.WindowSizeMsg:
		// Optional: Handle window resizing
	}

	// Forward input messages to the text input model
	if m.stage == stageInput {
		m.input, cmd = m.input.Update(msg)
	}

	return m, cmd
}

func (m *model) handleSelectStage(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.cursor = (m.cursor - 1 + len(searchOptions)) % len(searchOptions)
	case "down", "j":
		m.cursor = (m.cursor + 1) % len(searchOptions)
	case "enter":
		m.searchType = searchOptions[m.cursor]
		m.input.Placeholder = searchPrompts[m.searchType]
		m.input.Focus()
		m.stage = stageInput
	}
	return m, nil
}

func (m *model) handleInputStage(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		// Build and send the request
		return m.submitSearch()
	}

	// Pass all other key events to the text input for processing
	m.input, _ = m.input.Update(msg)
	return m, nil
}

// submitSearch builds the SearchRequest, transitions to loading, and sends the request.
func (m *model) submitSearch() (tea.Model, tea.Cmd) {
	inputValue := m.input.Value()
	if inputValue == "" {
		m.errorMsg = "Input cannot be empty."
		return m, nil
	}

	// 1. Build the IOCPayload based on the selected type
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

	// 2. Wrap payload in SearchRequest
	request := search.SearchRequest{
		CommunityUUID: m.communityUUID,
		Content:       payload,
	}

	// 3. Transition to loading state and start the network operation
	m.stage = stageLoading
	m.loadingMsg = fmt.Sprintf("Sending %s request to server...", m.searchType)
	m.errorMsg = ""
	m.resultMsg = ""
	m.input.Blur() // unfocus input field

	return m, sendRequestCmd(request)
}

func (m model) View() string {
	s := strings.Builder{}

	s.WriteString(titleStyle.Render(" Secure IOC Client ") + "\n\n")

	switch m.stage {
	case stageSelect:
		s.WriteString(promptStyle.Render("Select Search Type:") + "\n")
		for i, choice := range searchOptions {
			cursor := "  "
			if m.cursor == i {
				cursor = selectedStyle.Render(">")
				s.WriteString(fmt.Sprintf("%s %s\n", cursor, choice))
			} else {
				s.WriteString(fmt.Sprintf("%s %s\n", cursor, choice))
			}
		}
		s.WriteString("\n(Press Enter to confirm, q to quit)\n")

	case stageInput:
		s.WriteString(promptStyle.Render(searchPrompts[m.searchType]) + "\n")
		s.WriteString(m.input.View() + "\n\n")
		s.WriteString("(Press Enter to send, Esc to go back, q to quit)\n")

	case stageLoading:
		s.WriteString(statusStyle.Render("...Working...") + "\n")
		s.WriteString(m.loadingMsg + "\n")

	case stageResult:
		if m.errorMsg != "" {
			s.WriteString(errorStyle.Render("ERROR: ") + m.errorMsg + "\n\n")
		} else {
			s.WriteString(statusStyle.Render("SUCCESS:") + "\n")
			s.WriteString(m.resultMsg + "\n\n")
		}
		s.WriteString("(Press Esc to start a new search, q to quit)\n")
	}

	// Display persistent info (like UUID)
	s.WriteString(fmt.Sprintf("\nCommunity: %s\n", m.communityUUID))

	return appStyle.Render(s.String())
}

// sendEncryptedMessage encrypts the clear text (the signed JSON payload), posts it, and decrypts the response.
// The result is handled asynchronously by the TUI.
func sendEncryptedMessage(serverURL string, clearText string) error {
	// 1. Encrypt the outgoing message
	encryptedMsg, err := message.EncryptMessage(
		[]byte(clearText),
		ClientSigningKey,
		[]message.MessageContact{ServerContact})
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// 2. Marshal to JSON and send
	jsonPayload, err := json.Marshal(encryptedMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Simulate sending...
	resp, err := httpClient.Post(serverURL, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// 3. Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read server response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error status %d: %s", resp.StatusCode, string(responseBody))
	}

	// 4. Unmarshal the EncryptedMessage response
	var encryptedResponse message.EncryptedMessage
	if err := json.Unmarshal(responseBody, &encryptedResponse); err != nil {
		return fmt.Errorf("failed to parse encrypted response JSON: %w", err)
	}

	// 5. Decrypt and verify the response
	_, err = message.DecryptMessage(encryptedResponse, ClientDecryptionKey, []message.MessageContact{ServerContact})
	if err != nil {
		return fmt.Errorf("failed to decrypt or verify server response: %w", err)
	}

	// Success is implied by the lack of error from DecryptMessage and the OK status.
	return nil
}

func main() {
	log.SetFlags(log.Ltime) // Use original log settings

	// 1. Parse Arguments (Original CLI structure)
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Printf("Usage: %s <client_priv_file> <server_pub_file> [server_url]\n", os.Args[0])
		os.Exit(1)
	}

	clientPrivFile := os.Args[1]
	serverPubKeyFile := os.Args[2]
	ServerURL = "http://localhost:8080/decrypt"
	if len(os.Args) == 4 {
		ServerURL = os.Args[3]
	}

	// 2. Load Keys
	if err := initKeysFromFile(clientPrivFile, serverPubKeyFile); err != nil {
		log.Fatalf("Fatal initialization error: %v", err)
	}

	// This is a placeholder UUID.
	const communityUUID = "102a4868-74b9-41c3-b2de-694f02def520"

	// 3. TUI Execution
	fmt.Println("Starting Secure Message Client TUI...")
	p := tea.NewProgram(initialModel(communityUUID))
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}

}
