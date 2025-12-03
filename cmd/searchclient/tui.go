/*
 * Functions and data for the Text User Interface (TUI)
 */
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/FuraxFox/malswitch/internal/search"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

func initialModel(serverURL string, uuid string, clientPrivFile string, serverPubKeyFile string) model {
	ti := textinput.New()
	ti.Placeholder = "IOCs or Rule..."
	ti.Focus()
	ti.CharLimit = 200
	ti.Width = 80

	m := model{
		stage:         stageSelect,
		input:         ti,
		communityUUID: uuid,
		ServerURL:     serverURL,
	}

	// Load the specified key files
	if err := m.initKeysFromFile(clientPrivFile, serverPubKeyFile); err != nil {
		log.Fatalf("Fatal initialization error: %v", err)
	}

	return m
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
			s.WriteString(statusStyle.Render("SUCCESS: ") + m.resultMsg + "\n\n")
		}
		s.WriteString("(Press Esc to start a new search, q to quit)\n")
	}

	// Display persistent info (like UUID)
	s.WriteString(fmt.Sprintf("\nCommunity: %s\n", m.communityUUID))

	return appStyle.Render(s.String())
}
