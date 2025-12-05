/*
 * Functions and data for the Text User Interface (TUI)
 */
package main

import (
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/charmbracelet/bubbles/list"
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
	appStyle          = lipgloss.NewStyle().Padding(1, 2).BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#FFFFFF"))
	titleStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#7D56F4")).Padding(0, 1)
	listTitleStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#25A0F5")).Padding(0, 1)
	statusStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#25A0F5"))
	errorStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
	promptStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#EBCB8B"))
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	itemStyle         = lipgloss.NewStyle().PaddingLeft(4)
	paginationStyle   = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	helpStyle         = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)
	//selectedItemStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#7D56F4")).Padding(0, 1)
)

/////////////////////////////////////////////////////// Search type list widget

type SearchOption string

func (i SearchOption) FilterValue() string { return "" }

const listHeight = 12

// Map from option type to the prompt text
var searchPrompts = map[string]string{
	aiq.IOC_TYPE_IP_LIST:   "Enter IP addresses (comma-separated):",
	aiq.IOC_TYPE_HASH_LIST: "Enter Hashes (MD5/SHA, comma-separated):",
	aiq.IOC_TYPE_YARA_RULE: "Enter Yara Rule:",
	aiq.IOC_TYPE_TEXT:      "Enter Full Text Search String:",
}

// Search options available to the user
var searchOptions = []list.Item{
	SearchOption(aiq.IOC_TYPE_IP_LIST),
	SearchOption(aiq.IOC_TYPE_HASH_LIST),
	SearchOption(aiq.IOC_TYPE_YARA_RULE),
	SearchOption(aiq.IOC_TYPE_TEXT),
}

type searchOptionDelegate struct{}

func (d searchOptionDelegate) Height() int                             { return 1 }
func (d searchOptionDelegate) Spacing() int                            { return 0 }
func (d searchOptionDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d searchOptionDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	opt, ok := listItem.(SearchOption)
	if !ok {
		return
	}
	str := fmt.Sprintf("%d. %s", index+1, opt)
	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("> " + strings.Join(s, " "))
		}
	}
	fmt.Fprint(w, fn(str))
}

////////////////////////////////////////////////////// Interface initialisation

func initialModel(serverURL string, uuid string, clientPrivFile string, serverPubKeyFile string) model {
	ti := textinput.New()
	ti.Placeholder = "IOCs or Rule..."
	ti.Focus()
	ti.CharLimit = 200
	ti.Width = 78

	const defaultListWidth = 20

	l := list.New(searchOptions, searchOptionDelegate{}, defaultListWidth, listHeight)
	l.Title = "Select Search Type:"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = listTitleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	m := model{
		stage:          stageSelect,
		input:          ti,
		communityUUID:  uuid,
		ServerURL:      serverURL,
		lstSearchTypes: l,
	}

	// Load the specified key files
	if err := m.initKeysFromFile(clientPrivFile, serverPubKeyFile); err != nil {
		log.Fatalf("Fatal initialization error: %v", err)
	}

	return m
}

func (m model) Init() tea.Cmd {
	return nil
}

// /////////////////////////////////////////////////////// Message loop handling
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {

	// the view size was update
	case tea.WindowSizeMsg:
		// Optional: Handle window resizing
		m.height = msg.Height
		m.width = msg.Width
		m.input.Width = m.width - 2
		m.lstSearchTypes.SetWidth(m.width - 2)

	// A key was pressed
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyLeft:
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
	}

	switch m.stage {
	case stageSelect:
		return m.handleSelectStage(msg)
	case stageInput:
		return m.handleInputStage(msg)
	}
	// Forward input messages to the text input model
	switch m.stage {
	case stageInput:

	case stageSelect:

	}

	return m, cmd
}

func (m *model) handleSelectStage(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:

		switch keypress := msg.String(); keypress {
		case "enter":
			sel := m.lstSearchTypes.SelectedItem().(SearchOption)
			m.searchType = string(sel)

			m.input.Placeholder = searchPrompts[m.searchType]
			m.input.Focus()
			m.stage = stageInput

		}
	}

	var cmd tea.Cmd
	m.lstSearchTypes, cmd = m.lstSearchTypes.Update(msg)

	return m, cmd
}

func (m *model) handleInputStage(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "enter":
			// Build and send the request
			return m.submitSearch()
		}
	}
	var cmd tea.Cmd
	// Pass all other key events to the text input for processing
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

//////////////////////////////////////////////////////////// Update the display

func (m model) View() string {
	s := strings.Builder{}

	s.WriteString(titleStyle.Render(" Search Client ") + "\n\n")

	switch m.stage {
	case stageSelect:
		s.WriteString(m.lstSearchTypes.View())
		s.WriteString("\n(Press Enter to confirm, q to quit)\n")

	case stageInput:
		s.WriteString(promptStyle.Render(searchPrompts[m.searchType]) + "\n")
		s.WriteString(m.input.View() + "\n\n")
		s.WriteString("(Press Enter to send, Left arrow to go back, q to quit)\n")

	case stageLoading:
		s.WriteString(statusStyle.Render("...Working...") + "\n")
		s.WriteString(m.loadingMsg + "\n")

	case stageResult:
		if m.errorMsg != "" {
			s.WriteString(errorStyle.Render("ERROR: ") + m.errorMsg + "\n\n")
		} else {
			s.WriteString(statusStyle.Render("SUCCESS: ") + m.resultMsg + "\n\n")
		}
		s.WriteString("(Press Left Arrow to start a new search, q to quit)\n")
	}

	// Display persistent info (like UUID)
	s.WriteString(fmt.Sprintf("\nCommunity: %s\n", m.communityUUID))

	return appStyle.Render(s.String())
}

///////////////////////////////////////////// Sending the request to the server

// Msg to handle the result of the asynchronous network operation
type sendResultMsg struct {
	err    error
	result string // Decrypted response from server
}

// Command to start the asynchronous network operation
func (m *model) sendRequestCmd(request aiq.SearchRequest) tea.Cmd {
	return func() tea.Msg {

		data, err := request.Serialize()
		if err != nil {
			return sendResultMsg{err: fmt.Errorf("could not build signed message: %w", err)}
		}

		// Encrypt the  JSON payload as clearText
		ack, err := sendEncryptedMessage(m.ServerURL, &m.ClientKeys, &m.ServerContact, string(data))
		if err != nil {
			return sendResultMsg{err: err}
		}

		// Mock success acknowledgement (The server would usually send an ACK)
		return sendResultMsg{result: ack}
	}
}
