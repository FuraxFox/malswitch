/*
 * Functions and data for the Text User Interface (TUI)
 */
package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- TUI Constants and Styling ---

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

const MANAGE_COMMUNITY = "Manage Community"

////////////////////////////////////////////////////// Interface initialisation

func initialModel(serverURL string, uuid string, clientPrivFile string, serverPubKeyFile string, communityFile string, comm *aiq.Community) model {
	ti := textinput.New()
	ti.Placeholder = "IOCs or Rule..."
	ti.Focus()
	ti.CharLimit = 200
	ti.Width = 78

	const defaultListWidth = 60

	options := append([]list.Item{}, searchOptions...)
	if communityFile != "" {
		options = append(options, SearchOption(MANAGE_COMMUNITY))
	}

	l := list.New(options, searchOptionDelegate{}, defaultListWidth, listHeight)
	l.Title = "Select Search Type:"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = listTitleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle

	m := model{
		stage:             stageSelect,
		input:             ti,
		communityUUID:     uuid,
		ServerURL:         serverURL,
		lstSearchTypes:    l,
		community:         comm,
		communityFile:     communityFile,
		subscriptionQueue: []aiq_message.MessageContact{},
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

	case stageCommunity:
		s.WriteString(titleStyle.Render(" Community Management ") + "\n\n")
		s.WriteString(fmt.Sprintf("UID: %s\n", m.community.UUID))
		s.WriteString(fmt.Sprintf("Members: %d\n", len(m.community.Members)))
		s.WriteString("\nPending Subscriptions:\n")
		if len(m.subscriptionQueue) == 0 {
			s.WriteString("  (None)\n")
		} else {
			for i, sub := range m.subscriptionQueue {
				prefix := "  "
				if i == 0 {
					prefix = "> "
				}
				s.WriteString(fmt.Sprintf("%s%s (%s)\n",
					prefix,
					sub.Endpoint,
					base64.StdEncoding.EncodeToString(sub.SignatureKey[:8])))
			}
			s.WriteString("\n(Press 'a' to accept first, 'r' to reject first)\n")
		}
		s.WriteString("\n(Press Left Arrow to go back)\n")
	}

	// Display persistent info (like UUID)
	s.WriteString(fmt.Sprintf("\nCommunity: %s\n", m.communityUUID))

	return appStyle.Render(s.String())
}
