/*
 * Functions and data for the Text User Interface (TUI)
 */
package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// --- TUI Constants and Styling ---

const (
	stageSelect = iota
	stageInput
	stageLoading
	stageResult
	stageCommunity
)

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
			if m.stage == stageInput || m.stage == stageResult || m.stage == stageCommunity {
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

	return m, cmd
}

func (m *model) handleSelectStage(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:

		switch keypress := msg.String(); keypress {
		case "enter":
			sel := m.lstSearchTypes.SelectedItem().(SearchOption)
			if string(sel) == MANAGE_COMMUNITY {
				m.stage = stageCommunity
				return m, nil
			}
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
			// something
		}
	}
	var cmd tea.Cmd
	// Pass all other key events to the text input for processing
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *model) handleCommunityStage(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "a":
			if len(m.subscriptionQueue) > 0 {
				member := m.subscriptionQueue[0]
				m.subscriptionQueue = m.subscriptionQueue[1:]

				// Update community
				m.community.AddContact(member)
				if err := m.community.Sign(m.ClientKeys); err != nil {
					m.errorMsg = "Signing failed: " + err.Error()
					m.stage = stageResult
					return m, nil
				}
				if err := m.community.Save(m.communityFile); err != nil {
					m.errorMsg = "Saving failed: " + err.Error()
					m.stage = stageResult
					return m, nil
				}

				m.stage = stageLoading
				m.loadingMsg = fmt.Sprintf("Sending community update to %s...", member.Endpoint)
				return m, m.sendCommunityUpdateCmd(member)
			}
		case "r":
			if len(m.subscriptionQueue) > 0 {
				m.subscriptionQueue = m.subscriptionQueue[1:]
			}
		}
	}
	return m, nil
}
