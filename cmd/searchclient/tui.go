/*
 * Functions and data for the Text User Interface (TUI)
 */
package main

import (
	"fmt"

	"github.com/FuraxFox/malswitch/internal/aiq"
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

	case subscriptionMsg:
		m.subscriptionQueue = append(m.subscriptionQueue, *msg.member)
		return m, nil
	}

	switch m.stage {
	case stageSelect:
		return m.handleSelectStage(msg)
	case stageInput:
		return m.handleInputStage(msg)
	case stageCommunity:
		return m.handleCommunityStage(msg)
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
			return m.submitSearch()
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

///////////////////////////////////////////// Sending the request to the server

// Msg to handle the result of the asynchronous network operation
type sendResultMsg struct {
	err    error
	result string // Decrypted response from server
}

// Command to start the asynchronous network operation
func (m *model) sendRequestCmd(request aiq.RequestEnveloppe) tea.Cmd {
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
