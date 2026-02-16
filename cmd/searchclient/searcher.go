/*
 * Minimal client to a secure search server
 */
package main

import (
	"fmt"
	"strings"

	"github.com/FuraxFox/malswitch/internal/aiq"
	tea "github.com/charmbracelet/bubbletea"
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
