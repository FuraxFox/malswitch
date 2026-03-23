/*
 * Minimal client to a secure search server
 */
package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/FuraxFox/malswitch/internal/aiq"
	"github.com/FuraxFox/malswitch/internal/aiq_message"
	tea "github.com/charmbracelet/bubbletea"
)

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
