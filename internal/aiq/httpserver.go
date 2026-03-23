package aiq

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

// MaxRequestBodySize limits the size of incoming AIQ messages (e.g., 2MB)
const MaxRequestBodySize = 2 * 1024 * 1024

type AIQHTTPServer struct {
	listenURL      string
	listenAddr     string
	listenPath     string
	serverKeys     *aiq_message.PrivateKeySet
	mux            *http.ServeMux
	server         *http.Server
	correspondents []aiq_message.MessageContact
}

// CreateHTTPServer initialize a server instance
func CreateHTTPServer(URL string, keys *aiq_message.PrivateKeySet, contacts []aiq_message.MessageContact) (*AIQHTTPServer, error) {
	u, err := url.Parse(URL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %v", err)
	}

	addr := u.Host
	if !strings.Contains(addr, ":") {
		return nil, fmt.Errorf("owner endpoint does not specify a port: %s", addr)
	}

	if !(strings.HasPrefix(addr, "localhost:") || strings.HasPrefix(addr, "127.0.0.1:")) {
		if i := strings.LastIndex(addr, ":"); i != -1 {
			addr = addr[i:]
		}
	}

	mux := http.NewServeMux()

	// Initialize the underlying http.Server with timeouts
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	server := AIQHTTPServer{
		serverKeys:     keys,
		listenURL:      URL,
		listenAddr:     addr,
		listenPath:     u.Path,
		mux:            mux,
		server:         httpSrv,
		correspondents: contacts,
	}
	return &server, nil
}

func (svr *AIQHTTPServer) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	svr.mux.HandleFunc(pattern, handler)
}

// ReceiveMessage validates the request method, content-type, reads the body with size limits and try to verify and decrypt the message.
func (svr *AIQHTTPServer) ReceiveMessage(w http.ResponseWriter, r *http.Request) ([]byte, aiq_message.MessageContact, error) {
	// Check HTTP Method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return nil, aiq_message.MessageContact{}, fmt.Errorf("method not allowed: %v", r.Method)
	}

	// Check Content-Type is JSON
	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return nil, aiq_message.MessageContact{}, fmt.Errorf("unsupported media type: %s", contentType)
	}

	// Read the body with a LimitReader to prevent DoS
	bodyReader := io.LimitReader(r.Body, MaxRequestBodySize)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return nil, aiq_message.MessageContact{}, fmt.Errorf("failed to read body: %v", err)
	}
	defer r.Body.Close()

	// Basic validation
	if len(body) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return nil, aiq_message.MessageContact{}, fmt.Errorf("empty request body")
	}

	// Receive and decrypt AIQ message
	payload, sender, err := aiq_message.ReceiveMessage(body, svr.serverKeys.DecryptionKey, svr.correspondents)
	if err != nil {
		return nil, aiq_message.MessageContact{}, fmt.Errorf("failed to receive AIQ message: %w", err)
	}

	return payload, sender, nil
}

// Respond build and send an AIQ message answer
func (svr *AIQHTTPServer) Respond(w http.ResponseWriter, r *http.Request, recipientContact aiq_message.MessageContact, content string) error {

	// Encrypt response using server's signing key and client's public keys
	responseMsg, err := aiq_message.GenerateMessage([]byte(content), svr.serverKeys.SigningKey, []aiq_message.MessageContact{recipientContact})
	if err != nil {
		http.Error(w, "Failed to encrypt response", http.StatusInternalServerError)
		return fmt.Errorf("failed to encrypt response %v", err)
	}

	// Send encrypted response back
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseMsg)

	return nil
}

// ListenAndServe starts the server and implements graceful shutdown on OS signals.
func (svr *AIQHTTPServer) ListenAndServe() error {
	// Channel to listen for errors during startup
	serverErrors := make(chan error, 1)

	go func() {
		log.Printf("AIQ Server starting on %s%s", svr.listenAddr, svr.listenPath)
		serverErrors <- svr.server.ListenAndServe()
	}()

	// Channel to listen for interrupt signals (Ctrl+C, SIGTERM)
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return fmt.Errorf("server failed to start: %w", err)

	case sig := <-shutdown:
		log.Printf("Signal %v received, shutting down gracefully...", sig)

		// Create a deadline for the shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := svr.server.Shutdown(ctx); err != nil {
			svr.server.Close()
			return fmt.Errorf("could not stop server gracefully: %w", err)
		}
	}

	return nil
}
