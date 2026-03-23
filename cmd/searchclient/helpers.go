/*
 * Support functions: networking and files
 */
package main

import (
	"fmt"
	"log"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

// initKeysFromFile loads keys from the provided file paths, simulating the original logic.
func (m *model) initKeysFromFile(clientPrivFile, serverPubKeyFile string) error {
	var err error

	// Load Client's Full Private Key Set (sender)
	privKeys, err := aiq_message.LoadPrivateKeys(clientPrivFile)
	if err != nil {
		return fmt.Errorf("error loading client private key from %s: %w", clientPrivFile, err)
	}
	m.ClientKeys = privKeys

	// Load Server's Public Keys (recipient)
	m.ServerContact, err = aiq_message.LoadContactFromFile(serverPubKeyFile)
	if err != nil {
		return fmt.Errorf("error loading server public key from %s: %w", serverPubKeyFile, err)
	}

	log.Printf("Client initialized with full key pair from: %s", clientPrivFile)
	log.Printf("Client configured to communicate with server public key from: %s", serverPubKeyFile)
	return nil
}
