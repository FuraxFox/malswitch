package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

func doKeyGen(contactName string) error {
	// Generate all keys using the library function
	pubKeys, privKeys, err := aiq_message.GenerateKeySets()
	if err != nil {
		log.Fatalf("Fatal key generation error: %v", err)
	}

	// Prepare Private Keys structure for JSON output (Base64 encoded)
	privKeysJSON := aiq_message.PrivateKeySetJSON{
		DecryptionKey: base64.StdEncoding.EncodeToString(privKeys.DecryptionKey),
		SigningKey:    base64.StdEncoding.EncodeToString(privKeys.SigningKey),
	}

	// Write Public Keys to file (already in correct format)
	pubFileName := fmt.Sprintf("%s.pub", contactName)
	writeJSONFile(pubFileName, pubKeys)

	// 4. Write Private Keys to file
	privFileName := fmt.Sprintf("%s.priv", contactName)
	writeJSONFile(privFileName, privKeysJSON)

	fmt.Printf("\nKey generation successful for '%s'.\n", contactName)
	fmt.Printf("Public keys saved to: %s\n", pubFileName)
	fmt.Printf("Private keys saved to: %s\n", privFileName)
	fmt.Println("\n-- Public Key Contents (Encryption Key / Signature Key) --")
	fmt.Println(pubKeys.EncryptionKey)
	fmt.Println(pubKeys.SignatureKey)

	fmt.Println("\n-- Private Key Contents (Decryption Key / Signing Key) --")
	fmt.Println(privKeysJSON.DecryptionKey)
	fmt.Println(privKeysJSON.SigningKey)
	return nil
}

func doContactGen(contactName string, contactEndpoint string) error {
	// TODO
	// Generate all keys using the library function
	pubKeys, privKeys, err := aiq_message.GenerateKeySets()
	if err != nil {
		log.Fatalf("Fatal key generation error: %v", err)
	}

	// Prepare Private Keys structure for JSON output (Base64 encoded)
	privKeysJSON := aiq_message.PrivateKeySetJSON{
		DecryptionKey: base64.StdEncoding.EncodeToString(privKeys.DecryptionKey),
		SigningKey:    base64.StdEncoding.EncodeToString(privKeys.SigningKey),
	}

	contact := aiq_message.MessageContactJSON{
		Endpoint:      contactEndpoint,
		EncryptionKey: pubKeys.EncryptionKey,
		SignatureKey:  pubKeys.SignatureKey,
	}

	// Contact to file (already in correct format)
	contactFileName := fmt.Sprintf("%s.ctc", contactName)
	writeJSONFile(contactFileName, contact)

	// Write Private Keys to file
	privFileName := fmt.Sprintf("%s.priv", contactName)
	writeJSONFile(privFileName, privKeysJSON)

	fmt.Printf("\nKey generation successful for '%s'.\n", contactName)
	fmt.Printf("Contact saved to: %s\n", contactFileName)
	fmt.Printf("Private keys saved to: %s\n", privFileName)
	fmt.Println("\n-- Public Key Contents (Encryption Key / Signature Key) --")
	fmt.Println(pubKeys.EncryptionKey)
	fmt.Println(pubKeys.SignatureKey)

	fmt.Println("\n-- Private Key Contents (Decryption Key / Signing Key) --")
	fmt.Println(privKeysJSON.DecryptionKey)
	fmt.Println(privKeysJSON.SigningKey)
	return nil
}
