package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/FuraxFox/malswitch/internal/message"
)

/*
 */
func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <contact_name>\n", os.Args[0])
		fmt.Println("Example: go run msg-keygen.go Alice")
		os.Exit(1)
	}

	contactName := os.Args[1]

	pubKeys, privKeys, err := message.GenerateKeySets()
	if err != nil {
		log.Fatalf("Error while generating keys: %v", err)
	}

	// 4. Write Public Keys to file
	pubFileName := fmt.Sprintf("%s.pub", contactName)
	writeJSONFile(pubFileName, pubKeys)

	// 5. Write Private Keys to file
	privFileName := fmt.Sprintf("%s.priv", contactName)
	writeJSONFile(privFileName, privKeys)

	fmt.Printf("\nKey generation successful for '%s'.\n", contactName)
	fmt.Printf("Public keys saved to: %s\n", pubFileName)
	fmt.Printf("Private keys saved to: %s\n", privFileName)
	fmt.Println("\n-- Public Key Contents (Encryption Key / Signature Key) --")
	fmt.Println(pubKeys.EncryptionKey)
	fmt.Println(pubKeys.SignatureKey)

	fmt.Println("\n-- Private Key Contents (Decryption Key / Signing Key) --")
	fmt.Println(privKeys.DecryptionKey)
	fmt.Println(privKeys.SigningKey)
}

// writeJSONFile serializes data to JSON and saves it to the specified file.
func writeJSONFile(filename string, data interface{}) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create file %s: %v", filename, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Failed to encode JSON to file %s: %v", filename, err)
	}
}
