package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/FuraxFox/malswitch/internal/aiq_message"
)

// PrivateKeySetJSON defines the structure for the JSON file containing private keys.
// NOTE: These keys MUST be Base64 encoded strings for file output.
type PrivateKeySetJSON struct {
	DecryptionKey string `json:"X25519_Priv"`  // X25519 Private Key (Base64)
	SigningKey    string `json:"Ed25519_Priv"` // Ed25519 Private Key (Base64)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <contact_name>\n", os.Args[0])
		fmt.Println("Example: go run msg-keygen.go Alice")
		os.Exit(1)
	}

	contactName := os.Args[1]

	// 1. Generate all keys using the library function
	pubKeys, privKeys, err := aiq_message.GenerateKeySets()
	if err != nil {
		log.Fatalf("Fatal key generation error: %v", err)
	}

	// 2. Prepare Private Keys structure for JSON output (Base64 encoded)
	privKeysJSON := PrivateKeySetJSON{
		DecryptionKey: base64.StdEncoding.EncodeToString(privKeys.DecryptionKey),
		SigningKey:    base64.StdEncoding.EncodeToString(privKeys.SigningKey),
	}

	// 3. Write Public Keys to file (already in correct format)
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
		log.Fatalf("Failed to encode JSON to file %s: %v", err)
	}
}
