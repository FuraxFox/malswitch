package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

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

func doCommunityCreate(ownerPrivKey string, communityFile string) error {
	// TODO
	return nil
}

func doCommunityAppend(ownerPrivKey string, communityFile string, memberFile string) error {
	// TODO
	return nil
}

func doCommunityRemove(ownerPrivKey string, communityFile string, memberFile string) error {
	// TODO
	return nil
}

func usage(commandname string) {
	fmt.Println("Usage:")
	fmt.Printf("   %s keygen  <contact_name>\n", commandname)
	fmt.Printf("   %s contgen <contact_name> <contact endpoint>\n", commandname)
	fmt.Printf("   %s comcrea <owner private key file> <community file>\n", commandname)
	fmt.Printf("   %s comadd  <owner private key file> <community file> <member_signature_pubkey_file> <member_encryption_pubkey_file> <member endpoint>\n", commandname)
	fmt.Printf("   %s comdel  <owner private key file> <community file> <member_signature_pubkey_file> <member_encryption_pubkey_file>\n", commandname)
	fmt.Println("Example: ")
	fmt.Printf("  %s keygen Alice  \n", commandname)
	fmt.Printf("  %s contcrea Alice 'https://:8888' \n", commandname)
	fmt.Printf("  %s comcrea owner_key.priv mycommunity.cmy \n", commandname)
	fmt.Printf("  %s comadd  owner_key.priv  mycommunity.cmy bob.ctc \n", commandname)
	fmt.Printf("  %s comdel  owner_key.priv  mycommunity.cmy bob.ctc \n", commandname)
}

func main() {
	if len(os.Args) < 2 {
		commandname := os.Args[0]
		usage(commandname)
		os.Exit(1)
	}

	action := os.Args[1]

	switch action {
	case "keygen":
		contactName := os.Args[2]
		err := doKeyGen(contactName)
		if err != nil {
			log.Fatalf("Error while generating key for '%s' : %v", contactName, err)
		}
	case "contcrea":
		contactName := os.Args[2]
		contactEndpoint := os.Args[3]
		err := doContactGen(contactName, contactEndpoint)
		if err != nil {
			log.Fatalf("Error while generating contact for '%s' : %v", contactName, err)
		}

	case "comcrea":
		ownerKey := os.Args[2]
		communityFile := os.Args[2]

		err := doCommunityCreate(ownerKey, communityFile)
		if err != nil {
			log.Fatalf("Failed to create community '%s' : %v", communityFile, err)
		}
	case "comadd":
		ownerKey := os.Args[2]
		communityFile := os.Args[2]
		memberFile := os.Args[4]

		err := doCommunityAppend(ownerKey, communityFile, memberFile)
		if err != nil {
			log.Fatalf("Failed to add member do community '%s' : %v", communityFile, err)
		}

	case "comdel":
		ownerKey := os.Args[2]
		communityFile := os.Args[2]
		memberFile := os.Args[4]

		err := doCommunityRemove(ownerKey, communityFile, memberFile)
		if err != nil {
			log.Fatalf("Failed to delete member from community '%s' : %v", communityFile, err)
		}
	default:
		commandname := os.Args[0]
		usage(commandname)

		log.Fatalf("Un supported option '%s' ", action)
	}

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
