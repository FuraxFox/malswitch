package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/FuraxFox/malswitch/internal/message"
)

func main() {
	log.SetFlags(0)
	fmt.Println("--- Secure Message Demonstration (HPKE-Compliant Key Derivation) ---")

	// 1. Set up Sender and Recipient Keys
	_, senderEdPriv, _ := message.GenerateKeys() // Fixed: GenerateKeys returns 3 values
	_, r1EdPriv, _ := message.GenerateKeys()
	r1XPriv := message.Ed25519PrivateKeyToCurve25519(r1EdPriv)
	r1XPub, _ := message.DeriveX25519PublicKey(r1EdPriv)
	_, r2EdPriv, _ := message.GenerateKeys()
	r2XPriv := message.Ed25519PrivateKeyToCurve25519(r2EdPriv)
	r2XPub, _ := message.DeriveX25519PublicKey(r2EdPriv)
	r1EdPub := r1EdPriv.Public().(ed25519.PublicKey)
	r2EdPub := r2EdPriv.Public().(ed25519.PublicKey)

	fmt.Println("\n[Keys Generated]")
	fmt.Printf("R1 X25519 Public (Encrypt): %s\n", hex.EncodeToString(r1XPub))
	fmt.Printf("R2 X25519 Public (Encrypt): %s\n", hex.EncodeToString(r2XPub))

	recipients := []message.MessageContact{
		{EncryptionKey: r1XPub, SignatureKey: r1EdPub},
		{EncryptionKey: r2XPub, SignatureKey: r2EdPub},
	}

	// Use time.Now().UnixNano() for a unique, non-messagegraphic identifier
	plaintext := []byte("This is the secret message from the sender. Timestamp: " + strconv.FormatInt(time.Now().UnixNano(), 10))
	fmt.Printf("\nOriginal Message: %s\n", string(plaintext))

	// 2. Encryption
	fmt.Println("\n[Encrypting Message...]")
	encryptedMsg, err := message.EncryptMessage(plaintext, senderEdPriv, recipients)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Encrypted Data Size: %d bytes\n", len(encryptedMsg.Data))

	// 3. Decryption by Recipient 1
	fmt.Println("\n[Recipient 1 Decrypts...]")
	clearTextR1, err := message.DecryptMessage(encryptedMsg, r1XPriv, recipients)
	if err != nil {
		log.Fatalf("Decryption by R1 failed: %v", err)
	}
	fmt.Printf("Successfully Decrypted by R1: %s\n", string(clearTextR1))

	// 4. Decryption by Recipient 2
	fmt.Println("\n[Recipient 2 Decrypts...]")
	clearTextR2, err := message.DecryptMessage(encryptedMsg, r2XPriv, recipients)
	if err != nil {
		log.Fatalf("Decryption by R2 failed: %v", err)
	}
	fmt.Printf("Successfully Decrypted by R2: %s\n", string(clearTextR2))
}
