package search

type Search struct {
	Community        string
	EncryptedContent []byte
	Signature        []byte
	WrappedKeys      [][]byte
}

/*
import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

func main() {
	// 1. Generate Key Pair
	// pubKey is ed25519.PublicKey ([]byte of length 32)
	// privKey is ed25519.PrivateKey ([]byte of length 64)
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}
	fmt.Printf("✅ Key Pair Generated:\n")
	fmt.Printf("   Public Key Type: %T (Length: %d)\n", pubKey, len(pubKey))
	fmt.Printf("   Private Key Type: %T (Length: %d)\n\n", privKey, len(privKey))


	// 2. Define the Message to be Signed
	message := []byte("This is the confidential message to be signed.")
	fmt.Printf("➡️ Message to Sign: %s\n", message)


	// 3. Sign the Message
	// The result is ed25519.Signature (an alias for []byte of length 64)
	signature := ed25519.Sign(privKey, message)

	// Note: We cast the []byte result to the specific type ed25519.Signature
	// for clarity, although ed25519.Sign returns []byte which is compatible.
	var sig ed25519.Signature = signature

	fmt.Printf("➡️ Signature Generated:\n")
	fmt.Printf("   Signature Type: %T (Length: %d)\n\n", sig, len(sig))


	// 4. Verify the Signature
	// ed25519.Verify is the function we want to use.
	// It returns a boolean: true if the signature is valid, false otherwise.
	isValid := ed25519.Verify(pubKey, message, sig)

	fmt.Printf("✅ Verification Result:\n")
	if isValid {
		fmt.Println("   Signature is VALID! The message is authentic and hasn't been tampered with.")
	} else {
		fmt.Println("   Signature is INVALID! The message or signature may be corrupt.")
	}

	// --- Demonstration of Failure ---
	fmt.Println("\n--- Verification Failure Demo ---")

	// Tamper with the message
	tamperedMessage := []byte("This is the *tampered* message to be signed.")

	// Verify the original signature against the tampered message
	isInvalid := ed25519.Verify(pubKey, tamperedMessage, sig)

	fmt.Printf("Attempting to verify original signature against a *tampered* message...\n")
	fmt.Printf("Is the signature still valid? %t\n", isInvalid)
}
*/
