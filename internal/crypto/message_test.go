package crypto

import (
	"encoding/hex"
	"math/rand"
	"strconv"
	"testing"
)

// New: Required for HKDF-SHA256

// New: Required for HPKE-compliant key derivation

// --- Test Implementation (Functions remain the same, now testing the HKDF-based logic) ---

func TestSecureMessenger(t *testing.T) {
	t.Log("--- Secure Message Test Suite (HPKE-Compliant Key Derivation) ---")

	// 1. Set up Sender and Recipient Keys
	senderEdPub, senderEdPriv, _ := GenerateKeys()
	r1EdPub, r1EdPriv, _ := GenerateKeys()
	r1XPriv := ed25519PrivateKeyToCurve25519(r1EdPriv)
	r1XPub, _ := deriveX25519PublicKey(r1EdPriv)
	r2EdPub, r2EdPriv, _ := GenerateKeys()
	r2XPriv := ed25519PrivateKeyToCurve25519(r2EdPriv)
	r2XPub, _ := deriveX25519PublicKey(r2EdPriv)

	t.Logf("\n[Keys Generated]")
	t.Logf("Sender Ed25519 Public: %s", hex.EncodeToString(senderEdPub))
	t.Logf("R1 X25519 Public (Encrypt): %s", hex.EncodeToString(r1XPub))

	recipients := []MessageContact{
		{EncryptionKey: r1XPub, SignatureKey: r1EdPub},
		{EncryptionKey: r2XPub, SignatureKey: r2EdPub},
	}

	plaintext := []byte("This is the secret message from the sender. The current time is " + strconv.FormatInt(rand.Int63(), 10))
	t.Logf("\nOriginal Message: %s", string(plaintext))

	// --- Test Case 1: Successful Encryption and Decryption ---
	t.Run("Successful_Encryption_and_Decryption", func(t *testing.T) {
		encryptedMsg, err := EncryptMessage(plaintext, senderEdPriv, recipients)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		t.Logf("Encrypted Data Size: %d bytes", len(encryptedMsg.Data))

		// 3. Decryption by Recipient 1
		t.Run("Decrypt_by_R1", func(t *testing.T) {
			clearTextR1, err := DecryptMessage(encryptedMsg, r1XPriv, recipients)
			if err != nil {
				t.Fatalf("Decryption by R1 failed: %v", err)
			}
			if string(clearTextR1) != string(plaintext) {
				t.Errorf("Decrypted text mismatch.\nGot: %s\nExpected: %s", string(clearTextR1), string(plaintext))
			}
			t.Log("Successfully Decrypted by R1.")
		})

		// 4. Decryption by Recipient 2
		t.Run("Decrypt_by_R2", func(t *testing.T) {
			clearTextR2, err := DecryptMessage(encryptedMsg, r2XPriv, recipients)
			if err != nil {
				t.Fatalf("Decryption by R2 failed: %v", err)
			}
			if string(clearTextR2) != string(plaintext) {
				t.Errorf("Decrypted text mismatch.\nGot: %s\nExpected: %s", string(clearTextR2), string(plaintext))
			}
			t.Log("Successfully Decrypted by R2.")
		})
	})

	// --- Test Case 2: Tampering Test (Mutate Ciphertext) ---
	t.Run("Tampering_Check_Mutate_Data", func(t *testing.T) {
		encryptedMsg, err := EncryptMessage(plaintext, senderEdPriv, recipients)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		tamperedMsg := encryptedMsg
		tamperedMsg.Data[10] = tamperedMsg.Data[10] ^ 0xFF

		_, err = DecryptMessage(tamperedMsg, r1XPriv, recipients)
		expectedError := "signature verification failed: message has been tampered with or is from an unauthorized sender"
		if err == nil || err.Error() != expectedError {
			t.Errorf("Security failure: Tampered message was successfully decrypted or returned wrong error.\nExpected: %s\nGot: %v", expectedError, err)
		} else {
			t.Log("Decryption correctly failed after ciphertext tampering.")
		}
	})

	// --- Test Case 4: Decryption with wrong key (Negative Test) ---
	t.Run("Decryption_with_Wrong_Key", func(t *testing.T) {
		encryptedMsg, err := EncryptMessage(plaintext, senderEdPriv, recipients)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		_, _, wrongEdPriv, _ := GenerateKeys()
		wrongXPriv := ed25519PrivateKeyToCurve25519(wrongEdPriv)

		_, err = DecryptMessage(encryptedMsg, wrongXPriv, recipients)
		expectedError := "key unwrapping failed for all wrapped keys (shared secret mismatch or key data corruption)"
		if err == nil || err.Error() != expectedError {
			t.Errorf("Security failure: Decrypted message with wrong key or returned wrong error.\nExpected: %s\nGot: %v", expectedError, err)
		} else {
			t.Log("Decryption correctly failed with an unrelated private key.")
		}
	})
}
