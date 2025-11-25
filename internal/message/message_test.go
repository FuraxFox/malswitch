package message

import (
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func TestSecureMessenger(t *testing.T) {
	t.Log("--- Secure Message Test Suite (Normalized Message Signing) ---")

	// 1. Set up Sender and Recipient Keys
	senderEdPub, senderEdPriv, _ := GenerateKeys()
	r1EdPub, r1EdPriv, _ := GenerateKeys()
	r1XPriv := Ed25519PrivateKeyToCurve25519(r1EdPriv)
	r1XPub, _ := DeriveX25519PublicKey(r1EdPriv)
	r2EdPub, r2EdPriv, _ := GenerateKeys()
	r2XPub, _ := DeriveX25519PublicKey(r2EdPriv)

	t.Logf("\n[Keys Generated]")
	t.Logf("Sender Ed25519 Public: %s", hex.EncodeToString(senderEdPub))
	t.Logf("R1 X25519 Public (Encrypt): %s", hex.EncodeToString(r1XPub))

	recipients := []MessageContact{
		{EncryptionKey: r1XPub, SignatureKey: r1EdPub},
		{EncryptionKey: r2XPub, SignatureKey: r2EdPub},
	}

	plaintext := []byte("This is the secret message from the sender. The current timestamp is " + strconv.FormatInt(time.Now().UnixNano(), 10))
	t.Logf("\nOriginal Message: %s", string(plaintext))

	// --- Test Case 1: Successful Encryption and Decryption ---
	t.Run("Successful_Encryption_and_Decryption", func(t *testing.T) {
		encryptedMsg, err := EncryptMessage(plaintext, senderEdPriv, recipients)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		t.Logf("Normalized Message Length (for signing): %d chars", len(CreateNormalizedMessage(encryptedMsg)))

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
	})

	// --- Test Case 2: Tampering Check (Mutate Data String) ---
	t.Run("Tampering_Check_Mutate_Data", func(t *testing.T) {
		encryptedMsg, err := EncryptMessage(plaintext, senderEdPriv, recipients)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		tamperedMsg := encryptedMsg
		// Mutate the Base64 Data string. This change is reflected in the normalized message
		// used during decryption verification, causing the signature check to fail.
		runes := []rune(tamperedMsg.Data)
		if len(runes) > 10 {
			if runes[10] == 'A' {
				runes[10] = 'B'
			} else {
				runes[10] = 'A'
			}
			tamperedMsg.Data = string(runes)
		}

		_, err = DecryptMessage(tamperedMsg, r1XPriv, recipients)
		expectedError := "signature verification failed: message has been tampered with or is from an unauthorized sender"
		if err == nil || err.Error() != expectedError {
			t.Errorf("Security failure: Tampered Data should invalidate signature.\nExpected: %s\nGot: %v", expectedError, err)
		} else {
			t.Log("Decryption correctly failed after data tampering (signature mismatch).")
		}
	})

	// --- Test Case 3: Tampering Check (Mutate Wrapped Key) ---
	t.Run("Tampering_Check_Mutate_Wrapped_Key", func(t *testing.T) {
		encryptedMsg, err := EncryptMessage(plaintext, senderEdPriv, recipients)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		tamperedMsg := encryptedMsg
		// Mutate the first wrapped key string. This change is reflected in the normalized message
		// used during decryption verification, causing the signature check to fail.
		if len(tamperedMsg.WrappedKeys) > 0 {
			runes := []rune(tamperedMsg.WrappedKeys[0])
			if len(runes) > 10 {
				if runes[10] == 'X' {
					runes[10] = 'Y'
				} else {
					runes[10] = 'X'
				}
				tamperedMsg.WrappedKeys[0] = string(runes)
			}
		}

		_, err = DecryptMessage(tamperedMsg, r1XPriv, recipients)
		expectedError := "signature verification failed: message has been tampered with or is from an unauthorized sender"
		if err == nil || err.Error() != expectedError {
			t.Errorf("Security failure: Tampered Wrapped Key should invalidate signature.\nExpected: %s\nGot: %v", expectedError, err)
		} else {
			t.Log("Decryption correctly failed after wrapped key tampering (signature mismatch).")
		}
	})

	// --- Test Case 4: Decryption with wrong key (Negative Test - Unchanged) ---
	t.Run("Decryption_with_Wrong_Key", func(t *testing.T) {
		encryptedMsg, err := EncryptMessage(plaintext, senderEdPriv, recipients)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		_, wrongEdPriv, _ := GenerateKeys()
		wrongXPriv := Ed25519PrivateKeyToCurve25519(wrongEdPriv)

		_, err = DecryptMessage(encryptedMsg, wrongXPriv, recipients)
		expectedError := "key unwrapping failed for all wrapped keys (shared secret mismatch or key data corruption)"
		if err == nil || err.Error() != expectedError {
			t.Errorf("Security failure: Decrypted message with wrong key or returned wrong error.\nExpected: %s\nGot: %v", expectedError, err)
		} else {
			t.Log("Decryption correctly failed with an unrelated private key.")
		}
	})
}
