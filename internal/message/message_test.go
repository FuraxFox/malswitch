package message

import (
	"encoding/hex"
	"time"

	"strconv"
	"testing"
)

/*

// --- Struct Definitions (Copied from secure_messenger.go for test consistency) ---

// MessageContact holds the public keys for a party.
type MessageContact struct {
	EncryptionKey []byte // X25519 public key for DH key agreement
	SignatureKey  []byte // Ed25519 public key for signature verification
}

// EncryptedMessage holds the final message structure.
type EncryptedMessage struct {
	Version     int
	Data        []byte
	Signature   []byte
	WrappedKeys [][]byte
	Sender      MessageContact
}

// --- Helper Functions (Copied from secure_messenger.go) ---

func GenerateKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func ed25519PrivateKeyToCurve25519(edPriv ed25519.PrivateKey) []byte {
	var curvePriv [32]byte
	copy(curvePriv[:], edPriv[:32])
	return curvePriv[:]
}

// deriveX25519PublicKey calculates the X25519 public key from the Ed25519 private key.
// This is corrected to use the 2-argument slice-based signature compatible with Go 1.25.4.
func deriveX25519PublicKey(edPriv ed25519.PrivateKey) ([]byte, error) {
	x25519Priv := ed25519PrivateKeyToCurve25519(edPriv)

	// Use the 2-argument slice-based signature: X25519(privateKey, basepoint).
	// The function returns the calculated public key slice.
	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return x25519Pub, nil
}

// keyDerivationFunction uses HKDF (as HPKE mandates) to derive a strong, unique
// key encryption key (KEK) from the raw Diffie-Hellman shared secret.
func keyDerivationFunction(sharedSecret []byte, keyLen int) ([]byte, error) {
	// Salt is nil (optional), info provides context for key separation (HPKE Base Mode).
	kekInfo := []byte("HPKE_KEK_Wrap")

	// Create a new HKDF reader using SHA256 as the hash function
	h := hkdf.New(sha256.New, sharedSecret, nil, kekInfo)

	key := make([]byte, keyLen)
	if _, err := h.Read(key); err != nil {
		return nil, fmt.Errorf("hkdf read failed: %w", err)
	}
	return key, nil
}

// keyWrap now uses the HKDF-derived KEK.
func keyWrap(sharedSecret, chachaKey []byte) ([]byte, error) {
	// 1. Derive the Key Encryption Key (KEK) from the shared secret using HKDF
	kek, err := keyDerivationFunction(sharedSecret, 32)
	if err != nil {
		return nil, err
	}

	// 2. Use the KEK with ChaCha20-Poly1305 for AEAD key wrapping
	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD for key wrap: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	wrappedKey := aead.Seal(nil, nonce, chachaKey, nil)
	return wrappedKey, nil
}

// keyUnwrap now uses the HKDF-derived KEK.
func keyUnwrap(sharedSecret, wrappedKey []byte) ([]byte, error) {
	// 1. Derive the same Key Encryption Key (KEK) using HKDF
	kek, err := keyDerivationFunction(sharedSecret, 32)
	if err != nil {
		return nil, err
	}

	// 2. Use the KEK with ChaCha20-Poly1305 for AEAD key unwrapping
	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD for key unwrap: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())

	chachaKey, err := aead.Open(nil, nonce, wrappedKey, nil)
	if err != nil {
		return nil, errors.New("key unwrap failed (invalid tag)")
	}
	return chachaKey, nil
}

// EncryptMessage (Updated DH key exchange)
func EncryptMessage(clearText []byte, signatureKey ed25519.PrivateKey, recipients []MessageContact) (EncryptedMessage, error) {
	if len(clearText) == 0 || len(recipients) == 0 {
		return EncryptedMessage{}, errors.New("clear text or recipients list cannot be empty")
	}

	chachaKey := make([]byte, 32)
	if _, err := rand.Read(chachaKey); err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	senderX25519Priv := ed25519PrivateKeyToCurve25519(signatureKey)
	senderX25519Pub, err := deriveX25519PublicKey(signatureKey)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to derive sender X25519 public key: %w", err)
	}
	senderEd25519Pub := signatureKey.Public().(ed25519.PublicKey)

	msg := EncryptedMessage{
		Version: 1,
		Sender: MessageContact{
			EncryptionKey: senderX25519Pub,
			SignatureKey:  senderEd25519Pub,
		},
		WrappedKeys: make([][]byte, 0, len(recipients)),
	}

	aead, err := chacha20poly1305.New(chachaKey)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to create AEAD for data encryption: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, clearText, nil)
	msg.Data = ciphertext
	msg.Signature = ed25519.Sign(signatureKey, msg.Data)

	for i, recipient := range recipients {
		recipientX25519Pub := recipient.EncryptionKey

		if len(recipientX25519Pub) != 32 {
			return EncryptedMessage{}, fmt.Errorf("recipient %d X25519 public key size is incorrect (expected 32 bytes)", i)
		}

		// Calculate the raw shared secret (DH key agreement)
		// Using the 2-argument slice-based signature
		sharedSecret, err := curve25519.X25519(senderX25519Priv, recipientX25519Pub)
		if err != nil {
			return EncryptedMessage{}, fmt.Errorf("failed to perform DH key agreement for recipient %d: %w", i, err)
		}

		// Use the HKDF-compliant keyWrap
		wrappedKey, err := keyWrap(sharedSecret, chachaKey)
		if err != nil {
			return EncryptedMessage{}, fmt.Errorf("failed to wrap key for recipient %d: %w", i, err)
		}
		msg.WrappedKeys = append(msg.WrappedKeys, wrappedKey)
	}

	return msg, nil
}

// DecryptMessage (Updated DH key exchange)
func DecryptMessage(msg EncryptedMessage, decryptionKey []byte, correspondents []MessageContact) ([]byte, error) {
	if msg.Version != 1 {
		return nil, errors.New("unsupported message version")
	}

	if !ed25519.Verify(msg.Sender.SignatureKey, msg.Data, msg.Signature) {
		return nil, errors.New("signature verification failed: message has been tampered with or is from an unauthorized sender")
	}

	var chachaKey []byte
	var sharedSecret []byte // Now a slice

	if len(msg.Sender.EncryptionKey) != 32 || len(decryptionKey) != 32 {
		return nil, errors.New("key size error: sender encryption key or recipient decryption key is not 32 bytes")
	}

	// Calculate the raw shared secret (DH key agreement) once
	// Using the 2-argument slice-based signature
	var err error
	sharedSecret, err = curve25519.X25519(decryptionKey, msg.Sender.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform DH key agreement: %w", err)
	}

	for _, wrappedKey := range msg.WrappedKeys {
		var err error
		// Use the HKDF-compliant keyUnwrap
		chachaKey, err = keyUnwrap(sharedSecret, wrappedKey)

		if err == nil && len(chachaKey) == 32 {
			break
		}
		if err != nil && err.Error() != "key unwrap failed (invalid tag)" {
			// In a real test environment, this would be t.Logf
		}
		chachaKey = nil
	}

	if chachaKey == nil {
		return nil, errors.New("key unwrapping failed for all wrapped keys (shared secret mismatch or key data corruption)")
	}

	aead, err := chacha20poly1305.New(chachaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD for data decryption: %w", err)
	}

	if len(msg.Data) < aead.NonceSize() {
		return nil, errors.New("ciphertext is too short to contain a nonce and tag")
	}

	nonceSize := aead.NonceSize()
	nonce := msg.Data[:nonceSize]
	ciphertext := msg.Data[nonceSize:]

	clearText, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("data decryption failed: invalid ciphertext or AEAD tag")
	}

	return clearText, nil
}
*/
// --- Test Implementation (Functions remain the same, now testing the HKDF-based logic) ---

func TestSecureMessenger(t *testing.T) {
	t.Log("--- Secure Message Test Suite (HPKE-Compliant Key Derivation) ---")

	// 1. Set up Sender and Recipient Keys
	senderEdPub, senderEdPriv, _ := GenerateKeys()
	r1EdPub, r1EdPriv, _ := GenerateKeys()
	r1XPriv := Ed25519PrivateKeyToCurve25519(r1EdPriv)
	r1XPub, _ := DeriveX25519PublicKey(r1EdPriv)
	r2EdPub, r2EdPriv, _ := GenerateKeys()
	r2XPriv := Ed25519PrivateKeyToCurve25519(r2EdPriv)
	r2XPub, _ := DeriveX25519PublicKey(r2EdPriv)

	t.Logf("\n[Keys Generated]")
	t.Logf("Sender Ed25519 Public: %s", hex.EncodeToString(senderEdPub))
	t.Logf("R1 X25519 Public (Encrypt): %s", hex.EncodeToString(r1XPub))

	recipients := []MessageContact{
		{EncryptionKey: r1XPub, SignatureKey: r1EdPub},
		{EncryptionKey: r2XPub, SignatureKey: r2EdPub},
	}

	// Use time.Now().UnixNano() for a unique, non-cryptographic identifier
	plaintext := []byte("This is the secret message from the sender. The current timestamp is " + strconv.FormatInt(time.Now().UnixNano(), 10))
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

		// Generate an entirely new, unrelated key pair
		_, wrongEdPriv, _ := GenerateKeys() // Fixed: GenerateKeys returns 3 values, not 4
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
