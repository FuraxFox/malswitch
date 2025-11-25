package message

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// EncryptedMessage holds the final message structure, with binary fields encoded in Base64 for transport.
type EncryptedMessage struct {
	Version     int
	Data        string   // Base64 encoded ciphertext + nonce
	Signature   string   // Base64 encoded ed25519 signature of the normalized message
	WrappedKeys []string // List of Base64 encoded wrapped symmetric keys (one per recipient)
	Sender      MessageContact
}

// EncryptMessage encrypts the plaintext, signs the normalized message structure, and wraps the key for each recipient.
func EncryptMessage(clearText []byte, signatureKey ed25519.PrivateKey, recipients []MessageContact) (EncryptedMessage, error) {
	if len(clearText) == 0 || len(recipients) == 0 {
		return EncryptedMessage{}, errors.New("clear text or recipients list cannot be empty")
	}

	// 1. Generate symmetric key
	chachaKey := make([]byte, 32)
	if _, err := rand.Read(chachaKey); err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// 2. Generate sender's public keys
	senderX25519Priv := Ed25519PrivateKeyToCurve25519(signatureKey)
	senderX25519Pub, err := DeriveX25519PublicKey(signatureKey)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to derive sender X25519 public key: %w", err)
	}
	senderEd25519Pub := signatureKey.Public().(ed25519.PublicKey)

	// Initialize the message structure (without Data and Signature yet)
	msg := EncryptedMessage{
		Version: 1,
		Sender: MessageContact{
			EncryptionKey: senderX25519Pub,
			SignatureKey:  senderEd25519Pub,
		},
		WrappedKeys: make([]string, 0, len(recipients)),
	}

	// 3. Encrypt the clear text
	aead, err := chacha20poly1305.New(chachaKey)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to create AEAD for data encryption: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, clearText, nil)

	// Store Base64 Encoded ciphertext in the message struct
	msg.Data = base64.StdEncoding.EncodeToString(ciphertext)

	// 4. Wrap the symmetric key and store Base64 encoded wrapped keys
	for i, recipient := range recipients {
		recipientX25519Pub := recipient.EncryptionKey

		if len(recipientX25519Pub) != 32 {
			return EncryptedMessage{}, fmt.Errorf("recipient %d X25519 public key size is incorrect (expected 32 bytes)", i)
		}

		sharedSecret, err := curve25519.X25519(senderX25519Priv, recipientX25519Pub)
		if err != nil {
			return EncryptedMessage{}, fmt.Errorf("failed to perform DH key agreement for recipient %d: %w", i, err)
		}

		wrappedKey, err := keyWrap(sharedSecret, chachaKey)
		if err != nil {
			return EncryptedMessage{}, fmt.Errorf("failed to wrap key for recipient %d: %w", i, err)
		}

		msg.WrappedKeys = append(msg.WrappedKeys, base64.StdEncoding.EncodeToString(wrappedKey))
	}

	// 5. Create normalized message and sign it
	normalizedMessage := CreateNormalizedMessage(msg)
	signature := ed25519.Sign(signatureKey, normalizedMessage)

	// Store Base64 Encoded signature
	msg.Signature = base64.StdEncoding.EncodeToString(signature)

	return msg, nil
}

// DecryptMessage verifies the message, unwraps the key, and decrypts the ciphertext.
func DecryptMessage(msg EncryptedMessage, decryptionKey []byte, correspondents []MessageContact) ([]byte, error) {
	if msg.Version != 1 {
		return nil, errors.New("unsupported message version")
	}

	// 1. Verify the signature against the normalized message structure
	normalizedMessage := CreateNormalizedMessage(msg)

	decodedSignature, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base64 signature: %w", err)
	}

	// Crucial check: Verify signature
	if !ed25519.Verify(msg.Sender.SignatureKey, normalizedMessage, decodedSignature) {
		return nil, errors.New("signature verification failed: message has been tampered with or is from an unauthorized sender")
	}

	// 2. Try to unwrap the symmetric key
	var chachaKey []byte

	if len(msg.Sender.EncryptionKey) != 32 || len(decryptionKey) != 32 {
		return nil, errors.New("key size error: sender encryption key or recipient decryption key is not 32 bytes")
	}

	sharedSecret, err := curve25519.X25519(decryptionKey, msg.Sender.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform DH key agreement: %w", err)
	}

	for _, wrappedKeyStr := range msg.WrappedKeys {
		wrappedKey, err := base64.StdEncoding.DecodeString(wrappedKeyStr)
		if err != nil {
			log.Printf("Server: Failed to Base64 decode a wrapped key: %v", err)
			continue
		}

		chachaKey, err = keyUnwrap(sharedSecret, wrappedKey)

		if err == nil && len(chachaKey) == 32 {
			break
		}
		chachaKey = nil
	}

	if chachaKey == nil {
		return nil, errors.New("key unwrapping failed for all wrapped keys (shared secret mismatch or key data corruption)")
	}

	// 3. Decrypt the message
	aead, err := chacha20poly1305.New(chachaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD for data decryption: %w", err)
	}

	decodedData, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base64 data: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(decodedData) < nonceSize {
		return nil, errors.New("decoded ciphertext is too short to contain a nonce and tag")
	}

	nonce := decodedData[:nonceSize]
	ciphertext := decodedData[nonceSize:]

	clearText, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("data decryption failed: invalid ciphertext or AEAD tag")
	}

	return clearText, nil
}
