package message

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// --- Struct Definitions ---

// MessageContact holds the public keys for a party.
type MessageContact struct {
	EncryptionKey []byte // X25519 public key (binary)
	SignatureKey  []byte // Ed25519 public key (binary)
}

// EncryptedMessage holds the final message structure, with binary fields encoded in Base64 for transport.
type EncryptedMessage struct {
	Version     int      // always 1
	Data        string   // Base64 encoded ciphertext + nonce
	Signature   string   // Base64 encoded ed25519 signature of the normalized message
	WrappedKeys []string // List of Base64 encoded wrapped symmetric keys (one per recipient)
	Sender      MessageContact
}

// CreateNormalizedMessage generates a deterministic string from the message components for signing.
// Format: version(hex 2 digits) || wrapped_keys(joined Base64) || sender_pub_keys(X25519+Ed25519 Base64) || data(Base64)
func CreateNormalizedMessage(msg EncryptedMessage) []byte {
	// 1. Version (hex encoded on 2 digits)
	versionHex := fmt.Sprintf("%02x", msg.Version)

	// 2. Base64 encoded wrapped keys (joined by empty string or a delimiter, using empty string for compactness)
	wrappedKeysJoined := strings.Join(msg.WrappedKeys, "")

	// 3. Base 64 encoded sender public keys (X25519 + Ed25519)
	senderKeys := append(msg.Sender.EncryptionKey, msg.Sender.SignatureKey...)
	senderKeysBase64 := base64.StdEncoding.EncodeToString(senderKeys)

	// 4. Base64 encoded encrypted text (msg.Data is already Base64)
	dataBase64 := msg.Data

	// Concatenate all parts
	normalizedString := versionHex + wrappedKeysJoined + senderKeysBase64 + dataBase64

	// Return the byte representation of the normalized string
	return []byte(normalizedString)
}

// --- Main Functions ---

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

		wrappedKey, err := KeyWrap(sharedSecret, chachaKey)
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

	// Create the expected normalized message string
	normalizedMessage := CreateNormalizedMessage(msg)

	// Decode the received signature
	decodedSignature, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base64 signature: %w", err)
	}

	// Verify the signature using the sender's Ed25519 public key
	if !ed25519.Verify(msg.Sender.SignatureKey, normalizedMessage, decodedSignature) {
		return nil, errors.New("signature verification failed: message has been tampered with or is from an unauthorized sender")
	}

	// 2. Try to unwrap the symmetric key
	var chachaKey []byte
	var sharedSecret []byte

	if len(msg.Sender.EncryptionKey) != 32 || len(decryptionKey) != 32 {
		return nil, errors.New("key size error: sender encryption key or recipient decryption key is not 32 bytes")
	}

	sharedSecret, err = curve25519.X25519(decryptionKey, msg.Sender.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to perform DH key agreement: %w", err)
	}

	// Iterate through Base64 encoded wrapped keys
	for _, wrappedKeyStr := range msg.WrappedKeys {
		wrappedKey, err := base64.StdEncoding.DecodeString(wrappedKeyStr)
		if err != nil {
			log.Printf("Failed to Base64 decode a wrapped key: %v", err)
			continue
		}

		chachaKey, err = KeyUnwrap(sharedSecret, wrappedKey)

		if err == nil && len(chachaKey) == 32 {
			break
		}
		if err != nil && err.Error() != "key unwrap failed (invalid tag)" {
			log.Printf("Non-tag key unwrap error: %v", err)
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

	// Decode Base64 data (ciphertext + nonce)
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
