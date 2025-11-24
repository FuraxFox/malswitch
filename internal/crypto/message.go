package crypto

/*
Writing a golang program, can you write two functions defined below ?

The first one receives a cleartext buffer, a signature key and and a list of recipients (defined by a pairs of keys: a ed25519 key for encryption, and an ed25519 key for signature).


Recipients are defined as:
type MessageContact struct {
    EncryptionKey []byte // public key to write to the contact
    SignatureKey  []byte // public key to verify signature
}



It returns an encrypted message defined as :
type EncryptedMessage struct {
    Version       int    // always 1
    Data          []byte // encrypted data
    Signature     []byte // signature of the encrypted data
    Signature
    WrappedKeys [][]byte // list of wrapped keys
    Sender      MessageContact
}
The function has to :
- generate a key for chacha20-poly1305
- encrypt the clear text with chacha20-poly1305 algorithm
- sign the encrypted text with ed25519 algorithm
- wrap the symetric key with each recipient key with  X25519 algorithm

function signature is:
func EncryptMessage( clearTest []buffer, signatureKey []byte, recipients []MessageContact) ( EncryptedMessage, error)

The second function does the reverse :
It is defined as
func DecryptMessage( msg EncryptedMessage, decryptionKey []byte, correspondents []MessageContact) ( []byte, error)

The function:
- it uses the Sender SignatureKey to check the signature of the encrypted data, it checking the signature fails it returns an error
- then it tries to decrypt the messages wrapped keys until it finds one that decrypt or return an error
- with the unwrapped key it decrypts the message and returns it


*/

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256" // New: Required for HKDF-SHA256
	"errors"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf" // New: Required for HPKE-compliant key derivation
)

// --- Struct Definitions ---

// MessageContact holds the public keys for a party.
// EncryptionKey is the X25519 public key for Diffie-Hellman key agreement.
// SignatureKey is the Ed25519 public key for signature verification.
type MessageContact struct {
	EncryptionKey []byte // X25519 public key for DH key agreement
	SignatureKey  []byte // Ed25519 public key for signature verification
}

// EncryptedMessage holds the final message structure.
type EncryptedMessage struct {
	Version     int      // always 1
	Data        []byte   // encrypted data (ciphertext + Poly1305 tag)
	Signature   []byte   // ed25519 signature of the Data field
	WrappedKeys [][]byte // list of wrapped symmetric keys (one per recipient)
	Sender      MessageContact
}

// --- Helper Functions ---

// GenerateKeys generates a pair of Ed25519 public/private keys.
func GenerateKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// ed25519PrivateKeyToCurve25519 converts an Ed25519 private key to an X25519 private key.
func ed25519PrivateKeyToCurve25519(edPriv ed25519.PrivateKey) []byte {
	var curvePriv [32]byte
	copy(curvePriv[:], edPriv[:32])
	return curvePriv[:]
}

// deriveX25519PublicKey calculates the X25519 public key from the Ed25519 private key.
func deriveX25519PublicKey(edPriv ed25519.PrivateKey) ([]byte, error) {
	x25519Priv := ed25519PrivateKeyToCurve25519(edPriv)

	var x25519Pub [32]byte
	var x25519PrivArray [32]byte
	copy(x25519PrivArray[:], x25519Priv)

	// Use X25519 with the Basepoint for calculating the public key from the private scalar,
	// as ScalarBaseMult is deprecated and X25519 is the recommended API.
	if _, err := curve25519.X25519(&x25519Pub, &x25519PrivArray, curve25519.Basepoint); err != nil {
		return nil, err
	}
	return x25519Pub[:], nil
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

// keyWrap encrypts the symmetric key (chachaKey) using the DH shared secret's HKDF output (KEK).
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

	// Use a fixed zero nonce, uniqueness is guaranteed by the unique KEK derived from DH
	nonce := make([]byte, aead.NonceSize())

	wrappedKey := aead.Seal(nil, nonce, chachaKey, nil)
	return wrappedKey, nil
}

// keyUnwrap decrypts the symmetric key (chachaKey) using the DH shared secret's HKDF output (KEK).
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

// --- Main Functions ---

// EncryptMessage encrypts the plaintext, signs the ciphertext, and wraps the key for each recipient.
func EncryptMessage(clearText []byte, signatureKey ed25519.PrivateKey, recipients []MessageContact) (EncryptedMessage, error) {
	if len(clearText) == 0 || len(recipients) == 0 {
		return EncryptedMessage{}, errors.New("clear text or recipients list cannot be empty")
	}

	// 1. Generate a key for chacha20-poly1305 (32 bytes)
	chachaKey := make([]byte, 32)
	if _, err := rand.Read(chachaKey); err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// 2. Generate sender's X25519 key pair for DH key agreement (derived from Ed25519 private key)
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

	// 3. Encrypt the clear text with chacha20-poly1305 algorithm
	aead, err := chacha20poly1305.New(chachaKey)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to create AEAD for data encryption: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedMessage{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Prepend nonce to the ciphertext for easy retrieval
	ciphertext := aead.Seal(nonce, nonce, clearText, nil)
	msg.Data = ciphertext

	// 4. Sign the encrypted text with ed25519 algorithm
	msg.Signature = ed25519.Sign(signatureKey, msg.Data)

	// 5. Wrap the symmetric key with each recipient's key (X25519 DH + HKDF)
	for i, recipient := range recipients {
		recipientX25519Pub := recipient.EncryptionKey

		if len(recipientX25519Pub) != 32 {
			return EncryptedMessage{}, fmt.Errorf("recipient %d X25519 public key size is incorrect (expected 32 bytes)", i)
		}

		var recipientPub [32]byte
		copy(recipientPub[:], recipientX25519Pub)

		// Calculate the raw shared secret (DH key agreement)
		var sharedSecret [32]byte
		var senderPriv [32]byte
		copy(senderPriv[:], senderX25519Priv)

		if _, err := curve25519.X25519(&sharedSecret, &senderPriv, &recipientPub); err != nil {
			return EncryptedMessage{}, fmt.Errorf("failed to perform DH key agreement for recipient %d: %w", i, err)
		}

		// Wrap the symmetric key using the HKDF-derived KEK from the shared secret
		wrappedKey, err := keyWrap(sharedSecret[:], chachaKey)
		if err != nil {
			return EncryptedMessage{}, fmt.Errorf("failed to wrap key for recipient %d: %w", i, err)
		}
		msg.WrappedKeys = append(msg.WrappedKeys, wrappedKey)
	}

	return msg, nil
}

// DecryptMessage verifies the message, unwraps the key, and decrypts the ciphertext.
// The decryptionKey is the recipient's X25519 private key.
func DecryptMessage(msg EncryptedMessage, decryptionKey []byte, correspondents []MessageContact) ([]byte, error) {
	if msg.Version != 1 {
		return nil, errors.New("unsupported message version")
	}

	// 1. Check the signature of the encrypted data
	// The Sender.SignatureKey is the Ed25519 public key.
	if !ed25519.Verify(msg.Sender.SignatureKey, msg.Data, msg.Signature) {
		return nil, errors.New("signature verification failed: message has been tampered with or is from an unauthorized sender")
	}

	// 2. Try to decrypt the wrapped keys until one succeeds
	var chachaKey []byte
	var sharedSecret [32]byte
	var recipientPriv [32]byte
	var senderPub [32]byte

	// Sender's encryption key (X25519) is in msg.Sender.EncryptionKey
	if len(msg.Sender.EncryptionKey) != 32 || len(decryptionKey) != 32 {
		return nil, errors.New("key size error: sender encryption key or recipient decryption key is not 32 bytes")
	}

	copy(recipientPriv[:], decryptionKey)
	copy(senderPub[:], msg.Sender.EncryptionKey)

	// Calculate the raw shared secret (DH key agreement) once
	if _, err := curve25519.X25519(&sharedSecret, &recipientPriv, &senderPub); err != nil {
		return nil, fmt.Errorf("failed to perform DH key agreement: %w", err)
	}

	// Try to unwrap each key with the HKDF-derived KEK
	for _, wrappedKey := range msg.WrappedKeys {
		var err error
		chachaKey, err = keyUnwrap(sharedSecret[:], wrappedKey)

		if err == nil && len(chachaKey) == 32 {
			break
		}
		if err != nil && err.Error() != "key unwrap failed (invalid tag)" {
			log.Printf("Non-tag key unwrap error: %v", err)
		}
		chachaKey = nil // Reset key if it failed
	}

	if chachaKey == nil {
		return nil, errors.New("key unwrapping failed for all wrapped keys (shared secret mismatch or key data corruption)")
	}

	// 3. Decrypt the message
	aead, err := chacha20poly1305.New(chachaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD for data decryption: %w", err)
	}

	// The nonce is prepended to the ciphertext (msg.Data)
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

// --- Demonstration ---
/*
func main() {
	log.SetFlags(0)
	fmt.Println("--- Secure Message Demonstration (HPKE-Compliant Key Derivation) ---")

	// 1. Set up Sender and Recipient Keys
	senderEdPub, senderEdPriv, _ := GenerateKeys()
	r1EdPub, r1EdPriv, _ := GenerateKeys()
	r1XPriv := ed25519PrivateKeyToCurve25519(r1EdPriv)
	r1XPub, _ := deriveX25519PublicKey(r1EdPriv)
	r2EdPub, r2EdPriv, _ := GenerateKeys()
	r2XPriv := ed25519PrivateKeyToCurve25519(r2EdPriv)
	r2XPub, _ := deriveX25519PublicKey(r2EdPriv)

	fmt.Println("\n[Keys Generated]")
	fmt.Printf("R1 X25519 Public (Encrypt): %s\n", hex.EncodeToString(r1XPub))
	fmt.Printf("R2 X25519 Public (Encrypt): %s\n", hex.EncodeToString(r2XPub))

	recipients := []MessageContact{
		{EncryptionKey: r1XPub, SignatureKey: r1EdPub},
		{EncryptionKey: r2XPub, SignatureKey: r2EdPub},
	}

	plaintext := []byte("This is the secret message from the sender. Time: " + strconv.FormatInt(rand.Int63(), 10))
	fmt.Printf("\nOriginal Message: %s\n", string(plaintext))

	// 2. Encryption
	fmt.Println("\n[Encrypting Message...]")
	encryptedMsg, err := EncryptMessage(plaintext, senderEdPriv, recipients)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Encrypted Data Size: %d bytes\n", len(encryptedMsg.Data))

	// 3. Decryption by Recipient 1
	fmt.Println("\n[Recipient 1 Decrypts...]")
	clearTextR1, err := DecryptMessage(encryptedMsg, r1XPriv, recipients)
	if err != nil {
		log.Fatalf("Decryption by R1 failed: %v", err)
	}
	fmt.Printf("Successfully Decrypted by R1: %s\n", string(clearTextR1))

	// 4. Decryption by Recipient 2
	fmt.Println("\n[Recipient 2 Decrypts...]")
	clearTextR2, err := DecryptMessage(encryptedMsg, r2XPriv, recipients)
	if err != nil {
		log.Fatalf("Decryption by R2 failed: %v", err)
	}
	fmt.Printf("Successfully Decrypted by R2: %s\n", string(clearTextR2))
}
*/
