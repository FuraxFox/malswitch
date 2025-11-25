package message

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256" // NEW: Added for Base64 encoding/decoding
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// --- Helper Functions (Now Public) ---

// GenerateKeys generates a pair of Ed25519 public/private keys.
func GenerateKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Ed25519PrivateKeyToCurve25519 converts an Ed25519 private key to an X25519 private key.
func Ed25519PrivateKeyToCurve25519(edPriv ed25519.PrivateKey) []byte {
	var curvePriv [32]byte
	copy(curvePriv[:], edPriv[:32])
	return curvePriv[:]
}

// DeriveX25519PublicKey calculates the X25519 public key from the Ed25519 private key.
func DeriveX25519PublicKey(edPriv ed25519.PrivateKey) ([]byte, error) {
	x25519Priv := Ed25519PrivateKeyToCurve25519(edPriv)
	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return x25519Pub, nil
}

// KeyDerivationFunction uses HKDF to derive a Key Encryption Key (KEK).
func KeyDerivationFunction(sharedSecret []byte, keyLen int) ([]byte, error) {
	kekInfo := []byte("HPKE_KEK_Wrap")
	h := hkdf.New(sha256.New, sharedSecret, nil, kekInfo)
	key := make([]byte, keyLen)
	if _, err := h.Read(key); err != nil {
		return nil, fmt.Errorf("hkdf read failed: %w", err)
	}
	return key, nil
}

// KeyWrap encrypts the symmetric key (chachaKey) using the DH shared secret's HKDF output (KEK).
func KeyWrap(sharedSecret, chachaKey []byte) ([]byte, error) {
	kek, err := KeyDerivationFunction(sharedSecret, 32)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD for key wrap: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	wrappedKey := aead.Seal(nil, nonce, chachaKey, nil)
	return wrappedKey, nil
}

// KeyUnwrap decrypts the symmetric key (chachaKey) using the DH shared secret's HKDF output (KEK).
func KeyUnwrap(sharedSecret, wrappedKey []byte) ([]byte, error) {
	kek, err := KeyDerivationFunction(sharedSecret, 32)
	if err != nil {
		return nil, err
	}

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
