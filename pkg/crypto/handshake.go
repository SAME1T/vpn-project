package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeyPair, X25519 için public+private key üretir
func GenerateKeyPair() (public, private []byte, err error) {
	private = make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(private); err != nil {
		return nil, nil, fmt.Errorf("private key gen: %w", err)
	}
	public, err = curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("public key gen: %w", err)
	}
	return public, private, nil
}

// DeriveSharedKey, kendi private ile karşıdakinin public'ini alıp paylaşılan secret çıkarır
func DeriveSharedKey(ourPriv, theirPub []byte) ([]byte, error) {
	shared, err := curve25519.X25519(ourPriv, theirPub)
	if err != nil {
		return nil, fmt.Errorf("shared secret gen: %w", err)
	}
	// 32 byte’lık shared secret’i SHA-256 ile AES anahtarına çevir
	key := sha256.Sum256(shared)
	return key[:], nil
}
