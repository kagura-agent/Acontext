package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	userKEKSalt = []byte("acontext-user-kek")
	userKEKInfo = []byte("acontext envelope encryption user KEK")
)

// DeriveUserKEK derives a user KEK from the raw API key and pepper.
func DeriveUserKEK(apiKeyRaw, pepper string) ([]byte, error) {
	secret := []byte(apiKeyRaw + pepper)
	return DeriveKEK(secret, userKEKSalt, userKEKInfo)
}

// EncryptedMeta holds the metadata stored alongside an encrypted S3 object.
type EncryptedMeta struct {
	Algo           string // "AES-256-GCM"
	UserWrappedDEK string // base64(nonce + ciphertext)
}

// EncryptData encrypts plaintext using a user KEK and returns ciphertext + metadata.
// Generates a random DEK, encrypts data with it, then wraps the DEK with the user KEK.
func EncryptData(userKEK, plaintext []byte) (ciphertext []byte, meta *EncryptedMeta, err error) {
	if userKEK == nil {
		return nil, nil, errors.New("crypto: user KEK is required")
	}

	dek, err := GenerateDEK()
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err = Encrypt(dek, plaintext)
	if err != nil {
		return nil, nil, err
	}

	userWrapped, err := WrapDEK(userKEK, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: wrap DEK with user KEK: %w", err)
	}

	meta = &EncryptedMeta{
		Algo:           "AES-256-GCM",
		UserWrappedDEK: base64.StdEncoding.EncodeToString(userWrapped),
	}
	return ciphertext, meta, nil
}

// DecryptData decrypts ciphertext using a user KEK and the associated metadata.
func DecryptData(userKEK, ciphertext []byte, meta *EncryptedMeta) ([]byte, error) {
	if userKEK == nil {
		return nil, errors.New("crypto: user KEK is required")
	}
	if meta == nil {
		return nil, errors.New("crypto: encrypted metadata is required")
	}
	wrapped, err := base64.StdEncoding.DecodeString(meta.UserWrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode user wrapped DEK: %w", err)
	}
	dek, err := UnwrapDEK(userKEK, wrapped)
	if err != nil {
		return nil, err
	}
	return Decrypt(dek, ciphertext)
}

// RewrapDEK re-encrypts the DEK with a new user KEK (for key rotation).
// Uses the old user KEK to unwrap, then wraps with the new user KEK.
// Idempotent: if the DEK is already wrapped with newUserKEK, returns ("", nil)
// to signal the object was already rewrapped and should be skipped.
func RewrapDEK(meta *EncryptedMeta, oldUserKEK, newUserKEK []byte) (string, error) {
	if meta == nil {
		return "", errors.New("crypto: encrypted metadata is required")
	}
	wrapped, err := base64.StdEncoding.DecodeString(meta.UserWrappedDEK)
	if err != nil {
		return "", fmt.Errorf("crypto: decode user wrapped DEK: %w", err)
	}

	// Try unwrapping with old KEK first (normal case)
	dek, err := UnwrapDEK(oldUserKEK, wrapped)
	if err != nil {
		// Old KEK failed — try new KEK to check if already rewrapped
		if _, err2 := UnwrapDEK(newUserKEK, wrapped); err2 == nil {
			// Already rewrapped with new KEK — skip
			return "", nil
		}
		// Neither KEK works — return original error
		return "", err
	}

	newWrapped, err := WrapDEK(newUserKEK, dek)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(newWrapped), nil
}

// EncodeBase64 encodes bytes to standard base64 string.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes a standard base64 string to bytes.
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// MetadataToMap converts EncryptedMeta to S3-compatible metadata map.
func (m *EncryptedMeta) MetadataToMap() map[string]string {
	return map[string]string{
		"enc-algo":     m.Algo,
		"enc-dek-user": m.UserWrappedDEK,
	}
}

// MetadataFromMap extracts EncryptedMeta from S3 object metadata.
// Returns nil if the object is not encrypted (no enc-algo key).
func MetadataFromMap(metadata map[string]string) *EncryptedMeta {
	algo, ok := metadata["enc-algo"]
	if !ok || algo == "" {
		return nil
	}
	return &EncryptedMeta{
		Algo:           algo,
		UserWrappedDEK: metadata["enc-dek-user"],
	}
}
