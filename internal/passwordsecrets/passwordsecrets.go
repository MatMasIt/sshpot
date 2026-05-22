package passwordsecrets

// Package passwordsecrets implements the password storage and recovery format
// used by sshpot's CSV logger and decryptor utility.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	Plain                        = "plain"
	Hash                         = "hash"
	None                         = "none"
	EncX25519AES256GCM           = "enc_x25519_aes256gcm"
	EncX25519ChaCha20Poly1305    = "enc_x25519_chacha20poly1305"
	kdfInfo                      = "sshpot password encryption v1"
	passwordTruncationLimitBytes = 100
)

func NormalizeMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

func IsEncryptedMode(mode string) bool {
	switch NormalizeMode(mode) {
	case EncX25519AES256GCM, EncX25519ChaCha20Poly1305:
		return true
	default:
		return false
	}
}

func LoadX25519PublicKeyPEM(path string) (*ecdh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode public key %q: no PEM data found", path)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key %q: %w", path, err)
	}
	pub, ok := parsed.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key %q is not an X25519 public key", path)
	}
	return pub, nil
}

func LoadX25519PrivateKeyPEM(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode private key %q: no PEM data found", path)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %q: %w", path, err)
	}
	priv, ok := parsed.(*ecdh.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key %q is not an X25519 private key", path)
	}
	return priv, nil
}

func EncryptPassword(mode string, recipientPub *ecdh.PublicKey, password string) (string, error) {
	if recipientPub == nil {
		return "", fmt.Errorf("missing recipient public key")
	}

	mode = NormalizeMode(mode)
	curve := ecdh.X25519()
	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	ephemeralPub := ephemeralPriv.PublicKey().Bytes()

	sharedSecret, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return "", err
	}

	material, err := deriveKeyMaterial(sharedSecret)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, passwordTruncationLimitBytes+1)
	truncated := []byte(password)
	if len(truncated) > passwordTruncationLimitBytes {
		truncated = truncated[:passwordTruncationLimitBytes]
	}
	plaintext[0] = byte(len(truncated))
	copy(plaintext[1:], truncated)

	var ciphertext []byte
	switch mode {
	case EncX25519ChaCha20Poly1305:
		aead, err := chacha20poly1305.New(material.key)
		if err != nil {
			return "", err
		}
		ciphertext = aead.Seal(nil, material.nonce, plaintext, nil)
	default:
		block, err := aes.NewCipher(material.key)
		if err != nil {
			return "", err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		ciphertext = aead.Seal(nil, material.nonce, plaintext, nil)
	}

	out := append(ephemeralPub, ciphertext...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func DecryptPassword(mode string, recipientPriv *ecdh.PrivateKey, encoded string) (string, error) {
	if recipientPriv == nil {
		return "", fmt.Errorf("missing recipient private key")
	}

	mode = NormalizeMode(mode)
	if !IsEncryptedMode(mode) {
		return encoded, nil
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode password field: %w", err)
	}
	if len(raw) < 32 {
		return "", fmt.Errorf("encrypted password payload too short")
	}

	ephemeralPub, err := ecdh.X25519().NewPublicKey(raw[:32])
	if err != nil {
		return "", fmt.Errorf("parse ephemeral public key: %w", err)
	}

	sharedSecret, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return "", err
	}

	material, err := deriveKeyMaterial(sharedSecret)
	if err != nil {
		return "", err
	}

	ciphertext := raw[32:]
	var plaintext []byte
	switch mode {
	case EncX25519ChaCha20Poly1305:
		plaintext, err = openChaChaCiphertext(material.key, material.nonce, ciphertext)
		if err != nil {
			plaintext, err = openChaChaCiphertext(sharedSecret, material.nonce, ciphertext)
			if err != nil {
				return "", err
			}
		}
	default:
		block, err := aes.NewCipher(material.key)
		if err != nil {
			return "", err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		plaintext, err = aead.Open(nil, material.nonce, ciphertext, nil)
		if err != nil {
			return "", err
		}
	}

	if len(plaintext) == 0 {
		return "", fmt.Errorf("decrypted payload is empty")
	}
	declaredLength := int(plaintext[0])
	if declaredLength > len(plaintext)-1 {
		return "", fmt.Errorf("invalid decrypted payload length")
	}
	return string(plaintext[1 : 1+declaredLength]), nil
}

func openChaChaCiphertext(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

type keyMaterial struct {
	key   []byte
	nonce []byte
}

func deriveKeyMaterial(sharedSecret []byte) (*keyMaterial, error) {
	material := make([]byte, 44)
	h := hkdf.New(sha256.New, sharedSecret, make([]byte, 32), []byte(kdfInfo))
	if _, err := io.ReadFull(h, material); err != nil {
		return nil, err
	}
	return &keyMaterial{
		key:   material[:32],
		nonce: material[32:],
	}, nil
}
