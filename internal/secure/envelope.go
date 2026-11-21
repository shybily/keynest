package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/shybily/keynest/internal/config"
)

const Algorithm = "RSA-OAEP-256+A256GCM"

type Envelope struct {
	Algorithm    string `json:"algorithm"`
	KeyID        string `json:"keyId"`
	Version      int    `json:"version"`
	EncryptedKey string `json:"encryptedKey"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

func GenerateKeyPair(bits int) (privatePEM, publicPEM []byte, err error) {
	if bits < 2048 {
		return nil, nil, fmt.Errorf("RSA key size must be at least 2048 bits")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return privatePEM, publicPEM, nil
}

func Encrypt(publicPEM []byte, keyID string, address config.Address, version int, plaintext []byte) (Envelope, error) {
	publicKey, err := parsePublicKey(publicPEM)
	if err != nil {
		return Envelope{}, err
	}
	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		return Envelope{}, err
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return Envelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	aad := associatedData(keyID, address, version)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, contentKey, aad)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Algorithm: Algorithm, KeyID: keyID, Version: version,
		EncryptedKey: base64.RawStdEncoding.EncodeToString(encryptedKey),
		Nonce:        base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.RawStdEncoding.EncodeToString(ciphertext),
	}, nil
}

func Decrypt(privatePEM []byte, envelope Envelope, address config.Address) ([]byte, error) {
	if envelope.Algorithm != Algorithm {
		return nil, fmt.Errorf("unsupported encryption algorithm %q", envelope.Algorithm)
	}
	privateKey, err := parsePrivateKey(privatePEM)
	if err != nil {
		return nil, err
	}
	return DecryptWithKey(privateKey, envelope, address)
}

func DecryptWithKey(privateKey *rsa.PrivateKey, envelope Envelope, address config.Address) ([]byte, error) {
	if envelope.Algorithm != Algorithm {
		return nil, fmt.Errorf("unsupported encryption algorithm %q", envelope.Algorithm)
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	aad := associatedData(envelope.KeyID, address, envelope.Version)
	encryptedKey, err := base64.RawStdEncoding.DecodeString(envelope.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted key: %w", err)
	}
	contentKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt content key: %w", err)
	}
	if len(contentKey) != 32 {
		return nil, fmt.Errorf("decrypted content key has invalid length")
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce has invalid length")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt configuration: %w", err)
	}
	return plaintext, nil
}

func ParsePrivateKey(privatePEM []byte) (*rsa.PrivateKey, error) {
	return parsePrivateKey(privatePEM)
}

func parsePublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key must be RSA")
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA public key must be at least 2048 bits")
	}
	return key, nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key must be RSA")
		}
		if key.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA private key must be at least 2048 bits")
		}
		return key, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA private key must be at least 2048 bits")
	}
	return key, nil
}

func associatedData(keyID string, address config.Address, version int) []byte {
	return fmt.Appendf(nil, "%s\n%s\n%s\n%s\n%d", keyID, address.Project,
		address.Environment, address.Service, version)
}
