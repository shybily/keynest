package secure

import (
	"bytes"
	"testing"

	"github.com/shybily/keynest/internal/config"
)

func TestEnvelopeEncryptsAndBindsAddressAndVersion(t *testing.T) {
	privatePEM, publicPEM, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	address := config.Address{Project: "project", Environment: "prod", Service: "api"}
	plaintext := []byte(`{"database":{"password":"secret"}}`)
	envelope, err := Encrypt(publicPEM, "key-1", address, 12, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte(envelope.EncryptedKey + envelope.Nonce + envelope.Ciphertext)
	if bytes.Contains(encoded, []byte("secret")) {
		t.Fatal("encrypted envelope contains plaintext")
	}
	decoded, err := Decrypt(privatePEM, envelope, address)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("decrypted payload = %q", decoded)
	}
	wrongAddress := address
	wrongAddress.Service = "another-service"
	if _, err := Decrypt(privatePEM, envelope, wrongAddress); err == nil {
		t.Fatal("Decrypt() accepted a different service address")
	}
	envelope.Version++
	if _, err := Decrypt(privatePEM, envelope, address); err == nil {
		t.Fatal("Decrypt() accepted a different version")
	}
}
