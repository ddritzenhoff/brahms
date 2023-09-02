package gossip

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"gossiphers/internal/config"
	"os"
	"path/filepath"
	"testing"
)

const RSAKeySize int = 4096

func TestCrypto_NewCrypto(t *testing.T) {
	t.Parallel()
	t.Run("creates a new Crypto instance", func(t *testing.T) {
		// Create a temporary directory for testing
		tempDir, err := os.MkdirTemp("", "crypto_test")
		if err != nil {
			t.Fatal("Error creating temporary directory:", err)
		}
		defer os.RemoveAll(tempDir) // Clean up the temporary directory when done

		// Generate a test RSA key pair and save it to a file in the temporary directory
		privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
		if err != nil {
			t.Fatal("Error generating RSA key pair:", err)
		}

		pubKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
		pubKeyPEM := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubKeyBytes,
		}
		id, err := generateIdentity(&privateKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		str := id.String()
		pubKeyFilePath := filepath.Join(tempDir, str)
		err = os.WriteFile(pubKeyFilePath, pem.EncodeToMemory(pubKeyPEM), 0644)
		if err != nil {
			t.Fatal("Error writing public key to file:", err)
		}

		// Create a temporary GossipConfig for testing
		cfg := &config.GossipConfig{
			HostkeysPath: tempDir,
		}

		// Test case 1: Successful initialization
		cryptoInstance, err := NewCrypto(cfg)
		if err != nil {
			t.Fatal("Crypto initialization failed:", err)
		}

		// Check that the crypto instance has the expected public key
		if len(cryptoInstance.idToPub) != 1 {
			t.Fatal("Unexpected number of public keys in crypto instance:", len(cryptoInstance.idToPub))
		}

		// Test case 2: Folder not found
		nonExistentDir := "non_existent_directory"
		cfg.HostkeysPath = nonExistentDir
		_, err = NewCrypto(cfg)
		if err == nil {
			t.Fatal("Crypto initialization should fail for a non-existent directory, but it didn't.")
		}

		// Test case 3: Invalid PEM block
		invalidPEMFilePath := filepath.Join(tempDir, "invalid.pem")
		err = os.WriteFile(invalidPEMFilePath, []byte("invalid PEM data"), 0644)
		if err != nil {
			t.Fatal("Error writing invalid PEM data to file:", err)
		}

		cfg.HostkeysPath = tempDir
		_, err = NewCrypto(cfg)
		if err == nil {
			t.Fatal("Crypto initialization should fail for a file with invalid PEM data, but it didn't.")
		}
	})
}

func TestCrypto_GenerateIdentity(t *testing.T) {
	t.Parallel()
	t.Run("generates a valid identity", func(t *testing.T) {
		// Generate an RSA key pair for testing
		privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
		if err != nil {
			t.Fatal("Error generating RSA key pair:", err)
		}

		// Generate the Identity using the generateIdentity function
		identity, err := generateIdentity(&privateKey.PublicKey)
		if err != nil {
			t.Fatal("Error generating Identity:", err)
		}

		// Ensure the Identity has the correct size
		if len(string(*identity)) != sha256.Size {
			t.Fatalf("Identity has the wrong size: expected %d, received %d", sha256.Size, len(*identity))
		}

		// Ensure the String representation of the Identity is correct
		expectedString := hex.EncodeToString([]byte(*identity))
		if identity.String() != expectedString {
			t.Fatalf("String representation of Identity is incorrect: expected %s, received %s", expectedString, identity.String())
		}
	})
}

func TestCrypto_DecryptRSA(t *testing.T) {
	t.Parallel()
	t.Run("correctly decrypts data", func(t *testing.T) {
		// Generate an RSA key pair for testing
		privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
		if err != nil {
			t.Fatal("Error generating RSA key pair:", err)
		}

		// Create a Crypto instance with the public key
		c := &Crypto{
			cfg: &config.GossipConfig{
				PrivateKey: privateKey,
			},
			idToPub: map[Identity]rsa.PublicKey{
				"test_identity": privateKey.PublicKey,
			},
		}

		// Data to encrypt and decrypt
		message := []byte("Hello, World!")

		// Encrypt the message to obtain ciphertext
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, message, nil)
		if err != nil {
			t.Fatal("Error encrypting data:", err)
		}

		// Test case 1: Successful decryption
		plaintext, err := c.DecryptRSA(ciphertext)
		if err != nil {
			t.Fatal("Decryption failed:", err)
		}

		if !bytes.Equal(message, plaintext) {
			t.Fatal("Decrypted message does not match original message.")
		}

		// Test case 2: Decryption failure (invalid ciphertext)
		invalidCiphertext := []byte("InvalidCiphertext")
		_, err = c.DecryptRSA(invalidCiphertext)
		if err == nil {
			t.Fatal("Decryption failure should result in an error, but it didn't.")
		}
	})
}

func TestCrypto_EncryptRSA(t *testing.T) {
	t.Parallel()
	t.Run("correctly encrypts data", func(t *testing.T) {
		// Generate an RSA key pair for testing
		privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
		if err != nil {
			t.Fatal("Error generating RSA key pair:", err)
		}

		// Create a Crypto instance with the public key
		c := &Crypto{
			cfg: &config.GossipConfig{
				PrivateKey: privateKey,
			},
			idToPub: map[Identity]rsa.PublicKey{
				"test_identity": privateKey.PublicKey,
			},
		}

		// Data to encrypt
		message := []byte("Hello, World!")

		// Test case 1: Successful encryption
		ciphertext, err := c.EncryptRSA(message, "test_identity")
		if err != nil {
			t.Fatal("Encryption failed:", err)
		}

		// Test case 2: Identity not found
		_, err = c.EncryptRSA(message, "non_existent_identity")
		if err == nil {
			t.Fatal("Identity not found should result in an error, but it didn't.")
		}

		// Test case 3: Decryption
		decryptedMessage, err := c.DecryptRSA(ciphertext)
		if err != nil {
			t.Fatal("Decryption failed:", err)
		}
		if !bytes.Equal(message, decryptedMessage) {
			t.Fatal("Decrypted message does not match original message.")
		}
	})
}

func TestCrypto_Sign(t *testing.T) {
	t.Parallel()
	t.Run("creates a valid signature", func(t *testing.T) {
		// Create a Crypto instance with a known private key (for testing purposes)
		privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
		if err != nil {
			t.Fatal("Error generating RSA key pair:", err)
		}

		c := &Crypto{
			cfg: &config.GossipConfig{
				PrivateKey: privateKey,
			},
		}

		// Data to sign
		data := []byte("Hello, World!")

		// Call the Sign method
		signature, err := c.Sign(data)
		if err != nil {
			t.Fatal("Error signing data:", err)
		}

		// Verify the signature
		err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, hashData(data), signature)
		if err != nil {
			t.Fatal("Signature verification failed:", err)
		}
	})
}

func TestCrypto_VerifySignature(t *testing.T) {
	t.Parallel()
	t.Run("correctly verifies signature and returns error when applicable", func(t *testing.T) {
		// Generate an RSA key pair for testing
		privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
		if err != nil {
			t.Fatal("Error generating RSA key pair:", err)
		}

		// Create a Crypto instance with the public key
		c := &Crypto{
			cfg: &config.GossipConfig{
				PrivateKey: privateKey,
			},
			idToPub: map[Identity]rsa.PublicKey{
				"test_identity": privateKey.PublicKey,
			},
		}

		// Data to sign and verify
		message := []byte("Hello, World!")
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashData(message))
		if err != nil {
			t.Fatal("Error signing data:", err)
		}

		// Test case 1: Valid signature
		err = c.VerifySignature(message, signature, "test_identity")
		if err != nil {
			t.Fatal("Valid signature verification failed:", err)
		}

		// Test case 2: Invalid signature
		invalidSignature := []byte("InvalidSignature")
		err = c.VerifySignature(message, invalidSignature, "test_identity")
		if err == nil {
			t.Fatal("Invalid signature verification should fail but didn't.")
		}

		// Test case 3: Identity not found
		err = c.VerifySignature(message, signature, "non_existent_identity")
		if err == nil {
			t.Fatal("Identity not found verification should fail but didn't.")
		}
	})
}

func hashData(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
