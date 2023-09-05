package gossip

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"
)

func TestIdentity_NewIdentity(t *testing.T) {
	t.Parallel()
	t.Run("with valid hash", func(t *testing.T) {
		// Test valid input
		validHash := sliceRepeat(IdentitySize, byte(0x01))
		id, err := NewIdentity(validHash)
		if err != nil {
			t.Errorf("NewIdentity returned an error for valid input: %v", err)
		}

		// Verify the value of the created Identity
		if id.String() != hex.EncodeToString(validHash) {
			t.Errorf("NewIdentity returned unexpected Identity, expected: %s, got: %s", hex.EncodeToString(validHash), id.String())
		}
	})
	t.Run("with invalid hash", func(t *testing.T) {
		// Test invalid input (wrong size)
		invalidHash := make([]byte, IdentitySize-1)
		_, err := NewIdentity(invalidHash)
		if err == nil {
			t.Errorf("NewIdentity did not return an error for invalid input (wrong size)")
		}
	})
}

func TestIdentity_String(t *testing.T) {
	t.Parallel()
	t.Run("", func(t *testing.T) {
		// Create an Identity for testing
		validHash := sliceRepeat(IdentitySize, byte(0x01))
		id, err := NewIdentity(validHash)
		if err != nil {
			t.Error(err)
		}

		// Test the String method
		expectedString := hex.EncodeToString(validHash)
		if id.String() != expectedString {
			t.Errorf("Identity.String() returned unexpected result, expected: %s, got: %s", expectedString, id.String())
		}
	})
}

func TestNode_NewNode(t *testing.T) {
	t.Parallel()
	t.Run("with invalid identity (e.g., empty identity)", func(t *testing.T) {
		// Test valid input
		identityBytes := []byte("invalid_identity")
		address := "127.0.0.1:12345"
		_, err := NewNode(identityBytes, address)
		if err == nil {
			t.Errorf("NewNode returned an error for valid input: %v", err)
		}
	})
	t.Run("with proper address and identity", func(t *testing.T) {
		// Test valid input
		privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
		if err != nil {
			t.Fatal("Error generating RSA key pair:", err)
		}
		id, err := generateIdentity(&privateKey.PublicKey)
		if err != nil {
			t.Error(err)
		}
		address := "127.0.0.1:12345"
		node, err := NewNode(id.ToBytes(), address)
		if err != nil {
			t.Errorf("NewNode returned an error for valid input: %v", err)
		}

		// Verify the fields of the created node
		if node.Identity.String() != id.String() {
			t.Errorf("Node identity mismatch, expected: %s, got: %s", id.String(), node.Identity.String())
		}
		if node.Address != address {
			t.Errorf("Node address mismatch, expected: %s, got: %s", address, node.Address)
		}
	})
}

func TestNode_String(t *testing.T) {
	t.Parallel()
	t.Run("successfully generate string representation of node", func(t *testing.T) {
		// Create a node for testing
		// Generate a test RSA key pair and save it to a file in the temporary directory
		privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
		if err != nil {
			t.Fatal("Error generating RSA key pair:", err)
		}
		id, err := generateIdentity(&privateKey.PublicKey)
		if err != nil {
			t.Error(err)
		}

		address := "127.0.0.1:12345"
		node, err := NewNode(id.ToBytes(), address)
		if err != nil {
			t.Error(err)
		}

		// Test the String method
		expectedString := id.String() + "@" + address
		if node.String() != expectedString {
			t.Errorf("Node.String() returned unexpected result, expected: %s, got: %s", expectedString, node.String())
		}
	})
}
