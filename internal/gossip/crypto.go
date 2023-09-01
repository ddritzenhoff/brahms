package gossip

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"gossiphers/internal/config"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// Identity represents a SHA256 hash of a public key.
type Identity string

// NewIdentity generates a new Identity given a string if it is of the correct size.
func NewIdentity(id string) (Identity, error) {
	if len(id) != sha256.Size {
		return "", fmt.Errorf("id of wrong size: expected %d, received %d", sha256.Size, len(id))
	}
	return Identity(id), nil
}

// Crypto represents a container for all of the cryptographic functionality within the gossip protocol.
type Crypto struct {
	cfg *config.GossipConfig
	// idToPub represents the mapping of Identities to RSA public keys.
	idToPub map[Identity]rsa.PublicKey
}

// NewCrypto creates a new Crypto instance.
func NewCrypto(cfg *config.GossipConfig) (*Crypto, error) {
	// List files in the folder
	dirEntries, err := os.ReadDir(cfg.HostkeysPath)
	if err != nil {
		zap.L().Error("could not read folder", zap.Error(err))
		return nil, err
	}

	idToPub := make(map[Identity]rsa.PublicKey)
	// Loop through the files
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}

		// Construct the full file path
		id, err := NewIdentity(dirEntry.Name())
		if err != nil {
			zap.L().Error("could not construct identity from directory entry", zap.String("dirEntry", dirEntry.Name()), zap.Error(err))
			continue
		}
		filePath := filepath.Join(cfg.HostkeysPath, string(id))

		// Read the file contents
		fileBytes, err := os.ReadFile(filePath)
		if err != nil {
			zap.L().Error("could not read file", zap.String("filepath", filePath), zap.Error(err))
			continue
		}

		// Decode PEM blocks
		pemBlock, _ := pem.Decode(fileBytes)
		if pemBlock == nil {
			zap.L().Error("no PEM block found in the file", zap.String("filepath", filePath))
			continue
		}

		// Check the PEM block type
		switch pemBlock.Type {
		case "RSA PUBLIC KEY":
			// Decode public key
			publicKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
			if err != nil {
				zap.L().Error("could not parse public key", zap.Error(err))
				continue
			}

			// Verify whether the public key actually belongs to the identity.
			genID, err := generateIdentity(publicKey)
			if err != nil {
				zap.L().Error("could not generate identity from public key", zap.Error(err))
				continue
			}
			if string(*genID) != string(id) {
				zap.L().Error("mapping from public key to identity is incorrect", zap.String("id", string(id)), zap.String("genID", string(*genID)))
				continue
			}
			idToPub[id] = *publicKey

		default:
			zap.L().Error("unsupported PEM block type, skipping", zap.String("block type", pemBlock.Type))
			continue
		}
	}
	c := Crypto{
		cfg,
		idToPub,
	}
	return &c, nil
}

// generateIdentity generates an Identity from a public key.
func generateIdentity(pubKey *rsa.PublicKey) (*Identity, error) {
	if pubKey == nil {
		return nil, errors.New("public key is nil")
	}
	pubKeyBytes := x509.MarshalPKCS1PublicKey(pubKey)
	h := sha256.Sum256(pubKeyBytes)
	id, err := NewIdentity(string(h[:]))
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// DecryptRSA decrypts data with the node's RSA private key.
func (c *Crypto) DecryptRSA(ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.cfg.PrivateKey, ciphertext, nil)
	if err != nil {
		zap.L().Error("unable to decrypt message", zap.Error(err))
		return nil, err
	}
	return plaintext, nil
}

// EncryptRSA encrypts data with an RSA public key.
func (c *Crypto) EncryptRSA(msg []byte, id Identity) ([]byte, error) {
	pub, exists := c.idToPub[id]
	if !exists {
		zap.L().Error("identity to public key mapping does not exist", zap.String("id", string(id)))
		return nil, fmt.Errorf("identity to public key mapping does not exist: id %s", string(id))
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pub, msg, nil)
	if err != nil {
		zap.L().Error("unable to encrypt message", zap.Error(err))
		return nil, err
	}
	return ciphertext, nil
}

// Sign signs data with rsa-sha256.
func (c *Crypto) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, c.cfg.PrivateKey, crypto.SHA256, d)
}

// VerifySignature verifies the message using a rsa-sha256 signature.
func (c *Crypto) VerifySignature(message []byte, sig []byte, id Identity) error {
	pub, exists := c.idToPub[id]
	if !exists {
		zap.L().Error("identity to public key mapping does not exist", zap.String("id", string(id)))
		return fmt.Errorf("identity to public key mapping does not exist: id %s", string(id))
	}
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(&pub, crypto.SHA256, d, sig)
}
