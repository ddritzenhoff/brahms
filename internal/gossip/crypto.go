package gossip

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"gossiphers/internal/config"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

const (
	PacketKeySize = 32
	gcmNonceSize  = 12
)

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
		hash, err := hex.DecodeString(dirEntry.Name())
		if err != nil {
			return nil, fmt.Errorf("could not decode file name. Is the identity malformed? file name: %s", dirEntry.Name())
		}
		id, err := NewIdentity(hash)
		if err != nil {
			return nil, fmt.Errorf("could not construct identity from directory entry: %s", dirEntry.Name())
		}
		filePath := filepath.Join(cfg.HostkeysPath, dirEntry.Name())

		// Read the file contents
		fileBytes, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}

		// Decode PEM blocks
		pemBlock, _ := pem.Decode(fileBytes)
		if pemBlock == nil {
			return nil, fmt.Errorf("no PEM block found within the file: filepath %s", filePath)
		}

		// Check the PEM block type
		switch pemBlock.Type {
		case "RSA PUBLIC KEY":
			// Decode public key
			publicKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
			if err != nil {
				return nil, err
			}

			// Verify whether the public key actually belongs to the identity.
			genID, err := generateIdentity(publicKey)
			if err != nil {
				return nil, err
			}
			if genID.String() != id.String() {
				return nil, fmt.Errorf("mapping from public key to identity is incorrect: id %s, genID %s", id.String(), genID.String())
			}
			idToPub[*id] = *publicKey

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
	id, err := NewIdentity(h[:])
	if err != nil {
		return nil, err
	}
	return id, nil
}

// DecryptPacket decrypts a packet.
// The first bytes of the packet (equivalent to the size of the peers private key)
// contain the RSA-OAEP-encrypted 32B AES-GCM key and 12B nonce, which are used to then decrypt the rest of the packet
func (c *Crypto) DecryptPacket(ciphertext []byte) ([]byte, error) {
	aesKeyAndNonceBytes, err := rsa.DecryptOAEP(sha256.New(), nil, c.cfg.PrivateKey, ciphertext[:c.cfg.PrivateKey.Size()], nil)
	if err != nil {
		zap.L().Error("unable to decrypt packet key", zap.Error(err))
		return nil, err
	}
	aesBlock, err := aes.NewCipher(aesKeyAndNonceBytes[:PacketKeySize])
	if err != nil {
		zap.L().Error("unable to import packet aes key", zap.Error(err))
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		zap.L().Error("unable to create GCM for decryption", zap.Error(err))
		return nil, err
	}

	decryptedBytes := make([]byte, 0)
	decryptedBytes, err = aesGCM.Open(decryptedBytes, aesKeyAndNonceBytes[PacketKeySize:], ciphertext[c.cfg.PrivateKey.Size():], nil)
	if err != nil {
		zap.L().Warn("unable to decrypt message with aes gcm", zap.Error(err))
		return nil, err
	}

	return decryptedBytes, nil
}

// EncryptPacket encrypts a packet, by randomly generating an AES-GCM key and nonce to encrypt the message.
// The key and nonce are then RSA-OAEP encrypted with the receivers public key and prepended to the message.
func (c *Crypto) EncryptPacket(msg []byte, id Identity) ([]byte, error) {
	pub, exists := c.idToPub[id]
	if !exists {
		zap.L().Error("identity to public key mapping does not exist", zap.String("id", id.String()))
		return nil, fmt.Errorf("identity to public key mapping does not exist: id %s", id.String())
	}

	aesKeyAndNonceBytes := make([]byte, PacketKeySize+gcmNonceSize)
	_, err := rand.Read(aesKeyAndNonceBytes)
	if err != nil {
		zap.L().Error("could not generate aes key and iv", zap.Error(err))
		return nil, err
	}

	aesBlock, err := aes.NewCipher(aesKeyAndNonceBytes[:PacketKeySize])
	if err != nil {
		zap.L().Error("unable to initialize generated aes key", zap.Error(err))
		return nil, err
	}

	encryptedAesKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pub, aesKeyAndNonceBytes, nil)
	if err != nil {
		zap.L().Error("unable to encrypt aes key", zap.Error(err))
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	encryptedMessage := make([]byte, 0)
	encryptedMessage = aesGCM.Seal(encryptedMessage, aesKeyAndNonceBytes[PacketKeySize:], msg, nil)

	ciphertext := encryptedAesKey
	ciphertext = append(ciphertext, encryptedMessage...)
	return ciphertext, nil
}

// Sign signs data with rsa-sha256.
func (c *Crypto) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, c.cfg.PrivateKey, crypto.SHA256, h[:])
}

// VerifySignature verifies the message using a rsa-sha256 signature.
func (c *Crypto) VerifySignature(message []byte, sig []byte, id Identity) error {
	pub, exists := c.idToPub[id]
	if !exists {
		zap.L().Error("identity to public key mapping does not exist", zap.String("id", id.String()))
		return fmt.Errorf("identity to public key mapping does not exist: id %s", id.String())
	}
	h := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(&pub, crypto.SHA256, h[:], sig)
}
