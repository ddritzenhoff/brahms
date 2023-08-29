package challenge

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
)

// NonceSize represents the number of bytes a nonce is composed of.
const NonceSize int = 8

func SolveChallenge(challenge []byte, difficulty int, ctx context.Context) ([]byte, error) {
	checkHash := sha256.New()

	var nonce uint64 = 0
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, nonce)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			_, err := checkHash.Write(append(challenge, nonceBytes...))
			if err != nil {
				return nil, err
			}
			if countLeadingZeros(checkHash.Sum(nil)) >= difficulty {
				return nonceBytes, nil
			}
			checkHash.Reset()
			nonce = nonce + 1
			binary.BigEndian.PutUint64(nonceBytes, nonce)
		}
	}
}
