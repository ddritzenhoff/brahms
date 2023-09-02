package challenge

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"go.uber.org/zap"
)

// ChallengeSize represents the number of bytes a challenge is composed of.
const ChallengeSize int = 32

var (
	ErrInvalidDifficulty = errors.New("invalid difficulty level")
)

// The Challenger remains a list of 64B keys that are regularly rotated in the given interval.
// When generating a challenge the newest key in the rotation is used, for verification all keys in the rotation are valid.
type Challenger struct {
	keyRotation [][]byte
	r           int
}

// NewChallenger Generates a Challenger that accepts solved challenges generated in the timeframe [now-iv*(r+1), now-iv*r]
// iv describes the interval in which a key rotation occurs, r is the number of keys that stays valid
// A reasonable default could be iv=15s and r=4
func NewChallenger(iv time.Duration, r int) (*Challenger, error) {
	firstKey := make([]byte, 64)
	_, err := rand.Read(firstKey)
	if err != nil {
		return nil, err
	}
	ch := Challenger{
		keyRotation: [][]byte{firstKey},
		r:           r,
	}
	ch.startTicker(iv)
	return &ch, nil
}

// This ticker takes care of the actual key rotation in regular intervals iv
func (ch *Challenger) startTicker(iv time.Duration) {
	go func() {
		for range time.NewTicker(iv).C {
			newKey := make([]byte, 64)
			_, err := rand.Read(newKey)
			if err != nil {
				zap.L().Panic("Could not generate new key for Challenger", zap.Error(err))
			}
			if len(ch.keyRotation) < ch.r {
				ch.keyRotation = append(ch.keyRotation, newKey)
			} else {
				ch.keyRotation = append(ch.keyRotation[1:], newKey)
			}
		}
	}()
}

// NewChallenge returns the 32B hash generated by concatenating the current key rotation with the client address.
// These bytes can later be generated again deterministically to check whether a given challenge was generated with one of the keys in rotation
func (ch *Challenger) NewChallenge(identity []byte) ([]byte, error) {
	hashFunc := sha256.New()
	hashFunc.Write(append(ch.keyRotation[len(ch.keyRotation)-1], identity...))

	return hashFunc.Sum(nil), nil
}

// IsSolvedCorrectly validates a solved challenge with the generated nonce
// It checks that the challenge was generated by one of the currently active keys and that the solution satisfies the given difficulty
func (ch *Challenger) IsSolvedCorrectly(challenge []byte, nonce []byte, identity []byte, difficulty int) (bool, error) {
	hashFun := sha256.New()
	hashFun.Write(append(challenge, nonce...))
	checkHash := hashFun.Sum(nil)

	if difficulty >= len(checkHash)*8 || difficulty < 0 {
		zap.L().Error("Difficulty is not valid for utilized hash function", zap.Int("difficulty", difficulty))
		return false, ErrInvalidDifficulty
	}

	if countLeadingZeros(checkHash) < difficulty {
		return false, nil
	}

	challengeValid := false
	for i := len(ch.keyRotation) - 1; i >= 0; i-- {
		hashFun.Reset()
		_, err := hashFun.Write(append(ch.keyRotation[i], identity...))
		if err != nil {
			return false, err
		}
		if bytes.Equal(hashFun.Sum(nil), challenge) {
			challengeValid = true
			break
		}
	}
	return challengeValid, nil
}
