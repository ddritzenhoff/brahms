package challenge

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestSolveChallenge(t *testing.T) {
	t.Parallel()
	t.Run("simple challenge is solved quickly", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		challenge := []byte{0xBB, 0x3B, 0xA2, 0xFE, 0x17, 0xED, 0xB9, 0x0A}

		solution, err := SolveChallenge(challenge, 8, ctx)
		if err != nil {
			t.Error(err)
		}

		hashFunc := sha256.New()
		_, err = hashFunc.Write(append(challenge, solution...))
		if err != nil {
			t.Error(err)
		}

		if hashFunc.Sum(nil)[0] != 0x00 {
			t.Error("Generated solution is not valid")
		}
	})

	t.Run("difficult challenge times out with context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
		defer cancel()

		challenge := []byte{0xBB, 0x3B, 0xA2, 0xFE, 0x17, 0xED, 0xB9, 0x0A}

		startTime := time.Now()
		solution, err := SolveChallenge(challenge, 42, ctx)
		elapsedTime := time.Since(startTime)
		if err == nil {
			t.Error("challenge was unexpectedly solved", solution)
		}
		if !errors.Is(err, ctx.Err()) {
			t.Error("unexpected error", err)
		}
		if elapsedTime.Milliseconds() > 60 {
			t.Error("execution was longer than expected")
		}
	})
}
