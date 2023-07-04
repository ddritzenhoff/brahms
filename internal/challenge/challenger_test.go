package challenge

import (
	"bytes"
	"testing"
)

func TestChallenger_NewChallenge(t *testing.T) {
	t.Parallel()
	t.Run("challenge is created using most recent hash", func(t *testing.T) {
		exampleKey := make([]byte, 64)
		for i := range exampleKey {
			exampleKey[i] = 0x12
		}
		ch := challenger{keyRotation: [][]byte{exampleKey}}

		res, err := ch.NewChallenge("10.0.0.0")
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(res, []byte{0xBB, 0x3B, 0xA2, 0xFE, 0x17, 0xED, 0xB9, 0x0A}) {
			t.Error("created challenge is not equal to the expected one: ", res)
		}
	})
}

func TestChallenger_IsSolvedCorrectly(t *testing.T) {
	t.Parallel()
	t.Run("solved challenged is accepted as correct", func(t *testing.T) {
		exampleKey := make([]byte, 64)
		for i := range exampleKey {
			exampleKey[i] = 0x12
		}
		ch := challenger{keyRotation: [][]byte{exampleKey}}

		challenge := []byte{0xBB, 0x3B, 0xA2, 0xFE, 0x17, 0xED, 0xB9, 0x0A}
		solution := []byte{0x00, 0x00, 0x00, 0x00, 0x04, 0xF6, 0xA9, 0x03}

		correct, err := ch.IsSolvedCorrectly(challenge, solution, "10.0.0.0", 28)
		if err != nil {
			t.Error(err)
		}
		if !correct {
			t.Error("correct solution is not recognized")
		}
	})

	t.Run("incorrect challenge solution is denied", func(t *testing.T) {
		exampleKey := make([]byte, 64)
		for i := range exampleKey {
			exampleKey[i] = 0x12
		}
		ch := challenger{keyRotation: [][]byte{exampleKey}}

		challenge := []byte{0xBB, 0x3B, 0xA2, 0xFE, 0x17, 0xED, 0xB9, 0x0A}
		solution := []byte{0x00, 0x00, 0x00, 0x00, 0x04, 0xF6, 0xA9, 0x02}

		correct, err := ch.IsSolvedCorrectly(challenge, solution, "10.0.0.0", 28)
		if err != nil {
			t.Error(err)
		}
		if correct {
			t.Error("incorrect solution is accepted")
		}
	})

	t.Run("challenge solution with insufficient difficulty is denied", func(t *testing.T) {
		exampleKey := make([]byte, 64)
		for i := range exampleKey {
			exampleKey[i] = 0x12
		}
		ch := challenger{keyRotation: [][]byte{exampleKey}}

		challenge := []byte{0xBB, 0x3B, 0xA2, 0xFE, 0x17, 0xED, 0xB9, 0x0A}
		solution := []byte{0x00, 0x00, 0x00, 0x00, 0x04, 0xF6, 0xA9, 0x03}

		correct, err := ch.IsSolvedCorrectly(challenge, solution, "10.0.0.0", 42)
		if err != nil {
			t.Error(err)
		}
		if correct {
			t.Error("incorrect solution is accepted")
		}
	})
}
