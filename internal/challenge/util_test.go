package challenge

import "testing"

func TestCountLeadingZeros(t *testing.T) {
	t.Parallel()

	t.Run("Leading zeros are calculated correctly", func(t *testing.T) {
		n := countLeadingZeros([]byte{0b00000000, 0b00011110})
		if n != 11 {
			t.Error("Expected 11 leading zeros, got ", n)
		}
		n = countLeadingZeros([]byte{0b10000000, 0b00011110})
		if n != 0 {
			t.Error("Expected 0 leading zeros, got ", n)
		}
		n = countLeadingZeros([]byte{0b00000001, 0b00011110, 0b00011110, 0b00000000})
		if n != 7 {
			t.Error("Expected 7 leading zeros, got ", n)
		}
		n = countLeadingZeros([]byte{})
		if n != 0 {
			t.Error("Expected 0 leading zeros, got ", n)
		}
	})
}
