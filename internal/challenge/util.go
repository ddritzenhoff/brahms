package challenge

import "math/bits"

func countLeadingZeros(data []byte) int {
	leadingZeros := 0
	for i := 0; i < len(data); i++ {
		byteLeading := bits.LeadingZeros8(data[i])
		leadingZeros = leadingZeros + byteLeading
		if byteLeading != 8 {
			break
		}
	}
	return leadingZeros
}
