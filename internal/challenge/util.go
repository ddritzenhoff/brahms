package challenge

import "math/bits"

// countLeadingZeros counts the total number of 0 bits from the beginning of the slice until a 1 is encountered, or until the the slice has been completely traversed.
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
