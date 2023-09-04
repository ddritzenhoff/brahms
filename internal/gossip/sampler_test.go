package gossip

import (
	"bytes"
	"testing"
)

func TestSampler_Next(t *testing.T) {
	t.Parallel()

	t.Run("empty sampler is filled", func(t *testing.T) {
		sampler := Sampler{
			bias:            []byte{0x00, 0x01},
			elem:            nil,
			currentElemHash: nil,
		}
		mockAddr := "1.2.3.4:5678"
		mockIdentity := make([]byte, IdentitySize) // 0x0000..00
		node, err := NewNode(mockIdentity, mockAddr)
		if err != nil {
			t.Error(err)
		}
		sampler.Next(*node)

		if sampler.elem == nil {
			t.Error("Empty sampler did not accept new node")
		}
		if sampler.currentElemHash == nil || len(sampler.currentElemHash) != 32 {
			t.Error("Empty sampler did not save new element hash")
		}
	})

	t.Run("sampler replaces internal element", func(t *testing.T) {
		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := make([]byte, IdentitySize)
		oldNode, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}
		ffSlice := sliceRepeat(32, byte(0xFF))
		sampler := Sampler{
			bias:            []byte{0x00, 0x01},
			elem:            oldNode,
			currentElemHash: ffSlice,
		}
		mockAddr2 := "3.4.5.6:7890"
		mockIdentity2 := sliceRepeat(32, byte(0x11))
		node, err := NewNode(mockIdentity2, mockAddr2)
		if err != nil {
			t.Error(err)
		}
		sampler.Next(*node)

		if sampler.elem.Address != node.Address {
			t.Error("Sampler did not replace internal node Address")
		}
		if !bytes.Equal(sampler.elem.Identity.ToBytes(), node.Identity.ToBytes()) {
			t.Error("Sampler did not replace internal node Identity")
		}
		if bytes.Equal(sampler.currentElemHash, ffSlice) {
			t.Error("Sampler did not replace internal element hash")
		}
	})

	t.Run("sampler does not replace internal element", func(t *testing.T) {
		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := sliceRepeat(IdentitySize, byte(0x01))
		oldNode, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}
		zeroSlice := sliceRepeat(32, byte(0x00))
		sampler := Sampler{
			bias:            []byte{0x00, 0x01},
			elem:            oldNode,
			currentElemHash: zeroSlice,
		}
		mockAddr2 := "3.4.5.6:7890"
		mockIdentity2 := sliceRepeat(32, byte(0x11))
		node, err := NewNode(mockIdentity2, mockAddr2)
		if err != nil {
			t.Error(err)
		}
		sampler.Next(*node)

		if sampler.elem.Address != oldNode.Address {
			t.Error("Sampler replaced internal node Address")
		}
		if !bytes.Equal(sampler.elem.Identity.ToBytes(), oldNode.Identity.ToBytes()) {
			t.Error("Sampler replaced internal node Identity")
		}
		if !bytes.Equal(sampler.currentElemHash, zeroSlice) {
			t.Error("Sampler replaced internal element hash")
		}
	})
}

func TestSampler_Sample(t *testing.T) {
	t.Parallel()

	t.Run("sample returns internal node reference", func(t *testing.T) {
		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := sliceRepeat(IdentitySize, byte(0x01))
		node, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}
		sampler := Sampler{
			bias:            []byte{0x00, 0x01},
			elem:            node,
			currentElemHash: nil,
		}

		sampledNode := sampler.Sample()
		if sampledNode.Address != mockAddr1 {
			t.Error("Sampler did not return internal node reference Address")
		}
		if !bytes.Equal(sampledNode.Identity.ToBytes(), mockIdentity1) {
			t.Error("Sampler did not return internal node reference Identity")
		}
	})
}

func TestSamplerGroup_NewSampler(t *testing.T) {
	t.Parallel()

	t.Run("SamplerGroup is initialized correctly", func(t *testing.T) {
		sg, err := NewSamplerGroup(10)
		if err != nil {
			t.Error(err)
		}
		if len(sg.samplers) != 10 {
			t.Error("SamplerGroup has incorrect amount of internal samplers")
		}
		for _, s := range sg.samplers {
			if s.bias == nil || len(s.bias) == 0 {
				t.Error("Sampler in SamplerGroup is not initialized")
			}
		}
	})
}

func TestSamplerGroup_Update(t *testing.T) {
	t.Parallel()

	t.Run("SamplerGroup update changes internal state of all Samplers ", func(t *testing.T) {
		zeroSlice := sliceRepeat(32, byte(0x00))
		ffSlice := sliceRepeat(32, byte(0xFF))

		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := sliceRepeat(IdentitySize, byte(0x01))
		node1, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}

		mockAddr2 := "3.4.5.6:7890"
		mockIdentity2 := sliceRepeat(IdentitySize, byte(0x11))
		node2, err := NewNode(mockIdentity2, mockAddr2)
		if err != nil {
			t.Error(err)
		}

		sg := SamplerGroup{
			samplers: []Sampler{
				{
					bias:            []byte{0x01, 0x02},
					elem:            node1,
					currentElemHash: zeroSlice,
				},
				{
					bias:            []byte{0x02, 0x01},
					elem:            node2,
					currentElemHash: ffSlice,
				},
			},
		}

		mockAddr3 := "5.6.7.8:9012"
		mockIdentity3 := sliceRepeat(IdentitySize, byte(0x22))
		node3, err := NewNode(mockIdentity3, mockAddr3)
		if err != nil {
			t.Error(err)
		}
		sg.Update([]Node{*node3})

		if sg.samplers[0].elem.Address != node1.Address {
			t.Error("SamplerGroup updated first Sampler Address")
		}
		if !bytes.Equal(sg.samplers[0].elem.Identity.ToBytes(), node1.Identity.ToBytes()) {
			t.Error("SamplerGroup updated first Sampler Identity")
		}
		if sg.samplers[1].elem.Address != node3.Address {
			t.Error("SamplerGroup did not update second Sampler Address")
		}
		if !bytes.Equal(sg.samplers[1].elem.Identity.ToBytes(), node3.Identity.ToBytes()) {
			t.Error("SamplerGroup did not update second Sampler Identity")
		}
	})
}

func TestSamplerGroup_SampleAll(t *testing.T) {
	t.Parallel()

	t.Run("SamplerGroup returns all internal node references", func(t *testing.T) {
		mockAddr1 := "1.2.3.4:5678"
		mockIdentity1 := sliceRepeat(IdentitySize, byte(0x01))
		node1, err := NewNode(mockIdentity1, mockAddr1)
		if err != nil {
			t.Error(err)
		}

		mockAddr2 := "3.4.5.6:7890"
		mockIdentity2 := sliceRepeat(IdentitySize, byte(0x11))
		node2, err := NewNode(mockIdentity2, mockAddr2)
		if err != nil {
			t.Error(err)
		}

		sg := SamplerGroup{
			samplers: []Sampler{
				{
					bias:            []byte{0x01, 0x02},
					elem:            node1,
					currentElemHash: []byte{0x00, 0x00},
				},
				{
					bias:            []byte{0x02, 0x01},
					elem:            node2,
					currentElemHash: []byte{0x00, 0x00},
				},
				{
					bias:            []byte{0x03, 0x02},
					elem:            nil,
					currentElemHash: nil,
				},
			},
		}

		internalNodes := sg.SampleAll()
		if len(internalNodes) != 2 {
			t.Error("SamplerGroup did not return all internal nodes")
		}
		if internalNodes[0].Address != node1.Address || !bytes.Equal(internalNodes[0].Identity.ToBytes(), node1.Identity.ToBytes()) || internalNodes[1].Address != node2.Address || !bytes.Equal(internalNodes[1].Identity.ToBytes(), node2.Identity.ToBytes()) {
			t.Error("SamplerGroup did not return correct internal nodes")
		}
	})
}

func sliceRepeat[T any](size int, v T) []T {
	retVal := make([]T, 0, size)
	for i := 0; i < size; i++ {
		retVal = append(retVal, v)
	}
	return retVal
}
