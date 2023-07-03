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
		node := Node{Address: "someAddress"}
		sampler.Next(node)

		if *sampler.elem != node {
			t.Error("Empty sampler did not accept new node")
		}
		if sampler.currentElemHash == nil || len(sampler.currentElemHash) != 32 {
			t.Error("Empty sampler did not save new element hash")
		}
	})

	t.Run("sampler replaces internal element", func(t *testing.T) {
		oldNode := Node{Address: "someOldAddress"}
		ffSlice := sliceRepeat(32, byte(0xFF))
		sampler := Sampler{
			bias:            []byte{0x00, 0x01},
			elem:            &oldNode,
			currentElemHash: ffSlice,
		}
		node := Node{Address: "someAddress"}
		sampler.Next(node)

		if *sampler.elem != node {
			t.Error("Sampler did not replace internal node")
		}
		if bytes.Equal(sampler.currentElemHash, ffSlice) {
			t.Error("Sampler did not replace internal element hash")
		}
	})

	t.Run("sampler does not replace internal element", func(t *testing.T) {
		oldNode := Node{Address: "someOldAddress"}

		zeroSlice := sliceRepeat(32, byte(0x00))
		sampler := Sampler{
			bias:            []byte{0x00, 0x01},
			elem:            &oldNode,
			currentElemHash: zeroSlice,
		}

		sampler.Next(Node{Address: "someAddress"})

		if *sampler.elem != oldNode {
			t.Error("Sampler replaced internal node")
		}
		if !bytes.Equal(sampler.currentElemHash, zeroSlice) {
			t.Error("Sampler replaced internal element hash")
		}
	})
}

func TestSampler_Sample(t *testing.T) {
	t.Parallel()

	t.Run("sample returns internal node reference", func(t *testing.T) {
		node := Node{Address: "someOldAddress"}
		sampler := Sampler{
			bias:            []byte{0x00, 0x01},
			elem:            &node,
			currentElemHash: nil,
		}

		sampledNode := sampler.Sample()
		if *sampledNode != node {
			t.Error("Sampler did not return internal node reference")
		}
	})
}

func TestSamplerGroup_Init(t *testing.T) {
	t.Parallel()

	t.Run("SamplerGroup is initialized correctly", func(t *testing.T) {
		sg := SamplerGroup{}
		err := sg.Init(10)

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

		nodeOld1 := Node{
			Address: "nodeOld1",
		}
		nodeOld2 := Node{
			Address: "nodeOld2",
		}

		sg := SamplerGroup{
			samplers: []Sampler{
				{
					bias:            []byte{0x01, 0x02},
					elem:            &nodeOld1,
					currentElemHash: zeroSlice,
				},
				{
					bias:            []byte{0x02, 0x01},
					elem:            &nodeOld2,
					currentElemHash: ffSlice,
				},
			},
		}

		nodeNew1 := Node{
			Address: "nodeNew1",
		}
		sg.Update([]Node{nodeNew1})

		if *sg.samplers[0].elem != nodeOld1 {
			t.Error("SamplerGroup did not update first Sampler")
		}
		if *sg.samplers[1].elem != nodeNew1 {
			t.Error("SamplerGroup updated second Sampler")
		}
	})
}

func TestSamplerGroup_SampleAll(t *testing.T) {
	t.Parallel()

	t.Run("SamplerGroup returns all internal node references", func(t *testing.T) {
		node1 := Node{
			Address: "node1",
		}
		node2 := Node{
			Address: "node2",
		}

		sg := SamplerGroup{
			samplers: []Sampler{
				{
					bias:            []byte{0x01, 0x02},
					elem:            &node1,
					currentElemHash: []byte{0x00, 0x00},
				},
				{
					bias:            []byte{0x02, 0x01},
					elem:            &node2,
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
		if *internalNodes[0] != node1 || *internalNodes[1] != node2 {
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
