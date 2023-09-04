package gossip

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"go.uber.org/zap"
)

var (
	ErrInvalidSamplerAmount = errors.New("invalid amount of samplers, should be more than 0")
)

// Sampler represents the sampler as described within the Brahms algorithm. It is a building block for uniform sampling of unique elements from a data stream.
type Sampler struct {
	bias            []byte
	elem            *Node
	currentElemHash []byte
}

// Init creates a random bias element, which will be used in a random min-wise independent hash function.
func (s *Sampler) Init() error {
	s.elem = nil
	s.bias = make([]byte, 64)
	s.currentElemHash = nil
	_, err := rand.Read(s.bias)
	return err
}

// Next applies the random min-wise independent hash function to the passed-in Node, keeping whichever node has the lower hash value.
func (s *Sampler) Next(newElem Node) {
	hashFunc := sha256.New()
	_, err := hashFunc.Write(append(s.bias, newElem.Identity.ToBytes()...))
	if err != nil {
		zap.L().Panic("Unexpected error during hash calculation", zap.Error(err))
	}
	newHash := hashFunc.Sum(nil)

	if s.elem == nil || bytes.Compare(newHash, s.currentElemHash) < 0 {
		s.elem = &newElem
		s.currentElemHash = newHash
	}
}

// Sample returns a reference to the currently stored node.
func (s *Sampler) Sample() *Node {
	return s.elem
}

// SamplerGroup represents a collection of Samplers.
type SamplerGroup struct {
	samplers []Sampler
}

// NewSamplerGroup creates an initialized collection of Samplers.
func NewSamplerGroup(size int) (*SamplerGroup, error) {
	if size <= 0 {
		return nil, ErrInvalidSamplerAmount
	}
	samplers := make([]Sampler, size)
	for i, s := range samplers {
		err := s.Init()
		if err != nil {
			return nil, err
		}
		samplers[i] = s
	}

	return &SamplerGroup{
		samplers: samplers,
	}, nil
}

// Update invokes the min-wise indepedent hash function for each sampler with the given elements.
func (sg *SamplerGroup) Update(newElems []Node) {
	for _, newElem := range newElems {
		for i, s := range sg.samplers {
			s.Next(newElem)
			sg.samplers[i] = s
		}
	}
}

// RandomSubset returns a random subset of length n of the ViewList.
func (sg *SamplerGroup) RandomNodeSubset(n int) ([]*Node, error) {
	if n > len(sg.samplers) || n <= 0 {
		return nil, fmt.Errorf("RandomSubset: required size between 0 (non-inclusive) and |sg.samplers|")
	}
	copySlice := make([]*Sampler, len(sg.samplers))
	for ii := 0; ii < len(sg.samplers); ii++ {
		copySlice = append(copySlice, &sg.samplers[ii])
	}
	for i := n - 1; i > 0; i-- {
		// Generate a random index between 0 and i (inclusive)
		bigJ, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}
		if !bigJ.IsInt64() {
			return nil, fmt.Errorf("j is not of type int64: %s", bigJ.String())
		}
		j := bigJ.Int64()

		// Swap the elements at i and j
		copySlice[i], copySlice[j] = copySlice[j], copySlice[i]
	}

	nodes := make([]*Node, n)
	for ii := 0; ii < n; ii++ {
		nodes = append(nodes, copySlice[ii].Sample())
	}
	return nodes, nil
}

// SampleAll samples each sampler within the collection.
func (sg *SamplerGroup) SampleAll() []*Node {
	var samples []*Node
	for _, s := range sg.samplers {
		res := s.Sample()
		if res != nil {
			samples = append(samples, res)
		}
	}
	return samples
}
