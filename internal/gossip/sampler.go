package gossip

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"go.uber.org/zap"
)

var (
	ErrInvalidSamplerAmount = errors.New("invalid amount of samplers, should be more than 0")
)

type Sampler struct {
	bias            []byte
	elem            *Node
	currentElemHash []byte
}

func (s *Sampler) Init() error {
	s.elem = nil
	s.bias = make([]byte, 64)
	s.currentElemHash = nil
	_, err := rand.Read(s.bias)
	return err
}

func (s *Sampler) Next(newElem Node) {
	hashFunc := sha256.New()
	_, err := hashFunc.Write(append(s.bias, newElem.Identity...))
	if err != nil {
		zap.L().Panic("Unexpected error during hash calculation", zap.Error(err))
	}
	newHash := hashFunc.Sum(nil)

	if s.elem == nil || bytes.Compare(newHash, s.currentElemHash) < 0 {
		s.elem = &newElem
		s.currentElemHash = newHash
	}
}

func (s *Sampler) Sample() *Node {
	return s.elem
}

type SamplerGroup struct {
	samplers []Sampler
}

func (sg *SamplerGroup) Init(size int) error {
	if size <= 0 {
		return ErrInvalidSamplerAmount
	}
	sg.samplers = make([]Sampler, size)
	for i, s := range sg.samplers {
		err := s.Init()
		if err != nil {
			return err
		}
		sg.samplers[i] = s
	}
	return nil
}

func (sg *SamplerGroup) Update(newElems []Node) {
	for _, newElem := range newElems {
		for i, s := range sg.samplers {
			s.Next(newElem)
			sg.samplers[i] = s
		}
	}
}

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
