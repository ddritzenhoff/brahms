package gossip

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"hash"
)

var (
	ErrInvalidSamplerAmount = errors.New("invalid amount of samplers, should be more than 0")
)

type Sampler struct {
	hash            hash.Hash
	elem            *Node
	currentElemHash []byte
}

func (s *Sampler) init() error {
	s.elem = nil
	bias := make([]byte, 64)
	_, err := rand.Read(bias)
	if err != nil {
		return err
	}
	s.hash = crypto.SHA256.New()
	_, err = s.hash.Write(bias)
	return err
}

func (s *Sampler) next(newElem Node) {
	if s.elem == nil {
		s.elem = &newElem
		s.currentElemHash = s.hash.Sum([]byte(newElem.Identity()))
	} else {
		newHash := s.hash.Sum([]byte(newElem.Identity()))
		// when new hash smaller than old hash, replace element
		if bytes.Compare(newHash, s.currentElemHash) < 0 {
			s.elem = &newElem
			s.currentElemHash = newHash
		}
	}
}

func (s *Sampler) sample() *Node {
	return s.elem
}

type SamplerGroup struct {
	samplers []Sampler
}

func (sg *SamplerGroup) init(size int) error {
	if size <= 0 {
		return ErrInvalidSamplerAmount
	}
	sg.samplers = make([]Sampler, size)
	for _, s := range sg.samplers {
		err := s.init()
		if err != nil {
			return err
		}
	}
	return nil
}

func (sg *SamplerGroup) sampleAll() []*Node {
	var samples []*Node
	for _, s := range sg.samplers {
		res := s.sample()
		if res != nil {
			samples = append(samples, res)
		}
	}
	return samples
}

func (sg *SamplerGroup) update(newElems []Node) {
	for _, newElem := range newElems {
		for _, s := range sg.samplers {
			s.next(newElem)
		}
	}
}
