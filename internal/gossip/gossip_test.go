package gossip

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func Test_randSubset(t *testing.T) {
	t.Parallel()
	t.Run("with an empty slice and n == 0", func(t *testing.T) {
		emptySlice := []Node{}
		res, err := randSubset(emptySlice, 0)
		if err != nil {
			t.Error(err)
		}
		if len(res) != 0 {
			t.Error("expecting len of 0")
		}
	})
	t.Run("with a single-element slice with n = 1", func(t *testing.T) {
		nodes, err := createNodes(1)
		if err != nil {
			t.Error(err)
		}
		singleElementSlice := []Node{nodes[0]}
		resPtrs, err := randSubset(singleElementSlice, 1)
		if err != nil {
			t.Error(err)
		}
		res := dereferenceSlice(resPtrs)
		if len(res) != 1 {
			t.Error("Expected single-element slice, but got different length")
		}
		if res[0].Identity.String() != nodes[0].Identity.String() || res[0].Address != nodes[0].Address {
			t.Errorf("unexpected values. expected %s, received %s. expected %s, received %s", nodes[0].Identity.String(), res[0].Identity.String(), nodes[0].Address, res[0].Address)
		}
	})
	t.Run("with n == len(nodes)", func(t *testing.T) {
		uniqueSlice, err := createNodes(5)
		if err != nil {
			t.Error(err)
		}
		originalSlicePtrs, err := randSubset(uniqueSlice, 5)
		originalSlice := dereferenceSlice(originalSlicePtrs)
		if err != nil {
			t.Error(err)
		}
		if len(uniqueSlice) != len(originalSlice) {
			t.Error("Shuffled slice length differs from the original slice")
		}
		if reflect.DeepEqual(uniqueSlice, originalSlice) {
			t.Error("Shuffled slice is identical to the original slice")
		}
	})
	t.Run("with n > len(nodes)", func(t *testing.T) {
		largeSlice, err := createNodes(20)
		if err != nil {
			t.Error(err)
		}
		originalLargeSlicePtrs, err := randSubset(largeSlice, 40)
		if err != nil {
			t.Error(err)
		}
		originalLargeSlice := dereferenceSlice(originalLargeSlicePtrs)
		if len(largeSlice) != len(originalLargeSlice) {
			t.Error("Shuffled large slice length differs from the original slice")
		}
		if reflect.DeepEqual(largeSlice, originalLargeSlice) {
			t.Error("Shuffled large slice is identical to the original slice")
		}
	})
	t.Run("with n < len(nodes) and n > 0", func(t *testing.T) {
		repeatedSlice, err := createNodes(10)
		if err != nil {
			t.Error(err)
		}
		originalRepeatedSlicePtrs, err := randSubset(repeatedSlice, 5)
		if err != nil {
			t.Error(err)
		}
		if len(originalRepeatedSlicePtrs) != 5 {
			t.Errorf("expecting 5 but received %d", len(originalRepeatedSlicePtrs))
		}
	})
	t.Run("with n == 0 with non-empty slice", func(t *testing.T) {
		repeatedSlice, err := createNodes(10)
		if err != nil {
			t.Error(err)
		}
		originalRepeatedSlicePtrs, err := randSubset(repeatedSlice, 0)
		if err != nil {
			t.Error(err)
		}
		if originalRepeatedSlicePtrs == nil {
			t.Error("not supposed to have nil be returned. Expecting a slice of length 0")
		}
		if len(originalRepeatedSlicePtrs) != 0 {
			t.Error("expecting slice of length 0")
		}
	})
	t.Run("with n < 0", func(t *testing.T) {
		s, err := createNodes(10)
		if err != nil {
			t.Error(err)
		}
		_, err = randSubset(s, -3)
		if err == nil {
			t.Error("expecting errror")
		}
	})
}

func dereferenceSlice(nodes []*Node) []Node {
	res := make([]Node, len(nodes))
	for ii, node := range nodes {
		res[ii] = *node
	}
	return res
}

func createNodes(n int) ([]Node, error) {
	nodes := make([]Node, n)
	for ii := 0; ii < n; ii++ {

		h := sha256.Sum256([]byte(fmt.Sprintf("id%d", ii)))
		id, err := NewIdentity(h[:])
		if err != nil {
			return nil, err
		}
		node := Node{
			Identity: *id,
			Address:  fmt.Sprintf("addr%d", ii),
		}
		nodes[ii] = node
	}
	return nodes, nil
}
