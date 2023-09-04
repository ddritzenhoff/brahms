package gossip

import (
	"reflect"
	"testing"
)

func TestView_WithBootstrapNodes(t *testing.T) {
	t.Parallel()
	t.Run("the view's node slice is set to the passed-in bootstrap node slice", func(t *testing.T) {
		// Create some mock nodes and append them to the View
		node1 := Node{
			Identity: "id1",
			Address:  "node1.example.com",
		}

		node2 := Node{
			Identity: "id2",
			Address:  "node2.example.com",
		}

		// Create a new View
		view := NewView(WithBootstrapNodes([]Node{node1, node2}))

		// Check if the number of nodes matches the expected count
		if len(view.nodes) != 2 {
			t.Fatalf("Expected 2 nodes, but got %d", len(view.nodes))
		}

		// Check if the nodes were appended correctly
		if view.nodes[0].Identity != "id1" || view.nodes[0].Address != "node1.example.com" {
			t.Fatalf("Node 1 was not appended correctly")
		}

		if view.nodes[1].Identity != "id2" || view.nodes[1].Address != "node2.example.com" {
			t.Fatalf("Node 2 was not appended correctly")
		}
	})
}

func TestView_Clear(t *testing.T) {
	t.Parallel()
	t.Run("clear removes all elements from the view's node slice", func(t *testing.T) {
		// Create a new View
		view := NewView()

		// Create some mock nodes and append them to the View
		node1 := Node{
			Identity: "id1",
			Address:  "node1.example.com",
		}

		node2 := Node{
			Identity: "id2",
			Address:  "node2.example.com",
		}

		view.Append(node1)
		view.Append(node2)

		// Clear the View
		view.Clear()

		// Check if the View is empty after clearing
		if len(view.nodes) != 0 {
			t.Fatalf("Expected an empty View after clearing, but got %d nodes", len(view.nodes))
		}
	})
}

func TestView_Append(t *testing.T) {
	t.Parallel()
	t.Run("append adds an element to the end of the node slice", func(t *testing.T) {
		// Create a new View
		view := NewView()

		// Create some mock nodes
		node1 := Node{
			Identity: "id1",
			Address:  "node1.example.com",
		}

		node2 := Node{
			Identity: "id2",
			Address:  "node2.example.com",
		}

		// Append nodes to the View
		view.Append(node1)
		view.Append(node2)

		// Check if the number of nodes matches the expected count
		if len(view.nodes) != 2 {
			t.Fatalf("Expected 2 nodes, but got %d", len(view.nodes))
		}

		// Check if the nodes were appended correctly
		if view.nodes[0].Identity != "id1" || view.nodes[0].Address != "node1.example.com" {
			t.Fatalf("Node 1 was not appended correctly")
		}

		if view.nodes[1].Identity != "id2" || view.nodes[1].Address != "node2.example.com" {
			t.Fatalf("Node 2 was not appended correctly")
		}
	})
}

func TestView_GetAll(t *testing.T) {
	t.Parallel()
	t.Run("successfully creates a copy with the same values", func(t *testing.T) {
		// Create a new View
		view := NewView()

		// Mock nodes to add to the View
		node1 := Node{
			Identity: "id1",
			Address:  "address1",
		}
		node2 := Node{
			Identity: "id2",
			Address:  "address2",
		}

		// Append nodes to the View
		view.Append(node1)
		view.Append(node2)

		// Retrieve all nodes using GetAll()
		nodes := view.GetAll()

		// Check if the retrieved nodes match the expected nodes
		if len(nodes) != 2 {
			t.Fatalf("Expected 2 nodes, but got %d", len(nodes))
		}

		// Check if the nodes are distinct copies (compare memory addresses)
		if &nodes[0] == &node1 || &nodes[1] == &node2 {
			t.Fatalf("Nodes are not distinct copies")
		}

		// Check if the nodes' content is the same
		if !reflect.DeepEqual(nodes[0], node1) || !reflect.DeepEqual(nodes[1], node2) {
			t.Fatalf("Nodes content is not the same")
		}
	})
}
