// to expose the node interface and its implementations for testing purposes.
package trie

type MyMetaNode interface {
	encode() []byte // self-defined encoding

	GetPath() []byte
	SetPath([]byte)
	GetBlockNumber() uint64
	SetBlockNumber(uint64)
	GetChildrenPointer() []MyMetaNodeID
	SetChildrenPointer(childPointer MyMetaNodeID, position uint8)
	GetRLPBytes() []byte
	SetRLPBytes([]byte)
}

// todo
func DecodeMyMetaNode(buf []byte) (MyMetaNode, error) {
	return nil, nil
}

type MyMetaNodeID struct {
	Path        []byte // Path to the child node, hexToKeybytes(it.path) == it.key
	BlockNumber uint64 // previous Block number when the child node is changed
}

// nodeid + childPointer + RLPBytes
// leafnode is not included in merkel proof
type (
	MyFullMetaNode struct {
		NodeID          MyMetaNodeID
		ChildrenPointer [16]MyNodeID
		RLPBytes        []byte //RLP encoding of original full node, for merkel proof
	}
	MyShortMetaNode struct {
		NodeID          MyNodeID
		Key             []byte
		ChildrenPointer MyNodeID
		RLPBytes        []byte // RLP encoding of original short node, for merkel proof
	}
	// MyHashMetaNode struct { // todo: delete
	// 	NodeID MyNodeID
	// 	// RLPBytes []byte // RLP encoding of original hash node
	// }
	MyValueMetaNode struct {
		NodeID MyNodeID
		// RLPBytes []byte // RLP encoding of original value node
	}
)
