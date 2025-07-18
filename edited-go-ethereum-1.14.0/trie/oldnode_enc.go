// to expose the node interface and its implementations for testing purposes.
package trie

import (
	"github.com/ethereum/go-ethereum/rlp"
)

// using Recursive Length Prefix (RLP) encoding
// flag.hash is not encoded into final bytes
// hashNode: Encoded as raw bytes (the contents of the hashNode itself).
// valueNode: Encoded as raw bytes (the contents of the valueNode itself).
// fullNode is encoded as a list of up to 17 elements (its Children), empty child is char 0x80
// shortNode is encoded as a list with two elements: the Key and the Val (child), empty child is char 0x80
func oldNodeToBytes(n OldNode) []byte {
	w := rlp.NewEncoderBuffer(nil)
	n.encode(w)
	result := w.ToBytes() // Convert the buffer to bytes
	w.Flush()             // dst is nil, just Release the internal buffer
	return result
}

// fullNode is encoded as a list of up to 17 elements (its Children).
// Each child is encoded recursively (using its own encode method).
// If a child is nil, an empty string (rlp.EmptyString) is written.
func (n *OldFullNode) encode(w rlp.EncoderBuffer) {
	offset := w.List()
	for _, c := range n.Children {
		if c != nil {
			c.encode(w)
		} else {
			w.Write(rlp.EmptyString)
		}
	}
	w.ListEnd(offset)
}

// shortNode is encoded as a list with two elements: the Key and the Val.
func (n *OldShortNode) encode(w rlp.EncoderBuffer) {
	offset := w.List()
	w.WriteBytes(n.Key)
	if n.Val != nil {
		n.Val.encode(w)
	} else {
		w.Write(rlp.EmptyString)
	}
	w.ListEnd(offset)
}

// hashNode: Encoded as raw bytes (the contents of the hashNode itself).
func (n OldHashNode) encode(w rlp.EncoderBuffer) {
	w.WriteBytes(n)
}

// valueNode: Encoded as raw bytes (the contents of the valueNode itself).
func (n OldValueNode) encode(w rlp.EncoderBuffer) {
	w.WriteBytes(n)
}

func (n OldRawNode) encode(w rlp.EncoderBuffer) {
	w.Write(n)
}
