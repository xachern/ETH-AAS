// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

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
func nodeToBytes(n node) []byte {
	w := rlp.NewEncoderBuffer(nil)
	n.encode(w)
	result := w.ToBytes() // Convert the buffer to bytes
	w.Flush()             // dst is nil, just Release the internal buffer
	return result
}

// fullNode is encoded as a list of up to 17 elements (its Children).
// Each child is encoded recursively (using its own encode method).
// If a child is nil, an empty string (rlp.EmptyString) is written.
func (n *fullNode) encode(w rlp.EncoderBuffer) {
	offset := w.List() // start a list, add a new list header
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
func (n *shortNode) encode(w rlp.EncoderBuffer) {
	offset := w.List() // start a list, add a new list header
	w.WriteBytes(n.Key)
	if n.Val != nil {
		n.Val.encode(w)
	} else {
		w.Write(rlp.EmptyString)
	}
	w.ListEnd(offset)
}

// hashNode: Encoded as raw bytes (the contents of the hashNode itself).
func (n hashNode) encode(w rlp.EncoderBuffer) {
	w.WriteBytes(n)
}

// valueNode: Encoded as raw bytes (the contents of the valueNode itself).
func (n valueNode) encode(w rlp.EncoderBuffer) {
	w.WriteBytes(n)
}

func (n rawNode) encode(w rlp.EncoderBuffer) {
	w.Write(n)
}
