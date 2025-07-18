// Copyright 2014 The go-ethereum Authors
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
	"fmt"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

var oldIndices = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "[17]"}

type OldNode interface {
	cache() (OldHashNode, bool)
	encode(w rlp.EncoderBuffer) // flag.hash is not encoded into final bytes
	fstring(string) string
}

type (
	OldFullNode struct {
		Children [17]OldNode // Actual trie node data to encode/decode (needs custom encoder)
		flags    OldNodeFlag
	}
	OldShortNode struct {
		Key   []byte // key is the nibble of this trie node, which is one segment of full key path
		Val   OldNode
		flags OldNodeFlag
	}
	OldHashNode  []byte
	OldValueNode []byte // RLP encoded StateAccount, see forwardAccountTask()
)

func ConvertTrieNodeToOldNode(n node) OldNode {
	switch tn := n.(type) {
	case *fullNode:
		// Convert the children from `[]node` to `[]MyNode`
		children := [17]OldNode{}
		for i, child := range tn.Children {
			if child != nil {
				children[i] = ConvertTrieNodeToOldNode(child)
			}
		}
		return &OldFullNode{
			Children: children,
			flags:    ConvertTrieNodeFlagToOldNodeFlag(tn.flags),
		}
	case *shortNode:
		// Convert the `Val` field from `node` to `MyNode`

		return &OldShortNode{
			Key: tn.Key,
			Val: ConvertTrieNodeToOldNode(tn.Val),
		}
	case hashNode:
		return OldHashNode(tn)
	case valueNode:
		return OldValueNode(tn)
	default:
		return nil
	}
}
func ConvertTrieNodeFlagToOldNodeFlag(f nodeFlag) OldNodeFlag {
	return OldNodeFlag{
		hash:  OldHashNode(f.hash),
		dirty: f.dirty,
	}
}

// nilValueNode is used when collapsing internal trie nodes for hashing, since
// unset children need to serialize correctly.
var oldNilValueNode = OldValueNode(nil)

// EncodeRLP encodes a full node into the consensus RLP format.
func (n *OldFullNode) EncodeRLP(w io.Writer) error {
	eb := rlp.NewEncoderBuffer(w)
	n.encode(eb)
	return eb.Flush()
}

func (n *OldFullNode) copy() *OldFullNode   { copy := *n; return &copy }
func (n *OldShortNode) copy() *OldShortNode { copy := *n; return &copy }

// nodeFlag contains caching-related metadata about a node.
type OldNodeFlag struct {
	hash  OldHashNode // cached hash of the node (may be nil)
	dirty bool        // whether the node has changes that must be written to the database
}

func (n *OldFullNode) cache() (OldHashNode, bool)  { return n.flags.hash, n.flags.dirty }
func (n *OldShortNode) cache() (OldHashNode, bool) { return n.flags.hash, n.flags.dirty }
func (n OldHashNode) cache() (OldHashNode, bool)   { return nil, true }
func (n OldValueNode) cache() (OldHashNode, bool)  { return nil, true }

// Pretty printing.
func (n *OldFullNode) String() string  { return n.fstring("") }
func (n *OldShortNode) String() string { return n.fstring("") }
func (n OldHashNode) String() string   { return n.fstring("") }
func (n OldValueNode) String() string  { return n.fstring("") }

func (n *OldFullNode) fstring(ind string) string {
	resp := fmt.Sprintf("[\n%s  ", ind)
	for i, node := range &n.Children {
		if node == nil {
			resp += fmt.Sprintf("%s: <nil> ", indices[i])
		} else {
			resp += fmt.Sprintf("%s: %v", indices[i], node.fstring(ind+"  "))
		}
	}
	return resp + fmt.Sprintf("\n%s] ", ind)
}
func (n *OldShortNode) fstring(ind string) string {
	return fmt.Sprintf("{%x: %v} ", n.Key, n.Val.fstring(ind+"  "))
}
func (n OldHashNode) fstring(ind string) string {
	return fmt.Sprintf("<%x> ", []byte(n))
}
func (n OldValueNode) fstring(ind string) string {
	return fmt.Sprintf("%x ", []byte(n))
}

// rawNode is a simple binary blob used to differentiate between collapsed trie
// nodes and already encoded RLP binary blobs (while at the same time store them
// in the same cache fields).
type OldRawNode []byte

func (n OldRawNode) cache() (OldHashNode, bool) { panic("this should never end up in a live trie") }
func (n OldRawNode) fstring(ind string) string  { panic("this should never end up in a live trie") }

func (n OldRawNode) EncodeRLP(w io.Writer) error {
	_, err := w.Write(n)
	return err
}

// mustDecodeNode is a wrapper of decodeNode and panic if any error is encountered.
// func OldMustDecodeNode(buf []byte) OldNode {
// 	n, err := oldDecodeNode(buf)
// 	if err != nil {
// 		panic(fmt.Sprintf("node: %v", err))
// 	}
// 	return n
// }

// mustDecodeNodeUnsafe is a wrapper of decodeNodeUnsafe and panic if any error is
// encountered.
func OldMustDecodeNodeUnsafe(buf []byte) OldNode {
	n, err := oldDecodeNodeUnsafe(buf)
	if err != nil {
		panic(fmt.Sprintf("node: %v", err))
	}
	return n
}

// decodeNode parses the RLP encoding of a trie node. It will deep-copy the passed
// byte slice for decoding, so it's safe to modify the byte slice afterwards. The-
// decode performance of this function is not optimal, but it is suitable for most
// scenarios with low performance requirements and hard to determine whether the
// byte slice be modified or not.
func oldDecodeNode(buf []byte) (OldNode, error) {
	return oldDecodeNodeUnsafe(common.CopyBytes(buf))
}

// decodeNodeUnsafe parses the RLP encoding of a trie node. The passed byte slice
// will be directly referenced by node without bytes deep copy, so the input MUST
// not be changed after.
func oldDecodeNodeUnsafe(buf []byte) (OldNode, error) {
	if len(buf) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	elems, _, err := rlp.SplitList(buf)
	if err != nil {
		return nil, fmt.Errorf("decode error: %v", err)
	}
	switch c, _ := rlp.CountValues(elems); c {
	case 2:
		n, err := oldDecodeShort(elems)
		return n, oldWrapError(err, "short")
	case 17:
		n, err := oldDecodeFull(elems)
		return n, oldWrapError(err, "full")
	default:
		return nil, fmt.Errorf("invalid number of list elements: %v", c)
	}
}

func oldDecodeShort(elems []byte) (OldNode, error) {
	kbuf, rest, err := rlp.SplitString(elems)
	if err != nil {
		return nil, err
	}
	// flag := nodeFlag{hash: hash}
	// see go-ethereum-1.14.0/trie/node_test.go: BenchmarkDecodeShortNodeUnsafe()
	// blob := nodeToBytes(node)
	// hash := crypto.Keccak256(blob)
	// todo: when to use cached hash?
	// in original geth hash-store, hash is hold by parent, now it is stored in node cache to avoid recalculation
	// it will be used in proofHash() when flating trie node to bytes
	// but in final proof, nodeToBytes() will not contain the hash of this node
	// so we donot need to store hash in cache
	flag := OldNodeFlag{hash: nil}
	key := compactToHex(kbuf)
	if hasTerm(key) {
		// value node
		val, _, err := rlp.SplitString(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid value node: %v", err)
		}
		return &OldShortNode{key, OldValueNode(val), flag}, nil
	}
	r, _, err := oldDecodeRef(rest)
	if err != nil {
		return nil, oldWrapError(err, "val")
	}
	return &OldShortNode{key, r, flag}, nil
}

func oldDecodeFull(elems []byte) (*OldFullNode, error) {
	// n := &fullNode{flags: nodeFlag{hash: hash}}
	// see go-ethereum-1.14.0/trie/node_test.go: BenchmarkDecodeShortNodeUnsafe()
	// blob := nodeToBytes(node)
	// hash := crypto.Keccak256(blob)
	// todo: when to use cached hash?
	// in original geth hash-store, hash is hold by parent, now it is stored in node cache to avoid recalculation
	// it will be used in proofHash() when flating trie node to bytes
	// but in final proof, nodeToBytes() will not contain the hash of this node
	// so we donot need to store hash in cache
	n := &OldFullNode{flags: OldNodeFlag{hash: nil}}
	for i := 0; i < 16; i++ {
		cld, rest, err := oldDecodeRef(elems)
		if err != nil {
			return n, oldWrapError(err, fmt.Sprintf("[%d]", i))
		}
		n.Children[i], elems = cld, rest
	}
	val, _, err := rlp.SplitString(elems)
	if err != nil {
		return n, err
	}
	if len(val) > 0 {
		n.Children[16] = OldValueNode(val)
	}
	return n, nil
}

const oldHashLen = len(common.Hash{})

func oldDecodeRef(buf []byte) (OldNode, []byte, error) {
	kind, val, rest, err := rlp.Split(buf)
	if err != nil {
		return nil, buf, err
	}
	switch {
	case kind == rlp.List:
		// 'embedded' node reference. The encoding must be smaller
		// than a hash in order to be valid.
		if size := len(buf) - len(rest); size > hashLen {
			err := fmt.Errorf("oversized embedded node (size is %d bytes, want size < %d)", size, hashLen)
			return nil, buf, err
		}
		n, err := oldDecodeNode(buf)
		return n, rest, err
	case kind == rlp.String && len(val) == 0:
		// empty node
		return nil, rest, nil
	case kind == rlp.String && len(val) == 32:
		return OldHashNode(val), rest, nil
	default:
		return nil, nil, fmt.Errorf("invalid RLP string size %d (want 0 or 32)", len(val))
	}
}

// wraps a decoding error with information about the path to the
// invalid child node (for debugging encoding issues).
type OldDecodeError struct {
	what  error
	stack []string
}

func oldWrapError(err error, ctx string) error {
	if err == nil {
		return nil
	}
	if decErr, ok := err.(*decodeError); ok {
		decErr.stack = append(decErr.stack, ctx)
		return decErr
	}
	return &decodeError{err, []string{ctx}}
}

func (err *OldDecodeError) Error() string {
	return fmt.Sprintf("%v (decode path: %s)", err.what, strings.Join(err.stack, "<-"))
}
