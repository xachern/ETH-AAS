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
	"bytes"
	"container/heap"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// NodeResolver is used for looking up trie nodes before reaching into the real
// persistent layer. This is not mandatory, rather is an optimization for cases
// where trie nodes can be recovered from some external mechanism without reading
// from disk. In those cases, this resolver allows short circuiting accesses and
// returning them from memory.
type NodeResolver func(owner common.Hash, path []byte, hash common.Hash) []byte

// Iterator is a key-value trie iterator that traverses a Trie.
type Iterator struct {
	nodeIt NodeIterator

	Key   []byte // Current data key on which the iterator is positioned on
	Value []byte // Current data value on which the iterator is positioned on
	Err   error
}

// NewIterator creates a new key-value iterator from a node iterator.
// Note that the value returned by the iterator is raw. If the content is encoded
// (e.g. storage value is RLP-encoded), it's caller's duty to decode it.
func NewIterator(it NodeIterator) *Iterator {
	return &Iterator{
		nodeIt: it,
	}
}

// Next moves the iterator forward one key-value entry.
func (it *Iterator) Next() bool {
	for it.nodeIt.Next(true) {
		if it.nodeIt.Leaf() {
			it.Key = it.nodeIt.LeafKey()
			it.Value = it.nodeIt.LeafBlob()
			return true
		}
	}
	it.Key = nil
	it.Value = nil
	it.Err = it.nodeIt.Error()
	return false
}

// Prove generates the Merkle proof for the leaf node the iterator is currently
// positioned on.
func (it *Iterator) Prove() [][]byte {
	return it.nodeIt.LeafProof()
}

// NodeIterator is an iterator to traverse the trie pre-order.
type NodeIterator interface {
	// Next moves the iterator to the next node. If the parameter is false, any child
	// nodes will be skipped.
	Next(bool) bool

	// Error returns the error status of the iterator.
	Error() error

	// Hash returns the hash of the current node.
	Hash() common.Hash

	// Parent returns the hash of the parent of the current node. The hash may be the one
	// grandparent if the immediate parent is an internal node with no hash.
	Parent() common.Hash

	// Path returns the hex-encoded path to the current node.
	// Callers must not retain references to the return value after calling Next.
	// For leaf nodes, the last element of the path is the 'terminator symbol' 0x10.
	Path() []byte // trie.AddressToStateHexPath(address)==iter.Path()

	Stack() []string // old version geth's api, now deleted
	// add a method to get the stack of nodes
	MyStack() []*NodeIteratorState
	MyGenLeafProof(proofList ethdb.KeyValueWriter, new_db ethdb.Database, blocknum uint64) error

	// NodeBlob returns the rlp-encoded value of the current iterated node.
	// If the node is an embedded node in its parent, nil is returned then.
	NodeBlob() []byte

	// Leaf returns true iff the current node is a leaf node.
	Leaf() bool

	// LeafKey returns the key of the leaf. The method panics if the iterator is not
	// positioned at a leaf. Callers must not retain references to the value after
	// calling Next.
	LeafKey() []byte

	// LeafBlob returns the content of the leaf. The method panics if the iterator
	// is not positioned at a leaf. Callers must not retain references to the value
	// after calling Next.
	LeafBlob() []byte

	// LeafProof returns the Merkle proof of the leaf. The method panics if the
	// iterator is not positioned at a leaf. Callers must not retain references
	// to the value after calling Next.
	LeafProof() [][]byte
	// update prevBlockTrieDB with new block number
	MyLeafProof_gen_path_store(prevBlockTrieDB ethdb.Database, blockNumber uint64, baseBlockNumber uint64) []MyNode
	// MyLeafProof_query_for_test() []OldNode

	// AddResolver sets a node resolver to use for looking up trie nodes before
	// reaching into the real persistent layer.
	//
	// This is not required for normal operation, rather is an optimization for
	// cases where trie nodes can be recovered from some external mechanism without
	// reading from disk. In those cases, this resolver allows short circuiting
	// accesses and returning them from memory.
	//
	// Before adding a similar mechanism to any other place in Geth, consider
	// making trie.Database an interface and wrapping at that level. It's a huge
	// refactor, but it could be worth it if another occurrence arises.
	AddResolver(NodeResolver)
}

// NodeIteratorState represents the iteration state at one particular node of the
// trie, which can be resumed at a later invocation.
type NodeIteratorState struct {
	hash    common.Hash // Hash of the node being iterated (nil if not standalone)
	path    []byte      // Path to the node being iterated
	node    node        // Trie node being iterated
	parent  common.Hash // Hash of the first full ancestor node (nil if current is the root)
	index   int         // Child to be processed next
	pathlen int         // Length of the path to this node
}

func (it *NodeIteratorState) GetPath() []byte {
	return it.path
}

type nodeIterator struct {
	trie  *Trie                // Trie being iterated
	stack []*NodeIteratorState // Hierarchy of trie nodes persisting the iteration state, first is trie root, end if leaf node
	path  []byte               // Path to the current node
	err   error                // Failure set in case of an internal error in the iterator

	resolver NodeResolver         // optional node resolver for avoiding disk hits
	pool     []*NodeIteratorState // local pool for iteratorstates
}

// errIteratorEnd is stored in nodeIterator.err when iteration is done.
var errIteratorEnd = errors.New("end of iteration")

// seekError is stored in nodeIterator.err if the initial seek has failed.
type seekError struct {
	key []byte
	err error
}

func (e seekError) Error() string {
	return "seek error: " + e.err.Error()
}

func newNodeIterator(trie *Trie, start []byte) NodeIterator {
	if trie.Hash() == types.EmptyRootHash {
		return &nodeIterator{
			trie: trie,
			err:  errIteratorEnd,
		}
	}
	it := &nodeIterator{trie: trie}
	it.err = it.seek(start)
	return it
}

func (it *nodeIterator) putInPool(item *NodeIteratorState) {
	if len(it.pool) < 40 {
		item.node = nil
		it.pool = append(it.pool, item)
	}
}

func (it *nodeIterator) getFromPool() *NodeIteratorState {
	idx := len(it.pool) - 1
	if idx < 0 {
		return new(NodeIteratorState)
	}
	el := it.pool[idx]
	it.pool[idx] = nil
	it.pool = it.pool[:idx]
	return el
}

func (it *nodeIterator) AddResolver(resolver NodeResolver) {
	it.resolver = resolver
}

func (it *nodeIterator) Stack() []string {
	nodesStack := make([]string, len(it.stack))
	for i := range it.stack {
		nodesStack[i] = reflect.TypeOf(it.stack[i].node).String()
	}
	return nodesStack
}

func (it *nodeIterator) MyStack() []*NodeIteratorState {
	return it.stack
}

func (it *nodeIterator) Hash() common.Hash {
	if len(it.stack) == 0 {
		return common.Hash{}
	}
	return it.stack[len(it.stack)-1].hash
}

func (it *nodeIterator) Parent() common.Hash {
	if len(it.stack) == 0 {
		return common.Hash{}
	}
	return it.stack[len(it.stack)-1].parent
}

func (it *nodeIterator) Leaf() bool {
	return hasTerm(it.path)
}

func (it *nodeIterator) LeafKey() []byte {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			return hexToKeybytes(it.path)
		}
	}
	panic("not at leaf")
}

func (it *nodeIterator) LeafBlob() []byte {
	if len(it.stack) > 0 {
		if node, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			return node
		}
	}
	panic("not at leaf")
}

var RMN = uint64(50000000) // root magic number
// 3-level root subtree: root, 16 children, 256 grandchildren
// magic number of 256 subtrees
var SubMNs = []uint64{RMN + 1, RMN + 2, RMN + 3, RMN + 4, RMN + 5, RMN + 6, RMN + 7, RMN + 8, RMN + 9, RMN + 10, RMN + 11, RMN + 12, RMN + 13, RMN + 14, RMN + 15, RMN + 16,
	RMN + 17, RMN + 18, RMN + 19, RMN + 20, RMN + 21, RMN + 22, RMN + 23, RMN + 24, RMN + 25, RMN + 26, RMN + 27, RMN + 28, RMN + 29, RMN + 30, RMN + 31, RMN + 32,
	RMN + 33, RMN + 34, RMN + 35, RMN + 36, RMN + 37, RMN + 38, RMN + 39, RMN + 40, RMN + 41, RMN + 42, RMN + 43, RMN + 44, RMN + 45, RMN + 46, RMN + 47, RMN + 48,
	RMN + 49, RMN + 50, RMN + 51, RMN + 52, RMN + 53, RMN + 54, RMN + 55, RMN + 56, RMN + 57, RMN + 58, RMN + 59, RMN + 60, RMN + 61, RMN + 62, RMN + 63, RMN + 64,
	RMN + 65, RMN + 66, RMN + 67, RMN + 68, RMN + 69, RMN + 70, RMN + 71, RMN + 72, RMN + 73, RMN + 74, RMN + 75, RMN + 76, RMN + 77, RMN + 78, RMN + 79, RMN + 80,
	RMN + 81, RMN + 82, RMN + 83, RMN + 84, RMN + 85, RMN + 86, RMN + 87, RMN + 88, RMN + 89, RMN + 90, RMN + 91, RMN + 92, RMN + 93, RMN + 94, RMN + 95, RMN + 96,
	RMN + 97, RMN + 98, RMN + 99, RMN + 100, RMN + 101, RMN + 102, RMN + 103, RMN + 104, RMN + 105, RMN + 106, RMN + 107, RMN + 108, RMN + 109, RMN + 110, RMN + 111, RMN + 112,
	RMN + 113, RMN + 114, RMN + 115, RMN + 116, RMN + 117, RMN + 118, RMN + 119, RMN + 120, RMN + 121, RMN + 122, RMN + 123, RMN + 124, RMN + 125, RMN + 126, RMN + 127, RMN + 128,
	RMN + 129, RMN + 130, RMN + 131, RMN + 132, RMN + 133, RMN + 134, RMN + 135, RMN + 136, RMN + 137, RMN + 138, RMN + 139, RMN + 140, RMN + 141, RMN + 142, RMN + 143, RMN + 144,
	RMN + 145, RMN + 146, RMN + 147, RMN + 148, RMN + 149, RMN + 150, RMN + 151, RMN + 152, RMN + 153, RMN + 154, RMN + 155, RMN + 156, RMN + 157, RMN + 158, RMN + 159, RMN + 160,
	RMN + 161, RMN + 162, RMN + 163, RMN + 164, RMN + 165, RMN + 166, RMN + 167, RMN + 168, RMN + 169, RMN + 170, RMN + 171, RMN + 172, RMN + 173, RMN + 174, RMN + 175, RMN + 176,
	RMN + 177, RMN + 178, RMN + 179, RMN + 180, RMN + 181, RMN + 182, RMN + 183, RMN + 184, RMN + 185, RMN + 186, RMN + 187, RMN + 188, RMN + 189, RMN + 190, RMN + 191, RMN + 192,
	RMN + 193, RMN + 194, RMN + 195, RMN + 196, RMN + 197, RMN + 198, RMN + 199, RMN + 200, RMN + 201, RMN + 202, RMN + 203, RMN + 204, RMN + 205, RMN + 206, RMN + 207, RMN + 208,
	RMN + 209, RMN + 210, RMN + 211, RMN + 212, RMN + 213, RMN + 214, RMN + 215, RMN + 216, RMN + 217, RMN + 218, RMN + 219, RMN + 220, RMN + 221, RMN + 222, RMN + 223, RMN + 224,
	RMN + 225, RMN + 226, RMN + 227, RMN + 228, RMN + 229, RMN + 230, RMN + 231, RMN + 232, RMN + 233, RMN + 234, RMN + 235, RMN + 236, RMN + 237, RMN + 238, RMN + 239, RMN + 240,
	RMN + 241, RMN + 242, RMN + 243, RMN + 244, RMN + 245, RMN + 246, RMN + 247, RMN + 248, RMN + 249, RMN + 250, RMN + 251, RMN + 252, RMN + 253, RMN + 254, RMN + 255, RMN + 256}

func (it *nodeIterator) MyGenLeafProof(proofList ethdb.KeyValueWriter, new_db ethdb.Database, blocknum uint64) error {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			hasher := newHasher(false)
			defer returnHasherToPool(hasher)
			// proofs := make([][]byte, 0, len(it.stack))

			// root_subtree_node_path := make([][]byte, 0, 3)
			root_subtree_node_value := make([][]byte, 0, 3)
			find_first_subtree_flag := true
			var subtree_magic_number uint64
			for i, item := range it.stack[:len(it.stack)-1] {
				// Gather nodes that end up as hash nodes (or the root)
				node, hashed := hasher.proofHash(item.node)
				if _, ok := hashed.(hashNode); ok || i == 0 {
					encoded := nodeToBytes(node)
					// proofs = append(proofs, encoded)
					proofList.Put(item.path, encoded)

					// persist the proof to the new db, by subtree-based storage
					if i == 0 { // trie root
						root_path := "root"
						// root_path_bytes := []byte(root_path)
						// root_subtree_node_path = append(root_subtree_node_path, root_path_bytes)
						root_subtree_node_value = append(root_subtree_node_value, encoded)

						// key = root_magic_number + "_" + blocknum + "_" + "root"
						new_key := fmt.Sprintf("%d_%d_%s", RMN, blocknum, root_path)
						new_key_bytes := []byte(new_key)
						new_db.Put(new_key_bytes, encoded)
					} else if find_first_subtree_flag && len(item.path) >= 1 && len(item.path) <= 2 {
						// 2nd and 3rd level in root subtree
						// root_subtree_node_path = append(root_subtree_node_path, item.path)
						root_subtree_node_value = append(root_subtree_node_value, encoded)

						// key = root_magic_number + "_" + blocknum + "_" + path
						path_str := hex.EncodeToString(item.path[:]) // Encode []byte to hex string
						new_key := fmt.Sprintf("%d_%d_%s", RMN, blocknum, path_str)
						new_key_bytes := []byte(new_key)
						new_db.Put(new_key_bytes, encoded)
					} else if find_first_subtree_flag {
						//end of root subtree
						find_first_subtree_flag = false

						// subtree id is first 2 bytes of the path
						subtree_id_byte := item.path[:2]
						subtree_id_int := uint(subtree_id_byte[0])*16 + uint(subtree_id_byte[1])
						subtree_magic_number = SubMNs[subtree_id_int]

						// add root subtree as prefix tree
						// key = subtree_magic_number + "_" + blocknum + "_" + "prefix_tree"
						prefix_tree_key := fmt.Sprintf("%d_%d_prefix_tree", subtree_magic_number, blocknum)
						prefix_tree_key_bytes := []byte(prefix_tree_key)
						// value = value[0] + "_" + value[1] + "_" + value[2]
						var prefix_tree_value_bytes []byte
						delimiter_byte := []byte("_")
						for i := 0; i <= 1; i++ {
							prefix_tree_value_bytes = append(prefix_tree_value_bytes, root_subtree_node_value[i]...)
							prefix_tree_value_bytes = append(prefix_tree_value_bytes, delimiter_byte...)
						}
						prefix_tree_value_bytes = append(prefix_tree_value_bytes, root_subtree_node_value[2]...)
						new_db.Put(prefix_tree_key_bytes, prefix_tree_value_bytes)

						// now start the next subtree
						// add first node key of the subtree
						// key = subtree_magic_number + "_" + blocknum + "_" + "first_node"
						first_node_key := fmt.Sprintf("%d_%d_first_node", subtree_magic_number, blocknum)
						first_node_key_bytes := []byte(first_node_key)
						// value = path of node
						new_db.Put(first_node_key_bytes, item.path)

						// key = subtree_magic_number + "_" + blocknum + "_" + path
						path_str := hex.EncodeToString(item.path[:]) // Encode []byte to hex string
						new_key := fmt.Sprintf("%d_%d_%s", subtree_magic_number, blocknum, path_str)
						new_key_bytes := []byte(new_key)
						new_db.Put(new_key_bytes, encoded)
					} else { // not in root subtree
						//== todo: multi-level subtree
						// key = subtree_magic_number + "_" + blocknum + "_" + path
						path_str := hex.EncodeToString(item.path[:]) // Encode []byte to hex string
						new_key := fmt.Sprintf("%d_%d_%s", subtree_magic_number, blocknum, path_str)
						new_key_bytes := []byte(new_key)
						new_db.Put(new_key_bytes, encoded)
					}
					// log.Default().Printf("persist : %v", item.path)
					// fmt.Printf("persist : %v\n", item.path)
				}
			}
			// return proofs
			return nil
		}
	}
	panic("not at leaf")
}

// func (it *nodeIterator) MyLeafProof_query_for_test() []OldNode {
// 	if len(it.stack) > 0 {
// 		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
// 			hasher := newHasher(false)
// 			defer returnHasherToPool(hasher)
// 			proofs := make([]node, 0, len(it.stack))
// 			for i, item := range it.stack[:len(it.stack)-1] {
// 				// Gather nodes that end up as hash nodes (or the root)
// 				node, hashed := hasher.proofHash(item.node)
// 				if _, ok := hashed.(hashNode); ok || i == 0 {
// 					proofs = append(proofs, node)
// 				}
// 			}

//				// convert to MyNode
//				myProofs := make([]OldNode, 0, len(proofs))
//				for _, p := range proofs {
//					myProofs = append(myProofs, OldNode(p))
//				}
//				return myProofs
//			}
//		}
//		panic("not at leaf")
//	}
func uint64ToBytes(n uint64) []byte {
	buf := make([]byte, 8) // uint64占用8个字节
	binary.BigEndian.PutUint64(buf, n)
	return buf
}
func bytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

// update block number for each node in the proof
// persist node with new block into prevBlockTrieDB
func update_blockNumber_for_nodes(myProofs []MyNode, prevBlockTrieDB ethdb.Database, blockNumber uint64) {
	for i := len(myProofs) - 1; i >= 0; i-- {
		node := myProofs[i]
		switch node.(type) {
		case *MyValueNode:
			node.SetBlockNumber(blockNumber)
			prevBlockTrieDB.Put(node.GetPath(), uint64ToBytes(blockNumber))
		case *MyHashNode:
			node.SetBlockNumber(blockNumber)
			prevBlockTrieDB.Put(node.GetPath(), uint64ToBytes(blockNumber))
		case *MyShortNode:
			node.SetBlockNumber(blockNumber)
			prevBlockTrieDB.Put(node.GetPath(), uint64ToBytes(blockNumber))
			// update the child pointer
			childPath := myProofs[i+1].GetPath()
			if !bytes.HasPrefix(childPath, node.GetPath()) {
				panic("child path not match")
			}
			newChildPointer := MyNodeID{Path: childPath, BlockNumber: blockNumber}
			node.SetChildrenPointer(newChildPointer, 0)
			// update in-memory child: value field
			// childNode := node.(*MyShortNode).Val.(*MyValueNode)
			// childNode.SetBlockNumber(blockNumber)
		case *MyFullNode:
			node.SetBlockNumber(blockNumber)
			nodePath := node.GetPath()
			prevBlockTrieDB.Put(nodePath, uint64ToBytes(blockNumber))
			// find the child position by comparing the path
			// see findChild()
			var childPosition uint8
			childPath := myProofs[i+1].GetPath()
			// for root node, path is nil
			// if child is shortnode, not prefix, why?
			if bytes.HasPrefix(childPath, nodePath) {
				childPosition_byte := childPath[len(nodePath)]
				childPosition = uint8(childPosition_byte)
			} else {
				panic("child path not match")
			}
			newChildPointer := MyNodeID{Path: childPath, BlockNumber: blockNumber}
			// update the child pointer
			node.SetChildrenPointer(newChildPointer, childPosition)
		default:
			panic("unknown node type")
		}
	}
}

// update prevBlockTrieDB with new block number
// for init, set node's blockid to baseBlockNumber
// todo: stacknode for meta, proofnode for RLPbytes
func (it *nodeIterator) MyLeafProof_gen_path_store(prevBlockTrieDB ethdb.Database,
	blockNumber uint64, baseBlockNumber uint64) []MyNode {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			hasher := newHasher(false)
			defer returnHasherToPool(hasher)
			proofs := make([]node, 0)
			// tmp_shortCompactKey := make([][]byte, len(it.stack)) // todo: delete this, insert RLPBytes into MyMetaNode
			stackNodes := make([]node, 0)
			paths := make([][]byte, 0)

			// leaf node is not included in original proofs
			// but for path-store, we need to include leaf node
			for i, item := range it.stack {
				stackNodes = append(stackNodes, item.node)
				if i == 0 { // for root node, path is nil
					paths = append(paths, []byte(nil))
				} else {
					paths = append(paths, item.path)
				}
			}
			for i, item := range it.stack[:len(it.stack)-1] {
				// Gather nodes that end up as hash nodes (or the root)
				// need to check hashed is hashNode (whether has child)
				node, hashed := hasher.proofHash(item.node) // 对于shortnode, 它的key从hex变成了compact, 这会导致它的path不再是parent hex的prefix
				if _, ok := hashed.(hashNode); ok || i == 0 {
					proofs = append(proofs, node)
				}

				// _, isShortNode := node.(*shortNode)
				// if isShortNode {
				// 	stackNodes[i].(*shortNode).Original_Key = node.(*shortNode).Key
				// }
			}
			//todo: wrap proofs into MyNode

			// convert to MyNode
			var myProofs []MyNode
			for i, node := range stackNodes {
				// fill node with prev block
				// for init, set node's blockid to 0
				prevBlockNode := ConvertTrieNodeToMyNode(node, paths[i], prevBlockTrieDB, baseBlockNumber)
				myProofs = append(myProofs, prevBlockNode)
			}
			// update block number from leaf to root
			// persist node's blockid into prevBlockTrieDB
			// for changed node, set to latest block number;
			update_blockNumber_for_nodes(myProofs, prevBlockTrieDB, blockNumber)

			return myProofs
		}
	}
	panic("not at leaf")
}
func (it *nodeIterator) LeafProof() [][]byte {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			hasher := newHasher(false)
			defer returnHasherToPool(hasher)
			proofs := make([][]byte, 0, len(it.stack))

			for i, item := range it.stack[:len(it.stack)-1] {
				// Gather nodes that end up as hash nodes (or the root)
				node, hashed := hasher.proofHash(item.node)
				if _, ok := hashed.(hashNode); ok || i == 0 {
					proofs = append(proofs, nodeToBytes(node))
				}
			}
			return proofs
		}
	}
	panic("not at leaf")
}

func (it *nodeIterator) Path() []byte {
	return it.path
}

func (it *nodeIterator) NodeBlob() []byte {
	if it.Hash() == (common.Hash{}) {
		return nil // skip the non-standalone node
	}
	blob, err := it.resolveBlob(it.Hash().Bytes(), it.Path())
	if err != nil {
		it.err = err
		return nil
	}
	return blob
}

func (it *nodeIterator) Error() error {
	if it.err == errIteratorEnd {
		return nil
	}
	if seek, ok := it.err.(seekError); ok {
		return seek.err
	}
	return it.err
}

// Next moves the iterator to the next node, returning whether there are any
// further nodes. In case of an internal error this method returns false and
// sets the Error field to the encountered failure. If `descend` is false,
// skips iterating over any subnodes of the current node.
func (it *nodeIterator) Next(descend bool) bool {
	if it.err == errIteratorEnd {
		return false
	}
	if seek, ok := it.err.(seekError); ok {
		if it.err = it.seek(seek.key); it.err != nil {
			return false
		}
	}
	// Otherwise step forward with the iterator and report any errors.
	state, parentIndex, path, err := it.peek(descend)
	it.err = err
	if it.err != nil {
		return false
	}
	it.push(state, parentIndex, path)
	return true
}

func (it *nodeIterator) seek(prefix []byte) error {
	// The path we're looking for is the hex encoded key without terminator.
	key := keybytesToHex(prefix)
	key = key[:len(key)-1]
	// Move forward until we're just before the closest match to key.
	for {
		state, parentIndex, path, err := it.peekSeek(key)
		if err == errIteratorEnd {
			return errIteratorEnd
		} else if err != nil {
			return seekError{prefix, err}
		} else if bytes.Compare(path, key) >= 0 {
			return nil
		}
		it.push(state, parentIndex, path)
	}
}

// init initializes the iterator.
func (it *nodeIterator) init() (*NodeIteratorState, error) {
	root := it.trie.Hash()
	state := &NodeIteratorState{node: it.trie.root, index: -1}
	if root != types.EmptyRootHash {
		state.hash = root
	}
	return state, state.resolve(it, nil)
}

// peek creates the next state of the iterator.
func (it *nodeIterator) peek(descend bool) (*NodeIteratorState, *int, []byte, error) {
	// Initialize the iterator if we've just started.
	if len(it.stack) == 0 {
		state, err := it.init()
		return state, nil, nil, err
	}
	if !descend {
		// If we're skipping children, pop the current node first
		it.pop()
	}

	// Continue iteration to the next child
	for len(it.stack) > 0 {
		parent := it.stack[len(it.stack)-1]
		ancestor := parent.hash
		if (ancestor == common.Hash{}) {
			ancestor = parent.parent
		}
		state, path, ok := it.nextChild(parent, ancestor)
		if ok {
			if err := state.resolve(it, path); err != nil {
				return parent, &parent.index, path, err
			}
			return state, &parent.index, path, nil
		}
		// No more child nodes, move back up.
		it.pop()
	}
	return nil, nil, nil, errIteratorEnd
}

// peekSeek is like peek, but it also tries to skip resolving hashes by skipping
// over the siblings that do not lead towards the desired seek position.
func (it *nodeIterator) peekSeek(seekKey []byte) (*NodeIteratorState, *int, []byte, error) {
	// Initialize the iterator if we've just started.
	if len(it.stack) == 0 {
		state, err := it.init()
		return state, nil, nil, err
	}
	if !bytes.HasPrefix(seekKey, it.path) {
		// If we're skipping children, pop the current node first
		it.pop()
	}

	// Continue iteration to the next child
	for len(it.stack) > 0 {
		parent := it.stack[len(it.stack)-1]
		ancestor := parent.hash
		if (ancestor == common.Hash{}) {
			ancestor = parent.parent
		}
		state, path, ok := it.nextChildAt(parent, ancestor, seekKey)
		if ok {
			if err := state.resolve(it, path); err != nil {
				return parent, &parent.index, path, err
			}
			return state, &parent.index, path, nil
		}
		// No more child nodes, move back up.
		it.pop()
	}
	return nil, nil, nil, errIteratorEnd
}

func (it *nodeIterator) resolveHash(hash hashNode, path []byte) (node, error) {
	if it.resolver != nil {
		if blob := it.resolver(it.trie.owner, path, common.BytesToHash(hash)); len(blob) > 0 {
			if resolved, err := decodeNode(hash, blob); err == nil {
				return resolved, nil
			}
		}
	}
	// Retrieve the specified node from the underlying node reader.
	// it.trie.resolveAndTrack is not used since in that function the
	// loaded blob will be tracked, while it's not required here since
	// all loaded nodes won't be linked to trie at all and track nodes
	// may lead to out-of-memory issue.
	blob, err := it.trie.reader.node(path, common.BytesToHash(hash))
	if err != nil {
		return nil, err
	}
	// The raw-blob format nodes are loaded either from the
	// clean cache or the database, they are all in their own
	// copy and safe to use unsafe decoder.
	return mustDecodeNodeUnsafe(hash, blob), nil
}

func (it *nodeIterator) resolveBlob(hash hashNode, path []byte) ([]byte, error) {
	if it.resolver != nil {
		if blob := it.resolver(it.trie.owner, path, common.BytesToHash(hash)); len(blob) > 0 {
			return blob, nil
		}
	}
	// Retrieve the specified node from the underlying node reader.
	// it.trie.resolveAndTrack is not used since in that function the
	// loaded blob will be tracked, while it's not required here since
	// all loaded nodes won't be linked to trie at all and track nodes
	// may lead to out-of-memory issue.
	return it.trie.reader.node(path, common.BytesToHash(hash))
}

func (st *NodeIteratorState) resolve(it *nodeIterator, path []byte) error {
	if hash, ok := st.node.(hashNode); ok {
		resolved, err := it.resolveHash(hash, path)
		if err != nil {
			return err
		}
		st.node = resolved
		st.hash = common.BytesToHash(hash)
	}
	return nil
}

func (it *nodeIterator) findChild(n *fullNode, index int, ancestor common.Hash) (node, *NodeIteratorState, []byte, int) {
	var (
		path      = it.path
		child     node
		state     *NodeIteratorState
		childPath []byte
	)
	for ; index < len(n.Children); index++ {
		if n.Children[index] != nil {
			child = n.Children[index]
			hash, _ := child.cache()
			state = it.getFromPool()
			state.hash = common.BytesToHash(hash)
			state.node = child
			state.parent = ancestor
			state.index = -1
			state.pathlen = len(path)
			childPath = append(childPath, path...)
			childPath = append(childPath, byte(index))
			return child, state, childPath, index
		}
	}
	return nil, nil, nil, 0
}

func (it *nodeIterator) nextChild(parent *NodeIteratorState, ancestor common.Hash) (*NodeIteratorState, []byte, bool) {
	switch node := parent.node.(type) {
	case *fullNode:
		// Full node, move to the first non-nil child.
		if child, state, path, index := it.findChild(node, parent.index+1, ancestor); child != nil {
			parent.index = index - 1
			return state, path, true
		}
	case *shortNode:
		// Short node, return the pointer singleton child
		if parent.index < 0 {
			hash, _ := node.Val.cache()
			state := it.getFromPool()
			state.hash = common.BytesToHash(hash)
			state.node = node.Val
			state.parent = ancestor
			state.index = -1
			state.pathlen = len(it.path)
			path := append(it.path, node.Key...)
			return state, path, true
		}
	}
	return parent, it.path, false
}

// nextChildAt is similar to nextChild, except that it targets a child as close to the
// target key as possible, thus skipping siblings.
func (it *nodeIterator) nextChildAt(parent *NodeIteratorState, ancestor common.Hash, key []byte) (*NodeIteratorState, []byte, bool) {
	switch n := parent.node.(type) {
	case *fullNode:
		// Full node, move to the first non-nil child before the desired key position
		child, state, path, index := it.findChild(n, parent.index+1, ancestor)
		if child == nil {
			// No more children in this fullnode
			return parent, it.path, false
		}
		// If the child we found is already past the seek position, just return it.
		if bytes.Compare(path, key) >= 0 {
			parent.index = index - 1
			return state, path, true
		}
		// The child is before the seek position. Try advancing
		for {
			nextChild, nextState, nextPath, nextIndex := it.findChild(n, index+1, ancestor)
			// If we run out of children, or skipped past the target, return the
			// previous one
			if nextChild == nil || bytes.Compare(nextPath, key) >= 0 {
				parent.index = index - 1
				return state, path, true
			}
			// We found a better child closer to the target
			state, path, index = nextState, nextPath, nextIndex
		}
	case *shortNode:
		// Short node, return the pointer singleton child
		if parent.index < 0 {
			hash, _ := n.Val.cache()
			state := it.getFromPool()
			state.hash = common.BytesToHash(hash)
			state.node = n.Val
			state.parent = ancestor
			state.index = -1
			state.pathlen = len(it.path)
			path := append(it.path, n.Key...)
			return state, path, true
		}
	}
	return parent, it.path, false
}

func (it *nodeIterator) push(state *NodeIteratorState, parentIndex *int, path []byte) {
	it.path = path
	state.path = path
	it.stack = append(it.stack, state)
	if parentIndex != nil {
		*parentIndex++
	}
}

func (it *nodeIterator) pop() {
	last := it.stack[len(it.stack)-1]
	it.path = it.path[:last.pathlen]
	it.stack[len(it.stack)-1] = nil
	it.stack = it.stack[:len(it.stack)-1]
	// last is now unused
	it.putInPool(last)
}

func compareNodes(a, b NodeIterator) int {
	if cmp := bytes.Compare(a.Path(), b.Path()); cmp != 0 {
		return cmp
	}
	if a.Leaf() && !b.Leaf() {
		return -1
	} else if b.Leaf() && !a.Leaf() {
		return 1
	}
	if cmp := bytes.Compare(a.Hash().Bytes(), b.Hash().Bytes()); cmp != 0 {
		return cmp
	}
	if a.Leaf() && b.Leaf() {
		return bytes.Compare(a.LeafBlob(), b.LeafBlob())
	}
	return 0
}

type differenceIterator struct {
	a, b  NodeIterator // Nodes returned are those in b - a.
	eof   bool         // Indicates a has run out of elements
	count int          // Number of nodes scanned on either trie
}

// NewDifferenceIterator constructs a NodeIterator that iterates over elements in b that
// are not in a. Returns the iterator, and a pointer to an integer recording the number
// of nodes seen.
func NewDifferenceIterator(a, b NodeIterator) (NodeIterator, *int) {
	a.Next(true)
	it := &differenceIterator{
		a: a,
		b: b,
	}
	return it, &it.count
}

func (it *differenceIterator) Hash() common.Hash {
	return it.b.Hash()
}

func (it *differenceIterator) Parent() common.Hash {
	return it.b.Parent()
}

func (it *differenceIterator) Leaf() bool {
	return it.b.Leaf()
}

func (it *differenceIterator) LeafKey() []byte {
	return it.b.LeafKey()
}

func (it *differenceIterator) LeafBlob() []byte {
	return it.b.LeafBlob()
}

func (it *differenceIterator) LeafProof() [][]byte {
	return it.b.LeafProof()
}
func (it *differenceIterator) MyLeafProof_gen_path_store(prevBlockTrieDB ethdb.Database, blockNumber uint64, baseBlockNumber uint64) []MyNode {
	return it.b.MyLeafProof_gen_path_store(prevBlockTrieDB, blockNumber, baseBlockNumber)
}
func (it *differenceIterator) Path() []byte {
	return it.b.Path()
}

func (it *differenceIterator) Stack() []string {
	// You can combine the stack of both iterators a and b, or return one of them.
	// This example assumes we return the stack of b (you can adjust based on logic).
	return it.b.Stack()
}
func (it *differenceIterator) MyStack() []*NodeIteratorState {
	return it.b.MyStack()
}

func (it *differenceIterator) MyGenLeafProof(proofList ethdb.KeyValueWriter, new_db ethdb.Database, blocknum uint64) error {
	return it.b.MyGenLeafProof(proofList, new_db, blocknum)
}

func (it *differenceIterator) NodeBlob() []byte {
	return it.b.NodeBlob()
}

func (it *differenceIterator) AddResolver(resolver NodeResolver) {
	panic("not implemented")
}

func (it *differenceIterator) Next(bool) bool {
	// Invariants:
	// - We always advance at least one element in b.
	// - At the start of this function, a's path is lexically greater than b's.
	if !it.b.Next(true) {
		return false
	}
	it.count++

	if it.eof {
		// a has reached eof, so we just return all elements from b
		return true
	}

	for {
		switch compareNodes(it.a, it.b) {
		case -1:
			// b jumped past a; advance a
			if !it.a.Next(true) {
				it.eof = true
				return true
			}
			it.count++
		case 1:
			// b is before a
			return true
		case 0:
			// a and b are identical; skip this whole subtree if the nodes have hashes
			hasHash := it.a.Hash() == common.Hash{}
			if !it.b.Next(hasHash) {
				return false
			}
			it.count++
			if !it.a.Next(hasHash) {
				it.eof = true
				return true
			}
			it.count++
		}
	}
}

func (it *differenceIterator) Error() error {
	if err := it.a.Error(); err != nil {
		return err
	}
	return it.b.Error()
}

type nodeIteratorHeap []NodeIterator

func (h nodeIteratorHeap) Len() int            { return len(h) }
func (h nodeIteratorHeap) Less(i, j int) bool  { return compareNodes(h[i], h[j]) < 0 }
func (h nodeIteratorHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *nodeIteratorHeap) Push(x interface{}) { *h = append(*h, x.(NodeIterator)) }
func (h *nodeIteratorHeap) Pop() interface{} {
	n := len(*h)
	x := (*h)[n-1]
	*h = (*h)[0 : n-1]
	return x
}

type unionIterator struct {
	items *nodeIteratorHeap // Nodes returned are the union of the ones in these iterators
	count int               // Number of nodes scanned across all tries
}

// NewUnionIterator constructs a NodeIterator that iterates over elements in the union
// of the provided NodeIterators. Returns the iterator, and a pointer to an integer
// recording the number of nodes visited.
func NewUnionIterator(iters []NodeIterator) (NodeIterator, *int) {
	h := make(nodeIteratorHeap, len(iters))
	copy(h, iters)
	heap.Init(&h)

	ui := &unionIterator{items: &h}
	return ui, &ui.count
}

func (it *unionIterator) Hash() common.Hash {
	return (*it.items)[0].Hash()
}

func (it *unionIterator) Parent() common.Hash {
	return (*it.items)[0].Parent()
}

func (it *unionIterator) Leaf() bool {
	return (*it.items)[0].Leaf()
}

func (it *unionIterator) LeafKey() []byte {
	return (*it.items)[0].LeafKey()
}

func (it *unionIterator) LeafBlob() []byte {
	return (*it.items)[0].LeafBlob()
}

func (it *unionIterator) LeafProof() [][]byte {
	return (*it.items)[0].LeafProof()
}
func (it *unionIterator) MyLeafProof_gen_path_store(prevBlockTrieDB ethdb.Database, blockNumber uint64, baseBlockNumber uint64) []MyNode {
	return (*it.items)[0].MyLeafProof_gen_path_store(prevBlockTrieDB, blockNumber, baseBlockNumber)
}

func (it *unionIterator) Path() []byte {
	return (*it.items)[0].Path()
}

func (it *unionIterator) MyGenLeafProof(proofList ethdb.KeyValueWriter, new_db ethdb.Database, blocknum uint64) error {
	return (*it.items)[0].MyGenLeafProof(proofList, new_db, blocknum)
}

func (it *unionIterator) Stack() []string {
	// You can combine the stack of all iterators in the union, or return one of them.
	// This example assumes we return the stack of the first iterator (you can adjust based on logic).
	return (*it.items)[0].Stack()
}
func (it *unionIterator) MyStack() []*NodeIteratorState {
	return (*it.items)[0].MyStack()
}

func (it *unionIterator) NodeBlob() []byte {
	return (*it.items)[0].NodeBlob()
}

func (it *unionIterator) AddResolver(resolver NodeResolver) {
	panic("not implemented")
}

// Next returns the next node in the union of tries being iterated over.
//
// It does this by maintaining a heap of iterators, sorted by the iteration
// order of their next elements, with one entry for each source trie. Each
// time Next() is called, it takes the least element from the heap to return,
// advancing any other iterators that also point to that same element. These
// iterators are called with descend=false, since we know that any nodes under
// these nodes will also be duplicates, found in the currently selected iterator.
// Whenever an iterator is advanced, it is pushed back into the heap if it still
// has elements remaining.
//
// In the case that descend=false - eg, we're asked to ignore all subnodes of the
// current node - we also advance any iterators in the heap that have the current
// path as a prefix.
func (it *unionIterator) Next(descend bool) bool {
	if len(*it.items) == 0 {
		return false
	}

	// Get the next key from the union
	least := heap.Pop(it.items).(NodeIterator)

	// Skip over other nodes as long as they're identical, or, if we're not descending, as
	// long as they have the same prefix as the current node.
	for len(*it.items) > 0 && ((!descend && bytes.HasPrefix((*it.items)[0].Path(), least.Path())) || compareNodes(least, (*it.items)[0]) == 0) {
		skipped := heap.Pop(it.items).(NodeIterator)
		// Skip the whole subtree if the nodes have hashes; otherwise just skip this node
		if skipped.Next(skipped.Hash() == common.Hash{}) {
			it.count++
			// If there are more elements, push the iterator back on the heap
			heap.Push(it.items, skipped)
		}
	}
	if least.Next(descend) {
		it.count++
		heap.Push(it.items, least)
	}
	return len(*it.items) > 0
}

func (it *unionIterator) Error() error {
	for i := 0; i < len(*it.items); i++ {
		if err := (*it.items)[i].Error(); err != nil {
			return err
		}
	}
	return nil
}
