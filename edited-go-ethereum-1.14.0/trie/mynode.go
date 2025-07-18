// to expose the node interface and its implementations for testing purposes.

package trie

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

var MyIndices = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "[17]"}

type MyNode interface {
	cache() ([]byte, bool)
	encode(w rlp.EncoderBuffer) // RLP encoding
	fString(string) string

	GetPath() []byte
	SetPath([]byte)
	GetBlockNumber() uint64
	SetBlockNumber(uint64)
	GetChildrenPointer() []MyNodeID
	SetChildrenPointer(childPointer MyNodeID, position uint8)
	SetRLPBytes([]byte) //deep copy
	GetRLPBytes() []byte
}

type (
	MyFullNode struct {
		NodeID          MyNodeID
		Children        [17]MyNode // Actual trie node data to encode/decode (needs custom encoder)
		ChildrenPointer [16]MyNodeID
		RLPBytes        []byte // store original proof bytes
		Flags           MyNodeFlag
	}
	MyShortNode struct {
		NodeID          MyNodeID
		Key             []byte
		Original_Key    []byte // to generate original proof, may become compact key after LeafProof()
		Val             MyNode
		ChildrenPointer MyNodeID
		RLPBytes        []byte // store original proof bytes
		Flags           MyNodeFlag
	}
	MyHashNode struct {
		NodeID MyNodeID
		Hash   []byte // The original hash data
	}
	MyValueNode struct {
		NodeID   MyNodeID
		Value    []byte // The original value data
		RLPBytes []byte // store original proof bytes
	}
)

type MyNodeID struct {
	Path        []byte // Path to the child node, hexToKeybytes(it.path) == it.key
	BlockNumber uint64 // previous Block number when the child node is changed
}

// nodeFlag contains caching-related metadata about a node.
// add blockNumber and path to the nodeFlag
type MyNodeFlag struct {
	Hash  []byte // cached hash of the node (may be nil)
	Dirty bool   // whether the node has changes that must be written to the database
}

func GetMyNodeTypeName(n MyNode) string {
	switch n.(type) {
	case *MyFullNode:
		return "MyFullNode"
	case *MyShortNode:
		return "MyShortNode"
	case *MyHashNode:
		return "MyHashNode"
	case *MyValueNode:
		return "MyValueNode"
	default:
		return "Unknown"
	}
}

// fill the blockNumber and path of the node
// fill children with prev block, then update changed nodes
// for init, the node blockid is baseBlockNumber
// return: pointer of MyNode object
func ConvertTrieNodeToMyNode(n node, path []byte,
	prevBlockTrieDB ethdb.Database, baseBlockNumber uint64) MyNode {
	switch tn := n.(type) {
	case *fullNode:
		nodeID := MyNodeID{Path: path, BlockNumber: baseBlockNumber}
		buf, err := prevBlockTrieDB.Get(path)
		if err != nil {
			// log.Printf("Failed to get lastest blockid for node %v: %v", path, err)
			// by default, set blockNumber to 0/baseBlockNumber
			nodeID.BlockNumber = uint64(baseBlockNumber)
			block_buf := make([]byte, 8)
			binary.BigEndian.PutUint64(block_buf, uint64(baseBlockNumber))
			prevBlockTrieDB.Put(path, block_buf)
		} else {
			nodeID.BlockNumber = binary.BigEndian.Uint64(buf)
		}
		// Convert the children from `[]node` to `[]MyNode`
		children := [17]MyNode{}
		childrenPointer := [16]MyNodeID{}
		for i, child := range tn.Children {
			if child != nil {
				if i < 16 {
					// 创建独立的 childPath，避免引用问题
					childPath := make([]byte, len(path)+1)
					copy(childPath, path)
					childPath[len(path)] = byte(i)
					children[i] = ConvertTrieNodeToMyNode(child, childPath, prevBlockTrieDB, baseBlockNumber)
					// deep copy path
					childrenPointer[i] = MyNodeID{Path: childPath, BlockNumber: baseBlockNumber}
					buf, err := prevBlockTrieDB.Get(childPath)
					if err != nil {
						// log.Printf("Failed to get lastest blockid for node %v: %v", childPath, err)
						// by default, set blockNumber to 0/baseBlockNumber
						childrenPointer[i].BlockNumber = uint64(baseBlockNumber)
						block_buf := make([]byte, 8)
						binary.BigEndian.PutUint64(block_buf, uint64(baseBlockNumber))
						prevBlockTrieDB.Put(childPath, block_buf)
					} else {
						childrenPointer[i].BlockNumber = binary.BigEndian.Uint64(buf)
					}
				}
			} else { // if child is nil, init child pointer
				children[i] = nil
				if i < 16 {
					childrenPointer[i].Path = nil
					childrenPointer[i].BlockNumber = baseBlockNumber
					block_buf := make([]byte, 8)
					binary.BigEndian.PutUint64(block_buf, uint64(baseBlockNumber))
					prevBlockTrieDB.Put(append(path, byte(i)), block_buf)
				}
			}
		}
		return &MyFullNode{
			NodeID:          nodeID,
			Children:        children,
			ChildrenPointer: childrenPointer,
			Flags:           ConvertTrieNodeFlagToMyNodeFlag(tn.flags),
		}
	case *shortNode:
		nodeID := MyNodeID{Path: path, BlockNumber: baseBlockNumber}
		buf, err := prevBlockTrieDB.Get(path)
		if err != nil {
			// log.Printf("Failed to get lastest blockid for node %v: %v", path, err)
			// by default, set blockNumber to 0/baseBlockNumber
			nodeID.BlockNumber = uint64(baseBlockNumber)
			block_buf := make([]byte, 8)
			binary.BigEndian.PutUint64(block_buf, uint64(baseBlockNumber))
			prevBlockTrieDB.Put(path, block_buf)
		} else {
			nodeID.BlockNumber = binary.BigEndian.Uint64(buf)
		}
		// Convert the `Val` field from `node` to `MyNode`
		// 创建独立的 childPath，避免引用问题
		childPath := make([]byte, len(path)+len(tn.Key))
		copy(childPath, path)               // 拷贝原始 path
		copy(childPath[len(path):], tn.Key) // 拷贝 tn.Key
		childPointer := MyNodeID{Path: childPath, BlockNumber: baseBlockNumber}
		buf, err = prevBlockTrieDB.Get(childPath)
		if err != nil {
			// log.Printf("Failed to get lastest blockid for node %v: %v", childPath, err)
			// by default, set blockNumber to 0/baseBlockNumber
			childPointer.BlockNumber = uint64(baseBlockNumber)
			block_buf := make([]byte, 8)
			binary.BigEndian.PutUint64(block_buf, uint64(baseBlockNumber))
			prevBlockTrieDB.Put(childPath, block_buf)
		} else {
			childPointer.BlockNumber = binary.BigEndian.Uint64(buf)
		}

		// to generate original proof, need compact key for RLP encode()
		// hasher := newHasher(false)
		// defer returnHasherToPool(hasher)
		// node, hashed := hasher.proofHash(n) // whether is pure function or not?
		// var original_compact_key []byte
		// if _, ok := hashed.(hashNode); ok {
		// 	original_compact_key = node.(*shortNode).Key
		// 	// for testing
		// 	tmp_compact_key := HexToCompact(tn.Key)
		// 	if !bytes.Equal(original_compact_key, tmp_compact_key) {
		// 		log.Printf("Original compact key is different: %v, %v\n", original_compact_key, tmp_compact_key)
		// 	}
		// } else {
		// 	original_compact_key = nil
		// }
		original_compact_key := HexToCompact(tn.Key) // todo: maybe wrong

		return &MyShortNode{
			NodeID:          nodeID,
			Key:             tn.Key,
			Original_Key:    original_compact_key,
			Val:             ConvertTrieNodeToMyNode(tn.Val, childPath, prevBlockTrieDB, baseBlockNumber),
			ChildrenPointer: childPointer,
			Flags:           ConvertTrieNodeFlagToMyNodeFlag(tn.flags),
		}
	case hashNode:
		NodeID := MyNodeID{Path: path, BlockNumber: baseBlockNumber}
		buf, err := prevBlockTrieDB.Get(path)
		if err != nil {
			// log.Printf("Failed to get lastest blockid for node %v: %v", path, err)
			// by default, set blockNumber to 0/baseBlockNumber
			NodeID.BlockNumber = uint64(baseBlockNumber)
			block_buf := make([]byte, 8)
			binary.BigEndian.PutUint64(block_buf, uint64(baseBlockNumber))
			prevBlockTrieDB.Put(path, block_buf)
		} else {
			NodeID.BlockNumber = binary.BigEndian.Uint64(buf)
		}
		return &MyHashNode{
			NodeID: NodeID,
			Hash:   []byte(tn),
		}
	case valueNode:
		NodeID := MyNodeID{Path: path, BlockNumber: baseBlockNumber}
		buf, err := prevBlockTrieDB.Get(path)
		if err != nil {
			// log.Printf("Failed to get lastest blockid for node %v: %v", path, err)
			// by default, set blockNumber to 0
			NodeID.BlockNumber = uint64(baseBlockNumber)
			block_buf := make([]byte, 8)
			binary.BigEndian.PutUint64(block_buf, uint64(baseBlockNumber))
			prevBlockTrieDB.Put(path, block_buf)
		} else {
			NodeID.BlockNumber = binary.BigEndian.Uint64(buf)
		}
		return &MyValueNode{
			NodeID: NodeID,
			Value:  []byte(tn),
		}
	default:
		return nil
	}
}
func ConvertTrieNodeFlagToMyNodeFlag(f nodeFlag) MyNodeFlag {
	return MyNodeFlag{
		Hash:  f.hash,
		Dirty: f.dirty,
	}
}
func CompareMyNode(n1 *MyNode, n2 *MyNode) bool {
	if n1 == nil || n2 == nil {
		log.Printf("Node is nil\n")
		return false
	}
	if GetMyNodeTypeName(*n1) != GetMyNodeTypeName(*n2) {
		log.Printf("Node type is different: %v, %v\n", GetMyNodeTypeName(*n1), GetMyNodeTypeName(*n2))
		return false
	}
	switch n := (*n1).(type) {
	case *MyFullNode:
		n2 := (*n2).(*MyFullNode)
		if n.NodeID.BlockNumber != n2.NodeID.BlockNumber {
			log.Printf("BlockNumber is different: %v, %v\n", n.NodeID.BlockNumber, n2.NodeID.BlockNumber)
			return false
		}
		if !bytes.Equal(n.NodeID.Path, n2.NodeID.Path) {
			log.Printf("Path is different: %v, %v\n", n.NodeID.Path, n2.NodeID.Path)
			return false
		}
		for i, child := range n.ChildrenPointer {
			if child.BlockNumber != n2.ChildrenPointer[i].BlockNumber {
				log.Printf("BlockNumber is different: %v, %v\n", child.BlockNumber, n2.ChildrenPointer[i].BlockNumber)
				return false
			}
			if !bytes.Equal(child.Path, n2.ChildrenPointer[i].Path) {
				log.Printf("Path is different: %v, %v\n", child.Path, n2.ChildrenPointer[i].Path)
				return false
			}
		}
		// for i, child := range n.Children {
		// 	if !CompareMyNode(&child, &n2.Children[i]) {
		// 		return false
		// 	}
		// }
	case *MyShortNode:
		n2 := (*n2).(*MyShortNode)
		if n.NodeID.BlockNumber != n2.NodeID.BlockNumber {
			log.Printf("BlockNumber is different: %v, %v\n", n.NodeID.BlockNumber, n2.NodeID.BlockNumber)
			return false
		}
		if !bytes.Equal(n.NodeID.Path, n2.NodeID.Path) {
			log.Printf("Path is different: %v, %v\n", n.NodeID.Path, n2.NodeID.Path)
			return false
		}
		//childpointer
		if n.ChildrenPointer.BlockNumber != n2.ChildrenPointer.BlockNumber {
			log.Printf("BlockNumber is different: %v, %v\n", n.ChildrenPointer.BlockNumber, n2.ChildrenPointer.BlockNumber)
			return false
		}
		if !bytes.Equal(n.ChildrenPointer.Path, n2.ChildrenPointer.Path) {
			log.Printf("Path is different: %v, %v\n", n.ChildrenPointer.Path, n2.ChildrenPointer.Path)
			return false
		}
		if !bytes.Equal(n.Key, n2.Key) {
			log.Printf("Key is different: %v, %v\n", n.Key, n2.Key)
			return false
		}
		// if !CompareMyNode(&n.Val, &n2.Val) {
		// 	return false
		// }
	case *MyHashNode:
		n2 := (*n2).(*MyHashNode)
		if n.NodeID.BlockNumber != n2.NodeID.BlockNumber {
			log.Printf("BlockNumber is different: %v, %v\n", n.NodeID.BlockNumber, n2.NodeID.BlockNumber)
			return false
		}
		if !bytes.Equal(n.NodeID.Path, n2.NodeID.Path) {
			log.Printf("Path is different: %v, %v\n", n.NodeID.Path, n2.NodeID.Path)
			return false
		}
	case *MyValueNode:
		n2 := (*n2).(*MyValueNode)
		if n.NodeID.BlockNumber != n2.NodeID.BlockNumber {
			log.Printf("BlockNumber is different: %v, %v\n", n.NodeID.BlockNumber, n2.NodeID.BlockNumber)
			return false
		}
		if !bytes.Equal(n.NodeID.Path, n2.NodeID.Path) {
			log.Printf("Path is different: %v, %v\n", n.NodeID.Path, n2.NodeID.Path)
			return false
		}
		if !bytes.Equal(n.Value, n2.Value) {
			log.Printf("Value is different: %v, %v\n", n.Value, n2.Value)
			return false
		}
	default:
		return false
	}
	return true
}

// EncodeRLP encodes a full node into the consensus RLP format.
func (n *MyFullNode) EncodeRLP(w io.Writer) error {
	eb := rlp.NewEncoderBuffer(w)
	n.encode(eb)
	return eb.Flush()
}

func (n *MyFullNode) GetChildrenPointer() []MyNodeID {
	res := make([]MyNodeID, 16)
	copy(res, n.ChildrenPointer[:])
	return res
}
func (n *MyShortNode) GetChildrenPointer() []MyNodeID {
	res := make([]MyNodeID, 1)
	res[0] = n.ChildrenPointer
	return res
}
func (n *MyValueNode) GetChildrenPointer() []MyNodeID {
	return nil
}
func (n *MyHashNode) GetChildrenPointer() []MyNodeID {
	return nil
}
func (n *MyFullNode) SetChildrenPointer(children MyNodeID, position uint8) {
	n.ChildrenPointer[position] = children
}
func (n *MyShortNode) SetChildrenPointer(child MyNodeID, position uint8) {
	n.ChildrenPointer = child
}
func (n *MyValueNode) SetChildrenPointer(child MyNodeID, position uint8) {}
func (n *MyHashNode) SetChildrenPointer(child MyNodeID, position uint8)  {}

func (n *MyFullNode) GetPath() []byte  { return n.NodeID.Path }
func (n *MyShortNode) GetPath() []byte { return n.NodeID.Path }
func (n *MyHashNode) GetPath() []byte  { return n.NodeID.Path }
func (n *MyValueNode) GetPath() []byte { return n.NodeID.Path }

func (n *MyFullNode) SetPath(path []byte)  { n.NodeID.Path = path }
func (n *MyShortNode) SetPath(path []byte) { n.NodeID.Path = path }
func (n *MyHashNode) SetPath(path []byte)  { n.NodeID.Path = path }
func (n *MyValueNode) SetPath(path []byte) { n.NodeID.Path = path }

func (n *MyFullNode) GetBlockNumber() uint64  { return n.NodeID.BlockNumber }
func (n *MyShortNode) GetBlockNumber() uint64 { return n.NodeID.BlockNumber }
func (n *MyHashNode) GetBlockNumber() uint64  { return n.NodeID.BlockNumber }
func (n *MyValueNode) GetBlockNumber() uint64 { return n.NodeID.BlockNumber }

func (n *MyFullNode) SetBlockNumber(blockNumber uint64)  { n.NodeID.BlockNumber = blockNumber }
func (n *MyShortNode) SetBlockNumber(blockNumber uint64) { n.NodeID.BlockNumber = blockNumber }
func (n *MyHashNode) SetBlockNumber(blockNumber uint64)  { n.NodeID.BlockNumber = blockNumber }
func (n *MyValueNode) SetBlockNumber(blockNumber uint64) { n.NodeID.BlockNumber = blockNumber }

func (n *MyFullNode) SetRLPBytes(b []byte) {
	n.RLPBytes = make([]byte, len(b))
	copy(n.RLPBytes, b)
}
func (n *MyShortNode) SetRLPBytes(b []byte) {
	n.RLPBytes = make([]byte, len(b))
	copy(n.RLPBytes, b)
}
func (n *MyHashNode) SetRLPBytes(b []byte) {
	return
}
func (n *MyValueNode) SetRLPBytes(b []byte) {
	n.RLPBytes = make([]byte, len(b))
	copy(n.RLPBytes, b)
}

func (n *MyFullNode) GetRLPBytes() []byte {
	if n.RLPBytes == nil {
		n.RLPBytes = MyNodeToOriginalProofBytes(n)
	}
	return n.RLPBytes
}
func (n *MyShortNode) GetRLPBytes() []byte {
	if n.RLPBytes == nil {
		n.RLPBytes = MyNodeToOriginalProofBytes(n)
	}
	return n.RLPBytes
}
func (n *MyHashNode) GetRLPBytes() []byte { return nil }
func (n *MyValueNode) GetRLPBytes() []byte {
	if n.RLPBytes == nil {
		n.RLPBytes = MyNodeToOriginalProofBytes(n)
	}
	return n.RLPBytes
}

func (n *MyFullNode) copy() *MyFullNode   { copy := *n; return &copy }
func (n *MyShortNode) copy() *MyShortNode { copy := *n; return &copy }

func (n *MyFullNode) cache() ([]byte, bool)  { return n.Flags.Hash, n.Flags.Dirty }
func (n *MyShortNode) cache() ([]byte, bool) { return n.Flags.Hash, n.Flags.Dirty }
func (n *MyHashNode) cache() ([]byte, bool)  { return nil, true }
func (n *MyValueNode) cache() ([]byte, bool) { return nil, true }

// Pretty printing.
func (n *MyFullNode) String() string  { return n.fString("") }
func (n *MyShortNode) String() string { return n.fString("") }
func (n *MyHashNode) String() string  { return n.fString("") }
func (n *MyValueNode) String() string { return n.fString("") }

func (n *MyFullNode) fString(ind string) string {
	resp := fmt.Sprintf("[\n%s  ", ind)
	resp += fmt.Sprintf("Path: %x, BlockNumber: %d,", n.NodeID.Path, n.NodeID.BlockNumber)
	for i, node := range &n.Children {
		if node == nil {
			resp += fmt.Sprintf("%s: <nil> ", MyIndices[i])
		} else {
			resp += fmt.Sprintf("%s: %v", MyIndices[i], node.fString(ind+"  "))
		}
	}
	return resp + fmt.Sprintf("\n%s] ", ind)
}
func (n *MyShortNode) fString(ind string) string {
	return fmt.Sprintf("{Path %x,BlockNumber %d,Key %x: %v} ",
		n.NodeID.Path, n.NodeID.BlockNumber, n.Key, n.Val.fString(ind+"  "))
}
func (n *MyHashNode) fString(ind string) string {
	return fmt.Sprintf("<Path %x,BlockNumber %d,hash %x> ", n.NodeID.Path, n.NodeID.BlockNumber, n.Hash)
}
func (n *MyValueNode) fString(ind string) string {
	return fmt.Sprintf("|Path %x,BlockNumber %d,val %x| ", n.NodeID.Path, n.NodeID.BlockNumber, n.Value)
}

// original trie node encoding
// fullnode: 16 children
// shortnode: key, value
// valuenode: value
func MyNodeToOriginalProofBytes(n MyNode) []byte {
	w := rlp.NewEncoderBuffer(nil)
	n.encode(w)
	result := w.ToBytes()
	w.Flush()
	return result
}

func (n *MyFullNode) encode(w rlp.EncoderBuffer) {
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

func (n *MyShortNode) encode(w rlp.EncoderBuffer) {
	offset := w.List()
	w.WriteBytes(n.Original_Key)
	if n.Val != nil {
		n.Val.encode(w)
	} else {
		w.Write(rlp.EmptyString)
	}
	w.ListEnd(offset)
}

func (n *MyHashNode) encode(w rlp.EncoderBuffer) {
	w.WriteBytes(n.Hash)
}

func (n *MyValueNode) encode(w rlp.EncoderBuffer) {
	w.WriteBytes(n.Value)
}

func (n MyRawNode) encode(w rlp.EncoderBuffer) {
	w.Write(n)
}

// rawNode is a simple binary blob used to differentiate between collapsed trie
// nodes and already encoded RLP binary blobs (while at the same time store them
// in the same cache fields).
type MyRawNode []byte

func (n MyRawNode) cache() (MyHashNode, bool) { panic("this should never end up in a live trie") }
func (n MyRawNode) Fstring(ind string) string { panic("this should never end up in a live trie") }

func (n MyRawNode) EncodeRLP(w io.Writer) error {
	_, err := w.Write(n)
	return err
}

// mustDecodeNode is a wrapper of decodeNode and panic if any error is encountered.
// func myMustDecodeNode(buf []byte) MyNode {
// 	n, err := myDecodeNode(buf)
// 	if err != nil {
// 		panic(fmt.Sprintf("node: %v", err))
// 	}
// 	return n
// }

// mustDecodeNodeUnsafe is a wrapper of decodeNodeUnsafe and panic if any error is
// encountered.
func MyMustDecodeNodeUnsafe(buf []byte) MyNode {
	n, err := myDecodeNodeUnsafe(buf)
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
func myDecodeNode(buf []byte) (MyNode, error) {
	return myDecodeNodeUnsafe(common.CopyBytes(buf))
}

// decodeNodeUnsafe parses the RLP encoding of a trie node. The passed byte slice
// will be directly referenced by node without bytes deep copy, so the input MUST
// not be changed after.
func myDecodeNodeUnsafe(buf []byte) (MyNode, error) {
	if len(buf) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	elems, _, err := rlp.SplitList(buf)
	if err != nil {
		return nil, fmt.Errorf("decode error: %v", err)
	}
	switch c, _ := rlp.CountValues(elems); c {
	case 2:
		n, err := myDecodeShort(elems)
		return n, WrapError(err, "short")
	case 17:
		n, err := myDecodeFull(elems)
		return n, WrapError(err, "full")
	default:
		return nil, fmt.Errorf("invalid number of list elements: %v", c)
	}
}

// see trie/endcoding.go
// Trie keys are dealt with in three distinct encodings:
//
// KEYBYTES encoding contains the actual key and nothing else. This encoding is the
// input to most API functions.
//
// HEX encoding contains one byte for each nibble of the key and an optional trailing
// 'terminator' byte of value 0x10 which indicates whether or not the node at the key
// contains a value. Hex key encoding is used for nodes loaded in memory because it's
// convenient to access.
//
// COMPACT encoding is defined by the Ethereum Yellow Paper (it's called "hex prefix
// encoding" there) and contains the bytes of the key and a flag. The high nibble of the
// first byte contains the flag; the lowest bit encoding the oddness of the length and
// the second-lowest encoding whether the node at the key is a value node. The low nibble
// of the first byte is zero in the case of an even number of nibbles and the first nibble
// in the case of an odd number. All remaining nibbles (now an even number) fit properly
// into the remaining bytes. Compact encoding is used for nodes stored on disk.

// 1. trie.NodeIterator(start=keybytes) use account keybytes to start the iterator, see seek()
// 2. trie.NodeIterator.Path() return the hex path of the account, see LeafKey()
// keybytes: 32 bytem hex: 64 byte, key的每个字节被拆分为两部分（高 4 位和低 4 位），称为 nibbles

func KeybytesToHex(str []byte) []byte {
	l := len(str)*2 + 1
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}
	nibbles[l-1] = 16
	return nibbles
}

// hexToKeybytes turns hex nibbles into key bytes.
// This can only be used for keys of even length.
func HexToKeybytes(hex []byte) []byte {
	if hasTerm(hex) {
		hex = hex[:len(hex)-1]
	}
	if len(hex)&1 != 0 {
		panic("can't convert hex key of odd length")
	}
	key := make([]byte, len(hex)/2)
	decodeNibbles(hex, key)
	return key
}
func CompactToHex(compact []byte) []byte {
	if len(compact) == 0 {
		return compact
	}
	base := KeybytesToHex(compact)
	// delete terminator flag
	if base[0] < 2 {
		base = base[:len(base)-1]
	}
	// apply odd flag
	chop := 2 - base[0]&1
	return base[chop:]
}
func HexToCompact(hex []byte) []byte {
	terminator := byte(0)
	if hasTerm(hex) {
		terminator = 1
		hex = hex[:len(hex)-1]
	}
	buf := make([]byte, len(hex)/2+1)
	buf[0] = terminator << 5 // the flag byte
	if len(hex)&1 == 1 {
		buf[0] |= 1 << 4 // odd flag
		buf[0] |= hex[0] // first nibble is contained in the first byte
		hex = hex[1:]
	}
	decodeNibbles(hex, buf[1:])
	return buf
}

// see internal/ethapi/api.go: GetProof()
func AddressToStateKeyBytes(addr common.Address) []byte {
	keyBytes := crypto.Keccak256(addr.Bytes())
	return keyBytes
}

// see trie/proof.go: Prove()
func AddressToStateHexPath(addr common.Address) []byte {
	keyBytes := crypto.Keccak256(addr.Bytes())
	hex := KeybytesToHex(keyBytes)
	return hex
}
func AddressToStateCompactKey(addr common.Address) []byte {
	keyBytes := crypto.Keccak256(addr.Bytes())
	compact := HexToCompact(KeybytesToHex(keyBytes))
	return compact
}

// return true if a and b are equal
func CompareStateAccount(a *types.StateAccount, b *types.StateAccount) bool {
	if a.Nonce != b.Nonce {
		return false
	}
	if a.Balance.Cmp(b.Balance) != 0 {
		return false
	}
	if a.Root != b.Root {
		return false
	}
	if !bytes.Equal(a.CodeHash, b.CodeHash) {
		return false
	}
	return true
}
func myDecodeShort(elems []byte) (MyNode, error) {
	kbuf, rest, err := rlp.SplitString(elems)
	if err != nil {
		return nil, err
	}
	// flag := MyNodeFlag{Hash: hash}
	// see go-ethereum-1.14.0/trie/node_test.go: BenchmarkDecodeShortNodeUnsafe()
	// blob := nodeToBytes(node)
	// hash := crypto.Keccak256(blob)
	// todo: when to use cached hash?
	// in original geth hash-store, hash is hold by parent, now it is stored in node cache to avoid recalculation
	// it will be used in proofHash() when flating trie node to bytes
	// but in final proof, nodeToBytes() will not contain the hash of this node
	// so we donot need to store hash in cache
	flag := MyNodeFlag{Hash: nil, Dirty: false}
	key := CompactToHex(kbuf)
	if hasTerm(key) {
		// value node
		val, _, err := rlp.SplitString(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid value node: %v", err)
		}
		//todo: add blockNumber and path
		nodeID := MyNodeID{nil, 0}
		return &MyShortNode{
			Key:   key,
			Val:   &MyValueNode{nodeID, val, nil},
			Flags: flag}, nil
	}
	r, _, err := myDecodeRef(rest)
	if err != nil {
		return nil, WrapError(err, "val")
	}
	return &MyShortNode{Key: key, Val: r, Flags: flag}, nil
}

func myDecodeFull(elems []byte) (*MyFullNode, error) {
	// n := &MyFullNode{Flags: MyNodeFlag{Hash: hash}}
	n := &MyFullNode{Flags: MyNodeFlag{Hash: nil, Dirty: false}}
	for i := 0; i < 16; i++ {
		cld, rest, err := myDecodeRef(elems)
		if err != nil {
			return n, WrapError(err, fmt.Sprintf("[%d]", i))
		}
		n.Children[i], elems = cld, rest
	}
	val, _, err := rlp.SplitString(elems)
	if err != nil {
		return n, err
	}
	if len(val) > 0 {
		//todo: add blockNumber and path
		nodeID := MyNodeID{nil, 0}
		node := &MyValueNode{NodeID: nodeID, Value: val}
		n.Children[16] = node
	}
	return n, nil
}

const HashLen = len(common.Hash{})

func myDecodeRef(buf []byte) (MyNode, []byte, error) {
	kind, val, rest, err := rlp.Split(buf)
	if err != nil {
		return nil, buf, err
	}
	switch {
	case kind == rlp.List:
		// 'embedded' node reference. The encoding must be smaller
		// than a hash in order to be valid.
		if size := len(buf) - len(rest); size > HashLen {
			err := fmt.Errorf("oversized embedded node (size is %d bytes, want size < %d)", size, HashLen)
			return nil, buf, err
		}
		n, err := myDecodeNode(buf)
		return n, rest, err
	case kind == rlp.String && len(val) == 0:
		// empty node
		return nil, rest, nil
	case kind == rlp.String && len(val) == 32:
		//todo: add blockNumber and path
		nodeID := MyNodeID{nil, 0}
		node := &MyHashNode{NodeID: nodeID, Hash: val}
		return node, rest, nil
	default:
		return nil, nil, fmt.Errorf("invalid RLP string size %d (want 0 or 32)", len(val))
	}
}

// wraps a decoding error with information about the path to the
// invalid child node (for debugging encoding issues).
type MyDecodeError struct {
	What  error
	Stack []string
}

func WrapError(err error, ctx string) error {
	if err == nil {
		return nil
	}
	if decErr, ok := err.(*MyDecodeError); ok {
		decErr.Stack = append(decErr.Stack, ctx)
		return decErr
	}
	return &MyDecodeError{What: err, Stack: []string{ctx}}
}

func (err *MyDecodeError) Error() string {
	return fmt.Sprintf("%v (decode path: %s)", err.What, strings.Join(err.Stack, "<-"))
}
