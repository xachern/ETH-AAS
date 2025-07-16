package store

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"myeth/skiplist"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	// "github.com/huandu/skiplist"
)

// global file handler:  contract address
const Contract_address_dir = "~/code/geth/eth_aas/test_hash/point_storage_query"

const Contract_address_file = Contract_address_dir + "/contract_address.txt"

var Contract_address_file_handler *os.File

type MyProofNode struct {
	blob        []byte // original node bytes
	blockNumber uint64 // block number
	key         []byte // key of the node, may have been contained in the blob
}

// memory pool: map[account] = proof path, skiplists[account]= version list
// path = [node1, node2, ...] of account
type MyMemoryPool struct {
	Proofs              map[string][]trie.MyNode // accountHex+blocknumber -> proof path
	VersionLists        map[string]*VersionList  // string(accountHex) -> version list
	ProofDB             ethdb.Database
	VersionListDB       ethdb.Database
	proofCapacity       int
	versionListCapacity int
}

func NewMyMemoryPool(proofCapacity, versionListCapacity int, proofDB ethdb.Database, versionListDB ethdb.Database) *MyMemoryPool {
	return &MyMemoryPool{
		Proofs:              make(map[string][]trie.MyNode, proofCapacity),
		VersionLists:        make(map[string]*VersionList, versionListCapacity),
		ProofDB:             proofDB,
		VersionListDB:       versionListDB,
		proofCapacity:       proofCapacity,
		versionListCapacity: versionListCapacity,
	}
}

func (mp *MyMemoryPool) PutStorageSlot(accountHex []byte, blockNumber uint64, storageKeyBytes []byte, proof []trie.MyNode) {
	// key = accountHex + storageKeyBytes + blockNumber
	key := fmt.Sprintf("%x_%x_%d", accountHex, storageKeyBytes, blockNumber)
	fmt.Printf("PutStorageSlot , key: %s\n", key)
	if _, exists := mp.Proofs[key]; exists {
		return
	}
	mp.Proofs[key] = proof

	if len(mp.Proofs) > mp.proofCapacity {
		// key: accountHex + blockNumber, value: proofs bytes
		for nodeid, proof := range mp.Proofs {
			key_bytes := []byte(nodeid)
			proofBytes := proofListToBytes(proof)
			mp.ProofDB.Put(key_bytes, proofBytes)
		}
		//clear
		mp.Proofs = make(map[string][]trie.MyNode, mp.proofCapacity)
	}
}
func (mp *MyMemoryPool) GetStorageSlot(accountHex []byte, blockNumber uint64, storageKeyBytes []byte) []trie.MyNode {
	key := fmt.Sprintf("%x_%x_%d", accountHex, storageKeyBytes, blockNumber)
	if proof, exists := mp.Proofs[key]; exists {
		return proof
	}
	// check proofDB
	key_bytes := []byte(key)
	proofBytes, err := mp.ProofDB.Get(key_bytes)
	if err != nil {
		log.Fatalf("Failed to read proof from proofDB: %v", err)
		return nil
	}
	proof, err := BytesToProofList(proofBytes)
	if err != nil {
		log.Fatalf("Failed to decode proof: %v", err)
	}
	return proof
}

func (mp *MyMemoryPool) PutProof(accountHex []byte, blockNumber uint64, proof []trie.MyNode) {
	// key = accountHex + blockNumber
	key := fmt.Sprintf("%x_%d", accountHex, blockNumber)
	if _, exists := mp.Proofs[key]; exists {
		return
	}
	mp.Proofs[key] = proof

	if len(mp.Proofs) > mp.proofCapacity {
		// key: accountHex + blockNumber, value: proofs bytes
		for nodeid, proof := range mp.Proofs {
			// key = accountHex + blockNumber
			// key_bytes := []byte(nodeid)
			// split string by '_'
			parts := strings.Split(nodeid, "_")
			if len(parts) != 2 {
				log.Fatalf("Invalid nodeid format: %s", nodeid)
			}
			accountHex := []byte(parts[0])
			blockNumber, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				log.Fatalf("Failed to parse block number from nodeid: %s, error: %v", nodeid, err)
			}

			var bytes bytes.Buffer
			encoder := gob.NewEncoder(&bytes)
			encoder.Encode(accountHex)
			encoder.Encode(blockNumber)

			key_bytes := bytes.Bytes()
			proofBytes := proofListToBytes(proof)
			mp.ProofDB.Put(key_bytes, proofBytes)
		}
		//clear
		mp.Proofs = make(map[string][]trie.MyNode, mp.proofCapacity)
	}
}
func (mp *MyMemoryPool) GetProof(accountHex []byte, blockNumber uint64) []trie.MyNode {
	key := fmt.Sprintf("%x_%d", accountHex, blockNumber)
	if proof, exists := mp.Proofs[key]; exists {
		return proof
	}
	// check proofDB
	var bytes bytes.Buffer
	encoder := gob.NewEncoder(&bytes)
	encoder.Encode(accountHex)
	encoder.Encode(blockNumber)

	proofBytes, err := mp.ProofDB.Get(bytes.Bytes())
	if err != nil {
		log.Fatalf("Failed to read proof from proofDB: %v", err)
		return nil
	}
	proof, err := BytesToProofList(proofBytes)
	if err != nil {
		log.Fatalf("Failed to decode proof: %v", err)
	}
	return proof
}
func (mp *MyMemoryPool) AppendVersionList(accountHex []byte, blockNumber uint64) {
	accountHexStr := string(accountHex)
	if _, exists := mp.VersionLists[accountHexStr]; !exists { // create new skiplist
		// check VersionListDB
		key := fmt.Sprintf("%s_versions", accountHexStr)
		key_bytes := []byte(key)
		versionListBytes, err := mp.VersionListDB.Get(key_bytes)
		if err != nil { // key not exist
			mp.VersionLists[accountHexStr] = NewVersionList()
		} else {
			versionList, err := DeserializeVersionlist(versionListBytes)
			if err != nil {
				log.Fatalf("Failed to deserialize version list: %v", err)
			}
			mp.VersionLists[accountHexStr] = versionList
		}
	}
	// append to skiplist
	mp.VersionLists[accountHexStr].AddVersion(blockNumber)

	if len(mp.VersionLists) > mp.versionListCapacity {
		// key: accountHex + "_versions", value: skiplist
		for accountHexStr, versionList := range mp.VersionLists {
			key := fmt.Sprintf("%s_versions", accountHexStr)
			keyBytes := []byte(key)
			versionListBytes, err := versionList.Serialize()
			if err != nil {
				log.Fatalf("Failed to serialize version list: %v", err)
			}
			mp.VersionListDB.Put(keyBytes, versionListBytes)
		}
		//clear
		mp.VersionLists = make(map[string]*VersionList, mp.versionListCapacity)
	}
}
func ReadVersionList(account common.Address, versionListDB ethdb.Database) *VersionList {
	accountHex := trie.AddressToStateHexPath(account)
	accountHexStr := string(accountHex)

	key := fmt.Sprintf("%s_versions", accountHexStr)
	key_bytes := []byte(key)
	versionListBytes, err := versionListDB.Get(key_bytes)
	if err != nil {
		log.Fatalf("Failed to read version list for %s from versionListDB: %v", account.Hex(), err)
		return nil
	}
	versionList, err := DeserializeVersionlist(versionListBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize version list: %v", err)
	}
	return versionList
}

func (mp *MyMemoryPool) GetVersionList(accountHex []byte) *VersionList {
	accountHexStr := string(accountHex)
	if versionList, exists := mp.VersionLists[accountHexStr]; exists {
		return versionList
	}
	key := fmt.Sprintf("%s_versions", accountHexStr)
	key_bytes := []byte(key)
	versionListBytes, err := mp.VersionListDB.Get(key_bytes)
	if err != nil {
		log.Printf("Failed to read version list from versionListDB: %v", err)
		return nil
	}
	versionList, err := DeserializeVersionlist(versionListBytes)
	if err != nil {
		log.Printf("Failed to deserialize version list: %v", err)
		return nil
	}
	return versionList
}

func (mp *MyMemoryPool) Force_Flush() {
	total_proof := len(mp.Proofs)
	proof_cnt := 0
	for nodeid, proof := range mp.Proofs {
		// key = accountHex + blockNumber
		parts := strings.Split(nodeid, "_")
		if len(parts) != 2 {
			log.Fatalf("Invalid nodeid format: %s", nodeid)
		}
		accountHex := []byte(parts[0])
		blockNumber, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			log.Fatalf("Failed to parse block number from nodeid: %s, error: %v", nodeid, err)
		}

		var bytes bytes.Buffer
		encoder := gob.NewEncoder(&bytes)
		encoder.Encode(accountHex)
		encoder.Encode(blockNumber)

		proofBytes := proofListToBytes(proof)
		mp.ProofDB.Put(bytes.Bytes(), proofBytes)

		proof_cnt++
		if total_proof > 10000 && proof_cnt%100 == 0 {
			fmt.Printf("flushing proof %d/%d\n", proof_cnt, total_proof)
		}
	}

	// flush all skiplists to disk
	total_versionlist := len(mp.VersionLists)
	versionlist_cnt := 0
	for accountHexStr, versionList := range mp.VersionLists {
		key := fmt.Sprintf("%s_versions", accountHexStr)
		key_bytes := []byte(key)
		versionListBytes, err := versionList.Serialize()
		if err != nil {
			log.Fatalf("Failed to serialize version list: %v", err)
		}
		mp.VersionListDB.Put(key_bytes, versionListBytes)

		versionlist_cnt++
		if total_versionlist > 10000 && versionlist_cnt%100 == 0 {
			fmt.Printf("flushing versionlist %d/%d\n", versionlist_cnt, total_versionlist)
		}
	}

	//clear
	mp.Proofs = make(map[string][]trie.MyNode, mp.proofCapacity)
	mp.VersionLists = make(map[string]*VersionList, mp.versionListCapacity)
}

func (mp *MyMemoryPool) Flush_no_clear_testing() {
	total_proof := len(mp.Proofs)
	proof_cnt := 0
	for nodeid, proof := range mp.Proofs {
		key_bytes := []byte(nodeid)
		proofBytes := proofListToBytes(proof)
		mp.ProofDB.Put(key_bytes, proofBytes)

		proof_cnt++
		if total_proof > 10000 && proof_cnt%100 == 0 {
			fmt.Printf("flushing proof %d/%d\n", proof_cnt, total_proof)
		}
	}

	total_versionlist := len(mp.VersionLists)
	versionlist_cnt := 0
	for accountHexStr, versionList := range mp.VersionLists {
		key := fmt.Sprintf("%s_versions", accountHexStr)
		key_bytes := []byte(key)
		versionListBytes, err := versionList.Serialize()
		if err != nil {
			log.Fatalf("Failed to serialize version list: %v", err)
		}
		mp.VersionListDB.Put(key_bytes, versionListBytes)

		versionlist_cnt++
		if total_versionlist > 10000 && versionlist_cnt%100 == 0 {
			fmt.Printf("flushing versionlist %d/%d\n", versionlist_cnt, total_versionlist)
		}
	}
}

// ========================================================
// 1.in-memory proofList []trie.MyNode
// 2.on-disk proofBytes []byte
// 3.original merkel proof RLPBytes [][]byte
// 1 -> proofListToBytes() -> 2 -> BytesToProofList() ->1
// 2 -> BytesToOriginalMerkelProof_without_decoding() -> 3
// 1 -> ProofListToOriginalMerkelProof_without_encoding() -> 3
// ========================================================

// wrap old RLP bytes with blockNumber and path
// fullnode and shortnode stores pointer to children, pointer = {childBlocknumber}
// if child is nil, childBlock is set as 0
// nodeType: 1: fullNode, 2: shortNode, 3: hashNode, 4: valueNode
// schema : nodeType + nodeID + (optional) childPointer + RLP bytes
// fullNode schema:
//
//	1.nodeType + 2.blockNumber + 3.pathLen + 4.path +
//	5.childPointer + 6.RLPLen + 7.RLP bytes
//
// shortNode schema:
//
//	1.nodeType + 2.blockNumber + 3.pathLen + 4.path + 5.keyLen + 6.key
//	7.childPointer + 8.RLPLen + 9.RLP bytes
//
// valueNode and hashNode schema:
//
//	1.nodeType + 2.blockNumber + 3.pathLen + 4.path +
//	5.RLPLen + 6.RLP bytes
func encodeProofNode(n trie.MyNode) []byte {
	var (
		NodeTypeBytes     []byte
		blockNumberBytes  []byte
		pathLenBytes      []byte
		pathBytes         []byte
		childPointerBytes []byte
		RLPLenBytes       []byte
		RLPBytes          []byte
		buffer            []byte
		// for short node
		shortKeyLenBytes []byte
		shortKeyBytes    []byte
	)

	// 2. blockNumber
	blockNumberBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, n.GetBlockNumber())
	// 3. pathLen, 4. path,
	pathBytes = n.GetPath() // max len = 65
	pathLen := uint8(len(pathBytes))
	pathLenBytes = []byte{byte(pathLen)}
	// 1.NodeType, 5&6 short node key,
	// 7.childPointer: full node [16]childBlockNumber, short node {childBlockNumber}
	switch n.(type) {
	case *trie.MyFullNode:
		NodeTypeBytes = []byte{1}
		childPointerBytes = make([]byte, 8*16)
		for i, child := range n.(*trie.MyFullNode).ChildrenPointer {
			binary.BigEndian.PutUint64(childPointerBytes[i*8:], child.BlockNumber)
		}
	case *trie.MyShortNode:
		NodeTypeBytes = []byte{2}
		shortKeyBytes = n.(*trie.MyShortNode).NodeID.Path
		shortKeyLenBytes = []byte{uint8(len(shortKeyBytes))}
		childPointerBytes = make([]byte, 8)
		//child blocknumber
		if n.(*trie.MyShortNode).Val != nil {
			binary.BigEndian.PutUint64(childPointerBytes, n.(*trie.MyShortNode).ChildrenPointer.BlockNumber)
		} else {
			binary.BigEndian.PutUint64(childPointerBytes, uint64(0))
		}
		//child path
		childPtah := n.(*trie.MyShortNode).ChildrenPointer.Path
		childPathLen := uint8(len(childPtah))
		childPathLenBytes := []byte{byte(childPathLen)}
		childPointerBytes = append(childPointerBytes, childPathLenBytes...)
		childPointerBytes = append(childPointerBytes, childPtah...)
	case *trie.MyHashNode:
		NodeTypeBytes = []byte{3}
		childPointerBytes = nil
	case *trie.MyValueNode:
		NodeTypeBytes = []byte{4}
		childPointerBytes = nil
	default:
		log.Fatalf("Unknown node type: %T\n", n)
	}

	// 8. RLPLen, 9. RLP bytes
	RLPBytes = trie.MyNodeToOriginalProofBytes(n)
	RLPLenBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(RLPLenBytes, uint32(len(RLPBytes)))

	// Append all fields to the final byte slice
	buffer = append(buffer, NodeTypeBytes...)            //1. NodeType
	buffer = append(buffer, blockNumberBytes...)         //2.blockNumber
	buffer = append(buffer, pathLenBytes...)             //3. pathLen
	buffer = append(buffer, pathBytes...)                //4. path
	if shortKeyBytes != nil && shortKeyLenBytes != nil { //5&6 short node key
		buffer = append(buffer, shortKeyLenBytes...)
		buffer = append(buffer, shortKeyBytes...)
	}
	if childPointerBytes != nil { //7. childPointer
		buffer = append(buffer, childPointerBytes...)
	}
	buffer = append(buffer, RLPLenBytes...) //8. RLPLen
	buffer = append(buffer, RLPBytes...)    //9. RLP bytes

	// check length
	want_len := 1 + 8 + 1 + len(pathBytes) + len(childPointerBytes) + 4 + len(RLPBytes)

	if _, ok := n.(*trie.MyShortNode); ok {
		want_len = 1 + 8 + 1 + len(pathBytes) + 1 + len(shortKeyBytes) + len(childPointerBytes) + 4 + len(RLPBytes)
	}
	// tmp_len := len(NodeTypeBytes) + len(blockNumberBytes) + len(pathLenBytes) + len(pathBytes) + len(shortKeyLenBytes) + len(shortKeyBytes) + len(childPointerBytes) + len(RLPLenBytes) + len(RLPBytes)
	// if want_len != tmp_len {
	// 	fmt.Printf("want_len: %d, tmp_len: %d\n", want_len, tmp_len)
	// }
	if len(buffer) != want_len {
		log.Fatalf("Failed to serialize node, size: %d, expected: %d\n", len(buffer), want_len)
	}
	return buffer
}

//	type MyWrapFullnode struct{
//		NodeID          MyNodeID
//		ChildrenPointer [16]MyNodeID
//		RLPBytes []byte
//	}
//
// todo: wrap old node, {nodeID, childPointer, RLPBytes}
func decodeProofNode(data []byte) (trie.MyNode, error) {
	offset := 0

	//1.nodeType
	nodeType := data[offset]
	offset += 1
	//2.blockNumber
	if offset+8 > len(data) {
		return nil, fmt.Errorf("invalid data length for blockNumber")
	}
	blockNumber := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	//3.pathLen, 4.path
	pathLen := int(data[offset])
	offset += 1
	if offset+pathLen > len(data) {
		return nil, fmt.Errorf("invalid data length for path")
	}
	path := data[offset : offset+pathLen]
	offset += pathLen
	//5&6 short node key, 7.childPointer
	var node trie.MyNode
	switch nodeType {
	case 1: // fullNode
		childPointer := [16]trie.MyNodeID{}
		for i := 0; i < 16; i++ {
			if offset+8 > len(data) {
				return nil, fmt.Errorf("invalid data length for child pointer")
			}
			childPointer[i].Path = append(path, byte(i))
			childPointer[i].BlockNumber = binary.BigEndian.Uint64(data[offset : offset+8])
			offset += 8
		}
		nodeId := trie.MyNodeID{Path: path, BlockNumber: blockNumber}
		node = &trie.MyFullNode{
			NodeID:          nodeId,
			ChildrenPointer: childPointer,
		}
	case 2: // shortNode
		// short node key
		shortKeyLen := int(data[offset])
		offset += 1
		if offset+shortKeyLen > len(data) {
			return nil, fmt.Errorf("invalid data length for shortKey")
		}
		shortKey := data[offset : offset+shortKeyLen]
		offset += shortKeyLen
		// childPointer
		if offset+8 > len(data) {
			return nil, fmt.Errorf("invalid data length for shortNode child pointer")
		}
		childBlocknumber := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
		childPathLen := int(data[offset])
		offset += 1
		if offset+childPathLen > len(data) {
			return nil, fmt.Errorf("invalid data length for shortNode child path")
		}
		childPath := data[offset : offset+childPathLen]
		offset += childPathLen
		childPointer := trie.MyNodeID{Path: childPath, BlockNumber: childBlocknumber}
		nodeId := trie.MyNodeID{Path: path, BlockNumber: blockNumber}
		node = &trie.MyShortNode{
			NodeID:          nodeId,
			ChildrenPointer: childPointer,
			Key:             shortKey,
		}
	case 3: // hashNode
		nodeId := trie.MyNodeID{Path: path, BlockNumber: blockNumber}
		node = &trie.MyHashNode{
			NodeID: nodeId,
			Hash:   nil,
		}
	case 4: // valueNode
		nodeId := trie.MyNodeID{Path: path, BlockNumber: blockNumber}
		node = &trie.MyValueNode{
			NodeID: nodeId,
			Value:  nil, //todo: how to parse RLP bytes
		}
	}
	// 8. RLPLen, 9. RLP bytes
	if offset+4 > len(data) {
		return nil, fmt.Errorf("invalid data length for RLP length")
	}
	rlpLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if offset+int(rlpLen) > len(data) {
		return nil, fmt.Errorf("invalid data length for RLP bytes")
	}
	RLPBytes := data[offset : offset+int(rlpLen)]
	//todo: how to parse RLP bytes
	// deep copy
	switch node.(type) {
	case *trie.MyValueNode:
		node.(*trie.MyValueNode).SetRLPBytes(RLPBytes)
	case *trie.MyHashNode:
		log.Fatalf("hashNode should not have RLPBytes")
	case *trie.MyShortNode:
		node.(*trie.MyShortNode).SetRLPBytes(RLPBytes)
	case *trie.MyFullNode:
		node.(*trie.MyFullNode).SetRLPBytes(RLPBytes)
	}

	return node, nil
}

func extract_RLPBytes_without_decoding_from_ProofNodeBytes(data []byte) ([]byte, error) {
	offset := 0

	//1.nodeType
	nodeType := data[offset]
	offset += 1
	//2.blockNumber
	if offset+8 > len(data) {
		return nil, fmt.Errorf("invalid data length for blockNumber")
	}
	offset += 8
	//3.pathLen, 4.path
	pathLen := int(data[offset])
	offset += 1
	if offset+pathLen > len(data) {
		return nil, fmt.Errorf("invalid data length for path")
	}
	offset += pathLen
	//5&6 short node key, 7.childPointer
	switch nodeType {
	case 1: // fullNode
		for i := 0; i < 16; i++ {
			if offset+8 > len(data) {
				return nil, fmt.Errorf("invalid data length for child pointer")
			}
			offset += 8
		}
	case 2: // shortNode
		shortKeyLen := int(data[offset])
		offset += 1
		if offset+shortKeyLen > len(data) {
			return nil, fmt.Errorf("invalid data length for shortKey")
		}
		offset += shortKeyLen
		// childPointer
		if offset+8 > len(data) {
			return nil, fmt.Errorf("invalid data length for shortNode child pointer")
		}
		offset += 8
		childPathLen := int(data[offset])
		offset += 1
		if offset+childPathLen > len(data) {
			return nil, fmt.Errorf("invalid data length for shortNode child path")
		}
		offset += childPathLen
	}
	// 8. RLPLen, 9. RLP bytes
	if offset+4 > len(data) {
		return nil, fmt.Errorf("invalid data length for RLP length")
	}
	rlpLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if offset+int(rlpLen) > len(data) {
		return nil, fmt.Errorf("invalid data length for RLP bytes")
	}
	RLPBytes := data[offset : offset+int(rlpLen)]

	return RLPBytes, nil
}

func extract_RLPBytes_without_encoding_from_ProofNode(n trie.MyNode) []byte {
	return trie.MyNodeToOriginalProofBytes(n)
}

// donot change old RLP bytes,
// wrap it with blockNumber and path manually
// convert proof to bytes
// schema: nodeNum + {len, node bytes} of each node
func proofListToBytes(proof []trie.MyNode) []byte {
	// todo : optimize, seperate each node, decode node only when needed
	serialized_nodes := make([][]byte, len(proof))
	totalSize := 0
	// serialize each node
	for i, node := range proof {
		serialized_nodes[i] = encodeProofNode(node)
		totalSize += len(serialized_nodes[i])
	}

	var buffer []byte
	proofLen := []byte{byte(len(proof))} // max node count=65
	buffer = append(buffer, proofLen...)
	// Append the total size and the serialized nodes to the final byte slice
	for i := 0; i < len(serialized_nodes); i++ {
		nodeLen := uint32(len(serialized_nodes[i]))
		nodeLenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(nodeLenBytes, nodeLen)
		buffer = append(buffer, nodeLenBytes...)
		buffer = append(buffer, serialized_nodes[i]...)
	}

	return buffer
}

// convert bytes to proof by decoding each node
func BytesToProofList(data []byte) ([]trie.MyNode, error) {
	var proof []trie.MyNode
	offset := 0

	nodeCount := int(data[offset])
	offset += 1

	for i := 0; i < nodeCount; i++ {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("invalid data length for node length")
		}
		nodeLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(nodeLen) > len(data) {
			return nil, fmt.Errorf("invalid data length for node bytes")
		}
		nodeBytes := data[offset : offset+int(nodeLen)]
		offset += int(nodeLen)

		// parse this node
		node, err := decodeProofNode(nodeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse node %d: %w", i, err)
		}
		proof = append(proof, node)
	}

	return proof, nil
}

func BytesToOriginalMerkelProof_without_decoding(data []byte) ([][]byte, error) {
	var original_proof [][]byte
	offset := 0

	nodeCount := int(data[offset])
	offset += 1

	//exclude leaf node
	for i := 0; i < nodeCount-1; i++ {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("invalid data length for node length")
		}
		nodeLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(nodeLen) > len(data) {
			return nil, fmt.Errorf("invalid data length for node bytes")
		}
		nodeBytes := data[offset : offset+int(nodeLen)]
		offset += int(nodeLen)

		node_RLPBytes, _ := extract_RLPBytes_without_decoding_from_ProofNodeBytes(nodeBytes)
		original_proof = append(original_proof, node_RLPBytes)
	}

	return original_proof, nil
}
func ProofListToOriginalMerkelProof_without_encoding(proof []trie.MyNode) ([][]byte, error) {
	var original_proof [][]byte
	// exclude leafnode
	for _, node := range proof[:len(proof)-1] {
		node_RLPBytes := extract_RLPBytes_without_encoding_from_ProofNode(node)
		original_proof = append(original_proof, node_RLPBytes)
	}
	return original_proof, nil
}

type MyUndecProofNode struct {
	blockNumber uint64
	path        []byte
	bytes       []byte // original node bytes
}

func bytesToProofNodeWithoutDec(data []byte) []MyUndecProofNode {
	var proofNodes []MyUndecProofNode
	offset := 0

	for offset < len(data) {
		// schema: blockNumber + pathLen + path + nodeLen + node bytes

		// read blockNumber 8 byte
		blockNumber := binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8 // Move past the blockNumber field
		// read pathLen 4 byte
		pathLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4 // Move past the pathLen field
		// read path with pathLen bytes
		path := data[offset : offset+int(pathLen)]
		offset += int(pathLen) // Move past the path field
		// read nodeLen 4 byte
		nodeLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4 // Move past the nodeLen field
		// read node with nodeLen bytes
		nodeBytes := data[offset : offset+int(nodeLen)]
		offset += int(nodeLen) // Move the offset by the size of the node

		// donot convert bytes to original node
		proofNodes = append(proofNodes, MyUndecProofNode{blockNumber, path, nodeBytes})
	}

	return proofNodes
}

func bytesToProofBytesWithoutDec(data []byte) [][]byte {
	var proofBytes [][]byte
	offset := 0

	for offset < len(data) {
		// schema: blockNumber + pathLen + path + nodeLen + node bytes

		// read blockNumber 8 byte
		_ = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8 // Move past the blockNumber field
		// read pathLen 4 byte
		pathLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4 // Move past the pathLen field
		// read path with pathLen bytes
		_ = data[offset : offset+int(pathLen)]
		offset += int(pathLen) // Move past the path field
		// read nodeLen 4 byte
		nodeLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4 // Move past the nodeLen field
		// read node with nodeLen bytes
		nodeBytes := data[offset : offset+int(nodeLen)]
		offset += int(nodeLen) // Move the offset by the size of the node

		// Add the node to the proof list
		proofBytes = append(proofBytes, nodeBytes)
	}

	return proofBytes
}

func skiplistToBytes(skiplist *skiplist.SkipList) []byte {
	var buffer bytes.Buffer

	// Iterate over the skiplist and convert each block number (uint64) to bytes
	elem := skiplist.Front()
	for elem != nil {
		blockNumber := elem.Key().(uint64)
		// Serialize blockNumber (uint64) to 8-byte slice
		if err := binary.Write(&buffer, binary.BigEndian, blockNumber); err != nil {
			panic("Failed to write uint64 to buffer")
		}
		elem = elem.Next()
	}

	// Return the concatenated byte slice
	return buffer.Bytes()
}

func BytesToSkiplist(data []byte) *skiplist.SkipList {
	skiplist := skiplist.New(skiplist.Uint64)
	buffer := bytes.NewReader(data)

	for {
		var blockNumber uint64
		// Read the next 8 bytes and convert them into a uint64
		err := binary.Read(buffer, binary.BigEndian, &blockNumber)
		if err != nil {
			break // Stop reading when there are no more bytes to read
		}

		// value: nil or prev version leaf node
		skiplist.Set(blockNumber, nil)
	}

	return skiplist
}

func Fetch_accounts_of_block(oldDB ethdb.Database, blockNumber uint64) []common.Address {
	blockHash := rawdb.ReadCanonicalHash(oldDB, blockNumber)
	selected_block := rawdb.ReadBlock(oldDB, blockHash, blockNumber)
	if selected_block == nil {
		log.Fatalf("Failed to read block %v", blockNumber)
	}

	// iterate transactions and accounts
	accountSet := make(map[common.Address]bool)
	chainConfig := params.MainnetChainConfig
	blockTime := selected_block.Time()
	for _, tx := range selected_block.Transactions() {
		// extract from account
		signer := types.MakeSigner(chainConfig, new(big.Int).SetUint64(blockNumber), blockTime)
		from, err := types.Sender(signer, tx)
		if err != nil {
			log.Fatalf("Failed to get sender: %v", err)
		} else {
			accountSet[from] = true
		}
		// to account
		if tx.To() != nil {
			accountSet[*tx.To()] = true
		}
	}
	// set to list
	accountList := make([]common.Address, 0)
	for addr, _ := range accountSet {
		accountList = append(accountList, addr)
	}
	return accountList
}

func fetch_accounts_for_selected_block(oldDB ethdb.Database, selected_block *types.Block, blockNumber uint64) []common.Address {
	if selected_block == nil {
		log.Fatalf("selected_block is nil")
	}

	// iterate transactions and accounts
	accountSet := make(map[common.Address]bool)
	chainConfig := params.MainnetChainConfig
	blockTime := selected_block.Time()
	for _, tx := range selected_block.Transactions() {
		// extract from account
		signer := types.MakeSigner(chainConfig, new(big.Int).SetUint64(blockNumber), blockTime)
		from, err := types.Sender(signer, tx)
		if err != nil {
			log.Fatalf("Failed to get sender: %v", err)
		} else {
			accountSet[from] = true
		}
		// to account
		if tx.To() != nil {
			accountSet[*tx.To()] = true
		}
	}
	// set to list
	accountList := make([]common.Address, 0)
	for addr, _ := range accountSet {
		accountList = append(accountList, addr)
	}
	return accountList
}

type GenPathStore_Metrics struct {
	// TotalLeafNodeNum                int
	TotalAccountNum                 int // EOA + Contract
	TotalContractNum                int
	StorageSlotNum_of_all_Contracts int
	AvgStorageSlotNum_of_Contracts  float64 // StorageSlotNum_of_all_Contracts / TotalContractNum
}

func Start_gen_path_store_only_stateTrie(oldDB ethdb.Database,
	stateTrie_proofDB ethdb.Database, stateTrie_prevBlockDB ethdb.Database, stateTrie_versionListDB ethdb.Database,
	startBlockNumber uint64, endBlockNumber uint64, baseBlockNumber uint64) {

	// check latest block number
	latestBlockNumber := rawdb.ReadHeaderNumber(oldDB, rawdb.ReadHeadBlockHash(oldDB))
	if latestBlockNumber == nil {
		log.Fatalf("Failed to read the latest block number")
		return
	}
	fmt.Printf("Latest block number: %d\n", *latestBlockNumber)
	log.Printf("Latest block number: %d\n", *latestBlockNumber)
	// check endBlockNumber
	if endBlockNumber > *latestBlockNumber {
		endBlockNumber = *latestBlockNumber
	}

	// iterate blocks

	//stateTrie_memory_pool
	stateTrie_memory_pool := NewMyMemoryPool(100000, 100000, stateTrie_proofDB, stateTrie_versionListDB)

	metrics := GenPathStore_Metrics{}

	// iterate blocks
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		blockHash := rawdb.ReadCanonicalHash(oldDB, i)
		selected_block := rawdb.ReadBlock(oldDB, blockHash, i)
		if selected_block == nil {
			log.Fatalf("Failed to read block %v", i)
		}

		Gen_for_one_block_delta_only_stateTrie(i, selected_block, oldDB,
			stateTrie_memory_pool, stateTrie_prevBlockDB,
			baseBlockNumber, &metrics)
	}

	metrics.TotalAccountNum += len(stateTrie_memory_pool.Proofs)
	stateTrie_memory_pool.Force_Flush()

	fmt.Printf("total account num: %d\n", metrics.TotalAccountNum)
	log.Printf("total account num: %d\n", metrics.TotalAccountNum)
}

func Start_gen_path_store_with_storageTrie(oldDB ethdb.Database,
	stateTrie_proofDB ethdb.Database, stateTrie_prevBlockDB ethdb.Database, stateTrie_versionListDB ethdb.Database,
	storageTrie_proofDB ethdb.Database, storageTrie_prevBlockDB ethdb.Database, storageTrie_versionListDB ethdb.Database,
	startBlockNumber uint64, endBlockNumber uint64, baseBlockNumber uint64) {

	// check latest block number
	latestBlockNumber := rawdb.ReadHeaderNumber(oldDB, rawdb.ReadHeadBlockHash(oldDB))
	if latestBlockNumber == nil {
		log.Fatalf("Failed to read the latest block number")
		return
	}
	fmt.Printf("Latest block number: %d\n", *latestBlockNumber)
	log.Printf("Latest block number: %d\n", *latestBlockNumber)
	// check endBlockNumber
	if endBlockNumber > *latestBlockNumber {
		endBlockNumber = *latestBlockNumber
	}

	// iterate blocks
	stateTrie_memory_pool := NewMyMemoryPool(100000, 100000, stateTrie_proofDB, stateTrie_versionListDB)
	storageTrie_memory_pool := NewMyMemoryPool(100000, 100000, storageTrie_proofDB, storageTrie_versionListDB)

	metrics := GenPathStore_Metrics{}

	// iterate blocks
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		blockHash := rawdb.ReadCanonicalHash(oldDB, i)
		selected_block := rawdb.ReadBlock(oldDB, blockHash, i)
		if selected_block == nil {
			log.Fatalf("Failed to read block %v", i)
		}

		Gen_for_one_block_delta_with_storageTrie(i, selected_block, oldDB,
			stateTrie_memory_pool, stateTrie_prevBlockDB,
			storageTrie_memory_pool, storageTrie_prevBlockDB,
			baseBlockNumber, &metrics)
	}

	metrics.TotalAccountNum += len(stateTrie_memory_pool.Proofs)
	stateTrie_memory_pool.Force_Flush()
	storageTrie_memory_pool.Force_Flush()

	metrics.AvgStorageSlotNum_of_Contracts = float64(metrics.StorageSlotNum_of_all_Contracts) / float64(metrics.TotalContractNum)
	contract_portion := float64(metrics.TotalContractNum) / float64(metrics.TotalAccountNum)

	fmt.Printf("total account num: %d, contract num: %d (%.2f%%), total slot num %d, avg slot num %.2f \n", metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion*100, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)
	log.Printf("total account num: %d, contract num: %d (%.2f%%), total slot num %d, avg slot num %.2f \n", metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion*100, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)
}

// storageFlag: 0, only stateTrie; 1, only storageTrie; 2, both stateTrie and storageTrie
func Start_gen_path_store(oldDB ethdb.Database,
	stateTrie_proofDB ethdb.Database, stateTrie_prevBlockDB ethdb.Database, stateTrie_versionListDB ethdb.Database,
	storageTrie_proofDB ethdb.Database, storageTrie_prevBlockDB ethdb.Database, storageTrie_versionListDB ethdb.Database,
	startBlockNumber uint64, endBlockNumber uint64, baseBlockNumber uint64,
	storageFlag int) {

	// check latest block number
	latestBlockNumber := rawdb.ReadHeaderNumber(oldDB, rawdb.ReadHeadBlockHash(oldDB))
	if latestBlockNumber == nil {
		log.Fatalf("Failed to read the latest block number")
		return
	}
	fmt.Printf("Latest block number: %d\n", *latestBlockNumber)
	log.Printf("Latest block number: %d\n", *latestBlockNumber)
	// check endBlockNumber
	if endBlockNumber > *latestBlockNumber {
		endBlockNumber = *latestBlockNumber
	}

	// iterate blocks
	stateTrie_memory_pool := NewMyMemoryPool(100000, 100000, stateTrie_proofDB, stateTrie_versionListDB)
	storageTrie_memory_pool := NewMyMemoryPool(100000, 100000, storageTrie_proofDB, storageTrie_versionListDB)

	metrics := GenPathStore_Metrics{}

	// iterate blocks
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		blockHash := rawdb.ReadCanonicalHash(oldDB, i)
		selected_block := rawdb.ReadBlock(oldDB, blockHash, i)
		if selected_block == nil {
			log.Fatalf("Failed to read block %v", i)
		}

		switch storageFlag {
		case 0:
			Gen_for_one_block_delta_only_stateTrie(i, selected_block, oldDB,
				stateTrie_memory_pool, stateTrie_prevBlockDB,
				baseBlockNumber, &metrics)
		case 1:
			Gen_for_one_block_delta_only_storageTrie(i, selected_block, oldDB,
				stateTrie_memory_pool, stateTrie_prevBlockDB,
				storageTrie_memory_pool, storageTrie_prevBlockDB,
				baseBlockNumber, &metrics)
		case 2:
			Gen_for_one_block_delta_with_storageTrie(i, selected_block, oldDB,
				stateTrie_memory_pool, stateTrie_prevBlockDB,
				storageTrie_memory_pool, storageTrie_prevBlockDB,
				baseBlockNumber, &metrics)
		default:
			log.Fatalf("Invalid storageFlag: %d", storageFlag)
		}
	}

	metrics.TotalAccountNum += len(stateTrie_memory_pool.Proofs)
	stateTrie_memory_pool.Force_Flush()
	storageTrie_memory_pool.Force_Flush()

	if metrics.TotalContractNum > 0 {
		metrics.AvgStorageSlotNum_of_Contracts = float64(metrics.StorageSlotNum_of_all_Contracts) / float64(metrics.TotalContractNum)
	} else {
		metrics.AvgStorageSlotNum_of_Contracts = 0
	}
	contract_portion := float64(0)
	if metrics.TotalAccountNum > 0 {
		contract_portion = float64(metrics.TotalContractNum) / float64(metrics.TotalAccountNum)
	}
	fmt.Printf("total account num: %d, contract num: %d (%.2f%%), total slot num %d, avg slot num %.2f \n", metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion*100, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)
	log.Printf("total account num: %d, contract num: %d (%.2f%%), total slot num %d, avg slot num %.2f \n", metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion*100, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)
}

// return: existing leaf node num
func Gen_for_base_block(baseBlockNumber uint64, selected_block *types.Block,
	memory_pool *MyMemoryPool, total_leaf_node_num *int,
	oldDB ethdb.Database, prevBlockTrieDB ethdb.Database) uint64 {

	// state trie
	config := triedb.HashDefaults
	triedb := triedb.NewDatabase(oldDB, config)
	t, err := trie.NewStateTrie(trie.StateTrieID(selected_block.Root()), triedb)
	if err != nil {
		log.Fatalf("new state trie: %s", err)
	}

	// for all existing leaf nodes, update lastest blockid
	base_snap_leaf_num := uint64(0)
	iter, err := t.NodeIterator(nil)
	if err != nil {
		log.Fatalf("Failed to create iterator: %v", err)
	}
	for iter.Next(true) {
		if iter.Leaf() {
			*total_leaf_node_num += 1
			base_snap_leaf_num += 1
			accountHex := iter.Path()
			// 1.append to skip list
			memory_pool.AppendVersionList(accountHex, baseBlockNumber)
			// 2.construct changed subtree, convert old node to in-memory new proof node,
			//		but some in-memory new nodes may contain stale child blockid
			// 3.update lastest blockid for each node to prevBlockTrieDB: key=path, value=lastest blockid
			accountProof := iter.MyLeafProof_gen_path_store(prevBlockTrieDB, baseBlockNumber, baseBlockNumber)
			// 5. in-memory prooflist存入proofDB
			accountHexStr := string(accountHex)
			memory_pool.PutProof([]byte(accountHexStr), baseBlockNumber, accountProof)

			if base_snap_leaf_num%100 == 0 {
				fmt.Printf("\rBase Block %d, leaf node num: %d", baseBlockNumber, base_snap_leaf_num)
				log.Printf("Base Block %d, leaf node num: %d\n", baseBlockNumber, base_snap_leaf_num)
			}
		}
	}
	print("\n")
	// for testing, print changed paths
	return base_snap_leaf_num
}
func Gen_for_one_block_delta_only_stateTrie(blockNumber uint64, selected_block *types.Block,
	oldDB ethdb.Database,
	stateTrie_memory_pool *MyMemoryPool, stateTrie_prevBlockDB ethdb.Database,
	baseBlockNumber uint64, metrics *GenPathStore_Metrics) map[string]*[]trie.MyNode {

	acitiveAccountSet := fetch_accounts_for_selected_block(oldDB, selected_block, blockNumber)
	// sorted account hex
	activeAccountHexs := make([][]byte, 0)
	HexToAccount := make(map[string]common.Address) // reverse map
	for _, account := range acitiveAccountSet {
		accountHex := trie.AddressToStateHexPath(account)
		activeAccountHexs = append(activeAccountHexs, accountHex)
		HexToAccount[string(accountHex)] = account
	}
	sort.Slice(activeAccountHexs, func(i, j int) bool { return bytes.Compare(activeAccountHexs[i], activeAccountHexs[j]) < 0 })

	// 1.append to skip list
	for _, accountHex := range activeAccountHexs {
		stateTrie_memory_pool.AppendVersionList(accountHex, blockNumber)
	}

	// state trie
	config := triedb.HashDefaults
	triedb := triedb.NewDatabase(oldDB, config)
	state_trie, err := trie.NewStateTrie(trie.StateTrieID(selected_block.Root()), triedb)
	if err != nil {
		log.Fatalf("new state trie: %s", err)
	}

	// only for changed subtree, update prevBlockTrieDB, update in-memory prooflist
	changed_paths := make(map[string]*[]trie.MyNode) // key=string(hex path), value=root-to-leaf path nodes
	// var leafNodeNum, validLeafNodeNum int
	for _, accountHex := range activeAccountHexs {
		accountKeyBytes := trie.AddressToStateKeyBytes(HexToAccount[string(accountHex)])
		iter, err := state_trie.NodeIterator(accountKeyBytes)
		if err != nil {
			log.Fatalf("Failed to create iterator: %v", err)
		}
		tmp_cnt := 0
		for iter.Next(true) {
			if iter.Leaf() {
				if !bytes.Equal(iter.Path(), accountHex) {
					tmp_cnt++
					if tmp_cnt%1000 == 0 {
						fmt.Printf("\rWarning: continuously skip %d leaves", tmp_cnt)
					}
					if tmp_cnt > 50000 {
						fmt.Printf("\n Too many skips, give up this account %s\n", HexToAccount[string(accountHex)].Hex())
						tmp_cnt = 0
						break
					}
				}
				if tmp_cnt > 0 {
					fmt.Printf("\n")
					tmp_cnt = 0
				}

				hexPath := iter.Path()

				// 2.construct changed subtree
				// 3.update lastest blockid for each node to prevBlockTrieDB
				accountProof := iter.MyLeafProof_gen_path_store(stateTrie_prevBlockDB, blockNumber, baseBlockNumber)
				changed_paths[string(hexPath)] = &accountProof
				break
			}
		}
	}
	// 4.update in-memory prooflist
	for _, proof := range changed_paths {
		// update node blockid and child blockid
		for i := len(*proof) - 1; i >= 0; i-- {
			node := (*proof)[i]
			switch node.(type) {
			case *trie.MyValueNode:
				buf, err := stateTrie_prevBlockDB.Get(node.GetPath())
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", node.GetPath(), err)
				}
				node.SetBlockNumber(binary.BigEndian.Uint64(buf))
			case *trie.MyHashNode:
				buf, err := stateTrie_prevBlockDB.Get(node.GetPath())
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", node.GetPath(), err)
				}
				node.SetBlockNumber(binary.BigEndian.Uint64(buf))
			case *trie.MyShortNode:
				buf, err := stateTrie_prevBlockDB.Get(node.GetPath())
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", node.GetPath(), err)
				}
				node.SetBlockNumber(binary.BigEndian.Uint64(buf))
				// child blockid
				childPath := (*proof)[i+1].GetPath()
				if !bytes.HasPrefix(childPath, node.GetPath()) {
					panic("child path not match")
				}
				childBlockidBuf, err := stateTrie_prevBlockDB.Get(childPath)
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", childPath, err)
				}
				childBlockid := binary.BigEndian.Uint64(childBlockidBuf)
				newChildPointer := trie.MyNodeID{Path: childPath, BlockNumber: childBlockid}
				node.SetChildrenPointer(newChildPointer, 0)
				// update in-memory child, may has been updated
				// node.(*trie.MyShortNode).Val.(*trie.MyValueNode).SetBlockNumber(childBlockid)
			case *trie.MyFullNode:
				buf, err := stateTrie_prevBlockDB.Get(node.GetPath())
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", node.GetPath(), err)
				}
				node.SetBlockNumber(binary.BigEndian.Uint64(buf))
				// child blockid
				fullNodePath := node.GetPath()
				for i := 0; i < 16; i++ {
					// 创建独立的 childPath，避免引用问题
					childPath := make([]byte, len(fullNodePath)+1)
					copy(childPath, fullNodePath)
					childPath[len(fullNodePath)] = byte(i)
					childBlockidBuf, err := stateTrie_prevBlockDB.Get(childPath)
					if err != nil {
						log.Fatalf("Failed to get lastest blockid for node %v: %v", childPath, err)
					}
					childBlockid := binary.BigEndian.Uint64(childBlockidBuf)
					newChildPointer := trie.MyNodeID{Path: childPath, BlockNumber: childBlockid}
					node.SetChildrenPointer(newChildPointer, uint8(i))
				}
			default:
				log.Fatalf("Unknown node type: %T\n", node)
			}
		}
	}
	// 5. in-memory prooflist存入proofDB
	for accountHexStr, proof := range changed_paths {
		stateTrie_memory_pool.PutProof([]byte(accountHexStr), blockNumber, *proof)
	}

	metrics.TotalAccountNum += len(changed_paths)
	if blockNumber%100 == 0 {
		fmt.Printf("Block %d, total account num: %d\n", blockNumber, metrics.TotalAccountNum)
		log.Printf("Block %d, total account num: %d\n", blockNumber, metrics.TotalAccountNum)
	}
	// for testing, print changed paths
	// return changed_paths
	return nil
}
func Gen_for_one_block_delta_with_storageTrie(blockNumber uint64, selected_block *types.Block,
	oldDB ethdb.Database,
	stateTrie_memory_pool *MyMemoryPool, stateTrie_prevBlockDB ethdb.Database,
	storageTrie_memory_pool *MyMemoryPool, storageTrie_prevBlockDB ethdb.Database,
	baseBlockNumber uint64, metrics *GenPathStore_Metrics) map[string]*[]trie.MyNode {

	acitiveAccountSet := fetch_accounts_for_selected_block(oldDB, selected_block, blockNumber)
	// sorted account hex
	activeAccountHexs := make([][]byte, 0)
	HexToAccount := make(map[string]common.Address) // reverse map
	for _, account := range acitiveAccountSet {
		accountHex := trie.AddressToStateHexPath(account)
		activeAccountHexs = append(activeAccountHexs, accountHex)
		HexToAccount[string(accountHex)] = account
	}
	sort.Slice(activeAccountHexs, func(i, j int) bool { return bytes.Compare(activeAccountHexs[i], activeAccountHexs[j]) < 0 })

	// 1.append to skip list
	for _, accountHex := range activeAccountHexs {
		stateTrie_memory_pool.AppendVersionList(accountHex, blockNumber)
	}

	// state trie
	config := triedb.HashDefaults
	triedb := triedb.NewDatabase(oldDB, config)
	state_trie, err := trie.NewStateTrie(trie.StateTrieID(selected_block.Root()), triedb)
	if err != nil {
		log.Fatalf("new state trie: %s", err)
	}

	// only for changed subtree, update prevBlockTrieDB, update in-memory prooflist
	changed_paths := make(map[string]*[]trie.MyNode) // key=string(hex path), value=root-to-leaf path nodes
	// var leafNodeNum, validLeafNodeNum int
	for _, accountHex := range activeAccountHexs {
		accountKeyBytes := trie.AddressToStateKeyBytes(HexToAccount[string(accountHex)])
		iter, err := state_trie.NodeIterator(accountKeyBytes)
		if err != nil {
			log.Fatalf("Failed to create iterator: %v", err)
		}
		tmp_cnt := 0
		for iter.Next(true) {
			if iter.Leaf() {
				// leafNodeNum++
				if !bytes.Equal(iter.Path(), accountHex) {
					// log.Fatalf("NodeIterator not match: %v, %v\n", iter.Path(), accountHex)
					tmp_cnt++
					if tmp_cnt%1000 == 0 {
						fmt.Printf("\rWarning: continuously skip %d leaves", tmp_cnt)
					}
					if tmp_cnt > 50000 {
						fmt.Printf("\n Too many skips, give up this account %s\n", HexToAccount[string(accountHex)].Hex())
						tmp_cnt = 0
						break
					}
				}
				if tmp_cnt > 0 {
					fmt.Printf("\n")
					tmp_cnt = 0
				}

				hexPath := iter.Path()
				accountProof := iter.MyLeafProof_gen_path_store(stateTrie_prevBlockDB, blockNumber, baseBlockNumber)
				changed_paths[string(hexPath)] = &accountProof
				stateAccount, err := state_trie.GetAccount(HexToAccount[string(accountHex)])
				if err != nil {
					log.Fatalf("Failed to get account: %v", err)
				}
				if stateAccount != nil {
					storage_root := stateAccount.Root
					if storage_root != (common.Hash{}) && storage_root != types.EmptyRootHash {
						Contract_address_file_handler.WriteString(HexToAccount[string(accountHex)].Hex() + "," + strconv.FormatUint(blockNumber, 10) + "\n")
						block_state_root := selected_block.Root()
						contractAddr := HexToAccount[string(accountHex)]
						storage_trie_id := trie.StorageTrieID(block_state_root, crypto.Keccak256Hash(contractAddr.Bytes()), storage_root)
						storage_trie, err := trie.NewStateTrie(storage_trie_id, triedb)
						if err != nil {
							log.Fatalf("open storage trie error: %s", err)
						}

						storage_key_int := make([]int64, 0)
						storage_key_int = append(storage_key_int, 0)
						storage_keys := make([]common.Hash, 0)
						for _, key_int := range storage_key_int {
							key := common.BigToHash(big.NewInt(key_int))
							storage_keys = append(storage_keys, key)
						}
						for _, key := range storage_keys {
							storage_keyBytes := crypto.Keccak256(key.Bytes())
							storage_keyHex := trie.KeybytesToHex(storage_keyBytes)

							storage_iter, err := storage_trie.NodeIterator(storage_keyBytes)
							if err != nil {
								log.Fatalf("Failed to create storage iterator: %v", err)
							}
							for storage_iter.Next(true) {
								if storage_iter.Leaf() {
									currentPath := storage_iter.Path()

									if !bytes.Equal(storage_keyHex, currentPath) {
										log.Printf("PATH MISMATCH DETAILS:")
										log.Printf("  Expected: % 02x (len=%d)", storage_keyHex, len(storage_keyHex))
										log.Printf("  Received: % 02x (len=%d)", currentPath, len(currentPath))
										break
									}

									metrics.TotalContractNum += 1 // only slot 0

									fmt.Printf("block %d, contract %s\n", blockNumber, HexToAccount[string(accountHex)].Hex())

									// for one storage slot, get proof
									// todo: sepearte storage trie and state trie db
									// for storage trie, create prevBlockTrieDB, proofDB
									storageProof := storage_iter.MyLeafProof_gen_path_store(storageTrie_prevBlockDB, blockNumber, baseBlockNumber)
									// write to new storage trie db
									// key = contract address + storageKeyBytes + blkNumber
									// todo: replace accountHex with contract account address/contract account keybytes
									storageTrie_memory_pool.AppendVersionList(accountHex, blockNumber)
									storageTrie_memory_pool.PutStorageSlot(accountHex, blockNumber, storage_keyBytes, storageProof)
									break
								}
							}
						}
					}
				}

				break
			}
		}
	}

	for _, proof := range changed_paths {
		for i := len(*proof) - 1; i >= 0; i-- {
			node := (*proof)[i]
			switch node.(type) {
			case *trie.MyValueNode:
				buf, err := stateTrie_prevBlockDB.Get(node.GetPath())
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", node.GetPath(), err)
				}
				node.SetBlockNumber(binary.BigEndian.Uint64(buf))
			case *trie.MyHashNode:
				buf, err := stateTrie_prevBlockDB.Get(node.GetPath())
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", node.GetPath(), err)
				}
				node.SetBlockNumber(binary.BigEndian.Uint64(buf))
			case *trie.MyShortNode:
				buf, err := stateTrie_prevBlockDB.Get(node.GetPath())
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", node.GetPath(), err)
				}
				node.SetBlockNumber(binary.BigEndian.Uint64(buf))
				// child blockid
				childPath := (*proof)[i+1].GetPath()
				if !bytes.HasPrefix(childPath, node.GetPath()) {
					panic("child path not match")
				}
				childBlockidBuf, err := stateTrie_prevBlockDB.Get(childPath)
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", childPath, err)
				}
				childBlockid := binary.BigEndian.Uint64(childBlockidBuf)
				newChildPointer := trie.MyNodeID{Path: childPath, BlockNumber: childBlockid}
				node.SetChildrenPointer(newChildPointer, 0)
			case *trie.MyFullNode:
				buf, err := stateTrie_prevBlockDB.Get(node.GetPath())
				if err != nil {
					log.Fatalf("Failed to get lastest blockid for node %v: %v", node.GetPath(), err)
				}
				node.SetBlockNumber(binary.BigEndian.Uint64(buf))
				fullNodePath := node.GetPath()
				for i := 0; i < 16; i++ {
					childPath := make([]byte, len(fullNodePath)+1)
					copy(childPath, fullNodePath)
					childPath[len(fullNodePath)] = byte(i)
					childBlockidBuf, err := stateTrie_prevBlockDB.Get(childPath)
					if err != nil {
						log.Fatalf("Failed to get lastest blockid for node %v: %v", childPath, err)
					}
					childBlockid := binary.BigEndian.Uint64(childBlockidBuf)
					newChildPointer := trie.MyNodeID{Path: childPath, BlockNumber: childBlockid}
					node.SetChildrenPointer(newChildPointer, uint8(i))
				}
			default:
				log.Fatalf("Unknown node type: %T\n", node)
			}
		}
	}
	for accountHexStr, proof := range changed_paths {
		stateTrie_memory_pool.PutProof([]byte(accountHexStr), blockNumber, *proof)
	}

	metrics.TotalAccountNum += len(changed_paths)
	if blockNumber%100 == 0 {
		metrics.AvgStorageSlotNum_of_Contracts = float64(metrics.StorageSlotNum_of_all_Contracts) / float64(metrics.TotalContractNum)
		contract_portion := float64(metrics.TotalContractNum) / float64(metrics.TotalAccountNum)
		fmt.Printf("Block %d, total account num: %d, contract num: %d(%.2f), total slot num %d, avg slot num %.2f \n", blockNumber, metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)
		log.Printf("Block %d, total account num: %d, contract num: %d(%.2f), total slot num %d, avg slot num %.2f \n", blockNumber, metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)
	}
	return nil
}
func Gen_for_one_block_delta_only_storageTrie(blockNumber uint64, selected_block *types.Block,
	oldDB ethdb.Database,
	stateTrie_memory_pool *MyMemoryPool, stateTrie_prevBlockDB ethdb.Database,
	storageTrie_memory_pool *MyMemoryPool, storageTrie_prevBlockDB ethdb.Database,
	baseBlockNumber uint64, metrics *GenPathStore_Metrics) map[string]*[]trie.MyNode {

	acitiveAccountSet := fetch_accounts_for_selected_block(oldDB, selected_block, blockNumber)
	// sorted account hex
	activeAccountHexs := make([][]byte, 0)
	HexToAccount := make(map[string]common.Address) // reverse map
	for _, account := range acitiveAccountSet {
		accountHex := trie.AddressToStateHexPath(account)
		activeAccountHexs = append(activeAccountHexs, accountHex)
		HexToAccount[string(accountHex)] = account
	}
	sort.Slice(activeAccountHexs, func(i, j int) bool { return bytes.Compare(activeAccountHexs[i], activeAccountHexs[j]) < 0 })

	// 1.append to skip list
	for _, accountHex := range activeAccountHexs {
		stateTrie_memory_pool.AppendVersionList(accountHex, blockNumber)
	}

	// state trie
	config := triedb.HashDefaults
	triedb := triedb.NewDatabase(oldDB, config)
	state_trie, err := trie.NewStateTrie(trie.StateTrieID(selected_block.Root()), triedb)
	if err != nil {
		log.Fatalf("new state trie: %s", err)
	}

	for _, accountHex := range activeAccountHexs {
		accountKeyBytes := trie.AddressToStateKeyBytes(HexToAccount[string(accountHex)])
		iter, err := state_trie.NodeIterator(accountKeyBytes)
		if err != nil {
			log.Fatalf("Failed to create iterator: %v", err)
		}
		tmp_cnt := 0
		for iter.Next(true) {
			if iter.Leaf() {
				if !bytes.Equal(iter.Path(), accountHex) {
					tmp_cnt++
					if tmp_cnt%1000 == 0 {
						fmt.Printf("\rWarning: continuously skip %d leaves", tmp_cnt)
					}
					if tmp_cnt > 50000 {
						fmt.Printf("\n Too many skips, give up this account %s\n", HexToAccount[string(accountHex)].Hex())
						tmp_cnt = 0
						break
					}
				}
				if tmp_cnt > 0 {
					fmt.Printf("\n")
					tmp_cnt = 0
				}

				// check if is contract account
				stateAccount, err := state_trie.GetAccount(HexToAccount[string(accountHex)])
				if err != nil {
					log.Fatalf("Failed to get account: %v", err)
				}
				if stateAccount != nil {

					storage_root := stateAccount.Root
					if storage_root != (common.Hash{}) && storage_root != types.EmptyRootHash {
						metrics.TotalContractNum += 1
						Contract_address_file_handler.WriteString(HexToAccount[string(accountHex)].Hex() + "," + strconv.FormatUint(blockNumber, 10) + "\n")
						fmt.Printf("block %d, contract %s, storageRoot %s\n", blockNumber, HexToAccount[string(accountHex)].Hex(), storage_root.Hex())
						block_state_root := selected_block.Root()
						contractAddr := HexToAccount[string(accountHex)]
						storage_trie_id := trie.StorageTrieID(block_state_root, crypto.Keccak256Hash(contractAddr.Bytes()), storage_root)
						storage_trie, err := trie.NewStateTrie(storage_trie_id, triedb)
						if err != nil {
							log.Fatalf("open storage trie error: %s", err)
						}
						storage_iter, err := storage_trie.NodeIterator(nil)
						if err != nil {
							log.Fatalf("Failed to create storage iterator: %v", err)
						}
						for storage_iter.Next(true) {
							if storage_iter.Leaf() {
								metrics.StorageSlotNum_of_all_Contracts += 1
								storageProof := storage_iter.MyLeafProof_gen_path_store(storageTrie_prevBlockDB, blockNumber, baseBlockNumber)
								storage_keyHex := storage_iter.Path()
								storage_keyHexStr := string(storage_keyHex)
								fmt.Printf("Block %d, contract %s, storage key %v\n", blockNumber, contractAddr.Hex(), storage_keyHex)

								storageTrie_memory_pool.AppendVersionList(accountHex, blockNumber)
								storageTrie_memory_pool.PutProof([]byte(storage_keyHexStr), blockNumber, storageProof)
							}
						}
					}
				}

				break
			}
		}
	}

	if blockNumber%100 == 0 {
		if metrics.TotalContractNum > 0 {
			metrics.AvgStorageSlotNum_of_Contracts = float64(metrics.StorageSlotNum_of_all_Contracts) / float64(metrics.TotalContractNum)
		} else {
			metrics.AvgStorageSlotNum_of_Contracts = 0
		}
		contract_portion := float64(0)
		if metrics.TotalAccountNum > 0 {
			contract_portion = float64(metrics.TotalContractNum) / float64(metrics.TotalAccountNum)
		}
		fmt.Printf("Block %d, total account num: %d, contract num: %d(%.2f), total slot num %d, avg slot num %.2f \n", blockNumber, metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)
		log.Printf("Block %d, total account num: %d, contract num: %d(%.2f), total slot num %d, avg slot num %.2f \n", blockNumber, metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)
	}

	return nil
}

func ReadContractStorage(oldDB ethdb.Database, blockNumber uint64, contractAddr common.Address, storageRoot common.Hash) {
	// init state.database with ethdb.Database
	tmp_db := state.NewDatabase(oldDB)
	// assume snap is nil
	statedb, err := state.New(storageRoot, tmp_db, nil)

	if err != nil {
		log.Fatalf("Failed to create state database: %v", err)
	}
	// check storage root
	root2 := statedb.GetStorageRoot(contractAddr)
	if root2 != storageRoot {
		log.Fatalf("Failed to get storage root: %v, %v", root2, storageRoot)
	}
	// read contract code
	code := statedb.GetCode(contractAddr)
	if len(code) == 0 {
		log.Fatalf("Failed to get contract code")
	}
	// read storage slot, follow GetProof()
	storage_keys := []common.Hash{
		common.BigToHash(big.NewInt(0)),
		common.BigToHash(big.NewInt(1)),
		common.BigToHash(big.NewInt(2)),
	}
	for _, key := range storage_keys {
		value := statedb.GetState(contractAddr, key)
		fmt.Printf("Block %d, contract %s, storage key %s, value %s\n", blockNumber, contractAddr.Hex(), key.Hex(), value.Hex())
	}

}

func ensureDirExists(dirPath string) error {
	// 检查目录是否存在
	info, err := os.Stat(dirPath)
	if os.IsNotExist(err) {
		// 如果目录不存在，则创建
		err := os.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			return err
		}
		log.Printf("Directory %s created successfully", dirPath)
	} else if err != nil {
		// 如果发生其他错误，返回错误信息
		return err
	} else if !info.IsDir() {
		// 如果路径存在但不是目录，返回错误
		return &os.PathError{Op: "mkdir", Path: dirPath, Err: os.ErrInvalid}
	}
	return nil
}

func Start_gen_path_store_leveldb_only_stateTrie(chainDataPath string,
	myStoreDir string, startBlockNumber uint64, endBlockNumber uint64, baseBlockNumber uint64) {
	log.Printf("Start generating path store from block %d to %d, baseBlock=%d\n", startBlockNumber, endBlockNumber, baseBlockNumber)

	ancientPath := filepath.Join(chainDataPath, "ancient")
	oldDB, err := rawdb.Open(rawdb.OpenOptions{
		Type:              "leveldb",
		Directory:         chainDataPath,
		AncientsDirectory: ancientPath,
		Cache:             40960, // 40GB
		Handles:           500,
		Namespace:         "",
		ReadOnly:          true,
		Ephemeral:         false,
	})
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", chainDataPath, err)
	}
	defer oldDB.Close()

	stateTrie_proofDBPath := myStoreDir + "/stateTrie_proof_path_store"
	stateTrie_prevBlockDBPath := myStoreDir + "/stateTrie_prevBlock_store"
	stateTrie_verionlistDBPath := myStoreDir + "/stateTrie_versionlist_store"
	if err := ensureDirExists(stateTrie_proofDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(stateTrie_prevBlockDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(stateTrie_verionlistDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}

	stateTrie_proofDB, err := rawdb.NewPebbleDBDatabase(stateTrie_proofDBPath, 30720, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_proofDBPath, err)
	}
	defer stateTrie_proofDB.Close()

	stateTrie_prevBlockDB, err := rawdb.NewPebbleDBDatabase(stateTrie_prevBlockDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_prevBlockDBPath, err)
	}
	defer stateTrie_prevBlockDB.Close()

	stateTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(stateTrie_verionlistDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_verionlistDBPath, err)
	}
	defer stateTrie_versionlistDB.Close()

	Start_gen_path_store_only_stateTrie(oldDB, stateTrie_proofDB, stateTrie_prevBlockDB, stateTrie_versionlistDB,
		startBlockNumber, endBlockNumber, baseBlockNumber)
}

func Append_StorageTrie_for_contract(chainDataPath string,
	myStoreDir string, startBlockNumber uint64, endBlockNumber uint64, baseBlockNumber uint64,
	contractAddr common.Address) {

	log.Printf("Start generating path store from block %d to %d, baseBlock=%d\n", startBlockNumber, endBlockNumber, baseBlockNumber)

	ancientPath := filepath.Join(chainDataPath, "ancient")
	oldDB, err := rawdb.Open(rawdb.OpenOptions{
		Type:              "leveldb",
		Directory:         chainDataPath,
		AncientsDirectory: ancientPath,
		Cache:             40960, // 40GB
		Handles:           500,
		Namespace:         "",
		ReadOnly:          true,
		Ephemeral:         false,
	})
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", chainDataPath, err)
	}
	defer oldDB.Close()

	// state trie
	stateTrie_proofDBPath := myStoreDir + "/stateTrie_proof_path_store"
	stateTrie_prevBlockDBPath := myStoreDir + "/stateTrie_prevBlock_store"
	stateTrie_verionlistDBPath := myStoreDir + "/stateTrie_versionlist_store"
	if err := ensureDirExists(stateTrie_proofDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(stateTrie_prevBlockDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(stateTrie_verionlistDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}

	stateTrie_proofDB, err := rawdb.NewPebbleDBDatabase(stateTrie_proofDBPath, 30720, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_proofDBPath, err)
	}
	defer stateTrie_proofDB.Close()

	stateTrie_prevBlockDB, err := rawdb.NewPebbleDBDatabase(stateTrie_prevBlockDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_prevBlockDBPath, err)
	}
	defer stateTrie_prevBlockDB.Close()

	stateTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(stateTrie_verionlistDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_verionlistDBPath, err)
	}
	defer stateTrie_versionlistDB.Close()

	// storage trie
	storageTrie_proofDBPath := myStoreDir + "/storageTrie_proof_path_store"
	storageTrie_prevBlockDBPath := myStoreDir + "/storageTrie_prevBlock_store"
	storageTrie_verionlistDBPath := myStoreDir + "/storageTrie_versionlist_store"

	if err := ensureDirExists(storageTrie_proofDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(storageTrie_prevBlockDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(storageTrie_verionlistDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}

	storageTrie_proofDB, err := rawdb.NewPebbleDBDatabase(storageTrie_proofDBPath, 30720, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_proofDBPath, err)
	}
	defer storageTrie_proofDB.Close()

	storageTrie_prevBlockDB, err := rawdb.NewPebbleDBDatabase(storageTrie_prevBlockDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_prevBlockDBPath, err)
	}
	defer storageTrie_prevBlockDB.Close()

	storageTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(storageTrie_verionlistDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_verionlistDBPath, err)
	}
	defer storageTrie_versionlistDB.Close()

	// stateTrie_memory_pool
	stateTrie_memory_pool := NewMyMemoryPool(100000, 100000, stateTrie_proofDB, stateTrie_versionlistDB)
	// storageTrie_memory_pool
	storageTrie_memory_pool := NewMyMemoryPool(100000, 100000, storageTrie_proofDB, storageTrie_versionlistDB)

	metrics := GenPathStore_Metrics{}

	accountHex := trie.AddressToStateHexPath(contractAddr)
	versionList := stateTrie_memory_pool.GetVersionList(accountHex)
	if versionList == nil {
		log.Fatalf("version list is nil\n")
	}
	versions, _ := versionList.GetBoundingVersions(startBlockNumber, endBlockNumber)
	fmt.Printf("version len = %v\n", len(versions))

	for _, blockNumber := range versions {
		// fmt.Printf("1 block %d\n", blockNumber)

		blockHash := rawdb.ReadCanonicalHash(oldDB, blockNumber)
		selected_block := rawdb.ReadBlock(oldDB, blockHash, blockNumber)
		if selected_block == nil {
			log.Fatalf("Failed to read block %v", blockNumber)
		}

		// state trie
		config := triedb.HashDefaults
		triedb := triedb.NewDatabase(oldDB, config)
		state_trie, err := trie.NewStateTrie(trie.StateTrieID(selected_block.Root()), triedb)
		if err != nil {
			log.Fatalf("new state trie: %s", err)
		}

		// storage trie
		stateAccount, err := state_trie.GetAccount(contractAddr)
		if err != nil {
			log.Fatalf("Failed to get account: %v", err)
		}
		if stateAccount != nil {
			storage_root := stateAccount.Root
			if storage_root != (common.Hash{}) && storage_root != types.EmptyRootHash {
				metrics.TotalContractNum += 1

				block_state_root := selected_block.Root()
				contractAddr := contractAddr
				storage_trie_id := trie.StorageTrieID(block_state_root, crypto.Keccak256Hash(contractAddr.Bytes()), storage_root)
				storage_trie, err := trie.NewStateTrie(storage_trie_id, triedb)
				if err != nil {
					log.Fatalf("open storage trie error: %s", err)
				}

				storage_key_int := make([]int64, 0)
				storage_key_int = append(storage_key_int, 0)
				storage_keys := make([]common.Hash, 0)
				for _, key_int := range storage_key_int {
					key := common.BigToHash(big.NewInt(key_int))
					storage_keys = append(storage_keys, key)
				}
				for _, key := range storage_keys {
					storage_keyBytes := crypto.Keccak256(key.Bytes())
					storage_keyHex := trie.KeybytesToHex(storage_keyBytes)
					storage_iter, err := storage_trie.NodeIterator(storage_keyBytes)
					if err != nil {
						log.Fatalf("Failed to create storage iterator: %v", err)
					}
					for storage_iter.Next(true) {
						if storage_iter.Leaf() {
							currentPath := storage_iter.Path()

							if !bytes.Equal(storage_keyHex, currentPath) {
								log.Printf("PATH MISMATCH DETAILS:")
								log.Printf("  Expected: % 02x (len=%d)", storage_keyHex, len(storage_keyHex))
								log.Printf("  Received: % 02x (len=%d)", currentPath, len(currentPath))
								break
							}

							metrics.TotalContractNum += 1
							storageProof := storage_iter.MyLeafProof_gen_path_store(storageTrie_prevBlockDB, blockNumber, baseBlockNumber)
							storageTrie_memory_pool.AppendVersionList(accountHex, blockNumber)
							storageTrie_memory_pool.PutStorageSlot(accountHex, blockNumber, storage_keyBytes, storageProof)
							break
						}
					}
				}
			}
		}
	}

	metrics.TotalAccountNum += len(storageTrie_memory_pool.Proofs)
	storageTrie_memory_pool.Force_Flush()

	if metrics.TotalContractNum > 0 {
		metrics.AvgStorageSlotNum_of_Contracts = float64(metrics.StorageSlotNum_of_all_Contracts) / float64(metrics.TotalContractNum)
	} else {
		metrics.AvgStorageSlotNum_of_Contracts = 0
	}
	contract_portion := float64(0)
	if metrics.TotalAccountNum > 0 {
		contract_portion = float64(metrics.TotalContractNum) / float64(metrics.TotalAccountNum)
	}
	fmt.Printf("total account num: %d, contract num: %d (%.2f%%), total slot num %d, avg slot num %.2f \n", metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion*100, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)
	log.Printf("total account num: %d, contract num: %d (%.2f%%), total slot num %d, avg slot num %.2f \n", metrics.TotalAccountNum, metrics.TotalContractNum, contract_portion*100, metrics.StorageSlotNum_of_all_Contracts, metrics.AvgStorageSlotNum_of_Contracts)

}
func Start_gen_path_store_leveldb_with_storageTrie(chainDataPath string,
	myStoreDir string, startBlockNumber uint64, endBlockNumber uint64, baseBlockNumber uint64) {
	log.Printf("Start generating path store from block %d to %d, baseBlock=%d\n", startBlockNumber, endBlockNumber, baseBlockNumber)

	ancientPath := filepath.Join(chainDataPath, "ancient")
	oldDB, err := rawdb.Open(rawdb.OpenOptions{
		Type:              "leveldb",
		Directory:         chainDataPath,
		AncientsDirectory: ancientPath,
		Cache:             40960, // 40GB
		Handles:           500,
		Namespace:         "",
		ReadOnly:          true,
		Ephemeral:         false,
	})
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", chainDataPath, err)
	}
	defer oldDB.Close()

	// state trie
	stateTrie_proofDBPath := myStoreDir + "/stateTrie_proof_path_store"
	stateTrie_prevBlockDBPath := myStoreDir + "/stateTrie_prevBlock_store"
	stateTrie_verionlistDBPath := myStoreDir + "/stateTrie_versionlist_store"
	if err := ensureDirExists(stateTrie_proofDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(stateTrie_prevBlockDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(stateTrie_verionlistDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}

	stateTrie_proofDB, err := rawdb.NewPebbleDBDatabase(stateTrie_proofDBPath, 30720, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_proofDBPath, err)
	}
	defer stateTrie_proofDB.Close()

	stateTrie_prevBlockDB, err := rawdb.NewPebbleDBDatabase(stateTrie_prevBlockDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_prevBlockDBPath, err)
	}
	defer stateTrie_prevBlockDB.Close()

	stateTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(stateTrie_verionlistDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_verionlistDBPath, err)
	}
	defer stateTrie_versionlistDB.Close()

	// storage trie
	storageTrie_proofDBPath := myStoreDir + "/storageTrie_proof_path_store"
	storageTrie_prevBlockDBPath := myStoreDir + "/storageTrie_prevBlock_store"
	storageTrie_verionlistDBPath := myStoreDir + "/storageTrie_versionlist_store"
	if err := ensureDirExists(storageTrie_proofDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(storageTrie_prevBlockDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(storageTrie_verionlistDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}

	storageTrie_proofDB, err := rawdb.NewPebbleDBDatabase(storageTrie_proofDBPath, 30720, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_proofDBPath, err)
	}
	defer storageTrie_proofDB.Close()

	storageTrie_prevBlockDB, err := rawdb.NewPebbleDBDatabase(storageTrie_prevBlockDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_prevBlockDBPath, err)
	}
	defer storageTrie_prevBlockDB.Close()

	storageTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(storageTrie_verionlistDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_verionlistDBPath, err)
	}
	defer storageTrie_versionlistDB.Close()

	Start_gen_path_store_with_storageTrie(oldDB,
		stateTrie_proofDB, stateTrie_prevBlockDB, stateTrie_versionlistDB,
		storageTrie_proofDB, storageTrie_prevBlockDB, storageTrie_versionlistDB,
		startBlockNumber, endBlockNumber, baseBlockNumber)
}

// storageFlag: 0, only stateTrie; 1, only storageTrie; 2, both stateTrie and storageTrie
func Start_gen_path_store_leveldb(chainDataPath string,
	myStoreDir string, startBlockNumber uint64, endBlockNumber uint64, baseBlockNumber uint64,
	storageFlag int) {
	log.Printf("Start generating path store from block %d to %d, baseBlock=%d\n", startBlockNumber, endBlockNumber, baseBlockNumber)

	// oldDB, err := rawdb.NewLevelDBDatabase(chainDataPath, 10240, 2000, "", true)
	ancientPath := filepath.Join(chainDataPath, "ancient")
	oldDB, err := rawdb.Open(rawdb.OpenOptions{
		Type:              "leveldb",
		Directory:         chainDataPath,
		AncientsDirectory: ancientPath,
		Cache:             40960, // 40GB
		Handles:           500,
		Namespace:         "",
		ReadOnly:          true,
		Ephemeral:         false,
	})
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", chainDataPath, err)
	}
	defer oldDB.Close()

	// state trie
	stateTrie_proofDBPath := myStoreDir + "/stateTrie_proof_path_store"
	stateTrie_prevBlockDBPath := myStoreDir + "/stateTrie_prevBlock_store"
	stateTrie_verionlistDBPath := myStoreDir + "/stateTrie_versionlist_store"
	if err := ensureDirExists(stateTrie_proofDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(stateTrie_prevBlockDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(stateTrie_verionlistDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}

	stateTrie_proofDB, err := rawdb.NewPebbleDBDatabase(stateTrie_proofDBPath, 30720, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_proofDBPath, err)
	}
	defer stateTrie_proofDB.Close()

	stateTrie_prevBlockDB, err := rawdb.NewPebbleDBDatabase(stateTrie_prevBlockDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_prevBlockDBPath, err)
	}
	defer stateTrie_prevBlockDB.Close()

	stateTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(stateTrie_verionlistDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_verionlistDBPath, err)
	}
	defer stateTrie_versionlistDB.Close()

	// storage trie
	storageTrie_proofDBPath := myStoreDir + "/storageTrie_proof_path_store"
	storageTrie_prevBlockDBPath := myStoreDir + "/storageTrie_prevBlock_store"
	storageTrie_verionlistDBPath := myStoreDir + "/storageTrie_versionlist_store"
	if err := ensureDirExists(storageTrie_proofDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(storageTrie_prevBlockDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}
	if err := ensureDirExists(storageTrie_verionlistDBPath); err != nil {
		log.Fatalf("Failed to ensure directory exists: %v", err)
	}

	storageTrie_proofDB, err := rawdb.NewPebbleDBDatabase(storageTrie_proofDBPath, 30720, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_proofDBPath, err)
	}
	defer storageTrie_proofDB.Close()

	storageTrie_prevBlockDB, err := rawdb.NewPebbleDBDatabase(storageTrie_prevBlockDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_prevBlockDBPath, err)
	}
	defer storageTrie_prevBlockDB.Close()

	storageTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(storageTrie_verionlistDBPath, 10240, 200, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_verionlistDBPath, err)
	}
	defer storageTrie_versionlistDB.Close()

	Start_gen_path_store(oldDB,
		stateTrie_proofDB, stateTrie_prevBlockDB, stateTrie_versionlistDB,
		storageTrie_proofDB, storageTrie_prevBlockDB, storageTrie_versionlistDB,
		startBlockNumber, endBlockNumber, baseBlockNumber, storageFlag)
}
