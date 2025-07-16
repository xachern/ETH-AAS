package store

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

func Range_read_proof_wo_decode_path_store(account common.Address, startBlocknum uint64, endBlocknum uint64,
	kvstore ethdb.Database) [][]byte {
	// read skiplist
	key := fmt.Sprintf("%v_versions", trie.AddressToStateHexPath(account))
	key_bytes := []byte(key)
	versionListBytes, err := kvstore.Get(key_bytes)
	if err != nil {
		log.Fatalf("Failed to get skiplist %v: %v", account.Hex(), err)
		return nil
	}
	skiplist := BytesToSkiplist(versionListBytes)

	_ = skiplist

	return nil
}

// longestCommonPrefix returns the length of the common prefix between two byte slices
// return the length of the common prefix
func LongestCommonPrefix(a []byte, b []byte) int {
	minLength := min(len(a), len(b)) // Get the minimum length of the two slices
	var i int
	for i = 0; i < minLength; i++ {
		if a[i] != b[i] {
			break // Exit the loop when the bytes differ
		}
	}
	return i // Return the length of the common prefix
}

// try to find the account with longest common prefix within state trie
// in state trie, key is the keccak256 hash of account address
// so, find common prefix of keccak256 hash of two address
func Find_account_with_longest_common_prefix(account common.Address,
	candidates []common.Address) (target common.Address, commonLen int, commonKey []byte) {

	accountHex := trie.AddressToStateHexPath(account)
	candidateHexs := make([][32]byte, 0)
	for _, addr := range candidates {
		hex := trie.AddressToStateHexPath(addr)
		var tmp1 [32]byte
		copy(tmp1[:], hex)
		candidateHexs = append(candidateHexs, tmp1)
	}

	var targetAccount common.Address
	var maxCommonPrefixLen int
	for i, addr := range candidates {
		commonLen := LongestCommonPrefix(accountHex, candidateHexs[i][:])
		if commonLen > maxCommonPrefixLen {
			targetAccount = addr
			maxCommonPrefixLen = commonLen
		}
	}
	commonKey = accountHex[:maxCommonPrefixLen]

	return targetAccount, maxCommonPrefixLen, commonKey
}

// search the proof by chasing segments from trie root
// for each segment, find the account with longest common prefix
func Must_read_proof_segment_chasing(account common.Address, blockNumber uint64,
	oldDB ethdb.Database, memory_pool *MyMemoryPool) [][]byte {

	// accountKeyBytes := trie.AddressToStateKeyBytes(account)
	accountHex := trie.AddressToStateHexPath(account)

	var final_proof_bytes [][]byte
	// next_nodeID := trie.MyNodeID{Path: []byte(nil), BlockNumber: blockNumber} // root node
	current_blockNum := blockNumber
	current_path := []byte(nil) // start from root
	search_depth := 0

	for search_depth <= 65 && len(current_path) <= 65 {
		// read block account set
		accountList := Fetch_accounts_of_block(oldDB, current_blockNum)
		if accountList == nil {
			log.Fatalf("Failed to get account list of block %v", current_blockNum)
			return nil
		}

		next_account, commonLen, commonKey := Find_account_with_longest_common_prefix(account, accountList)
		if account.Cmp(next_account) == 0 { //this account is changed in this block
			// 1. read from in-memory []trie.MyNode
			key := fmt.Sprintf("%x_%d", accountHex, current_blockNum)
			if proofList, exists := memory_pool.Proofs[key]; exists {
				for _, proofNode := range proofList {
					if bytes.HasPrefix(current_path, proofNode.GetPath()) {
						continue
					}
					final_proof_bytes = append(final_proof_bytes, proofNode.GetRLPBytes())
				}
				return final_proof_bytes
			}
			// 2. read from proofDB
			key_bytes := []byte(key)
			proofBytes, _ := memory_pool.ProofDB.Get(key_bytes)
			proofList, _ := BytesToProofList(proofBytes)
			for _, proofNode := range proofList {
				if !bytes.HasPrefix(proofNode.GetPath(), current_path) {
					continue
				}
				final_proof_bytes = append(final_proof_bytes, proofNode.GetRLPBytes())
			}
		}

		//chase segment
		if commonLen == 0 {
			fmt.Printf("Failed to find the common prefix account, maybe root node\n")
			return nil
		}
		var next_account_proofList []trie.MyNode
		next_accountHex := trie.AddressToStateHexPath(next_account)
		key := fmt.Sprintf("%x_%d", next_accountHex, current_blockNum)
		if proofList, exists := memory_pool.Proofs[key]; exists {
			//1. read from in-memory []trie.MyNode
			next_account_proofList = proofList
		} else {
			//2. read from proofDB
			key_bytes := []byte(key)
			proofBytes, err := memory_pool.ProofDB.Get(key_bytes)
			if err != nil {
				fmt.Printf("Failed to get proof: %v\n", err)
				return nil
			}
			next_account_proofList, _ = BytesToProofList(proofBytes)
		}

		for i, proofNode := range next_account_proofList[:len(next_account_proofList)-1] {
			// compare commonKey with proofNode.path
			if len(next_account_proofList[i+1].GetPath()) <= commonLen {
				final_proof_bytes = append(final_proof_bytes, proofNode.GetRLPBytes())
				// deep copy
				current_path = make([]byte, len(proofNode.GetPath()))
				copy(current_path, proofNode.GetPath())
				search_depth++
				continue
			}
			if !bytes.HasPrefix(commonKey, proofNode.GetPath()) {
				fmt.Printf("Failed to find the next segment\n")
				return nil
			}
			final_proof_bytes = append(final_proof_bytes, proofNode.GetRLPBytes())
			current_path = make([]byte, len(proofNode.GetPath()))
			copy(current_path, proofNode.GetPath())
			search_depth++

			switch proofNode.(type) {
			case *trie.MyFullNode:
				fullNode := proofNode.(*trie.MyFullNode)
				// find the child position by comparing the path
				childPosition := uint8(accountHex[len(fullNode.GetPath())])
				childPointer := fullNode.ChildrenPointer[childPosition]
				current_blockNum = childPointer.BlockNumber
				current_path = make([]byte, len(childPointer.Path))
				copy(current_path, childPointer.Path)
			case *trie.MyShortNode:
				shortNode := proofNode.(*trie.MyShortNode)
				current_blockNum = shortNode.ChildrenPointer.BlockNumber
				current_path = make([]byte, len(shortNode.ChildrenPointer.Path))
				copy(current_path, shortNode.ChildrenPointer.Path)
			default: // MyHashNode, MyLeafNode,other
				fmt.Printf("Failed to find the next segment\n")
				return nil
			}
			if !bytes.HasPrefix(accountHex, current_path) {
				fmt.Printf("Failed to find the next segment\n")
				return nil
			}
			if current_blockNum == 0 {
				fmt.Printf("Failed to find the next segment\n")
				return nil
			}
			break
		}
		// for the last node, must be leafnode, no need to check
	}

	fmt.Printf("Failed to find the proof\n")
	return nil
}

// newDB for path store
// oldDB for block header and txns
func Point_read_original_state_proof_wo_decode_path_store(account common.Address, blockNumber uint64, memory_pool *MyMemoryPool) [][]byte {
	// read versionlist
	versionList := memory_pool.GetVersionList(trie.AddressToStateHexPath(account))

	//find the target block number
	has_version := versionList.ContainsVersion(blockNumber)
	if has_version {
		// fast path: there exist the full proof of this version
		// 1. read from in-memory []trie.MyNode
		accountHex := trie.AddressToStateHexPath(account)
		key := fmt.Sprintf("%x_%d", accountHex, blockNumber)
		if proofList, exists := memory_pool.Proofs[key]; exists {
			original_proof, _ := ProofListToOriginalMerkelProof_without_encoding(proofList)
			return original_proof
		}
		// 2. read from proofDB
		key_bytes := []byte(key)
		// memory_pool.ProofDB.AncientRange()
		proofBytes, _ := memory_pool.ProofDB.Get(key_bytes)
		original_proof, _ := BytesToOriginalMerkelProof_without_decoding(proofBytes)
		return original_proof
	} else {
		//slow path: traverse from state trie root,
		return Must_read_proof_segment_chasing(account, blockNumber, memory_pool.ProofDB, memory_pool)
	}
}

func Point_read_storage_proof_wo_decode_path_store(account common.Address, blockNumber uint64, storageSlotIndex int64, memory_pool *MyMemoryPool) [][]byte {
	// read versionlist
	versionList := memory_pool.GetVersionList(trie.AddressToStateHexPath(account))

	has_version := versionList.ContainsVersion(blockNumber)
	// has_version := true
	if has_version {
		// fast path: there exist the full proof of this version
		// 1. read from in-memory []trie.MyNode
		accountHex := trie.AddressToStateHexPath(account)
		storage_key := common.BigToHash(big.NewInt(storageSlotIndex))
		storage_keyBytes := crypto.Keccak256(storage_key.Bytes())
		key := fmt.Sprintf("%x_%x_%d", accountHex, storage_keyBytes, blockNumber)
		// fmt.Printf("read StorageSlot , key: %s\n", key)

		if proofList, exists := memory_pool.Proofs[key]; exists {
			original_proof, _ := ProofListToOriginalMerkelProof_without_encoding(proofList)
			return original_proof
		}
		// 2. read from proofDB
		key_bytes := []byte(key)
		proofBytes, _ := memory_pool.ProofDB.Get(key_bytes)
		// original_proof, _ := BytesToOriginalMerkelProof_without_decoding(proofBytes)
		// todo: decode proofBytes to proofList
		_ = proofBytes
		return nil
	} else {
		return Must_read_proof_segment_chasing(account, blockNumber, memory_pool.ProofDB, memory_pool)
	}
}

func Inner_range_state_query_from_path_store(account common.Address,
	startBlockNumber uint64, endBlockNumber uint64,
	oldDB ethdb.Database, memory_pool *MyMemoryPool,
	fast_path_used_time_microseconds *int64, slow_path_used_time_microseconds *int64) [][]byte {
	// 1. read from in-memory []trie.MyNode
	accountHex := trie.AddressToStateHexPath(account)
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	encoder.Encode(startBlockNumber)
	start_key := append(accountHex, buffer.Bytes()...)
	buffer.Reset()
	encoder.Encode(endBlockNumber + 1)
	end_key := append(accountHex, buffer.Bytes()...)
	// [start_key, end_key)
	iter := memory_pool.ProofDB.NewIterator2(start_key, end_key)
	var cnt uint64 = 0
	proofs := make([][]byte, 3)
	startTime := time.Now()
	for iter.Next() {
		// assign iter.Value() to the map with the current count as key
		key := iter.Key()
		fmt.Printf("key = %s\n", key)
		proofs = append(proofs, iter.Value())
		cnt += 1
	}
	endTime := time.Now()
	*fast_path_used_time_microseconds += endTime.Sub(startTime).Microseconds()

	return proofs
}

func Inner_range_state_query_from_path_store_wo_versionlist(account common.Address,
	startBlockNumber uint64, endBlockNumber uint64,
	oldDB ethdb.Database, memory_pool *MyMemoryPool) map[uint64][][]byte {

	tasks := make([]uint64, endBlockNumber-startBlockNumber+1)
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		tasks = append(tasks, i)
	}

	proofs := make(map[uint64][][]byte, len(tasks))
	// fast path
	for _, blockNumber := range tasks {
		proof := Point_read_original_state_proof_wo_decode_path_store(account, blockNumber, memory_pool)
		proofs[blockNumber] = proof //no deep copy
	}
	return proofs
}

func Start_point_state_query_proof_from_path_store_leveldb(stateTrie_proofDBPath string,
	stateTrie_verionlistDBPath string, stateTrie_prevBlockDBPath string,
	query_file_path string, output_file_path string) {

	proofDB, err := rawdb.NewPebbleDBDatabase(stateTrie_proofDBPath, 20480, 100, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_proofDBPath, err)
	}
	defer proofDB.Close()

	versionlistDB, err := rawdb.NewPebbleDBDatabase(stateTrie_verionlistDBPath, 10240, 100, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_verionlistDBPath, err)
	}
	defer versionlistDB.Close()

	point_state_query_proof_from_path_store(proofDB, versionlistDB, query_file_path, output_file_path)
}

func Start_point_storage_query_from_path_store_leveldb(
	storageTrie_proofDBPath string,
	storageTrie_verionlistDBPath string,
	query_file_path string, output_file_path string) {

	storageTrie_proofDB, err := rawdb.NewPebbleDBDatabase(storageTrie_proofDBPath, 20480, 100, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_proofDBPath, err)
	}
	defer storageTrie_proofDB.Close()

	storageTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(storageTrie_verionlistDBPath, 10240, 100, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_verionlistDBPath, err)
	}
	defer storageTrie_versionlistDB.Close()

	point_storage_query_proof_from_path_store(storageTrie_proofDB, storageTrie_versionlistDB, query_file_path, output_file_path)
}

func point_storage_query_proof_from_path_store(
	storageTrie_proofDB ethdb.Database,
	storageTrie_versionlistDB ethdb.Database,
	query_file_path string,
	output_file_path string) {

	// ouputfile, 保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	// query file
	query_file, err := os.Open(query_file_path)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer query_file.Close()

	var token string
	var addrNum int
	maxNum := 10000
	var addrs []common.Address
	var blockNums []uint64
	for {
		_, err := fmt.Fscanln(query_file, &token)
		if err != nil {
			break
		}
		token = strings.Trim(token, "\n")
		tokens := strings.Split(token, ",")
		if len(tokens) != 2 {
			log.Fatalf("Invalid query: %v", token)
		}
		address := common.HexToAddress(tokens[0][2:])

		addrs = append(addrs, address)
		blockNum, err := strconv.ParseUint(tokens[1], 10, 64)
		if err != nil {
			log.Fatalf("Failed to parse block number: %v", err)
		}
		blockNums = append(blockNums, blockNum)

		fmt.Printf("Parsed address: %s, block number: %d\n", address.Hex(), blockNum)

		addrNum++
		if addrNum >= maxNum {
			fmt.Printf("Read %d addresses\n", addrNum)
			break
		}
	}
	fmt.Printf("Total %d addr\n", addrNum)

	//storageTrie_memory_pool
	storageTrie_memory_pool := NewMyMemoryPool(50000, 50000, storageTrie_proofDB, storageTrie_versionlistDB)

	var totalLatency int64 = 0 // 累计总延迟
	startTime := time.Now()
	for i, addr := range addrs {
		// fmt.Printf("Address: %v\n", addr.Hex())
		blocknum := blockNums[i]
		storageSlotIndex := int64(0)
		singleStartTime := time.Now()
		// todo: state proof, open state proofdb
		// Point_read_original_state_proof_wo_decode_path_store(addr, blocknum, memory_pool)
		// storage proof
		Point_read_storage_proof_wo_decode_path_store(addr, blocknum, storageSlotIndex, storageTrie_memory_pool)
		singleEndTime := time.Now()

		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d,%v\n", i, latency))
		totalLatency += latency
	}

	endTime := time.Now()
	totalQueries := len(addrs)
	duration := endTime.Sub(startTime).Seconds() // 以秒为单位的时间差
	qps := float64(totalQueries) / duration      // 计算QPS
	averageLatency := float64(totalLatency) / float64(totalQueries)

	// 输出结果
	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Total time: %.2f seconds\n", duration)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Average latency: %.2f μs\n", averageLatency)

	// 输出到文件
	latencyFile.WriteString(fmt.Sprintf("Total queries: %d\n", totalQueries))
	latencyFile.WriteString(fmt.Sprintf("Total time: %.2f seconds\n", duration))
	latencyFile.WriteString(fmt.Sprintf("QPS: %.2f\n", qps))
	latencyFile.WriteString(fmt.Sprintf("Average latency: %.2f μs\n", averageLatency))
}

func point_state_query_proof_from_path_store(
	proofDB ethdb.Database,
	versionListDB ethdb.Database,
	query_file_path string,
	output_file_path string) {

	// ouputfile, 保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	// query file
	query_file, err := os.Open(query_file_path)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer query_file.Close()

	var token string
	var addrNum int
	maxNum := 1000
	var addrs []common.Address
	var blockNums []uint64
	for {
		_, err := fmt.Fscanln(query_file, &token)
		if err != nil {
			break
		}
		// token = addr,blocknumber\n
		token = strings.Trim(token, "\n")
		tokens := strings.Split(token, ",")
		if len(tokens) != 2 {
			log.Fatalf("Invalid query: %v", token)
		}
		// 去掉"0x"并将其转换为common.Address
		address := common.HexToAddress(tokens[0])

		addrs = append(addrs, address)
		blockNum, err := strconv.ParseUint(tokens[1], 10, 64)
		if err != nil {
			log.Fatalf("Failed to parse block number: %v", err)
		}
		blockNums = append(blockNums, blockNum)

		// fmt.Printf("Parsed address: %s, block number: %d\n", address.Hex(), blockNum)

		addrNum++
		if addrNum >= maxNum {
			fmt.Printf("Read %d addresses\n", addrNum)
			break
		}
	}
	fmt.Printf("Total %d addr\n", addrNum)

	//memory_pool
	memory_pool := NewMyMemoryPool(50000, 50000, proofDB, versionListDB)

	// cache in memory
	for i, addr := range addrs {
		// fmt.Printf("Address: %v\n", addr.Hex())
		blocknum := blockNums[i]
		proof := Point_read_original_state_proof_wo_decode_path_store(addr, blocknum, memory_pool)
		_ = proof
	}

	var totalLatency int64 = 0 // 累计总延迟
	startTime := time.Now()
	for i, addr := range addrs {
		// fmt.Printf("Address: %v\n", addr.Hex())
		blocknum := blockNums[i]
		singleStartTime := time.Now()
		proof := Point_read_original_state_proof_wo_decode_path_store(addr, blocknum, memory_pool)
		singleEndTime := time.Now()
		_ = proof

		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d,%v\n", i, latency))
		totalLatency += latency
	}

	endTime := time.Now()
	totalQueries := len(addrs)
	duration := endTime.Sub(startTime).Seconds() // 以秒为单位的时间差
	qps := float64(totalQueries) / duration      // 计算QPS
	averageLatency := float64(totalLatency) / float64(totalQueries)

	// 输出结果
	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Total time: %.2f seconds\n", duration)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Average latency: %.2f μs\n", averageLatency)

	// 输出到文件
	latencyFile.WriteString(fmt.Sprintf("Total queries: %d\n", totalQueries))
	latencyFile.WriteString(fmt.Sprintf("Total time: %.2f seconds\n", duration))
	latencyFile.WriteString(fmt.Sprintf("QPS: %.2f\n", qps))
	latencyFile.WriteString(fmt.Sprintf("Average latency: %.2f μs\n", averageLatency))
}

func Start_range_state_query_from_path_store_leveldb(chainDataPath string,
	proofDBPath string, verionlistDBPath string, prevBlockDBPath string,
	query_file_path string, max_query_num int, output_file_path string,
	startBlockNumber uint64, endBlockNumber uint64) {

	ancientPath := filepath.Join(chainDataPath, "ancient")
	oldDB, err := rawdb.Open(rawdb.OpenOptions{
		Type:              "leveldb",
		Directory:         chainDataPath,
		AncientsDirectory: ancientPath,
		Cache:             10240, // 10GB
		Handles:           200,
		Namespace:         "",
		ReadOnly:          true,
		Ephemeral:         false,
	})
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", chainDataPath, err)
	}
	defer oldDB.Close()

	proofDB, err := rawdb.NewPebbleDBDatabase(proofDBPath, 20480, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", proofDBPath, err)
	}
	defer proofDB.Close()

	prevBlockDB, err := rawdb.NewPebbleDBDatabase(prevBlockDBPath, 10240, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", prevBlockDBPath, err)
	}
	defer prevBlockDB.Close()

	versionlistDB, err := rawdb.NewPebbleDBDatabase(verionlistDBPath, 10240, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", verionlistDBPath, err)
	}
	defer versionlistDB.Close()

	// ouputfile, 保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	// query file
	query_file, err := os.Open(query_file_path)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer query_file.Close()

	var token string
	var addrNum int
	var addrs []common.Address
	for {
		_, err := fmt.Fscanln(query_file, &token)
		if err != nil {
			break
		}
		// token = addr\n
		token = strings.Trim(token, "\n")
		// 去掉"0x"并将其转换为common.Address
		address := common.HexToAddress(token)
		addrs = append(addrs, address)
		addrNum++
		if addrNum >= max_query_num {
			fmt.Printf("Read %d addresses\n", addrNum)
			break
		}
	}

	// check latest block number
	latestBlockNumber := rawdb.ReadHeaderNumber(oldDB, rawdb.ReadHeadBlockHash(oldDB))
	if latestBlockNumber == nil {
		log.Fatalf("Failed to read the latest block number")
		return
	}
	fmt.Printf("Latest block number: %d\n", *latestBlockNumber)
	// check endBlockNumber
	if endBlockNumber > *latestBlockNumber {
		endBlockNumber = *latestBlockNumber
	}

	//memory_pool
	memory_pool := NewMyMemoryPool(10000, 10000, proofDB, versionlistDB)

	var totalLatency int64 = 0 // 累计总延迟
	var fast_path_used_time int64 = 0
	var slow_path_used_time int64 = 0
	latencyFile.WriteString("id,latency(μs),versionLen\n")
	startTime := time.Now()
	for i, addr := range addrs {
		singleStartTime := time.Now()
		proof := Inner_range_state_query_from_path_store(addr, startBlockNumber, endBlockNumber, oldDB, memory_pool,
			&fast_path_used_time, &slow_path_used_time)
		singleEndTime := time.Now()
		_ = proof

		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d,%v,%d\n", i, latency, len(proof)))
		totalLatency += latency
	}
	endTime := time.Now()
	totalQueries := len(addrs)
	duration := endTime.Sub(startTime).Seconds() // 以秒为单位的时间差
	qps := float64(totalQueries) / duration      // 计算QPS
	averageLatency := float64(totalLatency) / float64(totalQueries)

	// 输出结果
	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Total time: %.2f seconds\n", duration)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Average latency: %.2f μs\n", averageLatency)
	fmt.Printf("Fast path used time: %v seconds (%.2f%%)\n", float64(fast_path_used_time)/1e6,
		float64(fast_path_used_time)/float64(fast_path_used_time+slow_path_used_time)*100)
	fmt.Printf("Slow path used time: %v seconds (%.2f%%)\n", float64(slow_path_used_time)/1e6,
		float64(slow_path_used_time)/float64(fast_path_used_time+slow_path_used_time)*100)

	// 输出到文件
	latencyFile.WriteString(fmt.Sprintf("Total queries: %d\n", totalQueries))
	latencyFile.WriteString(fmt.Sprintf("Total time: %.2f seconds\n", duration))
	latencyFile.WriteString(fmt.Sprintf("QPS: %.2f\n", qps))
	latencyFile.WriteString(fmt.Sprintf("Average latency: %.2f μs\n", averageLatency))
	latencyFile.WriteString(fmt.Sprintf("Fast path used time: %v seconds (%.2f%%)\n", float64(fast_path_used_time)/1e6,
		float64(fast_path_used_time)/float64(fast_path_used_time+slow_path_used_time)*100))
	latencyFile.WriteString(fmt.Sprintf("Slow path used time: %v seconds (%.2f%%)\n", float64(slow_path_used_time)/1e6,
		float64(slow_path_used_time)/float64(fast_path_used_time+slow_path_used_time)*100))
}

func Start_range_state_query_from_path_store_wo_versionlist_leveldb(chainDataPath string,
	proofDBPath string, verionlistDBPath string, prevBlockDBPath string,
	query_file_path string, max_query_num int, output_file_path string,
	startBlockNumber uint64, endBlockNumber uint64) {

	ancientPath := filepath.Join(chainDataPath, "ancient")
	oldDB, err := rawdb.Open(rawdb.OpenOptions{
		Type:              "leveldb",
		Directory:         chainDataPath,
		AncientsDirectory: ancientPath,
		Cache:             10240, // 10GB
		Handles:           200,
		Namespace:         "",
		ReadOnly:          true,
		Ephemeral:         false,
	})
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", chainDataPath, err)
	}
	defer oldDB.Close()

	proofDB, err := rawdb.NewPebbleDBDatabase(proofDBPath, 20480, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", proofDBPath, err)
	}
	defer proofDB.Close()

	prevBlockDB, err := rawdb.NewPebbleDBDatabase(prevBlockDBPath, 10240, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", prevBlockDBPath, err)
	}
	defer prevBlockDB.Close()

	versionlistDB, err := rawdb.NewPebbleDBDatabase(verionlistDBPath, 10240, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", verionlistDBPath, err)
	}
	defer versionlistDB.Close()

	// ouputfile, 保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	// query file
	query_file, err := os.Open(query_file_path)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer query_file.Close()

	var token string
	var addrNum int
	var addrs []common.Address
	for {
		_, err := fmt.Fscanln(query_file, &token)
		if err != nil {
			break
		}
		// token = addr\n
		token = strings.Trim(token, "\n")
		// 去掉"0x"并将其转换为common.Address
		address := common.HexToAddress(token)
		addrs = append(addrs, address)
		addrNum++
		if addrNum >= max_query_num {
			fmt.Printf("Read %d addresses\n", addrNum)
			break
		}
	}

	// check latest block number
	latestBlockNumber := rawdb.ReadHeaderNumber(oldDB, rawdb.ReadHeadBlockHash(oldDB))
	if latestBlockNumber == nil {
		log.Fatalf("Failed to read the latest block number")
		return
	}
	fmt.Printf("Latest block number: %d\n", *latestBlockNumber)
	// check endBlockNumber
	if endBlockNumber > *latestBlockNumber {
		endBlockNumber = *latestBlockNumber
	}

	//memory_pool
	memory_pool := NewMyMemoryPool(10000, 10000, proofDB, versionlistDB)

	var totalLatency int64 = 0 // 累计总延迟
	latencyFile.WriteString("id,latency(μs),versionLen\n")
	startTime := time.Now()
	for i, addr := range addrs {
		singleStartTime := time.Now()
		proof := Inner_range_state_query_from_path_store_wo_versionlist(addr, startBlockNumber, endBlockNumber, oldDB, memory_pool)
		singleEndTime := time.Now()

		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d, %d,%v\n", i, latency, len(proof)))
		totalLatency += latency
	}
	endTime := time.Now()
	totalQueries := len(addrs)
	duration := endTime.Sub(startTime).Seconds() // 以秒为单位的时间差
	qps := float64(totalQueries) / duration      // 计算QPS
	averageLatency := float64(totalLatency) / float64(totalQueries)

	// 输出结果
	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Total time: %.2f seconds\n", duration)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Average latency: %.2f μs\n", averageLatency)

	// 输出到文件
	latencyFile.WriteString(fmt.Sprintf("Total queries: %d\n", totalQueries))
	latencyFile.WriteString(fmt.Sprintf("Total time: %.2f seconds\n", duration))
	latencyFile.WriteString(fmt.Sprintf("QPS: %.2f\n", qps))
	latencyFile.WriteString(fmt.Sprintf("Average latency: %.2f μs\n", averageLatency))
}

func Start_range_storage_query_from_path_store_leveldb(chainDataPath string,
	stateTrie_proofDBPath string, stateTrie_verisonlistDBPath string,
	storageTrie_proofDBPath string, storageTrie_verionlistDBPath string,
	query_file_path string, output_file_path string,
	startBlockNumber uint64, endBlockNumber uint64) {

	ancientPath := filepath.Join(chainDataPath, "ancient")
	oldDB, err := rawdb.Open(rawdb.OpenOptions{
		Type:              "leveldb",
		Directory:         chainDataPath,
		AncientsDirectory: ancientPath,
		Cache:             10240, // 10GB
		Handles:           200,
		Namespace:         "",
		ReadOnly:          true,
		Ephemeral:         false,
	})
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", chainDataPath, err)
	}
	defer oldDB.Close()

	stateTrie_proofDB, err := rawdb.NewPebbleDBDatabase(stateTrie_proofDBPath, 20480, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_proofDBPath, err)
	}
	defer stateTrie_proofDB.Close()

	stateTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(stateTrie_verisonlistDBPath, 10240, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", stateTrie_proofDBPath, err)
	}
	defer stateTrie_versionlistDB.Close()

	storageTrie_proofDB, err := rawdb.NewPebbleDBDatabase(storageTrie_proofDBPath, 20480, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_proofDBPath, err)
	}
	defer storageTrie_proofDB.Close()

	storageTrie_versionlistDB, err := rawdb.NewPebbleDBDatabase(storageTrie_verionlistDBPath, 10240, 2000, "", false, false)
	if err != nil {
		log.Fatalf("Failed to open database at %v: %v", storageTrie_verionlistDBPath, err)
	}
	defer storageTrie_versionlistDB.Close()

	// ouputfile, 保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	// query file
	query_file, err := os.Open(query_file_path)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer query_file.Close()

	var token string
	var addrNum int
	var addrs []common.Address
	for {
		_, err := fmt.Fscanln(query_file, &token)
		if err != nil {
			break
		}
		// token = addr\n
		token = strings.Trim(token, "\n")
		// 去掉"0x"并将其转换为common.Address
		address := common.HexToAddress(token)
		addrs = append(addrs, address)
		addrNum++
	}

	// check latest block number
	latestBlockNumber := rawdb.ReadHeaderNumber(oldDB, rawdb.ReadHeadBlockHash(oldDB))
	if latestBlockNumber == nil {
		log.Fatalf("Failed to read the latest block number")
		return
	}
	fmt.Printf("Latest block number: %d\n", *latestBlockNumber)
	// check endBlockNumber
	if endBlockNumber > *latestBlockNumber {
		endBlockNumber = *latestBlockNumber
	}

	//stateTrie_memory_pool
	stateTrie_memory_pool := NewMyMemoryPool(10000, 10000, stateTrie_proofDB, stateTrie_versionlistDB)
	storageTrie_memory_pool := NewMyMemoryPool(10000, 10000, storageTrie_proofDB, storageTrie_versionlistDB)

	var totalLatency int64 = 0 // 累计总延迟
	var fast_path_used_time int64 = 0
	var slow_path_used_time int64 = 0
	latencyFile.WriteString("id,latency(μs)\n")
	startTime := time.Now()
	for i, addr := range addrs {
		singleStartTime := time.Now()
		Inner_range_storage_query_from_path_store(addr, startBlockNumber, endBlockNumber, oldDB,
			stateTrie_memory_pool, storageTrie_memory_pool,
			&fast_path_used_time, &slow_path_used_time)
		singleEndTime := time.Now()

		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d,%v\n", i, latency))
		totalLatency += latency
	}
	endTime := time.Now()
	totalQueries := len(addrs)
	duration := endTime.Sub(startTime).Seconds() // 以秒为单位的时间差
	qps := float64(totalQueries) / duration      // 计算QPS
	averageLatency := float64(totalLatency) / float64(totalQueries)

	// 输出结果
	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Total time: %.2f seconds\n", duration)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Average latency: %.2f μs\n", averageLatency)
	fmt.Printf("Fast path used time: %v seconds (%.2f%%)\n", float64(fast_path_used_time)/1e6,
		float64(fast_path_used_time)/float64(fast_path_used_time+slow_path_used_time)*100)
	fmt.Printf("Slow path used time: %v seconds (%.2f%%)\n", float64(slow_path_used_time)/1e6,
		float64(slow_path_used_time)/float64(fast_path_used_time+slow_path_used_time)*100)

	// 输出到文件
	latencyFile.WriteString(fmt.Sprintf("Total queries: %d\n", totalQueries))
	latencyFile.WriteString(fmt.Sprintf("Total time: %.2f seconds\n", duration))
	latencyFile.WriteString(fmt.Sprintf("QPS: %.2f\n", qps))
	latencyFile.WriteString(fmt.Sprintf("Average latency: %.2f μs\n", averageLatency))
	latencyFile.WriteString(fmt.Sprintf("Fast path used time: %v seconds (%.2f%%)\n", float64(fast_path_used_time)/1e6,
		float64(fast_path_used_time)/float64(fast_path_used_time+slow_path_used_time)*100))
	latencyFile.WriteString(fmt.Sprintf("Slow path used time: %v seconds (%.2f%%)\n", float64(slow_path_used_time)/1e6,
		float64(slow_path_used_time)/float64(fast_path_used_time+slow_path_used_time)*100))
}

func Inner_range_storage_query_from_path_store(account common.Address,
	startBlockNumber uint64, endBlockNumber uint64,
	oldDB ethdb.Database,
	stateTrie_memory_pool *MyMemoryPool,
	storageTrie_memory_pool *MyMemoryPool,
	fast_path_used_time_microseconds *int64, slow_path_used_time_microseconds *int64) {
	// read versionlist
	versionList := storageTrie_memory_pool.GetVersionList(trie.AddressToStateHexPath(account))

	fast_tasks, err := versionList.GetBoundingVersions(startBlockNumber, endBlockNumber)
	if err != nil {
		log.Fatalf("Failed to get bounding versions: %v", err)
	}
	// no version in the range
	if len(fast_tasks) == 0 {
		return
	}

	// var slow_tasks []uint64
	// if fast_tasks[0] > startBlockNumber {
	// 	slow_tasks = append(slow_tasks, startBlockNumber)
	// }
	// if fast_tasks[len(fast_tasks)-1] < endBlockNumber {
	// 	slow_tasks = append(slow_tasks, endBlockNumber)
	// }

	// version list: [v0, v1, v2, v3, v4]
	// read tasks: [L,v1-1, v1,v2-1, v2,v3-1, v3,R]
	// fast path task: [v1, v2, v3]
	// slow path task: L, v1-1, v2-1, v3-1, R

	// fast path
	for _, blockNumber := range fast_tasks {
		storageSlotIndex := int64(0)
		startTime := time.Now()
		Point_read_original_state_proof_wo_decode_path_store(account, blockNumber, stateTrie_memory_pool)
		Point_read_storage_proof_wo_decode_path_store(account, blockNumber, storageSlotIndex, storageTrie_memory_pool)
		endTime := time.Now()
		*fast_path_used_time_microseconds += endTime.Sub(startTime).Microseconds()
	}
	// slow path
	// for _, blockNumber := range slow_tasks {
	// 	startTime := time.Now()
	// 	proof := Must_read_proof_segment_chasing(account, blockNumber, oldDB, memory_pool)
	// 	endTime := time.Now()
	// 	*slow_path_used_time_microseconds += endTime.Sub(startTime).Microseconds()
	// 	proofs[blockNumber] = proof //no deep copy
	// }
}

// for test
func Get_block_proof_from_original_store(blockNumber uint64, oldDB ethdb.Database) map[common.Address][][]byte {
	blockHash := rawdb.ReadCanonicalHash(oldDB, blockNumber)
	selected_block := rawdb.ReadBlock(oldDB, blockHash, blockNumber)
	if selected_block == nil {
		log.Fatalf("Failed to read block %v", blockNumber)
	}

	acitiveAccountSet := Fetch_accounts_of_block(oldDB, blockNumber)
	// sorted account hex
	activeAccountHexs := make([][]byte, 0)
	HexToAccount := make(map[string]common.Address) // reverse map
	for _, account := range acitiveAccountSet {
		accountHex := trie.AddressToStateHexPath(account)
		activeAccountHexs = append(activeAccountHexs, accountHex)
		HexToAccount[string(accountHex)] = account
	}
	sort.Slice(activeAccountHexs, func(i, j int) bool { return bytes.Compare(activeAccountHexs[i], activeAccountHexs[j]) < 0 })

	// state trie
	config := triedb.HashDefaults
	triedb := triedb.NewDatabase(oldDB, config)
	trieId := trie.StateTrieID(selected_block.Root())
	t, err := trie.NewStateTrie(trieId, triedb)
	if err != nil {
		log.Fatalf("new state trie: %s", err)
	}

	// get state key of all address in accountSet
	// state key = keccak256(address.Bytes())
	// state hex path = KeybytesToHex(keccak256(address.Bytes()))

	all_proof := make(map[common.Address][][]byte, 0)
	for _, accountHex := range activeAccountHexs {
		accountKeyBytes := trie.AddressToStateKeyBytes(HexToAccount[string(accountHex)])
		iter, err := t.NodeIterator(accountKeyBytes)
		if err != nil {
			log.Fatalf("Failed to create iterator: %v", err)
		}
		for iter.Next(true) {
			if iter.Leaf() {
				if !bytes.Equal(iter.Path(), accountHex) {
					log.Fatalf("Failed to get leaf node for account %v", HexToAccount[string(accountHex)].Hex())
				}

				accountProof := iter.LeafProof()
				all_proof[HexToAccount[string(accountHex)]] = accountProof
				break
			}
		}
	}
	return all_proof
}

func Point_query_geth_proof_for_test(account common.Address, blockNumber uint64, oldDB ethdb.Database) [][]byte {
	blockHash := rawdb.ReadCanonicalHash(oldDB, blockNumber)
	selected_block := rawdb.ReadBlock(oldDB, blockHash, blockNumber)
	if selected_block == nil {
		log.Fatalf("Failed to read block %v", blockNumber)
	}

	// state trie
	config := triedb.HashDefaults
	triedb := triedb.NewDatabase(oldDB, config)
	trieId := trie.StateTrieID(selected_block.Root())
	t, err := trie.NewStateTrie(trieId, triedb)
	if err != nil {
		log.Fatalf("new state trie: %s", err)
	}

	accountKeyBytes := trie.AddressToStateKeyBytes(account)
	accountHex := trie.AddressToStateHexPath(account)
	iter, err := t.NodeIterator(accountKeyBytes)
	if err != nil {
		log.Fatalf("Failed to create iterator: %v", err)
	}
	for iter.Next(true) {
		if iter.Leaf() {
			if !bytes.Equal(iter.Path(), accountHex) {
				log.Fatalf("Failed to get leaf node for account %v", account.Hex())
			}

			accountProof := iter.LeafProof()
			return accountProof
		}
	}
	return nil
}
