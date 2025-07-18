package trie

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

func fetch_accounts_of_block(oldDB ethdb.Database, blockNumber uint64) []common.Address {
	selected_block := rawdb.ReadBlock(oldDB, rawdb.ReadCanonicalHash(oldDB, blockNumber), blockNumber)
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

func Test_check_childPointer(test *testing.T) {
	// find a path with multiple version nodes
	// read old node, generate new node, encode, decode, check pointer

	// check 3 block write set for find a path with multiple version nodes
	chaindata_path := "/mnt/ETH_4T/eth/eth_hash2m_pebbeldb/geth/chaindata"
	oldDB, err := rawdb.NewPebbleDBDatabase(chaindata_path, 1024, 2000, "", true, false)
	if err != nil {
		test.Fatalf("Failed to open database at %v: %v", chaindata_path, err)
	}
	blocks := []uint64{1990016, 1990017, 1990018}
	accountCnt := make(map[common.Address]uint64, 10)
	accountKeys := make(map[uint64][][]byte, 3)
	accountHexs := make(map[uint64][][]byte, 3)
	for _, blockNumber := range blocks {
		accounts := fetch_accounts_of_block(oldDB, blockNumber)
		for _, account := range accounts {
			if _, ok := accountCnt[account]; !ok {
				accountCnt[account] = 1
			} else {
				accountCnt[account]++
			}
			accountKeys[blockNumber] = append(accountKeys[blockNumber], AddressToStateKeyBytes(account))
			accountHexs[blockNumber] = append(accountHexs[blockNumber], AddressToStateHexPath(account))
		}
	}

	// common account: cnt >=2
	for account, cnt := range accountCnt {
		if cnt >= 2 {
			fmt.Printf("cnt: %v, Account: %v, keyHex: %v \n", cnt, account.Hex(), AddressToStateHexPath(account))
		}
	}
	// other account
	for account, cnt := range accountCnt {
		if cnt < 2 {
			fmt.Printf("cnt: %v, Account: %v, keyHex: %v \n", cnt, account.Hex(), AddressToStateHexPath(account))
		}
	}

	//check trie topology
	all_trie := NewEmpty(newTestDatabase(rawdb.NewMemoryDatabase(), rawdb.HashScheme))
	for blockNumber, blockKeys := range accountKeys {
		testdb := newTestDatabase(rawdb.NewMemoryDatabase(), rawdb.HashScheme)
		trie := NewEmpty(testdb)
		// insert accounts
		for _, accountKey := range blockKeys {
			value := make([]byte, 8)
			binary.BigEndian.PutUint64(value, blockNumber)
			trie.MustUpdate(accountKey, value)
			all_trie.MustUpdate(accountKey, value)
		}
		iter, err := trie.NodeIterator(nil)
		if err != nil {
			test.Fatalf("Failed to create iterator: %v", err)
		}
		// iter.path is keyHex: AddressToStateHexPath
		fmt.Printf("Block %v\n", blockNumber)
		for iter.Next(true) {
			path := iter.Path()
			// print path
			fmt.Printf("Path: %v\n", path)
		}
		fmt.Printf("\n\n\n")

		iter, err = all_trie.NodeIterator(nil)
		if err != nil {
			test.Fatalf("Failed to create iterator: %v", err)
		}
		fmt.Printf("All trie\n")
		for iter.Next(true) {
			path := iter.Path()
			// print path
			fmt.Printf("Path: %v\n", path)
		}
		fmt.Printf("\n\n\n")
	}

	iter, err := all_trie.NodeIterator(nil)
	if err != nil {
		test.Fatalf("Failed to create iterator: %v", err)
	}
	fmt.Printf("All trie\n")
	for iter.Next(true) {
		path := iter.Path()
		// print path
		fmt.Printf("Path: %v\n", path)
	}
}
