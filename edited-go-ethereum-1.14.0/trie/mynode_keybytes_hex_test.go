package trie_test

import (
	"bytes"
	"log"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

// 1. trie.NodeIterator(start=keybytes) use account keybytes to start the iterator, see seek()
// 2. trie.NodeIterator.Path() return the hex path of the account, see LeafKey()
func Test_account_key_and_hex(test *testing.T) {
	// trie.NodeIterator(start=keybytes), start is AddressToStateKey
	// node iterator path() is AddressToStateHexPath
	// check AddressToStateHexPath(address)==iter.path
	// check HexToKeybytes(iter.path)==keybytes==AddressToStateKey(address)

	// relation: address --hash--> keybytes
	// keybytes <--> hex path

	// when search trie, use hexPath: see proof.go

	// check 3 block write set for find a path with multiple version nodes
	chaindata_path := "/media/cxa/4T_ETH/eth/eth_hash2m_pebbeldb/geth/chaindata"
	oldDB, err := rawdb.NewPebbleDBDatabase(chaindata_path, 1024, 2000, "", true, false)
	if err != nil {
		test.Fatalf("Failed to open database at %v: %v", chaindata_path, err)
	}

	account := common.HexToAddress("0x7C04d98af1D44DB525491834eFA14121ac7073B1")
	accountKey := trie.AddressToStateKeyBytes(account)
	accountHex := trie.AddressToStateHexPath(account)
	blockNumber := uint64(1990016)
	blockHash := rawdb.ReadCanonicalHash(oldDB, blockNumber)
	selected_block := rawdb.ReadBlock(oldDB, blockHash, blockNumber)
	if selected_block == nil {
		log.Fatalf("Failed to read block %v", blockNumber)
	}
	// state trie
	config := triedb.HashDefaults
	triedb := triedb.NewDatabase(oldDB, config)
	t, err := trie.NewStateTrie(trie.StateTrieID(selected_block.Root()), triedb)
	if err != nil {
		log.Fatalf("new state trie: %s", err)
	}

	iter, err := t.NodeIterator(accountKey)
	if err != nil {
		test.Fatalf("Failed to create iterator: %v", err)
	}
	for iter.Next(true) {
		path := iter.Path()
		// leaf nodes, path is 64 hex bytes + 1 suffix byte = keccak256(account address) + 0x10
		if len(path) == 65 && path[len(path)-1] == 0x10 {
			// check AddressToStateHexPath(address)==iter.path
			if !bytes.Equal(path, accountHex) {
				test.Fatalf("Failed to iterate hex path: %v", accountHex)
			}
			// check HexToKeybytes(iter.path)==keybytes==AddressToStateKey(address)
			keybytes := trie.HexToKeybytes(path)
			if !bytes.Equal(keybytes, accountKey) {
				test.Fatalf("Failed to convert hex path to keybytes: %v", path)
			}
			break
		}
	}
}
