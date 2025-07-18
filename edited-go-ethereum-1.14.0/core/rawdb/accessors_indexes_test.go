// Copyright 2018 The go-ethereum Authors
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

package rawdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/blocktest"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

var newTestHasher = blocktest.NewHasher

type read_metric struct {
	DB_read_size       int
	Memory_read_size   int
	Result_memory_size int
}

func my_ReadHeaderNumber(db ethdb.KeyValueReader, hash common.Hash, metric *read_metric) *uint64 {
	data, _ := db.Get(headerNumberKey(hash))
	if len(data) != 8 {
		return nil
	}
	metric.DB_read_size += len(data)
	metric.DB_read_size += len(headerNumberKey(hash))

	number := binary.BigEndian.Uint64(data)
	return &number
}

func my_ReadTxLookupEntry(db ethdb.Reader, hash common.Hash, metric *read_metric) *uint64 {
	data, _ := db.Get(txLookupKey(hash))
	if len(data) == 0 {
		return nil
	}
	metric.DB_read_size += len(data)
	metric.DB_read_size += len(hash.Bytes())

	// Database v6 tx lookup just stores the block number
	if len(data) < common.HashLength {
		number := new(big.Int).SetBytes(data).Uint64()
		return &number
	}
	// Database v4-v5 tx lookup format just stores the hash
	if len(data) == common.HashLength {
		return my_ReadHeaderNumber(db, common.BytesToHash(data), metric)
	}
	// Finally try database v3 tx lookup format
	var entry LegacyTxLookupEntry
	if err := rlp.DecodeBytes(data, &entry); err != nil {
		log.Error("Invalid transaction lookup entry RLP", "hash", hash, "blob", data, "err", err)
		return nil
	}
	metric.Memory_read_size += len(entry.BlockHash.Bytes())
	// entry.BlockIndex
	metric.Memory_read_size += 8
	// entry.Index
	metric.Result_memory_size += 8
	return &entry.BlockIndex
}

func my_ReadCanonicalHash(db ethdb.Reader, number uint64, metric *read_metric) common.Hash {
	var data []byte
	db.ReadAncients(func(reader ethdb.AncientReaderOp) error {
		data, _ = reader.Ancient(ChainFreezerHashTable, number)
		if len(data) == 0 {
			// Get it by hash from leveldb
			data, _ = db.Get(headerHashKey(number))
		}
		metric.DB_read_size += len(data)
		metric.DB_read_size += len(headerHashKey(number))
		return nil
	})
	metric.Memory_read_size += len(common.BytesToHash(data))
	return common.BytesToHash(data)
}

func my_ReadBodyRLP(db ethdb.Reader, hash common.Hash, number uint64, metric *read_metric) rlp.RawValue {
	// First try to look up the data in ancient database. Extra hash
	// comparison is necessary since ancient database only maintains
	// the canonical data.
	var data []byte
	db.ReadAncients(func(reader ethdb.AncientReaderOp) error {
		// Check if the data is in ancients
		if isCanon(reader, number, hash) {
			data, _ = reader.Ancient(ChainFreezerBodiesTable, number)
			metric.DB_read_size += len(data)
			metric.DB_read_size += len(ChainFreezerBodiesTable)
			return nil
		}
		// If not, try reading from leveldb
		data, _ = db.Get(blockBodyKey(number, hash))
		metric.DB_read_size += len(data)
		metric.DB_read_size += len(blockBodyKey(number, hash))
		return nil
	})
	return data
}

func my_ReadBody(db ethdb.Reader, hash common.Hash, number uint64, metric *read_metric) *types.Body {
	data := my_ReadBodyRLP(db, hash, number, metric)
	if len(data) == 0 {
		return nil
	}
	body := new(types.Body)
	if err := rlp.DecodeBytes(data, body); err != nil {
		log.Error("Invalid block body RLP", "hash", hash, "err", err)
		return nil
	}
	if len(body.Transactions) > 0 {
		example_tx := body.Transactions[0]
		tx_size := example_tx.Size()
		metric.Memory_read_size += len(body.Transactions) * int(tx_size)
	}
	if len(body.Uncles) > 0 {
		example_header := body.Uncles[0]
		header_size := example_header.Size()
		metric.Memory_read_size += len(body.Uncles) * int(header_size)
	}
	return body
}

// simulate ReadTransaction() function
func Test_TxLookup_read_amplification(t *testing.T) {
	// chainDataPath := "/media/cxa/4T_ETH/eth/eth_hash2m_pebbeldb/geth/chaindata"
	chainDataPath := "/media/cxa/4T_ETH/eth/eth_hash_4m_pebbeldb/geth/chaindata"
	// chainDataPath := "/media/cxa/4T_ETH/eth/eth_test_hash_pebbeldb/geth/chaindata"
	db, err := NewPebbleDBDatabase(chainDataPath, 1024, 200, "", true, false)
	if err != nil {
		t.Fatalf("Failed to open database at %v: %v", chainDataPath, err)
	}
	defer db.Close()

	var txHash common.Hash
	// read tx from block 4.2m
	{
		blknum := uint64(4200000)
		blockHash := ReadCanonicalHash(db, blknum)
		selected_block := ReadBlock(db, blockHash, blknum)
		if selected_block == nil {
			t.Fatalf("Failed to read block %v", blknum)
		}

		// select one transactions and accounts
		txs := selected_block.Transactions()
		txHash = txs[0].Hash()
	}
	fmt.Printf("txHash: %s\n", txHash.Hex())

	read_metric := read_metric{}

	// 1. ReadTxLookupEntry
	blockNumber := my_ReadTxLookupEntry(db, txHash, &read_metric)
	if blockNumber == nil {
		t.Fatalf("Failed to read tx 's blockNumber")
	}

	// 2. ReadCanonicalHash
	blockHash := my_ReadCanonicalHash(db, *blockNumber, &read_metric)
	if blockHash == (common.Hash{}) {
		t.Fatalf("Failed to read block hash")
	}

	// 3. ReadBody
	body := my_ReadBody(db, blockHash, *blockNumber, &read_metric)
	if body == nil {
		t.Fatalf("Transaction referenced missing: number=%d, hash=%s", *blockNumber, blockHash)
	}
	for txIndex, tx := range body.Transactions {
		if tx.Hash() == txHash {
			fmt.Printf("find tx, txIndex: %d\n", txIndex)
			read_metric.Result_memory_size = int(tx.Size())
			break
		}
	}
	fmt.Printf("DB_read_size: %d\n", read_metric.DB_read_size)
	fmt.Printf("Memory_read_size: %d\n", read_metric.Memory_read_size)
	fmt.Printf("Result_memory_size: %d\n", read_metric.Result_memory_size)
	read_amplification_by_DB_read_size := float64(read_metric.DB_read_size) / float64(read_metric.Result_memory_size)
	fmt.Printf("read_amplification_by_DB_read_size: %f\n", read_amplification_by_DB_read_size)
	read_amplification_by_Memory_read_size := float64(read_metric.Memory_read_size) / float64(read_metric.Result_memory_size)
	fmt.Printf("read_amplification_by_Memory_read_size: %f\n", read_amplification_by_Memory_read_size)
}

// Tests that positional lookup metadata can be stored and retrieved.
func TestLookupStorage(t *testing.T) {
	tests := []struct {
		name                        string
		writeTxLookupEntriesByBlock func(ethdb.Writer, *types.Block)
	}{
		{
			"DatabaseV6",
			func(db ethdb.Writer, block *types.Block) {
				WriteTxLookupEntriesByBlock(db, block)
			},
		},
		{
			"DatabaseV4-V5",
			func(db ethdb.Writer, block *types.Block) {
				for _, tx := range block.Transactions() {
					db.Put(txLookupKey(tx.Hash()), block.Hash().Bytes())
				}
			},
		},
		{
			"DatabaseV3",
			func(db ethdb.Writer, block *types.Block) {
				for index, tx := range block.Transactions() {
					entry := LegacyTxLookupEntry{
						BlockHash:  block.Hash(),
						BlockIndex: block.NumberU64(),
						Index:      uint64(index),
					}
					data, _ := rlp.EncodeToBytes(entry)
					db.Put(txLookupKey(tx.Hash()), data)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := NewMemoryDatabase()

			tx1 := types.NewTransaction(1, common.BytesToAddress([]byte{0x11}), big.NewInt(111), 1111, big.NewInt(11111), []byte{0x11, 0x11, 0x11})
			tx2 := types.NewTransaction(2, common.BytesToAddress([]byte{0x22}), big.NewInt(222), 2222, big.NewInt(22222), []byte{0x22, 0x22, 0x22})
			tx3 := types.NewTransaction(3, common.BytesToAddress([]byte{0x33}), big.NewInt(333), 3333, big.NewInt(33333), []byte{0x33, 0x33, 0x33})
			txs := []*types.Transaction{tx1, tx2, tx3}

			block := types.NewBlock(&types.Header{Number: big.NewInt(314)}, txs, nil, nil, newTestHasher())

			// Check that no transactions entries are in a pristine database
			for i, tx := range txs {
				if txn, _, _, _ := ReadTransaction(db, tx.Hash()); txn != nil {
					t.Fatalf("tx #%d [%x]: non existent transaction returned: %v", i, tx.Hash(), txn)
				}
			}
			// Insert all the transactions into the database, and verify contents
			WriteCanonicalHash(db, block.Hash(), block.NumberU64())
			WriteBlock(db, block)
			tc.writeTxLookupEntriesByBlock(db, block)

			for i, tx := range txs {
				if txn, hash, number, index := ReadTransaction(db, tx.Hash()); txn == nil {
					t.Fatalf("tx #%d [%x]: transaction not found", i, tx.Hash())
				} else {
					if hash != block.Hash() || number != block.NumberU64() || index != uint64(i) {
						t.Fatalf("tx #%d [%x]: positional metadata mismatch: have %x/%d/%d, want %x/%v/%v", i, tx.Hash(), hash, number, index, block.Hash(), block.NumberU64(), i)
					}
					if tx.Hash() != txn.Hash() {
						t.Fatalf("tx #%d [%x]: transaction mismatch: have %v, want %v", i, tx.Hash(), txn, tx)
					}
				}
			}
			// Delete the transactions and check purge
			for i, tx := range txs {
				DeleteTxLookupEntry(db, tx.Hash())
				if txn, _, _, _ := ReadTransaction(db, tx.Hash()); txn != nil {
					t.Fatalf("tx #%d [%x]: deleted transaction returned: %v", i, tx.Hash(), txn)
				}
			}
		})
	}
}

func TestDeleteBloomBits(t *testing.T) {
	// Prepare testing data
	db := NewMemoryDatabase()
	for i := uint(0); i < 2; i++ {
		for s := uint64(0); s < 2; s++ {
			WriteBloomBits(db, i, s, params.MainnetGenesisHash, []byte{0x01, 0x02})
			WriteBloomBits(db, i, s, params.SepoliaGenesisHash, []byte{0x01, 0x02})
		}
	}
	check := func(bit uint, section uint64, head common.Hash, exist bool) {
		bits, _ := ReadBloomBits(db, bit, section, head)
		if exist && !bytes.Equal(bits, []byte{0x01, 0x02}) {
			t.Fatalf("Bloombits mismatch")
		}
		if !exist && len(bits) > 0 {
			t.Fatalf("Bloombits should be removed")
		}
	}
	// Check the existence of written data.
	check(0, 0, params.MainnetGenesisHash, true)
	check(0, 0, params.SepoliaGenesisHash, true)

	// Check the existence of deleted data.
	DeleteBloombits(db, 0, 0, 1)
	check(0, 0, params.MainnetGenesisHash, false)
	check(0, 0, params.SepoliaGenesisHash, false)
	check(0, 1, params.MainnetGenesisHash, true)
	check(0, 1, params.SepoliaGenesisHash, true)

	// Check the existence of deleted data.
	DeleteBloombits(db, 0, 0, 2)
	check(0, 0, params.MainnetGenesisHash, false)
	check(0, 0, params.SepoliaGenesisHash, false)
	check(0, 1, params.MainnetGenesisHash, false)
	check(0, 1, params.SepoliaGenesisHash, false)

	// Bit1 shouldn't be affect.
	check(1, 0, params.MainnetGenesisHash, true)
	check(1, 0, params.SepoliaGenesisHash, true)
	check(1, 1, params.MainnetGenesisHash, true)
	check(1, 1, params.SepoliaGenesisHash, true)
}
