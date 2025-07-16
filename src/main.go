package main

import (
	"fmt"
	"log"
	"myeth/src/store"
	"os"
)

func main() {
	log_file, err := os.Create("log.txt")
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer log_file.Close()
	log.SetOutput(log_file)

	test_generate_path_store()

	// test_point_state_query_geth()
	// test_point_state_query_path_store()

	// test_range_state_query_path_store()
	// test_range_state_query_path_store_wo_versionlist()
	// test_range_query_geth_versionlist()
	// test_range_query_state_geth_naive()
	// test_range_state_query_path_store2_diff_start()

	// test_range_query_state_geth_naive_motivation_expr(startBlockNum)
	// test_query_txn_geth_naive_motivation_expr()

	// test_scan_tx_by_block_2m_pebbeldb_geth_naive()
	// test_scan_tx_by_account_block_2m_pebbeldb_geth()
}

// first start geth ipc
// only query changed account
func test_point_state_query_geth() {
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	ipc_path := base_dir + "/geth.ipc"

	var query_file_path string
	var output_file_path string
	query_type := 2 // 1: ancient, 2: recent
	cnt_type := "100"
	query_file_base_dir := "../tests/point_query_ancient_800000_recent_1200000_end_1370000_cnt_" + cnt_type + "/"
	if query_type == 1 {
		query_file_path = query_file_base_dir + "ancient_query.txt"
		output_file_path = query_file_base_dir + "ancient_geth.txt"
	} else {
		query_file_path = query_file_base_dir + "recent_query.txt"
		output_file_path = query_file_base_dir + "recent_geth.txt"
	}

	point_query_state_geth(ipc_path, query_file_path, output_file_path)
	fmt.Printf("output file: %v\n", output_file_path)
}

func test_point_storage_query_geth() {
	// 打开现有文件,不存在则报错
	f, err := os.OpenFile(store.Contract_address_file, os.O_RDONLY, 0)
	if err != nil {
		log.Fatalf("打开合约地址文件失败: %v", err)
	}
	store.Contract_address_file_handler = f

	base_dir := "~/4T_ETH/eth/eth_leveldb"
	ipc_path := base_dir + "/geth.ipc"

	query_file_path := store.Contract_address_file
	output_file_path := store.Contract_address_dir + "/geth.txt"

	point_query_storage_geth(ipc_path, query_file_path, output_file_path)
	fmt.Printf("output file: %v\n", output_file_path)
}

func test_range_storage_query_geth() {
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	ipc_path := base_dir + "/geth.ipc"

	test_dir := "~/code/geth/state_trie_traversal/tests/range_storage_query"
	query_file_path := test_dir + "/contract_blk_6w_cnt_100.txt"
	output_file_path := test_dir + "/100_monthly_geth.txt"

	startBlock := uint64(50000)
	endBlock := uint64(50000 + 216000)

	// query_file_path := test_dir + "/contract_blk_60003_cnt_1.txt"
	// output_file_path := test_dir + "/test_geth.txt"

	// // 1: weekly, 50400 block; 2: monthly, 216,000 block
	// startBlock := uint64(60003)
	// endBlock := uint64(60003 + 50400)

	range_query_storage_geth(ipc_path, query_file_path, output_file_path, startBlock, endBlock)
	fmt.Printf("output file: %v\n", output_file_path)
}

// generate path store
// only store changed account
func test_generate_path_store() {
	baseBlockNumber := uint64(0) // base snapshot, default is 0, set as the first block number
	startBlockNumber := uint64(60000)
	endBlockNumber := uint64(4000000)

	store.Contract_address_file_handler, _ = os.OpenFile(
		store.Contract_address_file,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0644,
	)
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	chaindata_path := base_dir + "/geth/chaindata"

	{
		dir_for_path_store := base_dir + "/geth/pure_state_trie"

		// os delete directory for testing
		err := os.RemoveAll(dir_for_path_store)
		if err != nil {
			fmt.Printf("Error deleting directory: %v\n", err)
		}
		store.Start_gen_path_store_leveldb_only_stateTrie(chaindata_path, dir_for_path_store, startBlockNumber, endBlockNumber, baseBlockNumber)
	}
}

func test_point_state_query_path_store() {
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	dir_for_path_store := base_dir + "/geth/currrent_path_store"
	proofdb_path := dir_for_path_store + "/proof_path_store"
	prev_block_triedb_path := dir_for_path_store + "/prevBlockTriedb"
	verionlist_db_path := dir_for_path_store + "/versionlistDB"

	var query_file_path string
	var output_file_path string
	query_type := 1 // 1: ancient, 2: recent
	cnt_type := "100"
	query_file_base_dir := "../tests/point_query_ancient_800000_recent_1200000_end_1370000_cnt_" + cnt_type + "/"
	if query_type == 1 {
		query_file_path = query_file_base_dir + "ancient_query.txt"
		output_file_path = query_file_base_dir + "ancient_ours.txt"
	} else {
		query_file_path = query_file_base_dir + "recent_query.txt"
		output_file_path = query_file_base_dir + "recent_ours.txt"
	}

	store.Start_point_state_query_proof_from_path_store_leveldb(
		proofdb_path, verionlist_db_path, prev_block_triedb_path,
		query_file_path, output_file_path)
	fmt.Printf("output file: %v\n", output_file_path)
}

func test_range_query_geth_versionlist() {
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	ipc_path := base_dir + "/geth.ipc"

	dir_for_path_store := base_dir + "/geth/currrent_path_store"
	verionlist_db_path := dir_for_path_store + "/versionlistDB"

	// path store only before 160w
	// weekyl report: 1000000, 1050000
	var startBlockNum uint64
	var endBlockNum uint64

	var query_file_path string
	var output_file_path string

	var range_type_str string

	account_types := []int{1, 2, 3} // 1: cold, 2: medium, 3: hot
	range_types := []int{1, 2}      // 1: weekly, 5w block; 2: monthly, 216,000 block
	for _, range_type := range range_types {
		for _, account_type := range account_types {
			query_file_cnt := 100
			max_query_num := 1000

			if range_type == 2 {
				startBlockNum = uint64(1000000)
				endBlockNum = uint64(1216000)
				range_type_str = "monthly"
			} else {
				startBlockNum = uint64(1000000)
				endBlockNum = uint64(1050000)
				range_type_str = "weekly"
			}

			// query_file_path := "../tests/query_naive.txt"
			// // query_file := "../tests/range_query_100_addrs_1912208_1912212.txt"
			// output_file_path := "../tests/range_result_since_1912212_geth_version_50k.txt"

			query_file_base_dir := "../tests/range_query_cnt_" + fmt.Sprintf("%d", query_file_cnt) + "/"
			if account_type == 3 {
				query_file_path = query_file_base_dir + "hot_account.txt"
				output_file_path = query_file_base_dir + "hot_" + range_type_str + "_geth_version.txt"
			} else if account_type == 2 {
				query_file_path = query_file_base_dir + "medium_account.txt"
				output_file_path = query_file_base_dir + "medium_" + range_type_str + "_geth_version.txt"
			} else {
				query_file_path = query_file_base_dir + "cold_account.txt"
				output_file_path = query_file_base_dir + "cold_" + range_type_str + "_geth_version.txt"
			}

			range_query_geth_with_versionlist(ipc_path, query_file_path, max_query_num, output_file_path, startBlockNum, endBlockNum, verionlist_db_path)
			fmt.Printf("output file: %v\n", output_file_path)
		}
	}
}
func test_range_query_state_geth_naive_motivation_expr(startBlockNum uint64) {
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	ipc_path := base_dir + "/geth.ipc"

	// path store only before 160w
	// weekly report: 1000000, 1050000
	// startBlockNum = uint64(2000000)
	endBlockNum := startBlockNum + 100

	// var query_file_path string
	var output_file_path string

	// query_file_path = "../tests/motivation.txt"
	output_file_path = "../tests/motivation_state_geth.txt"
	range_query_state_geth_naive_motivation_expr(ipc_path, output_file_path, startBlockNum, endBlockNum)
	fmt.Printf("Output file: %v\n", output_file_path)
}

func test_query_txn_geth_naive_motivation_expr() {
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	ipc_path := base_dir + "/geth.ipc"

	// path store only before 160w
	// weekly report: 1000000, 1050000
	startBlockNum := uint64(2000000)
	endBlockNum := uint64(2001000)

	// var query_file_path string
	output_file_path := "../tests/motivation_txn_geth.txt"

	query_file_path := "../tests/motivation_txn_query.txt"
	// account := "0xADD1b97948e1e8083B2806762B006197D9DABF2C"

	scan_tx_by_account_block_geth_motivation_expr(ipc_path, query_file_path, output_file_path, startBlockNum, endBlockNum)
	fmt.Printf("Output file: %v\n", output_file_path)
}

func test_range_query_state_geth_naive() {
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	ipc_path := base_dir + "/geth.ipc"

	var startBlockNum uint64
	var endBlockNum uint64

	var query_file_path string
	var output_file_path string

	var range_type_str string

	account_types := []int{1, 2, 3} // 1: cold, 2: medium, 3: hot
	range_types := []int{1, 2}      // 1: weekly, 5w block; 2: monthly, 216,000 block
	for _, range_type := range range_types {
		for _, account_type := range account_types {
			query_file_cnt := 100
			max_query_num := 1000

			if range_type == 2 {
				startBlockNum = uint64(1000000)
				endBlockNum = uint64(1216000)
				range_type_str = "monthly"
			} else {
				startBlockNum = uint64(1000000)
				endBlockNum = uint64(1050000)
				range_type_str = "weekly"
			}

			query_file_base_dir := "../tests/range_query_cnt_" + fmt.Sprintf("%d", query_file_cnt) + "/"
			if account_type == 3 {
				query_file_path = query_file_base_dir + "hot_account.txt"
				output_file_path = query_file_base_dir + "hot_" + range_type_str + "_geth_naive.txt"
			} else if account_type == 2 {
				query_file_path = query_file_base_dir + "medium_account.txt"
				output_file_path = query_file_base_dir + "medium_" + range_type_str + "_geth_naive.txt"
			} else {
				// query_file_path = query_file_base_dir + "cold_account.txt"
				query_file_path = query_file_base_dir + "cold_account.txt"
				output_file_path = query_file_base_dir + "cold_" + range_type_str + "_geth_naive.txt"
			}
			range_query_state_geth_naive(ipc_path, query_file_path, max_query_num, output_file_path, startBlockNum, endBlockNum)
			fmt.Printf("Output file: %v\n", output_file_path)
		}
	}

}
func test_range_state_query_path_store() {
	// base_dir := "~/4T_ETH/eth/eth_test2_hash_leveldb"
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	chaindata_path := base_dir + "/geth/chaindata"

	dir_for_path_store := base_dir + "/geth/currrent_path_store"
	proofdb_path := dir_for_path_store + "/proof_path_store"
	prev_block_triedb_path := dir_for_path_store + "/prevBlockTriedb"
	verionlist_db_path := dir_for_path_store + "/versionlistDB"

	var startBlockNum uint64
	var endBlockNum uint64

	var query_file_path string
	var output_file_path string

	var range_type_str string

	account_types := []int{3} // 1: cold, 2: medium, 3: hot
	range_types := []int{1}   // 1: weekly, 5w block; 2: monthly, 216,000 block; 3: yearly, 2592000 block
	for _, range_type := range range_types {
		for _, account_type := range account_types {
			query_file_cnt := 100
			max_query_num := 1000

			if range_type == 2 {
				startBlockNum = uint64(1000000)
				endBlockNum = uint64(1216000)
				range_type_str = "monthly"
			} else if range_type == 3 {
				startBlockNum = uint64(500000)
				endBlockNum = uint64(2200000)
				range_type_str = "yearly"
			} else {
				startBlockNum = uint64(2000000)
				endBlockNum = uint64(2050000)
				range_type_str = "weekly"
			}

			query_file_base_dir := "../tests/range_query_cnt_" + fmt.Sprintf("%d", query_file_cnt) + "/"
			if account_type == 3 {
				query_file_path = query_file_base_dir + "hot_account.txt"
				output_file_path = query_file_base_dir + "hot_" + range_type_str + "_ours.txt"
			} else if account_type == 2 {
				query_file_path = query_file_base_dir + "medium_account.txt"
				output_file_path = query_file_base_dir + "medium_" + range_type_str + "_ours.txt"
			} else {
				query_file_path = query_file_base_dir + "cold_account.txt"
				output_file_path = query_file_base_dir + "cold_" + range_type_str + "_ours.txt"
			}

			fmt.Printf("startBlockNum: %v, endBlockNum: %v\n", startBlockNum, endBlockNum)
			store.Start_range_state_query_from_path_store_leveldb(chaindata_path,
				proofdb_path, verionlist_db_path, prev_block_triedb_path,
				query_file_path, max_query_num, output_file_path,
				startBlockNum, endBlockNum)
			fmt.Printf("output file: %v\n", output_file_path)
		}
	}
}

func test_range_state_query_path_store2_diff_start() {
	// base_dir := "~/4T_ETH/eth/eth_test2_hash_leveldb"
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	chaindata_path := base_dir + "/geth/chaindata"

	dir_for_path_store := base_dir + "/geth/currrent_path_store"
	proofdb_path := dir_for_path_store + "/proof_path_store"
	prev_block_triedb_path := dir_for_path_store + "/prevBlockTriedb"
	verionlist_db_path := dir_for_path_store + "/versionlistDB"

	var startBlockNum uint64
	var endBlockNum uint64

	var query_file_path string
	var output_file_path string

	var range_type_str string

	account_types := []int{1}                                                                            // 1: cold, 2: medium, 3: hot
	range_types := []int{1}                                                                              // 1: weekly, 5w block; 2: monthly, 216,000 block; 3: yearly, 2592000 block
	start_blks := []uint64{400000, 600000, 800000, 1000000, 1200000, 1400000, 1600000, 1800000, 2000000} // 800k, 1m, 1.2m, 1.5m, 1.7m, 2m
	for _, account_type := range account_types {
		for _, start_blk := range start_blks {
			for _, range_type := range range_types {

				query_file_cnt := 100
				max_query_num := 1000

				if range_type == 2 {
					startBlockNum = uint64(start_blk)
					endBlockNum = startBlockNum + uint64(50000)
					range_type_str = "monthly"
				} else if range_type == 3 {
					startBlockNum = uint64(500000)
					endBlockNum = uint64(2200000)
					range_type_str = "yearly"
				} else {
					startBlockNum = uint64(start_blk)
					endBlockNum = startBlockNum + uint64(50000)
					range_type_str = "weekly"
				}

				query_file_base_dir := "../tests/range_query_cnt_" + fmt.Sprintf("%d", query_file_cnt) + "/"
				if account_type == 3 {
					query_file_path = query_file_base_dir + "hot_account.txt"
					output_file_path = query_file_base_dir + "hot_" + fmt.Sprint(startBlockNum) + range_type_str + "_ours.txt"
				} else if account_type == 2 {
					query_file_path = query_file_base_dir + "medium_account.txt"
					output_file_path = query_file_base_dir + "medium_" + fmt.Sprint(startBlockNum) + range_type_str + "_ours.txt"
				} else {
					query_file_path = query_file_base_dir + "cold_account.txt"
					output_file_path = query_file_base_dir + "cold_" + fmt.Sprint(startBlockNum) + range_type_str + "_ours.txt"
				}

				fmt.Printf("startBlockNum: %v, endBlockNum: %v\n", startBlockNum, endBlockNum)
				store.Start_range_state_query_from_path_store_leveldb(chaindata_path,
					proofdb_path, verionlist_db_path, prev_block_triedb_path,
					query_file_path, max_query_num, output_file_path,
					startBlockNum, endBlockNum)
				fmt.Printf("output file: %v\n", output_file_path)
			}
		}
	}
}

func test_range_state_query_path_store_wo_versionlist() {
	base_dir := "~/4T_ETH/eth/eth_leveldb"
	chaindata_path := base_dir + "/geth/chaindata"

	dir_for_path_store := base_dir + "/geth/currrent_path_store"
	proofdb_path := dir_for_path_store + "/proof_path_store"
	prev_block_triedb_path := dir_for_path_store + "/prevBlockTriedb"
	verionlist_db_path := dir_for_path_store + "/versionlistDB"

	// path store only before 160w
	// weekyl report: 1000000, 1050000
	var startBlockNum uint64
	var endBlockNum uint64

	var query_file_path string
	var output_file_path string

	var range_type_str string

	account_types := []int{1, 2, 3} // 1: cold, 2: medium, 3: hot
	range_types := []int{1, 2}      // 1: weekly, 5w block; 2: monthly, 216,000 block
	for _, range_type := range range_types {
		for _, account_type := range account_types {
			query_file_cnt := 100
			max_query_num := 1000

			if range_type == 2 {
				startBlockNum = uint64(1000000)
				endBlockNum = uint64(1216000)
				range_type_str = "monthly"
			} else {
				startBlockNum = uint64(1000000)
				endBlockNum = uint64(1050000)
				range_type_str = "weekly"
			}

			query_file_base_dir := "../tests/range_query_cnt_" + fmt.Sprintf("%d", query_file_cnt) + "/"
			if account_type == 3 {
				query_file_path = query_file_base_dir + "hot_account.txt"
				output_file_path = query_file_base_dir + "hot_" + range_type_str + "_wo_versionlist.txt"
			} else if account_type == 2 {
				query_file_path = query_file_base_dir + "medium_account.txt"
				output_file_path = query_file_base_dir + "medium_" + range_type_str + "_wo_versionlist.txt"
			} else {
				query_file_path = query_file_base_dir + "cold_account.txt"
				output_file_path = query_file_base_dir + "cold_" + range_type_str + "_wo_versionlist.txt"
			}

			store.Start_range_state_query_from_path_store_wo_versionlist_leveldb(chaindata_path,
				proofdb_path, verionlist_db_path, prev_block_triedb_path,
				query_file_path, max_query_num, output_file_path,
				startBlockNum, endBlockNum)
			fmt.Printf("output file: %v\n", output_file_path)
		}
	}
}

func test_scan_tx_by_block_2m_pebbeldb_geth_naive() {
	ipc_path := "~/4T_ETH/eth/eth_hash2m_pebbeldb/geth.ipc"
	// query_file := "../tests/random_query_1990000_2000000.txt"
	output_file_path := "../tests/range_geth_naive_1999000_2000000.txt"

	// weekly report, [Jul-25-2016, Aug-02-2016]
	startBlockNum := uint64(1950000)
	endBlockNum := uint64(2000000)

	// AvgTxAmount
	// TxCnt
	scan_tx_by_block_geth(ipc_path, output_file_path, startBlockNum, endBlockNum)
	fmt.Printf("output file: %v\n", output_file_path)
}
func test_scan_tx_by_account_block_2m_pebbeldb_geth() {
	ipc_path := "~/4T_ETH/eth/eth_hash2m_pebbeldb/geth.ipc"
	// query_file := "../tests/random_query_1990000_2000000.txt"
	query_file := "../tests/query_naive.txt"
	output_file_path := "../tests/range_geth_naive_1999000_2000000.txt"

	// block range: 1912208 - 2002207 = 100000
	// startBlockNum := uint64(1912208 + 1)
	// endBlockNum := uint64(2002207 - 1)
	// weekly report, [Jul-25-2016, Aug-02-2016]
	startBlockNum := uint64(1950000)
	endBlockNum := uint64(2000000)

	// AvgOutAmount
	// OutDegree
	scan_tx_by_account_block_geth(ipc_path, query_file, output_file_path, startBlockNum, endBlockNum)
	fmt.Printf("output file: %v\n", output_file_path)
}
