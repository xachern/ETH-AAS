package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"myeth/src/store"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

func point_query_state_geth(IPCPath string, query_file_path string, output_file_path string) {
	// 打开一个文件来保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	//read queries from file
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
		// token = addr,blocknumber\n
		token = strings.Trim(token, "\n")
		tokens := strings.Split(token, ",")
		if len(tokens) != 2 {
			log.Fatalf("Invalid query: %v", token)
		}
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

	// api of geth
	client, err := ethclient.Dial(IPCPath)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	var totalLatency int64 = 0 // 累计总延迟
	startTime := time.Now()

	for i, addr := range addrs {
		blocknum := blockNums[i]
		// get proof from geth
		blockNumBigInt := new(big.Int).SetUint64(blocknum)
		singleStartTime := time.Now()
		proof_result, err := client.GetProof(context.Background(), addr, nil, blockNumBigInt)
		singleEndTime := time.Now()
		if err != nil {
			log.Fatalf("Failed to get proof: %v", err)
		}
		_ = proof_result

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

func point_query_storage_geth(IPCPath string, query_file_path string, output_file_path string) {
	// 打开一个文件来保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	//read queries from file
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
		// token = addr,blocknumber\n
		token = strings.Trim(token, "\n")
		tokens := strings.Split(token, ",")
		if len(tokens) != 2 {
			log.Fatalf("Invalid query: %v", token)
		}
		// 去掉"0x"并将其转换为common.Address
		address := common.HexToAddress(tokens[0][2:])
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

	// api of geth
	client, err := ethclient.Dial(IPCPath)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	var totalLatency int64 = 0 // 累计总延迟
	startTime := time.Now()

	for i, addr := range addrs {
		blocknum := blockNums[i]
		// get proof from geth
		blockNumBigInt := new(big.Int).SetUint64(blocknum)
		storageKey := make([]string, 0)
		storageKey = append(storageKey, "0x0")
		singleStartTime := time.Now()
		proof_result, err := client.GetProof(context.Background(), addr, storageKey, blockNumBigInt)
		singleEndTime := time.Now()
		if err != nil {
			log.Fatalf("Failed to get proof: %v", err)
		}
		_ = proof_result

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

func range_query_storage_geth(IPCPath string, query_file_path string, output_file_path string, startBlock uint64, endBlock uint64) {
	// 打开一个文件来保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	//read queries from file
	query_file, err := os.Open(query_file_path)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer query_file.Close()
	var token string
	var addrNum int
	maxNum := 10000
	var addrs []common.Address
	for {
		_, err := fmt.Fscanln(query_file, &token)
		if err != nil {
			break
		}
		// token = addr,blocknumber\n
		token = strings.Trim(token, "\n")
		// 去掉"0x"并将其转换为common.Address
		address := common.HexToAddress(token[2:])
		addrs = append(addrs, address)

		// fmt.Printf("Parsed address: %s, block number: %d\n", address.Hex(), blockNum)

		addrNum++
		if addrNum >= maxNum {
			fmt.Printf("Read %d addresses\n", addrNum)
			break
		}
	}

	// api of geth
	client, err := ethclient.Dial(IPCPath)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	var totalLatency int64 = 0 // 累计总延迟
	startTime := time.Now()

	for i, addr := range addrs {
		// get proof from geth
		storageKey := make([]string, 0)
		storageKey = append(storageKey, "0x0")
		singleStartTime := time.Now()
		for blockNum := startBlock; blockNum <= endBlock; blockNum++ {
			blockNumBigInt := new(big.Int).SetUint64(blockNum)
			client.GetProof(context.Background(), addr, storageKey, blockNumBigInt)
		}
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

func Fetch_accounts_of_block_geth(client *ethclient.Client, blockNumber uint64) []common.Address {
	selected_block, err := client.BlockByNumber(context.Background(), new(big.Int).SetUint64(blockNumber))
	if err != nil {
		log.Fatalf("Failed to read block %v: %v", blockNumber, err)
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

func range_query_state_geth_naive_motivation_expr(IPCPath string, output_file_path string,
	startBlockNum uint64, endBlockNum uint64) {

	// ouputfile, 保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	// api of geth
	client, err := ethclient.Dial(IPCPath)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	var totalQueries int64 = 0
	var totalLatency int64 = 0 // 累计总延迟
	var totalProofSize int64 = 0
	var totalResultSize int64 = 0
	latencyFile.WriteString("id,latency(μs),proofSize(byte),resultSize(byte),totalSize(byte)\n")
	startTime := time.Now()

	for blockNumber := startBlockNum; blockNumber <= endBlockNum; blockNumber++ {
		addrs := Fetch_accounts_of_block_geth(client, blockNumber)
		log.Default().Printf("Block %d, %d accounts\n", blockNumber, len(addrs))
		for _, addr := range addrs {
			singleStartTime := time.Now()
			blockNumBigInt := new(big.Int).SetUint64(blockNumber)
			proof, err := client.GetProof(context.Background(), addr, nil, blockNumBigInt)
			singleEndTime := time.Now()
			if err != nil {
				log.Fatalf("Failed to get proof: %v", err)
			}

			latency := singleEndTime.Sub(singleStartTime).Microseconds()

			ProofSize := 0
			ResultSize := 0
			for _, stateProof := range proof.AccountProof {
				ProofSize += len(stateProof) // Adjust based on actual struct fields
			}
			// Nonce is uint64 (8 bytes)
			ResultSize += 8
			// Balance is *big.Int (convert to bytes)
			if proof.Balance != nil {
				ResultSize += len(proof.Balance.Bytes())
			}

			latencyFile.WriteString(fmt.Sprintf("%d,%v,%d,%d,%d\n", blockNumber, latency, ProofSize, ResultSize, ProofSize+ResultSize))
			totalLatency += latency
			totalProofSize += int64(ProofSize)
			totalResultSize += int64(ResultSize)

			totalQueries += 1
		}
	}
	fmt.Printf("\n")

	endTime := time.Now()
	duration := endTime.Sub(startTime).Seconds() // 以秒为单位的时间差
	qps := float64(totalQueries) / duration      // 计算QPS
	averageLatency := float64(totalLatency) / float64(totalQueries)

	// 输出结果
	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Total time: %.2f seconds\n", duration)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Average latency: %.2f μs\n", averageLatency)
	fmt.Printf("Total proof size: %d bytes\n", totalProofSize)
	fmt.Printf("Total result size: %d bytes\n", totalResultSize)
	fmt.Printf("Total size: %d bytes\n", totalProofSize+totalResultSize)

	// 输出到文件
	latencyFile.WriteString(fmt.Sprintf("Total queries: %d\n", totalQueries))
	latencyFile.WriteString(fmt.Sprintf("Total time: %.2f seconds\n", duration))
	latencyFile.WriteString(fmt.Sprintf("QPS: %.2f\n", qps))
	latencyFile.WriteString(fmt.Sprintf("Average latency: %.2f μs\n", averageLatency))
	latencyFile.WriteString(fmt.Sprintf("Total proof size: %d bytes\n", totalProofSize))
	latencyFile.WriteString(fmt.Sprintf("Total result size: %d bytes\n", totalResultSize))
	latencyFile.WriteString(fmt.Sprintf("Total size: %d bytes\n", totalProofSize+totalResultSize))
}

func range_query_state_geth_naive(IPCPath string, query_file_path string, max_query_num int, output_file_path string,
	startBlockNum uint64, endBlockNum uint64) {

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

	// api of geth
	client, err := ethclient.Dial(IPCPath)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	var totalLatency int64 = 0 // 累计总延迟
	latencyFile.WriteString("id,latency(μs)\n")
	startTime := time.Now()

	for i, addr := range addrs {
		fmt.Printf("\rStart Query %d/%d", i, len(addrs))

		singleStartTime := time.Now()
		proof_result := range_query_geth_internal_naive(client, addr, startBlockNum, endBlockNum)
		singleEndTime := time.Now()
		_ = proof_result

		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d,%v\n", i, latency))
		totalLatency += latency
	}
	fmt.Printf("\n")

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

func scan_tx_by_account_block_geth_motivation_expr(IPCPath string, query_file_path string, output_file_path string,
	startBlockNum uint64, endBlockNum uint64) {
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
	for {
		_, err := fmt.Fscanln(query_file, &token)
		if err != nil {
			break
		}
		// token = addr,blocknumber\n
		token = strings.Trim(token, "\n")
		tokens := strings.Split(token, ",")

		// 去掉"0x"并将其转换为common.Address
		address := common.HexToAddress(tokens[0])
		addrs = append(addrs, address)

		// fmt.Printf("Parsed address: %s, block number: %d\n", address.Hex(), blockNum)

		addrNum++
		if addrNum >= maxNum {
			fmt.Printf("Read %d addresses\n", addrNum)
			break
		}
	}

	// api of geth
	client, err := ethclient.Dial(IPCPath)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	var totalLatency int64 = 0 // 累计总延迟
	var totalResultSize uint64 = 0

	startTime := time.Now()

	for i, addr := range addrs {
		singleStartTime := time.Now()
		// avgOutAmount := scan_tx_by_account_block_AvgOutAmount_geth_internal(client, addr, startBlockNum, endBlockNum)
		// singleEndTime := time.Now()
		// _ = avgOutAmount
		txs := scan_tx_by_account_block_OutDegree_geth_motivation_expr_internal(client, addr, startBlockNum, endBlockNum)
		singleEndTime := time.Now()

		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d,%v\n", i, latency))
		totalLatency += latency

		resultSize := uint64(0)
		for _, tx := range txs {
			resultSize += tx.Size() // Adjust based on actual struct fields
		}
		totalResultSize += resultSize
	}
	fmt.Printf("\n")

	endTime := time.Now()
	totalQueries := endBlockNum - startBlockNum + 1
	duration := endTime.Sub(startTime).Seconds() // 以秒为单位的时间差
	qps := float64(totalQueries) / duration      // 计算QPS
	averageLatency := float64(totalLatency) / float64(totalQueries)

	// 输出结果
	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Total time: %.2f seconds\n", duration)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Average latency: %.2f μs\n", averageLatency)
	fmt.Printf("Total size: %d bytes\n", totalResultSize)

	// 输出到文件
	latencyFile.WriteString(fmt.Sprintf("Total queries: %d\n", totalQueries))
	latencyFile.WriteString(fmt.Sprintf("Total time: %.2f seconds\n", duration))
	latencyFile.WriteString(fmt.Sprintf("QPS: %.2f\n", qps))
	latencyFile.WriteString(fmt.Sprintf("Average latency: %.2f μs\n", averageLatency))
	latencyFile.WriteString(fmt.Sprintf("Total result size: %d bytes\n", totalResultSize))

	fmt.Printf("Output file: %v\n", output_file_path)
}

func scan_tx_by_account_block_geth(IPCPath string, query_file_path string, output_file_path string,
	startBlockNum uint64, endBlockNum uint64) {
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
	for {
		_, err := fmt.Fscanln(query_file, &token)
		if err != nil {
			break
		}
		// token = addr,blocknumber\n
		token = strings.Trim(token, "\n")
		tokens := strings.Split(token, ",")

		// 去掉"0x"并将其转换为common.Address
		address := common.HexToAddress(tokens[0])
		addrs = append(addrs, address)

		// fmt.Printf("Parsed address: %s, block number: %d\n", address.Hex(), blockNum)

		addrNum++
		if addrNum >= maxNum {
			fmt.Printf("Read %d addresses\n", addrNum)
			break
		}
	}

	// api of geth
	client, err := ethclient.Dial(IPCPath)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	var totalLatency int64 = 0 // 累计总延迟
	startTime := time.Now()

	for i, addr := range addrs {
		singleStartTime := time.Now()
		// avgOutAmount := scan_tx_by_account_block_AvgOutAmount_geth_internal(client, addr, startBlockNum, endBlockNum)
		// singleEndTime := time.Now()
		// _ = avgOutAmount
		outDegree := scan_tx_by_account_block_OutDegree_geth_internal(client, addr, startBlockNum, endBlockNum)
		singleEndTime := time.Now()
		_ = outDegree

		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d,%v\n", i, latency))
		totalLatency += latency

		fmt.Printf("\rQuery %d/%d", i, len(addrs))
	}
	fmt.Printf("\n")

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

	fmt.Printf("Output file: %v\n", output_file_path)
}

func scan_tx_by_block_geth(IPCPath string, output_file_path string,
	startBlockNum uint64, endBlockNum uint64) {
	// ouputfile, 保存每个查询的延迟
	latencyFile, err := os.Create(output_file_path) // create or overwrite if exists
	if err != nil {
		log.Fatalf("Failed to create latency file: %v", err)
	}
	defer latencyFile.Close()

	// api of geth
	client, err := ethclient.Dial(IPCPath)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	var totalLatency int64 = 0 // 累计总延迟
	startTime := time.Now()
	singleStartTime := time.Now()

	cnt := scan_tx_by_block_TxCnt_geth_internal(client, startBlockNum, endBlockNum)
	_ = cnt
	// avgAmount := scan_tx_by_block_AvgTxAmount_geth_internal(client, startBlockNum, endBlockNum)
	// _ = avgAmount
	singleEndTime := time.Now()

	latency := singleEndTime.Sub(singleStartTime).Microseconds()
	latencyFile.WriteString(fmt.Sprintf("%v\n", latency))
	totalLatency += latency

	endTime := time.Now()
	totalQueries := 1
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

func range_query_geth_with_versionlist(IPCPath string,
	query_file_path string, max_query_num int,
	output_file_path string,
	startBlockNum uint64, endBlockNum uint64,
	verionlistDBPath string) {

	versionlistDB, err := rawdb.NewPebbleDBDatabase(verionlistDBPath, 10240, 100, "", false, false)
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

	// api of geth
	client, err := ethclient.Dial(IPCPath)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	defer client.Close()

	var totalLatency int64 = 0 // 累计总延迟
	latencyFile.WriteString("id,latency(μs),versionLen\n")
	startTime := time.Now()

	for i, addr := range addrs {
		singleStartTime := time.Now()
		proof_result := range_query_geth_internal_versionlist(client, addr, startBlockNum, endBlockNum, versionlistDB)
		singleEndTime := time.Now()
		_ = proof_result

		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d,%v,%d\n", i, latency, len(proof_result)))
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

func scan_tx_by_account_block_OutDegree_geth_motivation_expr_internal(client *ethclient.Client, account common.Address,
	startBlockNumber uint64, endBlockNumber uint64) []*types.Transaction {
	tasks := make([]uint64, endBlockNumber-startBlockNumber+1)
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		tasks = append(tasks, i)
	}
	// get txs from geth
	txs := make([]*types.Transaction, 0)
	for _, blockNumber := range tasks {
		blockNumBigInt := new(big.Int).SetUint64(blockNumber)
		block, err := client.BlockByNumber(context.Background(), blockNumBigInt)
		if err != nil {
			log.Fatalf("Failed to get block: %v", err)
		}
		chainConfig := params.MainnetChainConfig
		blockTime := block.Time()
		for _, tx := range block.Transactions() {
			// if tx.To() == nil {
			// 	TotalInAmount.Add(TotalInAmount, tx.Value())
			// }
			// get from address from signed
			signer := types.MakeSigner(chainConfig, new(big.Int).SetUint64(blockNumber), blockTime)
			from, err := types.Sender(signer, tx)
			if err != nil {
				log.Fatalf("Failed to get sender: %v", err)
			}
			if account.Cmp(from) == 0 {
				txs = append(txs, tx)
			}
		}
	}
	return txs
}

func scan_tx_by_account_block_OutDegree_geth_internal(client *ethclient.Client, account common.Address,
	startBlockNumber uint64, endBlockNumber uint64) int {
	tasks := make([]uint64, endBlockNumber-startBlockNumber+1)
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		tasks = append(tasks, i)
	}
	// get txs from geth
	OutDegree := 0
	for _, blockNumber := range tasks {
		blockNumBigInt := new(big.Int).SetUint64(blockNumber)
		block, err := client.BlockByNumber(context.Background(), blockNumBigInt)
		if err != nil {
			log.Fatalf("Failed to get block: %v", err)
		}
		chainConfig := params.MainnetChainConfig
		blockTime := block.Time()
		for _, tx := range block.Transactions() {
			// if tx.To() == nil {
			// 	TotalInAmount.Add(TotalInAmount, tx.Value())
			// }
			// get from address from signed
			signer := types.MakeSigner(chainConfig, new(big.Int).SetUint64(blockNumber), blockTime)
			from, err := types.Sender(signer, tx)
			if err != nil {
				log.Fatalf("Failed to get sender: %v", err)
			}
			if account.Cmp(from) == 0 {
				OutDegree++
			}
		}
	}
	return OutDegree
}

func scan_tx_by_account_block_AvgOutAmount_geth_internal(client *ethclient.Client, account common.Address,
	startBlockNumber uint64, endBlockNumber uint64) *big.Int {
	tasks := make([]uint64, endBlockNumber-startBlockNumber+1)
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		tasks = append(tasks, i)
	}
	// get txs from geth
	TotalOutAmount := new(big.Int)
	cnt := 0
	for _, blockNumber := range tasks {
		blockNumBigInt := new(big.Int).SetUint64(blockNumber)
		block, err := client.BlockByNumber(context.Background(), blockNumBigInt)
		if err != nil {
			log.Fatalf("Failed to get block: %v", err)
		}
		cnt += len(block.Transactions())
		chainConfig := params.MainnetChainConfig
		blockTime := block.Time()
		for _, tx := range block.Transactions() {
			// if tx.To() == nil {
			// 	TotalInAmount.Add(TotalInAmount, tx.Value())
			// }
			// get from address from signed
			signer := types.MakeSigner(chainConfig, new(big.Int).SetUint64(blockNumber), blockTime)
			from, err := types.Sender(signer, tx)
			if err != nil {
				log.Fatalf("Failed to get sender: %v", err)
			}
			if account.Cmp(from) == 0 {
				TotalOutAmount.Add(TotalOutAmount, tx.Value())
			}
		}
	}
	avgOutAmount := new(big.Int).Div(TotalOutAmount, big.NewInt(int64(cnt)))
	return avgOutAmount
}

func scan_tx_by_block_TxCnt_geth_internal(client *ethclient.Client, startBlockNumber uint64, endBlockNumber uint64) int {
	tasks := make([]uint64, endBlockNumber-startBlockNumber+1)
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		tasks = append(tasks, i)
	}
	// get txs from geth
	cnt := 0
	for _, blockNumber := range tasks {
		blockNumBigInt := new(big.Int).SetUint64(blockNumber)
		block, err := client.BlockByNumber(context.Background(), blockNumBigInt)
		if err != nil {
			log.Fatalf("Failed to get block: %v", err)
		}
		cnt += len(block.Transactions())
	}
	return cnt
}

func scan_tx_by_block_AvgTxAmount_geth_internal(client *ethclient.Client, startBlockNumber uint64, endBlockNumber uint64) *big.Int {
	tasks := make([]uint64, endBlockNumber-startBlockNumber+1)
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		tasks = append(tasks, i)
	}
	// get txs from geth
	TotalAmount := new(big.Int)
	cnt := 0
	for _, blockNumber := range tasks {
		blockNumBigInt := new(big.Int).SetUint64(blockNumber)
		block, err := client.BlockByNumber(context.Background(), blockNumBigInt)
		if err != nil {
			log.Fatalf("Failed to get block: %v", err)
		}
		cnt += len(block.Transactions())
		for _, tx := range block.Transactions() {
			TotalAmount.Add(TotalAmount, tx.Value())
		}
	}
	avgAmount := new(big.Int).Div(TotalAmount, big.NewInt(int64(cnt)))
	return avgAmount
}
func range_query_geth_internal_naive(client *ethclient.Client, account common.Address,
	startBlockNumber uint64, endBlockNumber uint64) map[uint64]*ethclient.AccountResult {

	tasks := make([]uint64, endBlockNumber-startBlockNumber+1)
	for i := startBlockNumber; i <= endBlockNumber; i++ {
		tasks = append(tasks, i)
	}

	// get account state proof from geth
	proofs := make(map[uint64]*ethclient.AccountResult, len(tasks))
	for _, blockNumber := range tasks {
		blockNumBigInt := new(big.Int).SetUint64(blockNumber)
		proof_result, err := client.GetProof(context.Background(), account, nil, blockNumBigInt)
		if err != nil {
			log.Fatalf("Failed to get proof: %v", err)
		}
		proofs[blockNumber] = proof_result //no deep copy
	}
	return proofs
}

func range_query_geth_internal_versionlist(client *ethclient.Client, account common.Address,
	startBlockNumber uint64, endBlockNumber uint64,
	verionlistDB ethdb.Database) map[uint64]*ethclient.AccountResult {

	// read skiplist
	versionList := store.ReadVersionList(account, verionlistDB)

	fast_tasks, err := versionList.GetBoundingVersions(startBlockNumber, endBlockNumber)
	if err != nil {
		// fetch all versions for testing
		version_num := versionList.Cardinality()
		min_version := versionList.MinVersion()
		max_version := versionList.MaxVersion()
		log.Printf("VersionList len: %d, min: %d, max: %d", version_num, min_version, max_version)

		log.Fatalf("Failed to get bounding versions: %v", err)
		return nil
	}

	var slow_tasks []uint64
	if len(fast_tasks) == 0 {
		slow_tasks = append(slow_tasks, startBlockNumber)
		slow_tasks = append(slow_tasks, endBlockNumber)
	} else {
		if fast_tasks[0] > startBlockNumber {
			slow_tasks = append(slow_tasks, startBlockNumber)
		}
		if fast_tasks[len(fast_tasks)-1] < endBlockNumber {
			slow_tasks = append(slow_tasks, endBlockNumber)
		}
	}

	tasks := append(fast_tasks, slow_tasks...)

	// get proof from geth
	proofs := make(map[uint64]*ethclient.AccountResult, len(tasks))
	for _, blockNumber := range tasks {
		blockNumBigInt := new(big.Int).SetUint64(blockNumber)
		proof_result, err := client.GetProof(context.Background(), account, nil, blockNumBigInt)
		if err != nil {
			log.Fatalf("Failed to get proof at block %d: %v", blockNumber, err)
		}
		proofs[blockNumber] = proof_result //no deep copy
	}
	return proofs
}
