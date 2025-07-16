package columnStore

import (
	"context"
	"os"
	"strings"
	"time"

	// "crypto/tls"
	"fmt"
	"log"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/ethereum/go-ethereum/common"
)

func test_connect() {
	conn, err := connect()
	if err != nil {
		panic((err))
	}

	ctx := context.Background()
	rows, err := conn.Query(ctx, "SELECT name,toString(uuid) as uuid_str FROM system.tables LIMIT 5")
	if err != nil {
		log.Fatal(err)
	}

	for rows.Next() {
		var (
			name, uuid string
		)
		if err := rows.Scan(
			&name,
			&uuid,
		); err != nil {
			log.Fatal(err)
		}
		log.Printf("name: %s, uuid: %s",
			name, uuid)
	}
}

func connect() (driver.Conn, error) {
	var (
		ctx       = context.Background()
		conn, err = clickhouse.Open(&clickhouse.Options{
			Addr: []string{"127.0.0.1:9000"},
			Auth: clickhouse.Auth{
				Database: "default",
				Username: "default",
				Password: "",
			},
			ClientInfo: clickhouse.ClientInfo{
				Products: []struct {
					Name    string
					Version string
				}{
					{Name: "an-example-go-client", Version: "0.1"},
				},
			},

			Debugf: func(format string, v ...interface{}) {
				fmt.Printf(format, v)
			},
			Settings: clickhouse.Settings{
				"max_execution_time": 60,
			},
			Compression: &clickhouse.Compression{
				Method: clickhouse.CompressionLZ4,
			},
			// TLS: &tls.Config{
			// 	InsecureSkipVerify: true,
			// },
			BlockBufferSize: 10,
		})
	)

	if err != nil {
		return nil, err
	}

	if err := conn.Ping(ctx); err != nil {
		if exception, ok := err.(*clickhouse.Exception); ok {
			fmt.Printf("Exception [%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		}
		return nil, err
	}
	return conn, nil
}

func scan_tx_by_account_block_column_store(query_file_path string, output_file_path string, startBlockNum uint64, endBlockNum uint64) {
	conn, err := connect()
	if err != nil {
		panic((err))
	}

	// ouputfile
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
		token = strings.Trim(token, "\n")
		address := common.HexToAddress(token)
		addrs = append(addrs, address)
		addrNum++
	}

	ctx := context.Background()

	var totalLatency int64 = 0
	latencyFile.WriteString("id,latency(μs)\n")
	startTime := time.Now()
	for _, addr := range addrs {
		sql := fmt.Sprintf(`SELECT BlockNumber, hex(TxHash), hex(FromAddr), hex(ToAddr) 
			FROM test1.txn WHERE FromAddr=unhex(substring('%s', 3)) and BlockNumber >= %d and BlockNumber <= %d`,
			addr.Hex(), startBlockNum, endBlockNum)

		rows, err := conn.Query(ctx, sql)
		if err != nil {
			log.Fatal(err)
		}
		for rows.Next() {
			var (
				BlockNumber uint64
				TxHash      string
				FromAddr    string
				ToAddr      string
			)
			if err := rows.Scan(&BlockNumber, &TxHash, &FromAddr, &ToAddr); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("BlockNumber=%d,TxHash=%s,FromAddr=%s,ToAddr=%s\n", BlockNumber, TxHash, FromAddr, ToAddr)
		}
		rows.Close()
	}
	endTime := time.Now()
	totalQueries := len(addrs)
	duration := endTime.Sub(startTime).Seconds()
	qps := float64(totalQueries) / duration
	averageLatency := float64(totalLatency) / float64(totalQueries)

	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Total time: %.2f seconds\n", duration)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Average latency: %.2f μs\n", averageLatency)

	latencyFile.WriteString(fmt.Sprintf("Total queries: %d\n", totalQueries))
	latencyFile.WriteString(fmt.Sprintf("Total time: %.2f seconds\n", duration))
	latencyFile.WriteString(fmt.Sprintf("QPS: %.2f\n", qps))
	latencyFile.WriteString(fmt.Sprintf("Average latency: %.2f μs\n", averageLatency))
}

func Build_dataset_scan_tx_by_account_block_column_store(query_file_path string, output_file_path string, startBlockNum uint64, endBlockNum uint64) {
	conn, err := connect()
	if err != nil {
		panic((err))
	}

	// ouputfile
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
		token = strings.Trim(token, "\n")
		address := common.HexToAddress(token)
		addrs = append(addrs, address)
		addrNum++
	}

	ctx := context.Background()

	var totalLatency int64 = 0
	latencyFile.WriteString("id,latency(μs)\n")
	startTime := time.Now()
	for i, addr := range addrs {
		scan_sql := fmt.Sprintf(`SELECT BlockNumber, hex(TxHash), hex(FromAddr), hex(ToAddr) 
		FROM test1.txn WHERE FromAddr=unhex(substring('%s', 3)) and BlockNumber >= %d and BlockNumber <= %d`,
			addr.Hex(), startBlockNum, endBlockNum)

		singleStartTime := time.Now()
		rows, err := conn.Query(ctx, scan_sql)
		singleEndTime := time.Now()
		latency := singleEndTime.Sub(singleStartTime).Microseconds()
		latencyFile.WriteString(fmt.Sprintf("%d,%d\n", i, latency))
		totalLatency += latency

		if err != nil {
			log.Fatal(err)
		}
		rows.Close()
	}
	endTime := time.Now()
	totalQueries := len(addrs)
	duration := endTime.Sub(startTime).Seconds()
	qps := float64(totalQueries) / duration
	averageLatency := float64(totalLatency) / float64(totalQueries)

	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Total time: %.2f seconds\n", duration)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Average latency: %.2f μs\n", averageLatency)

	latencyFile.WriteString(fmt.Sprintf("Total queries: %d\n", totalQueries))
	latencyFile.WriteString(fmt.Sprintf("Total time: %.2f seconds\n", duration))
	latencyFile.WriteString(fmt.Sprintf("QPS: %.2f\n", qps))
	latencyFile.WriteString(fmt.Sprintf("Average latency: %.2f μs\n", averageLatency))
}
