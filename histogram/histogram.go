package histogram

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
)

type BucketType interface {
	~string | ~int | ~int64
	constraints.Ordered
}

type Histogram[T BucketType] struct {
	title   string
	buckets map[T]int64
	total   int64
}

func New[T BucketType](title string) *Histogram[T] {
	return &Histogram[T]{
		title:   title,
		buckets: map[T]int64{},
	}
}

func (h *Histogram[T]) Observe(bucket T) {
	h.buckets[bucket]++
	h.total++
}

func (h *Histogram[T]) Print(w io.Writer) {
	fmt.Printf("%s (top 3):\n", h.title)
	sortedKeys := h.sortedKeys()
	len := len(sortedKeys)
	if len > 100 {
		len = 100
	}
	for i, k := range sortedKeys[:len] {
		ratio := float64(h.buckets[k]) / float64(h.total) * 100
		// if ratio < 1 { //less than 1%
		// 	continue
		// }
		fmt.Fprintf(w, "%v: %.02f%% (%d)\n", k, ratio, h.buckets[k])

		if i == 2 {
			break
		}
	}
	fmt.Println()
}

func (h *Histogram[T]) PrintAverage(w io.Writer) {
	// check T is int or int64
	isInt := false
	isInt64 := false
	if _, ok := any(T(0)).(int); ok {
		isInt = true
	}
	if _, ok := any(T(0)).(int64); ok {
		isInt64 = true
	}
	if !isInt && !isInt64 {
		log.Println("Histogram: PrintAverage only supports int or int64 types")
		return
	}

	fmt.Printf("%s:\n", h.title)
	sortedKeys := h.sortedKeys()
	len := len(sortedKeys)
	if len > 100 {
		len = 100
	}
	var average float64
	for _, k := range sortedKeys[:len] {
		if isInt {
			average += float64(any(k).(int)) * float64(h.buckets[k]) / float64(h.total)
		} else if isInt64 {
			average += float64(any(k).(int64)) * float64(h.buckets[k]) / float64(h.total)
		}
	}
	fmt.Fprintf(w, "Average: %.02f\n", average)
	fmt.Println()
}

// func (h *Histogram[T]) PrintIntAverage(w io.Writer) {
// 	// check T is int
// 	fmt.Printf("%s:\n", h.title)
// 	sortedKeys := h.sortedKeys()
// 	len := len(sortedKeys)
// 	if len > 100 {
// 		len = 100
// 	}
// 	var average float64
// 	for _, k := range sortedKeys[:len] {
// 		average += float64(k) * float64(h.buckets[k]) / float64(h.total)
// 	}
// 	fmt.Fprintf(w, "Average: %.02f\n", average)
// 	fmt.Println()
// }

func (h *Histogram[T]) ToCSV(filename string) error {
	var sb strings.Builder
	for _, k := range h.sortedKeys() {
		ratio := float64(h.buckets[k]) / float64(h.total) * 100
		if ratio < 0.01 {
			continue
		}
		sb.WriteString(fmt.Sprintf("%v,%.02f,%d\n", k, ratio, h.buckets[k]))
	}
	if err := os.WriteFile(filename, []byte(sb.String()), 0o755); err != nil {
		return fmt.Errorf("writing to file: %s", err)
	}
	log.Printf("saved %s\n", filename)

	return nil
}

func (h *Histogram[T]) sortedKeys() []T {
	var keys []T
	for k := range h.buckets {
		keys = append(keys, k)
	}
	// slices.SortFunc(keys, func(a, b T) bool {
	// 	return h.buckets[a] > h.buckets[b]
	// })
	// Adjust comparison function to return an int (positive, zero, negative)
	slices.SortFunc(keys, func(a, b T) int {
		if h.buckets[a] > h.buckets[b] {
			return -1 // Sort in descending order
		} else if h.buckets[a] < h.buckets[b] {
			return 1
		}
		return 0
	})
	return keys
}
