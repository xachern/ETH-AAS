package skiplist

import (
	"fmt"
	"testing"
)

func Test_find_prev(t *testing.T) {
	list := New(Int)
	list.Set(5, "five")
	list.Set(10, "ten")
	list.Set(12, "twelve")
	list.Set(15, "fifteen")
	list.Set(20, "twenty")

	// 测试 FindPrev
	key := 3
	elem := list.FindPrev(nil, key)
	if elem != nil {
		fmt.Printf("FindPrev: Key: %v, Value: %v\n", elem.Key(), elem.Value.(string))
	} else {
		fmt.Println("FindPrev: No element found")
	}

	key = 13
	elem = list.FindPrev(nil, key)
	if elem != nil {
		fmt.Printf("FindPrev: Key: %v, Value: %v\n", elem.Key(), elem.Value.(string))
	} else {
		fmt.Println("FindPrev: No element found")
	}

	key = 23
	elem = list.FindPrev(nil, key)
	if elem != nil {
		fmt.Printf("FindPrev: Key: %v, Value: %v\n", elem.Key(), elem.Value.(string))
	} else {
		fmt.Println("FindPrev: No element found")
	}
}
