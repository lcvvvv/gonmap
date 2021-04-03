package gonmap

import (
	"fmt"
	"testing"
)

func TestGonmap(t *testing.T) {
	Init()
	n := New()
	for i := 1; i <= 10000; i++ {
		fmt.Println("开始探测端口", i)
		n.Scan("113.240.241.82", i).Show()
	}
}
