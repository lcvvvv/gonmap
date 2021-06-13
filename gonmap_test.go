package gonmap

import (
	"fmt"
	"testing"
	"time"
)

func TestPortscan(t *testing.T) {
	fmt.Println(PortScan("www.baidu.com:4433", 2*time.Second))

}

func TestGonmap(t *testing.T) {

}
