package gonmap

import (
	"kscan/lib/gonmap/simplenet"
	"strings"
	"time"
)

func PortScan(netloc string, duration time.Duration) bool {
	result, err := simplenet.Send("tcp", netloc, "", duration, 0)
	if err == nil {
		return true
	}
	if len(result) > 0 {
		return true
	}
	if strings.Contains(err.Error(), "STEP1") {
		return false
	} else {
		return true
	}
}
