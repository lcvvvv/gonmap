package gonmap

import (
	"fmt"
	"kscan/lib/ping"
	"time"
)

func HostDiscovery(ip string) (online bool) {
	online = ping.Check(ip)
	if online {
		return true
	}
	online = tcpCheck(ip)
	if online {
		return true
	}
	return false
}

func HostDiscoveryIcmp(ip string) (online bool) {
	online = ping.Check(ip)
	if online {
		return true
	}
	return false
}

func tcpCheck(ip string) bool {
	tcpArr := []int{21, 22, 23, 80, 443, 445, 8080, 3389}
	for _, port := range tcpArr {
		netloc := fmt.Sprintf("%s:%d", ip, port)
		online := PortScan("tcp", netloc, time.Second*2)
		if online {
			return true
		}
	}
	return false
}
