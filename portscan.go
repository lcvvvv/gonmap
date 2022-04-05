package gonmap

import (
	"context"
	"fmt"
	"kscan/core/gonmap/lib/simplenet"
	"net"
	"strings"
	"time"
)

func PortScan(protocol string, addr string, port int, duration time.Duration) bool {
	netloc := fmt.Sprintf("%s:%d", addr, port)
	data := ""
	if port == 25 || port == 110 {
		data = "\n"
	}
	result, err := simplenet.Send(protocol, false, netloc, data, duration, 0)
	if err == nil {
		return true
	}
	if len(result) > 0 {
		return true
	}
	//将在建立连接环节失败的，标记为不存活
	if strings.Contains(err.Error(), "STEP1") {
		return false
	}
	if port == 25 || port == 110 {
		//特殊网络环境在Windows系统下110、25端口会被误识别为open，标记为不存活
		if strings.Contains(err.Error(), "forcibly closed by the remote host") {
			return false
		}
		if strings.Contains(err.Error(), "timeout STEP3:READ") {
			return false
		}
	}
	return true
}

func DnsScan(addr string) bool {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 7 * time.Second,
			}
			return d.DialContext(ctx, "udp", addr)
		},
	}
	_, err := r.LookupHost(context.Background(), "localhost")
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return false
		}
	}
	return true
}
