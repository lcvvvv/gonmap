package gonmap

import (
	"context"
	"time"
)

func GetTcpBanner(ip string, port int, nmap *Nmap, timeout time.Duration) *TcpBanner {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resChan := make(chan *TcpBanner)
	go func() {
		var r TcpBanner
		defer func() {
			if err := recover(); err != nil {
				if &r != nil {
					if r.Response.Length() > 0 {
						logger.Printf("Target:%s:%d, get tcpBanner is error:%v, response length is:%d",
							ip, port, err, r.Response.Length())
					}
				}
			}
		}()
		r = nmap.Scan(ip, port)
		resChan <- &r
	}()

	for {
		select {
		case <-ctx.Done():
			close(resChan)
			banner := NewTcpBanner(ip, port)
			return banner.CLOSED()
		case res := <-resChan:
			close(resChan)
			return res
		}
	}
}
