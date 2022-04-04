package gonmap

import (
	"context"
	"fmt"
	"kscan/lib/urlparse"
	"time"
)

func GetTcpBanner(ip string, port int, nmap *Nmap, timeout time.Duration) *TcpBanner {
	netloc := fmt.Sprintf("%s:%d", ip, port)
	parse, err := urlparse.Load(netloc)
	if err != nil {
		logger.Println(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resChan := make(chan *TcpBanner)
	go func() {
		var r TcpBanner
		defer func() {
			if err := recover(); err != nil {
				if &r != nil {
					if r.Response.Length() > 0 {
						logger.Println(err, ",", parse.UnParse(), ",", r.status, ",response length is :", r.Response.Length())
					}
				}
			}
		}()
		r = nmap.Scan(parse.Netloc, parse.Port)
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
