package gonmap

import (
	"fmt"
	"kscan/lib/gonmap/shttp"
	"kscan/lib/gorpc"
	"kscan/lib/slog"
	"kscan/lib/urlparse"
	"strings"
	"time"
)

var (
	HttpHost    = ""
	HttpPath    = ""
	HttpTimeout = 5 * time.Second
)

func InitAppBannerDiscernConfig(host, path, proxy string, timeout time.Duration) {
	HttpHost = host
	HttpPath = path
	HttpTimeout = timeout
	shttp.InitSHttp(host, proxy, timeout)
}

func GetAppBannerFromTcpBanner(banner *TcpBanner) *AppBanner {
	url := fmt.Sprintf("%s://%s", banner.TcpFinger.Service, banner.Target.uri)
	parse, _ := urlparse.Load(url)
	if banner.TcpFinger.Service == "ssl" {
		parse.Scheme = "https"
		if HttpPath != "" {
			parse.Path = HttpPath
		}
	} else if strings.Contains(banner.Response.string, "HTTP") {
		url = "http://" + banner.Target.uri
		parse, _ := urlparse.Load(url)
		if HttpPath != "" {
			parse.Path = HttpPath
		}
	}
	return getAppBanner(parse, banner)
}

func GetAppBannerFromUrl(url *urlparse.URL) *AppBanner {
	if url.Scheme != "http" && url.Scheme != "https" {
		netloc := fmt.Sprintf("%s:%d", url.Netloc, url.Port)
		banner := GetTcpBanner(netloc, New(), HttpTimeout*20)
		if banner == nil {
			return nil
		}
		if banner.Status == Closed {
			return nil
		}
		return GetAppBannerFromTcpBanner(banner)
	}

	if url.Port == 0 && url.Scheme == "" {
		url.Port = 80
		url.Scheme = "http"
	}
	if url.Port == 0 && url.Scheme == "https" {
		url.Port = 443
	}
	if url.Port == 0 {
		url.Port = 80
	}
	return getAppBanner(url, nil)
}

func getAppBanner(url *urlparse.URL, tcpBanner *TcpBanner) *AppBanner {
	r := NewAppBanner()
	r.IPAddr = url.Netloc
	r.Port = url.Port
	r.Protocol = url.Scheme

	if tcpBanner != nil {
		r.LoadTcpBanner(tcpBanner)
	}

	if url.Scheme == "http" || url.Scheme == "https" {
		httpFinger := getHttpFinger(url, false)
		//若请求不成功则进行多处
		retry := 3
		for i := 1; i < retry; i++ {
			if httpFinger.StatusCode == 0 {
				time.Sleep(time.Second * 10)
				httpFinger = getHttpFinger(url, false)
			} else {
				break
			}
		}
		r.LoadHttpFinger(httpFinger)
	}

	if url.Scheme == "rpc" || url.Scheme == "dcerpc" {
		url.Scheme = "rpc"
		r.Protocol = "rpc"
		RpcFinger, _ := gorpc.GetFinger(url.Netloc)
		if RpcFinger != nil {
			r.LoadRpcFinger(RpcFinger)
		}
	}

	if url.Scheme == "rdp" {
		//todo
	}

	if r.StatusCode == 0 {
		return nil
	}

	if r.Response == "" {
		return nil
	}

	return r
}

func getHttpFinger(url *urlparse.URL, loop bool) *HttpFinger {
	r := NewHttpFinger(url)
	resp, err := shttp.Get(url.UnParse())
	if err != nil {
		if loop == true {
			return r
		}
		if strings.Contains(err.Error(), "server gave HTTP response") {
			//HTTP协议重新获取指纹
			if url.Scheme == "http" && url.Port == 80 {
				url.Scheme = "https"
				url.Port = 443
			} else {
				url.Scheme = "http"
			}
			return getHttpFinger(url, true)
		}
		if strings.Contains(err.Error(), "malformed HTTP response") {
			//HTTPS协议重新获取指纹
			url.Scheme = "https"
			return getHttpFinger(url, true)
		}
		slog.Debug(err.Error())
		return r
	}
	//if strings.Contains(getResponse(shttp.GetBody(resp)), "The plain HTTP request was sent to HTTPS port") {
	//	//HTTPS协议重新获取指纹
	//	url.Scheme = "https"
	//	return getHttpFinger(url, true)
	//}
	if url.Scheme == "https" {
		r.LoadCert(resp)
	}
	r.LoadHttpResponse(url, resp)
	return r
}
