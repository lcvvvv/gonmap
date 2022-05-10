package gonmap

import (
	"fmt"
	"github.com/lcvvvv/gonmap/lib/gorpc"
	"github.com/lcvvvv/gonmap/lib/shttp"
	"github.com/lcvvvv/gonmap/lib/urlparse"
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
	url := fmt.Sprintf("%s://%s", banner.TcpFinger.Service, banner.Target.URI())
	parse, _ := urlparse.Load(url)
	if banner.TcpFinger.Service == "ssl" {
		parse.Scheme = "https"
	}
	if banner.status == Unknown || banner.status == Open {
		if strings.Contains(banner.Response.string, "HTTP") {
			url = "http://" + banner.Target.URI()
			parse, _ = urlparse.Load(url)
		}
	}
	return getAppBanner(parse, banner)
}

func GetAppBannerFromUrlString(urlString string) *AppBanner {
	Url, err := urlparse.Load(urlString)
	if err != nil {
		logger.Println(err)
	}
	if Url.Scheme != "http" && Url.Scheme != "https" {
		banner := GetTcpBanner(Url.Netloc, Url.Port, New(), HttpTimeout*20)
		if banner == nil {
			return nil
		}
		if banner.status == Closed {
			return nil
		}
		return GetAppBannerFromTcpBanner(banner)
	}
	if Url.Port == 0 && Url.Scheme == "http" {
		Url.Port = 80
	}
	if Url.Port == 0 && Url.Scheme == "https" {
		Url.Port = 443
	}
	if Url.Port == 0 {
		Url.Port = 80
	}
	return getAppBanner(Url, nil)
}

func getAppBanner(url *urlparse.URL, tcpBanner *TcpBanner) *AppBanner {
	r := NewAppBanner()
	r.IPAddr = url.Netloc
	r.Port = url.Port
	r.Protocol = url.Scheme

	if tcpBanner != nil {
		r.LoadTcpBanner(tcpBanner)
		r.Protocol = tcpBanner.TcpFinger.Service
	}

	if url.Scheme == "http" || url.Scheme == "https" {
		if HttpPath != "" {
			url.Path = HttpPath
		}
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

	if r.Response == "" {
		r.Protocol = "unknown"
		r.SetInfo("MaybeProtocolIs :" + GuessProtocol(r.Port))
		r.AppDigest = "ResponseIsEmpty"
	}

	if r.StatusCode == ERROR_NOT_SUCH_HOST {
		return nil
	}

	if r.StatusCode == 0 && r.Response == "" {
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
		if strings.Contains(err.Error(), "no such host") {
			r.StatusCode = ERROR_NOT_SUCH_HOST
		}
		logger.Println(err.Error())
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
