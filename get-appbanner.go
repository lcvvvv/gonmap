package gonmap

import (
	"fmt"
	"github.com/lcvvvv/urlparse"
	"kscan/lib/gonmap/shttp"
	"kscan/lib/slog"
	"strings"
)

func GetAppBannerFromTcpBanner(banner *TcpBanner) *AppBanner {
	var appBanner = NewAppBanner()
	var url string
	if banner.TcpFinger.Service == "http" || banner.TcpFinger.Service == "https" {
		url = fmt.Sprintf("%s://%s", banner.TcpFinger.Service, banner.Uri)
		parse, _ := urlparse.Load(url)
		appBanner = getAppBanner(parse)
		appBanner.LoadTcpBanner(banner)
		if appBanner.Response == "" {
			return nil
		}
		return appBanner
	}
	if banner.TcpFinger.Service == "ssl" && strings.Contains(banner.Response.string, "HTTP") {
		url = fmt.Sprintf("https://%s", banner.Uri)
		parse, _ := urlparse.Load(url)
		appBanner = getAppBanner(parse)
		appBanner.LoadTcpBanner(banner)
		if appBanner.Response == "" {
			return nil
		}
		return appBanner
	}
	if strings.Contains(banner.Response.string, "HTTP") {
		url = "http://" + banner.Uri
		parse, _ := urlparse.Load(url)
		appBanner = getAppBanner(parse)
		appBanner.LoadTcpBanner(banner)
		if appBanner.Response == "" {
			return nil
		}
		return appBanner
	}
	appBanner.LoadTcpBanner(banner)
	if appBanner.Response == "" {
		return nil
	}
	return appBanner
}

func GetAppBannerFromUrl(url *urlparse.URL) *AppBanner {
	banner := getAppBanner(url)

	if banner.StatusCode == 0 {
		return nil
	}

	return banner
}

func getAppBanner(url *urlparse.URL) *AppBanner {
	r := NewAppBanner()
	r.LoadHttpFinger(getHttpFinger(url, false))
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
			url.Scheme = "http"
			return getHttpFinger(url, true)
		}
		if strings.Contains(err.Error(), "malformed HTTP response") {
			//HTTP协议重新获取指纹
			url.Scheme = "https"
			return getHttpFinger(url, true)
		}
		slog.Debug(err.Error())
		return r
	}
	if url.Scheme == "https" {
		r.LoadCert(resp)
	}
	r.LoadHttpResponse(url, resp)
	return r
}
