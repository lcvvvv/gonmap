package gonmap

import (
	"fmt"
	"kscan/app"
	"kscan/lib/gonmap/shttp"
	"kscan/lib/slog"
	"kscan/lib/urlparse"
	"strings"
	"time"
)

func GetAppBannerFromTcpBanner(banner *TcpBanner) *AppBanner {
	var appBanner = NewAppBanner()
	var url string
	if banner.TcpFinger.Service == "http" || banner.TcpFinger.Service == "https" {
		url = fmt.Sprintf("%s://%s", banner.TcpFinger.Service, banner.Target.uri)
		parse, _ := urlparse.Load(url)
		if app.Setting.Path != "" {
			parse.Path = app.Setting.Path
		}
		appBanner = getAppBanner(parse)
		appBanner.LoadTcpBanner(banner)
		if appBanner.Response == "" {
			return nil
		}
		return appBanner
	}
	if banner.TcpFinger.Service == "ssl" {
		url = fmt.Sprintf("https://%s", banner.Target.uri)
		parse, _ := urlparse.Load(url)
		if app.Setting.Path != "" {
			parse.Path = app.Setting.Path
		}
		appBanner = getAppBanner(parse)
		appBanner.LoadTcpBanner(banner)
		if appBanner.Response == "" {
			return nil
		}
		return appBanner
	}
	if strings.Contains(banner.Response.string, "HTTP") {
		url = "http://" + banner.Target.uri
		parse, _ := urlparse.Load(url)
		if app.Setting.Path != "" {
			parse.Path = app.Setting.Path
		}
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
	if url.Port == 0 {
		url.Port = 80
		if url.Scheme == "" {
			url.Scheme = "http"
		}
	}
	if url.Scheme == "" {
		netloc := fmt.Sprintf("%s:%d", url.Netloc, url.Port)
		banner := GetTcpBanner(netloc, New(), app.Setting.Timeout*10)
		if banner.Status == "CLOSED" {
			return nil
		}
		return GetAppBannerFromTcpBanner(banner)
	}
	banner := getAppBanner(url)
	if banner.StatusCode == 0 {
		return nil
	}
	return banner
}

func getAppBanner(url *urlparse.URL) *AppBanner {
	r := NewAppBanner()
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
