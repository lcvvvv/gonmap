package shttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"kscan/core/slog"
	"kscan/lib/chinese"
	"kscan/lib/misc"
	"kscan/lib/urlparse"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

var (
	UserAgents = []string{
		"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
		"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
		"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
		"Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
		"Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
		"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
		"Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
		"Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
		"Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
		"Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
		"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
		"Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
	}
	NoTextExt = []string{
		".ico", ".png", ".gif", ".png", ".jpg", ".bmp",
		".zip", ".rar",
	}
	Timeout = 5 * time.Second
	Host    = ""
	Proxy   = ""
)

func InitSHttp(host, proxy string, timeout time.Duration) {
	Host = host
	Proxy = proxy
	Timeout = timeout
}

func GetFavicon(url urlparse.URL) (*http.Response, error) {
	url.Path = "/favicon.ico"
	return Get(url.UnParse())
}

func Get(Url string) (*http.Response, error) {
	request, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Add("User-Agent", getUserAgent())
	request.Header.Add("Cookie", "rememberMe=b69375edcb2b3c5084c02bd9690b6625")
	request.Close = true

	tr := &http.Transport{}
	(*tr).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	(*tr).DisableKeepAlives = false
	client := &http.Client{}
	//修改HTTP超时时间
	if Timeout != 0 {
		ctx, _ := context.WithTimeout(context.Background(), Timeout)
		request.WithContext(ctx)
		client.Timeout = Timeout
	}
	//修改HOST值
	if Host != "" {
		request.Host = Host
	}
	//修改代理选项
	if Proxy != "" {
		uri, _ := url.Parse(Proxy)
		(*tr).Proxy = http.ProxyURL(uri)
	}
	client.Transport = tr
	resp, err := client.Do(request)
	if err != nil {
		return resp, err
	}
	if misc.IsInStrArr(NoTextExt, path.Ext(Url)) == false {
		body2UTF8(resp)
	}
	return resp, err
}

func Header2String(header http.Header) string {
	var result string
	for i := range header {
		result = strings.Join([]string{result, fmt.Sprintf("%s: %s\n", i, header.Get(i))}, "")
	}
	return result
}

func body2UTF8(resp *http.Response) {
	if strings.Contains(resp.Header.Get("Content-Type"), "utf-8") {
		return
	}
	bodyBuf, err := misc.ReadAll(resp.Body, time.Second*5)
	if err != nil {
		slog.Debug(err)
	}
	utf8Buf := chinese.ByteToUTF8(bodyBuf)
	resp.Body = ioutil.NopCloser(bytes.NewReader(utf8Buf))
}

func GetBody(resp *http.Response) io.Reader {
	bodyBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		slog.Debug(err.Error())
	}
	resp.Body = ioutil.NopCloser(bytes.NewReader(bodyBuf))
	return bytes.NewReader(bodyBuf)
}

func getUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	i := rand.Intn(len(UserAgents))
	return UserAgents[i]
}
