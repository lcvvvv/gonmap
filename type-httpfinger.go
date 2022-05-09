package gonmap

import (
	"crypto/x509"
	"github.com/PuerkitoBio/goquery"
	"github.com/lcvvvv/gonmap/lib/httpfinger"
	"github.com/lcvvvv/gonmap/lib/iconhash"
	"github.com/lcvvvv/gonmap/lib/misc"
	"github.com/lcvvvv/gonmap/lib/shttp"
	"github.com/lcvvvv/gonmap/lib/urlparse"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

type HttpFinger struct {
	URL            *urlparse.URL
	StatusCode     int
	Response       string
	ResponseDigest string
	Title          string
	Header         string

	//HeaderDigest  string
	//HashFinger    string
	//KeywordFinger string

	Finger           *TcpFinger
	PeerCertificates *x509.Certificate
}

const ERROR_NOT_SUCH_HOST = 0x0010001

func NewHttpFinger(url *urlparse.URL) *HttpFinger {
	return &HttpFinger{
		URL:            url,
		StatusCode:     0,
		Response:       "",
		ResponseDigest: "",
		Title:          "",
		Header:         "",
		//HashFinger:       "",
		//KeywordFinger:    "",
		Finger:           newFinger(),
		PeerCertificates: nil,
	}
}

func (h *HttpFinger) LoadHttpResponse(url *urlparse.URL, resp *http.Response) {
	h.Title = getTitle(shttp.GetBody(resp))
	h.StatusCode = resp.StatusCode
	h.Header = getHeader(*resp)
	h.Response = getResponse(shttp.GetBody(resp))
	h.ResponseDigest = getResponseDigest(shttp.GetBody(resp))

	var componentSlice []string
	if component := getFingerByHash(*url); component != "" {
		componentSlice = append(componentSlice, "icon:"+component)
	}
	if component := getFingerByKeyword(h.Header, h.Title, h.Response); component != "" {
		componentSlice = append(componentSlice, component)
	}
	h.Finger.ApplicationComponent = strings.Join(componentSlice, ",")
	//h.HashFinger = getFingerByHash(*url)
	//h.KeywordFinger = getFingerByKeyword(h.Header, h.Title, h.Response)
	if h.Title == "" {
		switch h.StatusCode {
		case 100:
			h.Title = "100 Continue"
		case 101:
			h.Title = "101 Switching Protocols"
		case 201:
			h.Title = "201 Created"
		case 202:
			h.Title = "202 Accepted"
		case 203:
			h.Title = "203 Non-Authoritative Information"
		case 204:
			h.Title = "204 No Content"
		case 205:
			h.Title = "205 Reset Content"
		case 206:
			h.Title = "206 Partial Content"
		case 300:
			h.Title = "300 Multiple Choices"
		case 301:
			h.Title = "301 Moved Permanently"
		case 302:
			h.Title = "302 Found"
		case 303:
			h.Title = "303 See Other"
		case 304:
			h.Title = "304 Not Modified"
		case 305:
			h.Title = "305 Use Proxy"
		case 306:
			h.Title = "306 Unused"
		case 307:
			h.Title = "307 Temporary Redirect"
		case 400:
			h.Title = "400 Bad Request"
		case 401:
			h.Title = "401 Unauthorized"
		case 402:
			h.Title = "402 Payment Required"
		case 403:
			h.Title = "403 Forbidden"
		case 404:
			h.Title = "404 Not Found"
		case 405:
			h.Title = "405 Method Not Allowed"
		case 406:
			h.Title = "406 Not Acceptable"
		case 407:
			h.Title = "407 Proxy Authentication Required"
		case 408:
			h.Title = "408 Request Time-out"
		case 409:
			h.Title = "409 Conflict"
		case 410:
			h.Title = "410 Gone"
		case 411:
			h.Title = "411 Length Required"
		case 412:
			h.Title = "412 Precondition Failed"
		case 413:
			h.Title = "413 Request Entity Too Large"
		case 414:
			h.Title = "414 Request-URI Too Large"
		case 415:
			h.Title = "415 Unsupported Media Type"
		case 416:
			h.Title = "416 Requested range not satisfiable"
		case 417:
			h.Title = "417 Expectation Failed"
		case 500:
			h.Title = "500 Internal Server Error"
		case 501:
			h.Title = "501 Not Implemented"
		case 502:
			h.Title = "502 Bad Gateway"
		case 503:
			h.Title = "503 Service Unavailable"
		case 504:
			h.Title = "504 Gateway Time-out"
		case 505:
			h.Title = "505 HTTP Version not supported"
		default:
			h.Title = "No Title"
		}
	}
	_ = resp.Body.Close()
}

func getTitle(resp io.Reader) string {
	query, err := goquery.NewDocumentFromReader(resp)
	if err != nil {
		logger.Println(err.Error())
		return ""
	}
	result := query.Find("title").Text()
	result = misc.FixLine(result)
	//Body.Close()
	return result
}

func getHeader(resp http.Response) string {
	return shttp.Header2String(resp)
}

func getResponse(resp io.Reader) string {
	body, err := ioutil.ReadAll(resp)
	if err != nil {
		logger.Println(err.Error())
		return ""
	}
	bodyStr := string(body)
	return bodyStr
}

func getResponseDigest(resp io.Reader) string {

	var result string

	query, err := goquery.NewDocumentFromReader(CopyIoReader(&resp))
	if err != nil {
		logger.Println(err.Error())
		return ""
	}

	query.Find("script").Each(func(_ int, tag *goquery.Selection) {
		tag.Remove() // 把无用的 tag 去掉
	})
	query.Find("style").Each(func(_ int, tag *goquery.Selection) {
		tag.Remove() // 把无用的 tag 去掉
	})
	query.Find("textarea").Each(func(_ int, tag *goquery.Selection) {
		tag.Remove() // 把无用的 tag 去掉
	})
	query.Each(func(_ int, tag *goquery.Selection) {
		result = result + tag.Text()
	})

	result = misc.FixLine(result)

	result = misc.FilterPrintStr(result)

	result = misc.StrRandomCut(result, 20)

	if len(result) == 0 {
		b, _ := ioutil.ReadAll(CopyIoReader(&resp))
		result = string(b)
		result = misc.FixLine(result)
		result = misc.FilterPrintStr(result)
		result = misc.StrRandomCut(result, 20)
	}

	return result
}

func getFingerByKeyword(header string, title string, body string) string {
	return httpfinger.KeywordFinger.Match(header, title, body)
}

func getFingerByHash(url urlparse.URL) string {
	resp, err := shttp.GetFavicon(url)
	if err != nil {
		logger.Println(url.UnParse() + err.Error())
		return ""
	}
	if resp.StatusCode != 200 {
		//logger.Println(url.UnParse() + "no favicon file")
		return ""
	}
	hash, err := iconhash.Get(resp.Body)
	if err != nil {
		logger.Println(url.UnParse() + err.Error())
		return ""
	}
	_ = resp.Body.Close()
	return httpfinger.FaviconHash.Match(hash)
}

func (h *HttpFinger) LoadCert(resp *http.Response) {
	h.PeerCertificates = resp.TLS.PeerCertificates[0]
}
