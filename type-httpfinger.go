package gonmap

import (
	"crypto/x509"
	"github.com/PuerkitoBio/goquery"
	"io"
	"io/ioutil"
	"kscan/core/gonmap/lib/shttp"
	"kscan/lib/httpfinger"
	"kscan/lib/iconhash"
	"kscan/lib/misc"
	"kscan/lib/urlparse"
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
	h.Header = getHeader(resp.Header.Clone())
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

func getHeader(header http.Header) string {
	return shttp.Header2String(header)
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
