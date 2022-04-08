package gonmap

import (
	"fmt"
	"github.com/lcvvvv/gonmap/lib/chinese"
	"github.com/lcvvvv/gonmap/lib/gorpc"
	"github.com/lcvvvv/gonmap/lib/misc"
	"github.com/lcvvvv/gonmap/lib/urlparse"
	"strconv"
	"strings"
)

type AppBanner struct {
	//端口号
	Port int
	//IP地址
	IPAddr string
	//IP地址
	Path string
	//端口开放状态码
	StatusCode int
	//HTTP协议标题，其他协议正文摘要
	AppDigest string
	//返回包全文
	Response string
	//端口开放协议类型
	Protocol string
	//fingerprintMap
	fingerPrint map[string]string
}

func NewAppBanner() *AppBanner {
	banner := &AppBanner{}
	banner.fingerPrint = make(map[string]string)
	return banner
}

func (a *AppBanner) URL() string {
	u, _ := urlparse.Load(fmt.Sprintf("%s://%s:%d%s", a.Protocol, a.IPAddr, a.Port, a.Path))
	return u.UnParse()
}

func (a *AppBanner) Netloc() string {
	return fmt.Sprintf("%s:%d", a.IPAddr, a.Port)
}

func (a *AppBanner) LoadHttpFinger(finger *HttpFinger) {
	a.IPAddr = finger.URL.Netloc
	a.Path = finger.URL.Path
	a.Port = finger.URL.Port
	a.AppDigest = finger.Title
	a.AppDigest = a.makeAppDigest()
	a.StatusCode = finger.StatusCode
	if finger.StatusCode != 0 {
		a.Response = finger.Header + "\t\n" + finger.Response
		a.Protocol = finger.URL.Scheme
	}
	a.SetCertSubject(func() string {
		if finger.PeerCertificates != nil {
			strCert := finger.PeerCertificates.Subject.String()
			strCert = chinese.ToUTF8(strCert)
			return strCert
		} else {
			return ""
		}
	}())
	a.SetResponseDigest(finger.ResponseDigest)

	if finger.StatusCode == 0 && a.Protocol == "" {
		a.Protocol = "unknown"
	}

	a.loadTcpFinger(finger.Finger)
}

func (a *AppBanner) LoadTcpBanner(banner *TcpBanner) {
	if a.StatusCode == 0 {
		if banner.TcpFinger.Service == "http" || banner.TcpFinger.Service == "https" {
			a.StatusCode = 500
		} else {
			a.StatusCode = 200
		}
		a.Protocol = func() string {
			if banner.TcpFinger.Service != "" {
				return banner.TcpFinger.Service
			}
			if a.Protocol != "" {
				return a.Protocol
			}
			return "unknown"
		}()
		a.Port = misc.Str2Int(strings.Split(banner.Target.URI(), ":")[1])
		a.IPAddr = strings.Split(banner.Target.URI(), ":")[0]

		a.Response = banner.Response.string
		a.AppDigest = func() string {
			appDigest := misc.FixLine(a.Response)
			appDigest = misc.FilterPrintStr(appDigest)
			appDigest = misc.MustLength(appDigest, 10)
			return appDigest
		}()
	}

	a.loadTcpFinger(banner.TcpFinger)
}

func (a *AppBanner) makeAppDigest() string {
	digest := a.AppDigest
	digest = misc.FixLine(digest)
	digest = misc.FilterPrintStr(digest)
	if digest == "" {
		return strings.ToUpper(a.Protocol)
	}
	return digest
}

//返回包摘要
func (a *AppBanner) SetResponseDigest(s string) {
	a.fingerPrint["ResponseDigest"] += s
}

//Http IconHash指纹识别信息
func (a *AppBanner) SetHashFinger(s string) {
	a.fingerPrint["HashFinger"] += s
}

//Http 关键字指纹识别信息
func (a *AppBanner) SetKeywordFinger(s string) {
	a.fingerPrint["KeywordFinger"] += s
}

//Https 证书信息
func (a *AppBanner) SetCertSubject(s string) {
	a.fingerPrint["CertSubject"] += s
}

//端口开放 产品信息
func (a *AppBanner) SetProductName(s string) {
	a.fingerPrint["ProductName"] += s
}

//端口开放 产品版本信息
func (a *AppBanner) SetVersion(s string) {
	a.fingerPrint["Version"] += s
}

//主机名称
func (a *AppBanner) SetHostname(s string) {
	a.fingerPrint["Hostname"] += s
}

//操作系统名称
func (a *AppBanner) SetOperatingSystem(s string) {
	a.fingerPrint["OperatingSystem"] += s
}

//设备类型
func (a *AppBanner) SetDeviceType(s string) {
	a.fingerPrint["DeviceType"] += s
}

//端口其他信息
func (a *AppBanner) SetInfo(s string) {
	a.fingerPrint["Info"] += s
}

//应用层协议协议
func (a *AppBanner) SetApplicationComponent(component string) {
	a.fingerPrint["ApplicationComponent"] += component
}

func (a *AppBanner) Map() map[string]string {
	bannerMap := make(map[string]string)
	bannerMap["Response"] = a.Response
	bannerMap["URL"] = a.URL()
	bannerMap["Port"] = strconv.Itoa(a.Port)
	bannerMap["IPAddr"] = a.IPAddr
	bannerMap["AppDigest"] = a.AppDigest
	bannerMap["Protocol"] = a.Protocol
	bannerMap["StatusCode"] = strconv.Itoa(a.StatusCode)
	for key, value := range a.fingerPrint {
		bannerMap[key] = value
	}
	return bannerMap
}

func (a *AppBanner) FingerPrint() map[string]string {
	return a.fingerPrint
}

func (a *AppBanner) LoadRpcFinger(finger *gorpc.Finger) {
	a.AppDigest = finger.Value()[0]

	if len(a.AppDigest) == 0 {
		a.AppDigest = "NoName"
	}

	a.StatusCode = 200
	a.SetHostname(finger.ValueString())
}

func (a *AppBanner) loadTcpFinger(finger *TcpFinger) {
	a.SetProductName(finger.ProductName)
	a.SetInfo(finger.Info)
	a.SetDeviceType(finger.DeviceType)
	a.SetOperatingSystem(finger.OperatingSystem)
	a.SetHostname(finger.Hostname)
	a.SetVersion(finger.Version)
	a.SetApplicationComponent(finger.ApplicationComponent)
}
