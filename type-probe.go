package gonmap

import (
	"errors"
	"gonmap/scan"
	"regexp"
	"time"
)

type probe struct {
	rarity       int
	ports        *port
	sslports     *port
	totalwaitms  time.Duration
	tcpwrappedms time.Duration
	request      *request
	matchGroup   []*match
	fallback     string

	response        *response
	softMatchFilter string
}

func newProbe() *probe {
	return &probe{
		rarity:       1,
		ports:        newPort(),
		sslports:     newPort(),
		totalwaitms:  time.Duration(0),
		tcpwrappedms: time.Duration(0),
		request:      newRequest(),
		matchGroup:   []*match{},
		fallback:     "",

		response:        newResponse(),
		softMatchFilter: "",
	}
}

func (this *probe) Scan(target scan.target) bool {
	response, err := this.send(target)
	if err != nil {
		slog.Debug(err.Error())
		return false
	}
	this.response.string = response
	return true
}

func (this *probe) Match() bool {
	var regular *regexp.Regexp
	var err error
	var finger = newFinger()
	for _, match := range this.matchGroup {
		if this.softMatchFilter != "" {
			if match.service != this.softMatchFilter {
				continue
			}
		}
		regular, err = regexp.Compile(match.pattern)
		if err != nil {
			//slog.Debug(fmt.Sprintf("%s:%s",err.Error(),match.pattern))
			continue
		}
		if regular.matchGrouptring(this.response.string) {
			if match.soft {
				//如果为软捕获，这设置筛选器
				finger.service = match.service
				this.softMatchFilter = match.service
			} else {
				//如果为硬捕获则直接设置指纹信息
				finger = this.makeFinger(regular.FindStringSubmatch(this.response.string), match.versioninfo)
				finger.service = match.service
				this.response.finger = finger
				return true
			}
		}
	}
	if finger.service != "" {
		this.response.finger = finger
		return true
	} else {
		return false
	}
}

func (this *probe) makeFinger(strArr []string, versioninfo *finger) *finger {
	versioninfo.info = this.fixFingerValue(versioninfo.info, strArr)
	versioninfo.devicetype = this.fixFingerValue(versioninfo.devicetype, strArr)
	versioninfo.hostname = this.fixFingerValue(versioninfo.hostname, strArr)
	versioninfo.operatingsystem = this.fixFingerValue(versioninfo.operatingsystem, strArr)
	versioninfo.productname = this.fixFingerValue(versioninfo.productname, strArr)
	versioninfo.version = this.fixFingerValue(versioninfo.version, strArr)
	return versioninfo
}

func (this *probe) fixFingerValue(value string, strArr []string) string {
	return value
}

func (this *probe) send(target scan.target) (string, error) {
	if this.sslports.Len() == 0 && this.ports.Len() == 0 {
		return stcp.Send(this.request.protocol, target.netloc, this.request.string, this.tcpwrappedms)
	}
	if this.sslports.IsExist(target.port) {
		return stls.Send(this.request.protocol, target.netloc, this.request.string, this.tcpwrappedms)
	}
	if this.ports.IsExist(target.port) {
		return stcp.Send(this.request.protocol, target.netloc, this.request.string, this.tcpwrappedms)
	}
	return "", errors.New("无匹配端口，故未进行扫描")
	//return stcp.Send(this.request.protocol, target.netloc, this.request.string, this.tcpwrappedms)
}
