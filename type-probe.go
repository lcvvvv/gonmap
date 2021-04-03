package gonmap

import (
	"errors"
	"fmt"
	"gonmap/simplenet"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var PROBE_LOAD_REGEXP = regexp.MustCompile("^(UDP|TCP) ([a-zA-Z0-9-_./]+) (?:q\\|([^|]*)\\|)$")
var PROBE_INT_REGEXP = regexp.MustCompile(`^(\d+)$`)
var PROBE_STRING_REGEXP = regexp.MustCompile(`^([a-zA-Z0-9-_./]+)$`)

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
		totalwaitms:  time.Duration(0),
		tcpwrappedms: time.Duration(0),

		ports:      newPort(),
		sslports:   newPort(),
		request:    newRequest(),
		matchGroup: []*match{},
		fallback:   "",

		response:        newResponse(),
		softMatchFilter: "",
	}
}

func (p *probe) loads(sArr []string) {
	for _, s := range sArr {
		p.load(s)
	}
}

func (p *probe) scan(t *target) (string, error) {

	if p.ports.Exist(t.port) {
		data, err := simplenet.Send(p.request.protocol, t.uri, p.request.string, p.totalwaitms, 512)
		if err == nil {
			return data, err
		}
	}
	return simplenet.TLSSend(p.request.protocol, t.uri, p.request.string, p.totalwaitms, 512)
}

func (p *probe) match(s string) *finger {
	var f = newFinger()
	for _, m := range p.matchGroup {
		//实现软筛选
		if p.softMatchFilter != "" {
			if m.service != p.softMatchFilter {
				continue
			}
		}
		//fmt.Println("开始匹配正则：",m.pattern)
		if m.patternRegexp.MatchString(s) {
			fmt.Println("成功匹配指纹：", m.pattern, "所在probe为：", p.request.name)
			if m.soft {
				//如果为软捕获，这设置筛选器
				f.service = m.service
				p.softMatchFilter = m.service
				continue
			} else {
				//如果为硬捕获则直接设置指纹信息
				f = m.versioninfo
				f.service = m.service
				return f
			}
		}
	}
	p.softMatchFilter = ""
	if f.service != "" {
		return f
	} else {
		return nil
	}
}

func (p *probe) load(s string) {
	//分解命令
	i := strings.Index(s, " ")
	commandName := s[:i]
	commandArgs := s[i+1:]
	//逐行处理
	switch commandName {
	case "Probe":
		p.loadProbe(commandArgs)
	case "match":
		p.loadMatch(commandArgs, false)
	case "softmatch":
		p.loadMatch(commandArgs, true)
	case "ports":
		p.loadPorts(commandArgs, false)
	case "sslports":
		p.loadPorts(commandArgs, true)
	case "totalwaitms":
		p.totalwaitms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "tcpwrappedms":
		p.tcpwrappedms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "rarity":
		p.rarity = p.getInt(commandArgs)
	case "fallback":
		p.fallback = p.getString(commandArgs)
	}
}

func (p *probe) loadProbe(s string) {
	//Probe <protocol> <probename> <probestring>
	if !PROBE_LOAD_REGEXP.MatchString(s) {
		panic(errors.New("probe 语句格式不正确"))
	}
	args := PROBE_LOAD_REGEXP.FindStringSubmatch(s)
	if args[1] == "" || args[2] == "" {
		panic(errors.New("probe 参数格式不正确"))
	}
	p.request.protocol = args[1]
	p.request.name = args[1] + "_" + args[2]
	str := args[3]
	str = strings.ReplaceAll(str, `\0`, `\x00`)
	str = strings.ReplaceAll(str, `"`, `${double-quoted}`)
	str = `"` + str + `"`
	str, _ = strconv.Unquote(str)
	str = strings.ReplaceAll(str, `${double-quoted}`, `"`)
	p.request.string = str
}

func (p *probe) loadMatch(s string, soft bool) {
	m := newMatch()
	//"match": misc.MakeRegexpCompile("^([a-zA-Z0-9-_./]+) m\\|([^|]+)\\|([is]{0,2}) (.*)$"),
	//match <service> <pattern>|<patternopt> [<versioninfo>]
	//	"matchVersioninfoProductname": misc.MakeRegexpCompile("p/([^/]+)/"),
	//	"matchVersioninfoVersion":     misc.MakeRegexpCompile("v/([^/]+)/"),
	//	"matchVersioninfoInfo":        misc.MakeRegexpCompile("i/([^/]+)/"),
	//	"matchVersioninfoHostname":    misc.MakeRegexpCompile("h/([^/]+)/"),
	//	"matchVersioninfoOS":          misc.MakeRegexpCompile("o/([^/]+)/"),
	//	"matchVersioninfoDevice":      misc.MakeRegexpCompile("d/([^/]+)/"),
	if !m.load(s, soft) {
		panic(errors.New("match 语句参数不正确"))
	}
	p.matchGroup = append(p.matchGroup, m)
}

func (p *probe) loadPorts(s string, ssl bool) {
	if ssl {
		if !p.sslports.LoadS(s) {
			panic(errors.New("sslports 语句参数不正确"))
		}
	} else {
		if !p.ports.LoadS(s) {
			panic(errors.New("ports 语句参数不正确"))
		}
	}
}

func (p *probe) getInt(expr string) int {
	if !PROBE_INT_REGEXP.MatchString(expr) {
		panic(errors.New("totalwaitms or tcpwrappedms 语句参数不正确"))
	}
	i, _ := strconv.Atoi(PROBE_INT_REGEXP.FindStringSubmatch(expr)[1])
	return i
}

func (p *probe) getString(expr string) string {
	if !PROBE_STRING_REGEXP.MatchString(expr) {
		panic(errors.New("fallback 语句参数不正确"))
	}
	return PROBE_STRING_REGEXP.FindStringSubmatch(expr)[1]
}

func (p *probe) Clean() {
	p.ports = newPort()
	p.sslports = newPort()

	p.request = newRequest()
	p.matchGroup = []*match{}
	p.fallback = ""

	p.response = newResponse()
	p.softMatchFilter = ""
}

//
//func (this *probe) Scan(target scan.target) bool {
//	response, err := this.send(target)
//	if err != nil {
//		slog.Debug(err.Error())
//		return false
//	}
//	this.response.string = response
//	return true
//}
//
//func (this *probe) Match() bool {
//	var regular *regexp.Regexp
//	var err error
//	var finger = newFinger()
//	for _, match := range this.matchGroup {
//		if this.softMatchFilter != "" {
//			if match.service != this.softMatchFilter {
//				continue
//			}
//		}
//		regular, err = regexp.Compile(match.pattern)
//		if err != nil {
//			//slog.Debug(fmt.Sprintf("%s:%s",err.Error(),match.pattern))
//			continue
//		}
//		if regular.matchGrouptring(this.response.string) {
//			if match.soft {
//				//如果为软捕获，这设置筛选器
//				finger.service = match.service
//				this.softMatchFilter = match.service
//			} else {
//				//如果为硬捕获则直接设置指纹信息
//				finger = this.makeFinger(regular.FindStringSubmatch(this.response.string), match.versioninfo)
//				finger.service = match.service
//				this.response.finger = finger
//				return true
//			}
//		}
//	}
//	if finger.service != "" {
//		this.response.finger = finger
//		return true
//	} else {
//		return false
//	}
//}
//
//func (this *probe) makeFinger(strArr []string, versioninfo *finger) *finger {
//	versioninfo.info = this.fixFingerValue(versioninfo.info, strArr)
//	versioninfo.devicetype = this.fixFingerValue(versioninfo.devicetype, strArr)
//	versioninfo.hostname = this.fixFingerValue(versioninfo.hostname, strArr)
//	versioninfo.operatingsystem = this.fixFingerValue(versioninfo.operatingsystem, strArr)
//	versioninfo.productname = this.fixFingerValue(versioninfo.productname, strArr)
//	versioninfo.version = this.fixFingerValue(versioninfo.version, strArr)
//	return versioninfo
//}
//
//func (this *probe) fixFingerValue(value string, strArr []string) string {
//	return value
//}
//
//func (this *probe) send(target scan.target) (string, error) {
//	if this.sslports.Len() == 0 && this.ports.Len() == 0 {
//		return stcp.Send(this.request.protocol, target.netloc, this.request.string, this.tcpwrappedms)
//	}
//	if this.sslports.IsExist(target.port) {
//		return stls.Send(this.request.protocol, target.netloc, this.request.string, this.tcpwrappedms)
//	}
//	if this.ports.IsExist(target.port) {
//		return stcp.Send(this.request.protocol, target.netloc, this.request.string, this.tcpwrappedms)
//	}
//	return "", errors.New("无匹配端口，故未进行扫描")
//	//return stcp.Send(this.request.protocol, target.netloc, this.request.string, this.tcpwrappedms)
//}
