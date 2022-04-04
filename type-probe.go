package gonmap

import (
	"errors"
	"kscan/core/gonmap/simplenet"
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

	response        response
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

func (p *probe) scan(t target, ssl bool) (string, error) {
	if ssl {
		return simplenet.TLSSend(p.request.protocol, t.URI(), p.request.string, p.totalwaitms, 512)
	} else {
		return simplenet.Send(p.request.protocol, t.URI(), p.request.string, p.totalwaitms, 512)
	}
}

func (p *probe) match(s string) *TcpFinger {
	var f = newFinger()
	if p.matchGroup == nil {
		return f
	}
	for _, m := range p.matchGroup {
		//实现软筛选
		if p.softMatchFilter != "" {
			if m.service != p.softMatchFilter {
				continue
			}
		}
		//logger.Println("开始匹配正则：", m.service, m.patternRegexp.String())
		if m.patternRegexp.MatchString(s) {
			//标记当前正则
			f.MatchRegexString = m.patternRegexp.String()
			if m.soft {
				//如果为软捕获，这设置筛选器
				f.Service = m.service
				p.softMatchFilter = m.service
				continue
			} else {
				//如果为硬捕获则直接获取指纹信息
				m.makeVersionInfo(s, f)
				f.Service = m.service
				return f
			}
		}
	}
	//清空软匹配过滤器
	p.softMatchFilter = ""
	return f
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
	//match <Service> <pattern>|<patternopt> [<versioninfo>]
	//	"matchVersioninfoProductname": misc.MakeRegexpCompile("p/([^/]+)/"),
	//	"matchVersioninfoVersion":     misc.MakeRegexpCompile("v/([^/]+)/"),
	//	"matchVersioninfoInfo":        misc.MakeRegexpCompile("i/([^/]+)/"),
	//	"matchVersioninfoHostname":    misc.MakeRegexpCompile("h/([^/]+)/"),
	//	"matchVersioninfoOS":          misc.MakeRegexpCompile("o/([^/]+)/"),
	//	"matchVersioninfoDevice":      misc.MakeRegexpCompile("d/([^/]+)/"),
	if m.load(s, soft) == false {
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
