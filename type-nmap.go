package gonmap

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

type Nmap struct {
	exclude    *port
	probeGroup map[string]*probe
	probeSort  []string

	portProbeMap   map[int][]string
	usedProbeSlice []string

	target target
	filter int

	response response
	finger   *TcpFinger
}

func (n *Nmap) Scan(ip string, port int) TcpBanner {
	n.target.host = ip
	n.target.port = port

	//拼接端口探测队列，全端口探测放在最后
	b := NewTcpBanner(ip, port)

	//对特殊端口优先发起特定探针
	if IsInIntArr(BypassAllProbePortMap, port) {
		b.Load(n.ScanByProbeSlice(n.portProbeMap[port]))
		if b.status == Closed || (b.status == Matched && b.TcpFinger.Service != "ssl") {
			return b
		}
	} else { //非特殊端口，会优先进行全局探针测试
		//开始使用全局探针进行测试
		b.Load(n.ScanByProbeSlice(AllProbeMap))
		if b.status == Closed || (b.status == Matched && b.TcpFinger.Service != "ssl") {
			return b
		}
		//开始进行特定探针测试
		b.Load(n.ScanByProbeSlice(n.portProbeMap[port]))
		if b.status == Closed || (b.status == Matched && b.TcpFinger.Service != "ssl") {
			return b
		}
	}

	//开始SSL探针测试
	if b.TcpFinger.Service != "ssl" {
		b.Load(n.ScanByProbeSlice(SSLProbeMap))
		if b.status == Closed {
			return b
		}
	}

	if b.status == Matched {
		if b.TcpFinger.Service != "ssl" {
			return b
		}
		b.Load(n.ScanByProbeSlice(SSLSecondProbeMap))

		if b.TcpFinger.Service == "http" {
			b.TcpFinger.Service = "https"
		}

		if b.status == Closed || b.status == Matched {
			return b
		}
	}

	return b
}

func (n *Nmap) getTcpBanner(p *probe) *TcpBanner {
	tcpBanner := NewTcpBanner(n.target.host, n.target.port)

	resp, err := p.scan(n.target)

	if err != nil {
		logger.Println(resp, err)
		if strings.Contains(err.Error(), "STEP1") {
			return tcpBanner.CLOSED()
		}
		if strings.Contains(err.Error(), "STEP2") {
			return tcpBanner.CLOSED()
		}
		return tcpBanner.OPEN()
	}

	tcpBanner.Response = resp
	//若存在返回包，则开始捕获指纹

	tcpBanner.TcpFinger = n.getFinger(resp, p.request.name)

	if tcpBanner.TcpFinger.Service == "" {
		return tcpBanner.OPEN()
	} else {
		return tcpBanner.MATCHED()
	}
	//如果成功匹配指纹，则直接返回指纹
}

func (n *Nmap) AddMatch(probeName string, expr string) {
	n.probeGroup[probeName].loadMatch(expr, false)
}

func (n *Nmap) setTimeout(timeout time.Duration) {
	if timeout == 0 {
		return
	}
	for _, p := range n.probeGroup {
		p.totalwaitms = timeout
		p.tcpwrappedms = timeout
	}
}

func (n *Nmap) isCommand(line string) bool {
	//删除注释行和空行
	if len(line) < 2 {
		return false
	}
	if line[:1] == "#" {
		return false
	}
	//删除异常命令
	commandName := line[:strings.Index(line, " ")]
	commandArr := []string{
		"Exclude", "Probe", "match", "softmatch", "ports", "sslports", "totalwaitms", "tcpwrappedms", "rarity", "fallback",
	}
	for _, item := range commandArr {
		if item == commandName {
			return true
		}
	}
	return false
}

func (n *Nmap) getFinger(response response, requestName string) *TcpFinger {
	data := n.convResponse(response.string)

	finger := n.probeGroup[requestName].match(data)

	if response.tls {
		if finger.Service == "http" {
			finger.Service = "https"
		}
	}

	if finger.Service != "" || n.probeGroup[requestName].fallback == "" {
		//标记当前探针名称
		finger.ProbeName = requestName
		return finger
	}

	fallback := n.probeGroup[requestName].fallback
	for fallback != "" {
		logger.Println(requestName, " fallback is :", fallback)
		finger = n.probeGroup[fallback].match(data)
		fallback = n.probeGroup[fallback].fallback
		if finger.Service != "" {
			break
		}
	}
	//标记当前探针名称
	finger.ProbeName = requestName
	return finger
}

func (n *Nmap) convResponse(s1 string) string {
	//	为了适配go语言的沙雕正则，只能讲二进制强行转换成UTF-8
	b1 := []byte(s1)
	var r1 []rune
	for _, i := range b1 {
		r1 = append(r1, rune(i))
	}
	s2 := string(r1)
	return s2
}

func (n *Nmap) loads(s string) {
	lines := strings.Split(s, "\n")
	var probeArr []string
	p := newProbe()
	for _, line := range lines {
		if !n.isCommand(line) {
			continue
		}
		commandName := line[:strings.Index(line, " ")]
		if commandName == "Exclude" {
			n.loadExclude(line)
			continue
		}
		if commandName == "Probe" {
			if len(probeArr) != 0 {
				p.loads(probeArr)
				n.pushProbe(p)
			}
			probeArr = []string{}
			p.Clean()
		}
		probeArr = append(probeArr, line)
	}
	p.loads(probeArr)
	n.pushProbe(p)
}

func (n *Nmap) loadExclude(expr string) {
	var exclude = newPort()
	expr = expr[strings.Index(expr, " ")+1:]
	for _, s := range strings.Split(expr, ",") {
		if !exclude.Load(s) {
			panic(errors.New("exclude 语句格式错误"))
		}
	}
	n.exclude = exclude
}

func (n *Nmap) pushProbe(p *probe) {
	PROBE := newProbe()
	*PROBE = *p

	n.probeSort = append(n.probeSort, p.request.name)
	n.probeGroup[p.request.name] = PROBE

	//建立端口扫描对应表，将根据端口号决定使用何种请求包
	//如果端口列表为空，则为全端口
	if p.rarity > n.filter {
		return
	}
	//0记录所有使用的探针
	n.portProbeMap[0] = append(n.portProbeMap[0], p.request.name)

	//分别压入sslports,ports
	for _, i := range p.ports.value {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.request.name)
	}
	for _, i := range p.sslports.value {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.request.name)
	}

}

func (n *Nmap) ScanByProbeSlice(probeSlice []string) *TcpBanner {
	b := NewTcpBanner(n.target.host, n.target.port)
	for _, requestName := range probeSlice {
		if IsInStrArr(n.usedProbeSlice, requestName) {
			continue
		}
		b.Load(n.getTcpBanner(n.probeGroup[requestName]))
		//如果端口未开放，则等待10s后重新连接
		if b.status == Closed {
			time.Sleep(time.Second * 10)
			b.Load(n.getTcpBanner(n.probeGroup[requestName]))
		}
		logger.Printf("Target:%s,Probe:%s,Status:%s,Service:%s,Response:%s", b.Target.URI(), requestName, b.StatusDisplay(), b.TcpFinger.Service, strconv.Quote(b.Response.string))
		if b.status == Closed || b.status == Matched {
			break
		}
		if n.target.port == 53 {
			if DnsScan(n.target.URI()) {
				b.TcpFinger.Service = "dns"
				b.Response.string = "dns"
				b.MATCHED()
			} else {
				b.CLOSED()
			}
			break
		}
	}
	return &b
}

func (n *Nmap) fixFallback() {
	for probeName, probeType := range n.probeGroup {
		fallback := probeType.fallback
		if fallback == "" {
			continue
		}
		if _, ok := n.probeGroup["TCP_"+fallback]; ok {
			n.probeGroup[probeName].fallback = "TCP_" + fallback
		} else {
			n.probeGroup[probeName].fallback = "UDP_" + fallback
		}
	}
}
