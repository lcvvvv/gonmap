package gonmap

import (
	"errors"
	"kscan/core/slog"
	"strconv"
	"strings"
	"time"
)

var NMAP *Nmap

var BypassAllProbePortMap = []int{161, 137, 139, 135, 389, 548, 1433, 6379, 1883, 5432, 1521, 3389, 3388, 3389, 33890, 33900}
var SSLSecondProbeMap = []string{"TCP_TerminalServerCookie", "TCP_TerminalServer"}
var AllProbeMap = []string{"TCP_GetRequest", "TCP_NULL"}
var SSLProbeMap = []string{"TCP_TLSSessionReq", "TCP_SSLSessionReq", "TCP_SSLv23SessionReq"}

//r["PROBE"] 总探针数、r["MATCH"] 总指纹数 、r["USED_PROBE"] 已使用探针数、r["USED_MATCH"] 已使用指纹数
func Init(filter int, timeout time.Duration) map[string]int {
	//初始化NMAP探针库
	InitNMAP()
	//fmt.Println("初始化了")
	NMAP = &Nmap{
		exclude:        newPort(),
		probeGroup:     make(map[string]*probe),
		probeSort:      []string{},
		portProbeMap:   make(map[int][]string),
		usedProbeSlice: []string{},
		probeFilter:    0,
		target:         target{},
		response:       newResponse(),
		finger:         nil,
		filter:         5,
	}
	NMAP.filter = filter
	for i := 0; i <= 65535; i++ {
		NMAP.portProbeMap[i] = []string{}
	}
	NMAP.loads(NMAP_SERVICE_PROBES + NMAP_CUSTOMIZE_PROBES)
	//修复fallback
	NMAP.fixFallback()
	//将TCP_GetRequest的fallback参数设置为NULL探针，避免漏资产
	NMAP.probeGroup["TCP_GetRequest"].fallback = "TCP_NULL"
	//配置超时时间
	NMAP.setTimeout(timeout)
	//新增自定义指纹信息
	NMAP.AddMatch("TCP_GetRequest", `echo m|^GET / HTTP/1.0\r\n\r\n$|s`)
	NMAP.AddMatch("TCP_GetRequest", `mongodb m|.*It looks like you are trying to access MongoDB.*|s p/MongoDB/`)
	NMAP.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]+\r\n)*?Server: ([^\r\n]+)| p/$1/`)
	NMAP.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d|`)
	NMAP.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MariaDB server| p/MariaDB/`)
	NMAP.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MySQL server| p/MySQL/`)
	NMAP.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	NMAP.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	NMAP.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00| p/MariaDB/ v/$1/`)
	NMAP.AddMatch("TCP_NULL", `redis m|-DENIED Redis is running in.*| p/Redis/ i/Protected mode/`)
	NMAP.AddMatch("TCP_NULL", `ftp m|^220 H3C Small-FTP Server Version ([\d.]+).* | p/H3C Small-FTP/ v/$1/`)
	NMAP.AddMatch("TCP_redis-server", `redis m|^.*redis_version:([.\d]+)\n|s p/Redis key-value store/ v/$1/ cpe:/a:redislabs:redis:$1/`)
	NMAP.AddMatch("TCP_redis-server", `redis m|^-NOAUTH Authentication required.|s p/Redis key-value store/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^.*Welcome to visit (.*) series router!.*|s p/$1 Router/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^Username: ??|`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^.*Telnet service is disabled or Your telnet session has expired due to inactivity.*|s i/Disabled/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^.*Telnet connection from (.*) refused.*|s i/Refused/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^.*Command line is locked now, please retry later.*\x0d\x0a\x0d\x0a|s i/Locked/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^.*Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet.*|s`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^telnetd:|s`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^.*Quopin CLI for (.*)\x0d\x0a\x0d\x0a|s p/$1/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^\x0d\x0aHello, this is FRRouting \(version ([\d.]+)\).*|s p/FRRouting/ v/$1/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^.*User Access Verification.*Username:|s`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^Connection failed.  Windows CE Telnet Service cannot accept anymore concurrent users.|s o/Windows/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^\x0d\x0a\x0d\x0aWelcome to the host.\x0d\x0a.*|s o/Windows/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^.*Welcome Visiting Huawei Home Gateway\x0d\x0aCopyright by Huawei Technologies Co., Ltd.*Login:|s p/Huawei/`)
	NMAP.AddMatch("TCP_NULL", `telnet m|^..\x01..\x03..\x18..\x1f|s p/Huawei/`)
	NMAP.AddMatch("TCP_TerminalServerCookie", `ms-wbt-server m|^\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02.*\0\x02\0\0\0| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a`)
	//优化检测逻辑，及端口对应的默认探针
	NMAP.portProbeMap[3390] = append(NMAP.portProbeMap[3390], "TCP_TerminalServer")
	NMAP.portProbeMap[3390] = append(NMAP.portProbeMap[3390], "TCP_TerminalServerCookie")
	NMAP.portProbeMap[33890] = append(NMAP.portProbeMap[33890], "TCP_TerminalServer")
	NMAP.portProbeMap[33890] = append(NMAP.portProbeMap[33890], "TCP_TerminalServerCookie")
	NMAP.portProbeMap[33900] = append(NMAP.portProbeMap[33900], "TCP_TerminalServer")
	NMAP.portProbeMap[33900] = append(NMAP.portProbeMap[33900], "TCP_TerminalServerCookie")
	NMAP.portProbeMap[7890] = append(NMAP.portProbeMap[7890], "TCP_Socks5")
	NMAP.portProbeMap[7891] = append(NMAP.portProbeMap[7891], "TCP_Socks5")
	NMAP.portProbeMap[4000] = append(NMAP.portProbeMap[4000], "TCP_Socks5")
	NMAP.portProbeMap[2022] = append(NMAP.portProbeMap[2022], "TCP_Socks5")
	NMAP.portProbeMap[6000] = append(NMAP.portProbeMap[6000], "TCP_Socks5")
	NMAP.portProbeMap[7000] = append(NMAP.portProbeMap[7000], "TCP_Socks5")
	return NMAP.Status()
}

func InitNMAP() {
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, "${backquote}", "`")
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `\1`, `$1`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?=\\)`, `(?:\\)`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?=[\w._-]{5,15}\r?\n$)`, `(?:[\w._-]{5,15}\r?\n$)`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?:[^\r\n]*r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?:[^\r\n]*\r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?:[^\r\n]+\r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?!2526)`, ``)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?!400)`, ``)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?!\0\0)`, ``)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?!/head>)`, ``)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?!HTTP|RTSP|SIP)`, ``)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?!.*[sS][sS][hH]).*`, `.*`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?!\xff)`, `.`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?!x)`, `[^x]`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?<=.)`, `(?:.)`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `(?<=\?)`, `(?:\?)`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `\x20\x02\x00.`, `\x20\x02..`)
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `match rtmp`, `# match rtmp`)
	NMAP_SERVICE_PROBES = ReplaceAll(NMAP_SERVICE_PROBES, `nmap`, `pamn`)
}

func New() *Nmap {
	n := &Nmap{}
	*n = *NMAP
	return n
}

type Nmap struct {
	exclude        *port
	probeGroup     map[string]*probe
	probeSort      []string
	probeFilter    int
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
		if b.status == Closed || b.status == Matched {
			return b
		}
	}

	return b
}

func (n *Nmap) getTcpBanner(p *probe) *TcpBanner {
	b := NewTcpBanner(n.target.host, n.target.port)

	tls := p.sslports.Exist(n.target.port)

	data, err := p.scan(n.target, tls)

	if err != nil {
		slog.Debug(data, err)
	}
	if err != nil {
		b.ErrorMsg = err
		if strings.Contains(err.Error(), "STEP1") {
			//slog.Debug(err.Error())
			if n.target.port == 137 || n.target.port == 161 {
				return b.OPEN()
			}
			return b.CLOSED()
		}
		//if p.request.protocol == "UDP" {
		//	return b.CLOSED()
		//}
		return b.OPEN()
	}

	b.Response.string = data
	//若存在返回包，则开始捕获指纹
	//slog.Debugf("成功捕获到返回包，返回包为：%v\n", data)
	//fmt.Printf("成功捕获到返回包，返回包长度为：%x\n", len(data))

	b.TcpFinger = n.getFinger(data, p.request.name)

	//slog.Debug(b.TcpFinger.Service)

	if b.TcpFinger.Service == "" {
		return b.OPEN()
	} else {
		if tls {
			if b.TcpFinger.Service == "http" {
				b.TcpFinger.Service = "https"
			}
		}
		return b.MATCHED()
	}
	//如果成功匹配指纹，则直接返回指纹
}

func (n *Nmap) AddMatch(probeName string, expr string) {
	n.probeGroup[probeName].loadMatch(expr, false)
}

func (n *Nmap) Status() map[string]int {
	r := make(map[string]int)
	r["PROBE"] = len(NMAP.probeSort)
	r["MATCH"] = 0
	for _, p := range NMAP.probeGroup {
		r["MATCH"] += len(p.matchGroup)
	}
	//fmt.Printf("成功加载探针：【%d】个,指纹【%d】条\n", PROBE_COUNT,MATCH_COUNT)
	r["USED_PROBE"] = len(NMAP.portProbeMap[0])
	r["USED_MATCH"] = 0
	for _, p := range NMAP.portProbeMap[0] {
		r["USED_MATCH"] += len(NMAP.probeGroup[p].matchGroup)
	}
	//fmt.Printf("本次扫描将使用探针:[%d]个,指纹[%d]条\n", USED_PROBE_COUNT,USED_MATCH_COUNT)
	return r
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

func (n *Nmap) getFinger(data string, requestName string) *TcpFinger {
	data = n.convResponse(data)

	f := n.probeGroup[requestName].match(data)

	if f.Service != "" || n.probeGroup[requestName].fallback == "" {
		return f
	}

	fallback := n.probeGroup[requestName].fallback
	for fallback != "" {
		slog.Debug("fallback:", fallback)
		f = n.probeGroup[fallback].match(data)
		fallback = n.probeGroup[fallback].fallback
		if f.Service != "" {
			continue
		}
	}
	return f
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
		slog.Debug("now start ", requestName)
		b.Load(n.getTcpBanner(n.probeGroup[requestName]))
		//如果端口未开放，则等待10s后重新连接
		if b.status == Closed {
			time.Sleep(time.Second * 10)
			b.Load(n.getTcpBanner(n.probeGroup[requestName]))
		}
		slog.Debugf("Target:%s,Probe:%s,Status:%s,Service:%s,Response:%s", b.Target.URI(), requestName, b.StatusDisplay(), b.TcpFinger.Service, strconv.Quote(b.Response.string))
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

func SetScanVersion() {
	//-sV参数深度解析
	AllProbeMap = NMAP.probeSort
}
