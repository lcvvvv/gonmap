package gonmap

import (
	"errors"
	"fmt"
	"kscan/lib/misc"
	"kscan/lib/slog"
	"strings"
	"time"
)

var NMAP *Nmap

//r["PROBE"] 总探针数、r["MATCH"] 总指纹数 、r["USED_PROBE"] 已使用探针数、r["USED_MATCH"] 已使用指纹数
func Init(filter int, timeout time.Duration) map[string]int {
	//初始化NMAP探针库
	InitNMAP()
	//fmt.Println("初始化了")
	NMAP = &Nmap{
		exclude:     newPort(),
		probeGroup:  make(map[string]*probe),
		probeSort:   []string{},
		portMap:     make(map[int][]string),
		allPortMap:  []string{},
		probeFilter: 0,
		target:      newTarget(),
		response:    newResponse(),
		finger:      nil,
		filter:      5,
	}
	NMAP.filter = filter
	for i := 0; i <= 65535; i++ {
		NMAP.portMap[i] = []string{}
	}
	NMAP.loads(NMAP_SERVICE_PROBES + NMAP_CUSTOMIZE_PROBES)
	NMAP.AddAllProbe("TCP_NULL")
	NMAP.AddAllProbe("TCP_GetRequest")
	NMAP.AddAllProbe("TCP_SSLv23SessionReq")
	NMAP.AddAllProbe("TCP_SSLSessionReq")
	NMAP.AddAllProbe("TCP_TLSSessionReq")
	NMAP.setTimeout(timeout)
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
	exclude     *port
	probeGroup  map[string]*probe
	probeSort   []string
	probeFilter int
	portMap     map[int][]string
	allPortMap  []string

	target target
	filter int

	response response
	finger   *TcpFinger
}

func (n *Nmap) Scan(ip string, port int) TcpBanner {
	n.target.host = ip
	n.target.port = port
	n.target.uri = fmt.Sprintf("%s:%d", ip, port)

	//拼接端口探测队列，全端口探测放在最后
	b := NewTcpBanner(n.target)
	//生成探针清单
	var probeList []string
	if port == 161 || port == 137 || port == 139 || port == 135 ||
		port == 1433 || port == 6379 || port == 1883 || port == 5432 || port == 1521 {
		probeList = append(n.portMap[port], n.allPortMap...)
	} else {
		probeList = append(n.allPortMap, n.portMap[port]...)
	}
	probeList = misc.RemoveDuplicateElement(probeList)
	//针对探针清单，开始进行全端口探测
	//slog.Debug(probeList)
	for _, requestName := range probeList {
		tls := n.probeGroup[requestName].sslports.Exist(n.target.port)
		nTcpBanner := n.getTcpBanner(n.probeGroup[requestName], tls)
		if nTcpBanner.Status == "CLOSED" {
			time.Sleep(time.Second * 10)
			nTcpBanner = n.getTcpBanner(n.probeGroup[requestName], tls)
		}
		b.Load(nTcpBanner)
		if n.probeGroup[requestName].request.protocol == "TCP" {
			slog.Debug(b.Target.URI(), b.Status, b.TcpFinger.Service, b.Response)
		}
		if b.Status == "CLOSED" || b.Status == "MATCHED" {
			break
		}
		if n.target.port == 53 {
			if DnsScan(n.target.uri) {
				b.TcpFinger.Service = "dns"
				b.Response.string = "dns"
				b.MATCHED()
			} else {
				b.CLOSED()
			}
			break
		}
	}
	//ssl协议二次识别
	if b.TcpFinger.Service == "ssl" {
		b.OPEN()
		sslServiceArr := []string{
			"TCP_TerminalServerCookie",
			"TCP_TerminalServer",
		}
		var t *TcpBanner
		for _, requestName := range sslServiceArr {
			//slog.debug("ssl针对性识别：", requestName, "权重为", n.probeGroup[requestName].rarity)
			t = n.getTcpBanner(n.probeGroup[requestName], false)
			if t.Status == "CLOSED" || t.Status == "MATCHED" {
				b.Load(t)
				break
			}
			t = n.getTcpBanner(n.probeGroup[requestName], true)
			if t.Status == "CLOSED" || t.Status == "MATCHED" {
				b.Load(t)
				break
			}
		}
	}
	//进行最后输出修饰
	if b.TcpFinger.Service == "ssl/http" {
		b.TcpFinger.Service = "https"
	}
	if b.TcpFinger.Service == "ssl/https" {
		b.TcpFinger.Service = "https"
	}
	if b.TcpFinger.Service == "ms-wbt-server" {
		b.TcpFinger.Service = "rdp"
	}
	if b.TcpFinger.Service == "microsoft-ds" {
		b.TcpFinger.Service = "smb"
	}
	if b.TcpFinger.Service == "netbios-ssn" {
		b.TcpFinger.Service = "netbios"
	}
	if b.TcpFinger.Service == "oracle-tns" {
		b.TcpFinger.Service = "oracle"
	}
	if b.TcpFinger.Service == "msrpc" {
		b.TcpFinger.Service = "rpc"
	}
	if b.TcpFinger.Service == "ms-sql-s" {
		b.TcpFinger.Service = "mssql"
	}
	if b.TcpFinger.Service == "domain" {
		b.TcpFinger.Service = "dns"
	}
	if b.TcpFinger.Service == "svnserve" {
		b.TcpFinger.Service = "svn"
	}
	if b.TcpFinger.Service == "ssl" && n.target.port == 3389 {
		b.TcpFinger.Service = "rdp"
	}
	return b
}

func (n *Nmap) getTcpBanner(p *probe, tls bool) *TcpBanner {
	b := NewTcpBanner(n.target)
	data, err := p.scan(n.target, tls)
	if p.request.protocol == "TCP" && err != nil {
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

func (n *Nmap) AddAllProbe(probeName string) {
	n.allPortMap = append(n.allPortMap, probeName)
}

func (n *Nmap) Filter(i int) {
	n.filter = i
}

func (n *Nmap) Status() map[string]int {
	r := make(map[string]int)
	r["PROBE"] = len(NMAP.probeSort)
	r["MATCH"] = 0
	for _, p := range NMAP.probeGroup {
		r["MATCH"] += len(p.matchGroup)
	}
	//fmt.Printf("成功加载探针：【%d】个,指纹【%d】条\n", PROBE_COUNT,MATCH_COUNT)
	r["USED_PROBE"] = len(NMAP.portMap[0])
	r["USED_MATCH"] = 0
	for _, p := range NMAP.portMap[0] {
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

func (n *Nmap) getFinger(data string, requestName string) TcpFinger {
	data = n.convResponse(data)
	f := n.probeGroup[requestName].match(data)
	if f.Service == "" {
		if n.probeGroup[requestName].fallback != "" {
			return n.probeGroup["TCP_"+n.probeGroup[requestName].fallback].match(data)
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
	//if p.ports.length == 0 && p.sslports.length == 0 {
	//	fmt.Println(p.request.name)
	//}
	n.probeSort = append(n.probeSort, p.request.name)
	n.probeGroup[p.request.name] = PROBE

	//建立端口扫描对应表，将根据端口号决定使用何种请求包
	//如果端口列表为空，则为全端口
	if p.rarity > n.filter {
		return
	}
	//0记录所有使用的探针
	n.portMap[0] = append(n.portMap[0], p.request.name)

	//if p.ports.length+p.sslports.length == 0 {
	//	p.ports.Fill()
	//	p.sslports.Fill()
	//	n.allPortMap = append(n.allPortMap, p.request.name)
	//	return
	//}
	//分别压入sslports,ports
	for _, i := range p.ports.value {
		n.portMap[i] = append(n.portMap[i], p.request.name)
	}
	for _, i := range p.sslports.value {
		n.portMap[i] = append(n.portMap[i], p.request.name)
	}

}
