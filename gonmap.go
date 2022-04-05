package gonmap

import (
	"log"
	"os"
	"strings"
	"time"
)

var NMAP *Nmap

var BypassAllProbePortMap = []int{161, 137, 139, 135, 389, 443, 548, 1433, 6379, 1883, 5432, 1521, 3389, 3388, 3389, 33890, 33900}
var SSLSecondProbeMap = []string{"TCP_TerminalServerCookie", "TCP_TerminalServer"}
var AllProbeMap = []string{"TCP_GetRequest", "TCP_NULL"}
var SSLProbeMap = []string{"TCP_TLSSessionReq", "TCP_SSLSessionReq", "TCP_SSLv23SessionReq"}

var ProbesCount = 0     //探针数
var MatchCount = 0      //指纹数
var UsedProbesCount = 0 //已使用探针数
var UsedMatchCount = 0  //已使用探针数

var logger = Logger(log.New(os.Stderr, "[gonmap] ", log.Ldate|log.Ltime|log.Lshortfile))

type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

func SetLogger(v Logger) {
	logger = v
}

//r["PROBE"] 总探针数、r["MATCH"] 总指纹数 、r["USED_PROBE"] 已使用探针数、r["USED_MATCH"] 已使用指纹数
func Init(filter int) {
	//初始化NMAP探针库
	repairNMAPString()
	NMAP = &Nmap{
		exclude:        newPort(),
		probeGroup:     make(map[string]*probe),
		probeSort:      []string{},
		portProbeMap:   make(map[int][]string),
		usedProbeSlice: []string{},

		target:   target{},
		response: newResponse(),
		finger:   nil,
		filter:   5,
	}
	NMAP.filter = filter
	for i := 0; i <= 65535; i++ {
		NMAP.portProbeMap[i] = []string{}
	}
	NMAP.loads(NMAP_SERVICE_PROBES + NMAP_CUSTOMIZE_PROBES)
	//修复fallback
	NMAP.fixFallback()
	//新增自定义指纹信息
	customNMAPMatch()
	//优化检测逻辑，及端口对应的默认探针
	optimizeNMAPProbes()
	//输出统计数据状态
	statistical()
}

func statistical() {
	ProbesCount = len(NMAP.probeSort)
	for _, p := range NMAP.probeGroup {
		MatchCount += len(p.matchGroup)
	}
	UsedProbesCount = len(NMAP.portProbeMap[0])
	for _, p := range NMAP.portProbeMap[0] {
		UsedMatchCount += len(NMAP.probeGroup[p].matchGroup)
	}
}

func repairNMAPString() {
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, "${backquote}", "`")
	NMAP_SERVICE_PROBES = strings.ReplaceAll(NMAP_SERVICE_PROBES, `q|GET / HTTP/1.0\r\n\r\n|`,
		`q|GET / HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)\r\nAccept: */*\r\n\r\n|`)
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

func customNMAPMatch() {
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

}

func optimizeNMAPProbes() {
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
	//将TCP_GetRequest的fallback参数设置为NULL探针，避免漏资产
	NMAP.probeGroup["TCP_GetRequest"].fallback = "TCP_NULL"
	NMAP.probeGroup["TCP_TerminalServerCookie"].fallback = "TCP_GetRequest"
	NMAP.probeGroup["TCP_TerminalServer"].fallback = "TCP_GetRequest"
}

func New() *Nmap {
	n := &Nmap{}
	*n = *NMAP
	return n
}

func SetScanVersion() {
	//-sV参数深度解析
	AllProbeMap = NMAP.probeSort
}

func SetTimeout(timeout time.Duration) {
	//配置超时时间
	NMAP.setTimeout(timeout)
}
