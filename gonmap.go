package gonmap

import (
	"errors"
	"fmt"
	"strings"
)

var NMAP *nmap

//r["PROBE"] 总探针数、r["MATCH"] 总指纹数 、r["USED_PROBE"] 已使用探针数、r["USED_MATCH"] 已使用指纹数
func Init(filter int) map[string]int {
	//fmt.Println("初始化了")
	r := make(map[string]int)
	NMAP_SERVICE_PROBES = strings.Replace(NMAP_SERVICE_PROBES, "${backquote}", "`", -1)
	NMAP = &nmap{
		exclude:     newPort(),
		probeGroup:  make(map[string]*probe),
		probeSort:   []string{},
		portMap:     make(map[int][]string),
		allPortMap:  []string{},
		probeFilter: 0,
		target:      newTarget(),
		response:    nil,
		finger:      nil,
		filter:      5,
	}
	NMAP.filter = filter
	for i := 0; i <= 65535; i++ {
		NMAP.portMap[i] = []string{}
	}
	NMAP.loads(NMAP_SERVICE_PROBES)
	NMAP.allPortMap = append(NMAP.allPortMap, "TCP_GetRequest")

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

func New() *nmap {
	n := &nmap{}
	*n = *NMAP
	return n
}

type nmap struct {
	exclude *port

	probeGroup  map[string]*probe
	probeSort   []string
	probeFilter int
	portMap     map[int][]string
	allPortMap  []string

	target *target
	filter int

	response *response
	finger   *finger
}

func (n *nmap) Scan(ip string, port int) *portinfo {
	n.target.host = ip
	n.target.port = port
	n.target.uri = fmt.Sprintf("%s:%d", ip, port)

	//fmt.Println(n.portMap[port])
	//拼接端口探测队列，全端口探测放在最后
	portinfo := newPortInfo()
	//开始特定端口探测
	for _, requestName := range n.portMap[port] {
		//fmt.Println("开始探测：", requestName, "权重为", n.probeGroup[requestName].rarity)
		tls := n.probeGroup[requestName].sslports.Exist(n.target.port)
		portinfo = n.getPortInfo(n.probeGroup[requestName], n.target, tls)
		if portinfo.status == "CLOSE" || portinfo.status == "MATCHED" {
			break
		}
	}
	if portinfo.status == "CLOSE" || portinfo.status == "MATCHED" {
		return portinfo
	}
	//开始全端口探测
	for _, requestName := range n.allPortMap {
		fmt.Println("开始全端口探测：", requestName, "权重为", n.probeGroup[requestName].rarity)
		portinfo = n.getPortInfo(n.probeGroup[requestName], n.target, false)
		if portinfo.status == "CLOSE" || portinfo.status == "MATCHED" {
			break
		}
		portinfo = n.getPortInfo(n.probeGroup[requestName], n.target, true)
		if portinfo.status == "CLOSE" || portinfo.status == "MATCHED" {
			break
		}
	}
	return portinfo
}

func (n *nmap) getPortInfo(p *probe, target *target, tls bool) *portinfo {
	portinfo := newPortInfo()
	data, err := p.scan(target, tls)
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return portinfo.CLOSED()
		}
		if strings.Contains(err.Error(), "close") {
			return nil
		}
		fmt.Println(err)
		return portinfo
	} else {
		portinfo.response.string = data
		//若存在返回包，则开始捕获指纹
		//fmt.Printf("成功捕获到返回包，返回包为：%x\n", data)
		//fmt.Printf("成功捕获到返回包，返回包长度为：%x\n", len(data))
		portinfo.finger = n.getFinger(data, p.request.name)
		if portinfo.finger.service == "" {
			return portinfo.OPEN()
		} else {
			return portinfo.MATCHED()
		}
		//如果成功匹配指纹，则直接返回指纹
	}
}

func (n *nmap) getFinger(data string, requestName string) *finger {
	data = n.convResponse(data)
	f := n.probeGroup[requestName].match(data)
	if f.service == "" {
		if n.probeGroup[requestName].fallback != "" {
			return n.probeGroup["TCP_"+n.probeGroup[requestName].fallback].match(data)
		}
	}
	return f
}

func (n *nmap) convResponse(s1 string) string {
	//	为了适配go语言的沙雕正则，只能讲二进制强行转换成UTF-8
	b1 := []byte(s1)
	r1 := []rune{}
	for _, i := range b1 {
		r1 = append(r1, rune(i))
	}
	s2 := string(r1)
	return s2
}

func (n *nmap) loads(s string) {
	lines := strings.Split(s, "\n")
	probeArr := []string{}
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

func (n *nmap) loadExclude(expr string) {
	var exclude = newPort()
	expr = expr[strings.Index(expr, " ")+1:]
	for _, s := range strings.Split(expr, ",") {
		if !exclude.Load(s) {
			panic(errors.New("exclude 语句格式错误"))
		}
	}
	n.exclude = exclude
}

func (n *nmap) pushProbe(p *probe) {
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

	if p.ports.length+p.sslports.length == 0 {
		p.ports.Fill()
		p.sslports.Fill()
		n.allPortMap = append(n.allPortMap, p.request.name)
		return
	}
	//分别压入sslports,ports
	for _, i := range p.ports.value {
		n.portMap[i] = append(n.portMap[i], p.request.name)
	}
	for _, i := range p.sslports.value {
		n.portMap[i] = append(n.portMap[i], p.request.name)
	}

}

func (n *nmap) isCommand(line string) bool {
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

func (n *nmap) Filter(i int) {
	n.filter = i
}
