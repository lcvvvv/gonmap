package gonmap

import (
	"regexp"
	"strconv"
	"strings"
)

var PORT_LOAD_REGEXP = regexp.MustCompile("^(\\d+)(?:-(\\d+))?$")
var PORT_LOAD_REGEXPS = regexp.MustCompile("^(\\d+(?:-\\d+)?)(?:,\\d+(?:-\\d+)?)*$")

type port struct {
	value  []int
	length int
}

func newPort() *port {
	return &port{
		value:  []int{},
		length: 0,
	}
}

func (i *port) Exist(v int) bool {
	if IsInIntArr(i.value, v) {
		return true
	} else {
		return false
	}
}

func (i *port) Push(v int) bool {
	if v > 65535 || v < 0 {
		return false
	}
	if i.Exist(v) {
		return false
	}
	i.value = append(i.value, v)
	i.length += 1
	return true
}

func (i *port) Pushs(iArr []int) int {
	var res int
	for _, v := range iArr {
		if i.Push(v) {
			res += 1
		}
	}
	return res
}

func (i *port) Len() int {
	return i.length
}

func (i *port) Load(expr string) bool {
	if !PORT_LOAD_REGEXP.MatchString(expr) {
		return false
	}
	rArr := PORT_LOAD_REGEXP.FindStringSubmatch(expr)
	var startPort, endPort int
	startPort, _ = strconv.Atoi(rArr[1])
	if rArr[2] != "" {
		endPort, _ = strconv.Atoi(rArr[2])
	} else {
		endPort = startPort
	}
	//fmt.Println(startPort,endPort)
	portArr := Xrange(startPort, endPort)
	i.Pushs(portArr)
	return true
}

func (p *port) LoadS(str string) bool {
	if !PORT_LOAD_REGEXPS.MatchString(str) {
		return false
	}
	for _, s := range strings.Split(str, ",") {
		p.Load(s)
		//if IsInIntArr(p.value,3389){
		//	fmt.Println(s)
		//	os.Exit(0)
		//}
	}
	return true
}

func (p *port) Fill() {
	p.Pushs(Xrange(1, 65535))
}
