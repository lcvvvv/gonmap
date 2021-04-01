package gonmap

import (
	"fmt"
	"gonmap/scan"
	"os"
	"strings"
)

func Init() {
	NMAP_SERVICE_PROBES = strings.Replace(NMAP_SERVICE_PROBES, "${backquote}", "`", -1)

}

func New() {
	n := nmap{
		exclude:     newPort(),
		probeGroup:  make(map[string]*probe),
		probeSort:   []string{},
		probeFilter: 0,
		target:      nil,
		response:    nil,
		finger:      nil,
	}
}

func Main() {
	probes := scan.New()
	probes.Load(os.Open("nmap-service-probes.go"))
	//probes.Show()

	t := scan.NewTarget()
	t.Load("www.baidu.com:443", "www.baidu.com", 443)
	fmt.Println(probes.Scan(t))
}

type nmap struct {
	exclude *port

	probeGroup  map[string]*probe
	probeSort   []string
	probeFilter int

	target *target

	response *response
	finger   *finger
}
