package gonmap

import "fmt"

type portinfo struct {
	response *response
	finger   *finger
	status   string
}

func newPortInfo() *portinfo {
	return &portinfo{
		response: newResponse(),
		finger:   newFinger(),
		status:   "UNKNOW",
	}
}

func (p *portinfo) Length() int {
	return p.response.Length()
}

func (p *portinfo) Response() string {
	return p.response.string
}

func (p *portinfo) Status() string {
	return p.status
}

func (p *portinfo) Service() string {
	return p.finger.service
}

func (p *portinfo) Info() string {
	var s string
	if p.finger.productname != "" {
		s += fmt.Sprintf("Product:%s,", p.finger.productname)
	}
	if p.finger.version != "" {
		s += fmt.Sprintf("Version:%s,", p.finger.version)
	}
	if p.finger.operatingsystem != "" {
		s += fmt.Sprintf("OS:%s,", p.finger.operatingsystem)
	}
	if p.finger.hostname != "" {
		s += fmt.Sprintf("HostName:%s,", p.finger.hostname)
	}
	if p.finger.devicetype != "" {
		s += fmt.Sprintf("DeviceType:%s,", p.finger.devicetype)
	}
	if p.finger.info != "" {
		s += fmt.Sprintf("OtherInfo:%s,", p.finger.info)
	}
	if s != "" {
		s = s[:len(s)-1]
	}
	return s
}

func (p *portinfo) Map() map[string]string {
	return p.finger.Map()
}

func (p *portinfo) CLOSED() *portinfo {
	p.status = "CLOSED"
	return p
}

func (p *portinfo) OPEN() *portinfo {
	p.status = "OPEN"
	return p
}

func (p *portinfo) MATCHED() *portinfo {
	p.status = "MATCHED"
	return p
}
