package gonmap

import "fmt"

type PortInfomation struct {
	response *response
	finger   *Finger
	status   string
}

func newPortInfo() *PortInfomation {
	return &PortInfomation{
		response: newResponse(),
		finger:   newFinger(),
		status:   "UNKNOW",
	}
}

func (p *PortInfomation) Length() int {
	return p.response.Length()
}

func (p *PortInfomation) Response() string {
	return p.response.string
}

func (p *PortInfomation) Status() string {
	return p.status
}

func (p *PortInfomation) Service() string {
	return p.finger.Service
}

func (p *PortInfomation) Info() string {
	var s string
	if p.finger.ProductName != "" {
		s += fmt.Sprintf("Product:%s,", p.finger.ProductName)
	}
	if p.finger.Version != "" {
		s += fmt.Sprintf("Version:%s,", p.finger.Version)
	}
	if p.finger.OperatingSystem != "" {
		s += fmt.Sprintf("OS:%s,", p.finger.OperatingSystem)
	}
	if p.finger.Hostname != "" {
		s += fmt.Sprintf("HostName:%s,", p.finger.Hostname)
	}
	if p.finger.DeviceType != "" {
		s += fmt.Sprintf("DeviceType:%s,", p.finger.DeviceType)
	}
	if p.finger.Info != "" {
		s += fmt.Sprintf("OtherInfo:%s,", p.finger.Info)
	}
	if s != "" {
		s = s[:len(s)-1]
	}
	return s
}

func (p *PortInfomation) CLOSED() *PortInfomation {
	p.status = "CLOSED"
	return p
}

func (p *PortInfomation) OPEN() *PortInfomation {
	p.status = "OPEN"
	return p
}

func (p *PortInfomation) MATCHED() *PortInfomation {
	p.status = "MATCHED"
	return p
}

func (p *PortInfomation) Finger() *Finger {
	return p.finger
}
