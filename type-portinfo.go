package gonmap

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
