package gonmap

type PortInfomation struct {
	response *response
	finger   *Finger
	status   string
	errorMsg error
}

func newPortInfo() *PortInfomation {
	return &PortInfomation{
		response: newResponse(),
		finger:   newFinger(),
		status:   "UNKNOWN",
		errorMsg: nil,
	}
}

func (p *PortInfomation) Load(np *PortInfomation) {
	if p.status == "CLOSED" || p.status == "MATCHED" {
		return
	}
	if p.status == "UNKNOWN" {
		*p = *np
	}
	if p.status == "OPEN" && np.status != "CLOSED" && np.status != "UNKNOWN" {
		*p = *np
	}
	//fmt.Println("加载完成后端口状态为：",p.status)
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
