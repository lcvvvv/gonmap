package gonmap

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

func (p *portinfo) STATUS() string {
	return p.status
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
