package gonmap

const (
	Closed  = 0x00001
	Open    = 0x00002
	Matched = 0x00003
	Unknown = 0x00004
)

type TcpBanner struct {
	Target    target
	Response  response
	TcpFinger *TcpFinger
	ErrorMsg  error

	status int
}

func NewTcpBanner(target target) TcpBanner {
	return TcpBanner{
		Target:    target,
		Response:  newResponse(),
		TcpFinger: newFinger(),
		status:    Unknown,
		ErrorMsg:  nil,
	}
}

func (p *TcpBanner) Load(np *TcpBanner) {
	if p.status == Unknown {
		*p = *np
	}
	if p.status == Closed {
		*p = *np
	}
	if p.status == Open && np.status != Unknown && np.status != Closed {
		*p = *np
	}
	if p.status == Matched && np.status == Matched && np.TcpFinger.Service != "ssl" {
		*p = *np
	}
}

func (p *TcpBanner) Length() int {
	return p.Response.Length()
}

func (p *TcpBanner) CLOSED() *TcpBanner {
	p.status = Closed
	return p
}

func (p *TcpBanner) OPEN() *TcpBanner {
	p.status = Open
	p.TcpFinger.Service = "unknown"
	return p
}

func (p *TcpBanner) MATCHED() *TcpBanner {
	p.status = Matched
	return p
}

func (p *TcpBanner) Status() string {
	switch p.status {
	case 0x00001:
		return "Closed"
	case 0x00002:
		return "Open"
	case 0x00003:
		return "Matched"
	case 0x00004:
		return "Unknown"
	default:
		return "Unknown"
	}
}
