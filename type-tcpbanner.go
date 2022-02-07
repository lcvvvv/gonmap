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
	TcpFinger TcpFinger
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
	if p.status == Closed || p.status == Matched {
		return
	}
	if p.status == Unknown {
		*p = *np
	}
	if p.status == Open && np.status != Closed && np.status != Unknown {
		*p = *np
	}
	//fmt.Println("加载完成后端口状态为：",p.status)
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
