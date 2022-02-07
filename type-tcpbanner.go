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
	Status    int
	ErrorMsg  error
}

func NewTcpBanner(target target) TcpBanner {
	return TcpBanner{
		Target:    target,
		Response:  newResponse(),
		TcpFinger: newFinger(),
		Status:    Unknown,
		ErrorMsg:  nil,
	}
}

func (p *TcpBanner) Load(np *TcpBanner) {
	if p.Status == Closed || p.Status == Matched {
		return
	}
	if p.Status == Unknown {
		*p = *np
	}
	if p.Status == Open && np.Status != Closed && np.Status != Unknown {
		*p = *np
	}
	//fmt.Println("加载完成后端口状态为：",p.status)
}

func (p *TcpBanner) Length() int {
	return p.Response.Length()
}

func (p *TcpBanner) CLOSED() *TcpBanner {
	p.Status = Closed
	return p
}

func (p *TcpBanner) OPEN() *TcpBanner {
	p.Status = Open
	return p
}

func (p *TcpBanner) MATCHED() *TcpBanner {
	p.Status = Matched
	return p
}
