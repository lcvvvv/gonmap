package gonmap

type response struct {
	string string
	tls    bool
}

func newResponse() response {
	return response{
		string: "",
		tls:    false,
	}
}

func (r response) Length() int {
	return len(r.string)
}

func (r response) Value() string {
	return r.string
}

func (r response) TLS() bool {
	return r.tls
}
