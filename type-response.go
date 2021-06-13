package gonmap

type response struct {
	string string
}

func newResponse() response {
	return response{
		string: "",
	}
}

func (r response) Length() int {
	return len(r.string)
}
