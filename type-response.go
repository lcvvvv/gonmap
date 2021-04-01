package gonmap

type response struct {
	string string
}

func newResponse() *response {
	return &response{
		string: "",
	}
}
