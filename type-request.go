package gonmap

type request struct {
	//Probe <protocol> <probename> <probestring>
	protocol string
	name     string
	string   string
}

func newRequest() *request {
	return &request{
		protocol: "",
		name:     "",
		string:   "",
	}
}
