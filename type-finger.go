package gonmap

type finger struct {
	service         string
	productname     string
	version         string
	info            string
	hostname        string
	operatingsystem string
	devicetype      string
	//  p/vendorproductname/
	//	v/version/
	//	i/info/
	//	h/hostname/
	//	o/operatingsystem/
	//	d/devicetype/
}

func newFinger() *finger {
	return &finger{
		service:         "",
		productname:     "",
		version:         "",
		info:            "",
		hostname:        "",
		operatingsystem: "",
		devicetype:      "",
	}
}
