package gonmap

import "fmt"

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

func (f *finger) Show() {
	fmt.Println("service:", f.service)
	fmt.Println("productname:", f.productname)
	fmt.Println("version:", f.version)
	fmt.Println("info:", f.info)
	fmt.Println("hostname:", f.hostname)
	fmt.Println("operatingsystem:", f.operatingsystem)
	fmt.Println("devicetype:", f.devicetype)
}
