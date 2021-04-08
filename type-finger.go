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

func (f *finger) Map() map[string]string {
	r := make(map[string]string)
	r["service"] = f.service
	r["productname"] = f.productname
	r["version"] = f.version
	r["info"] = f.info
	r["hostname"] = f.hostname
	r["operatingsystem"] = f.operatingsystem
	r["devicetype"] = f.devicetype
	return r
}

//func (f *finger) Show() {
//	fmt.Println("service:", f.service)
//	fmt.Println("productname:", f.productname)
//	fmt.Println("version:", f.version)
//	fmt.Println("info:", f.info)
//	fmt.Println("hostname:", f.hostname)
//	fmt.Println("operatingsystem:", f.operatingsystem)
//	fmt.Println("devicetype:", f.devicetype)
//}
