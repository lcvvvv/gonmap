package gonmap

type Finger struct {
	Service         string
	ProductName     string
	Version         string
	Info            string
	Hostname        string
	OperatingSystem string
	DeviceType      string
	//  p/vendorproductname/
	//	v/version/
	//	i/info/
	//	h/hostname/
	//	o/operatingsystem/
	//	d/devicetype/
}

func newFinger() *Finger {
	return &Finger{
		Service:         "",
		ProductName:     "",
		Version:         "",
		Info:            "",
		Hostname:        "",
		OperatingSystem: "",
		DeviceType:      "",
	}
}
