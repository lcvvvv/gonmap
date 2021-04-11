package gonmap

import "fmt"

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

func (f *Finger) Information() string {
	var s string
	if f.ProductName != "" {
		s += fmt.Sprintf("Product:%s,", f.ProductName)
	}
	if f.Version != "" {
		s += fmt.Sprintf("Version:%s,", f.Version)
	}
	if f.OperatingSystem != "" {
		s += fmt.Sprintf("OS:%s,", f.OperatingSystem)
	}
	if f.Hostname != "" {
		s += fmt.Sprintf("HostName:%s,", f.Hostname)
	}
	if f.DeviceType != "" {
		s += fmt.Sprintf("DeviceType:%s,", f.DeviceType)
	}
	if f.Info != "" {
		s += fmt.Sprintf("OtherInfo:%s,", f.Info)
	}
	if s != "" {
		s = s[:len(s)-1]
	}
	return s
}
