package gonmap

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPortScan(t *testing.T) {
	Init(9)
	tcpBanner := GetTcpBanner("www.baidu.com", 80, New(), time.Second*5)
	fmt.Print(tcpBanner.Response)
}

func TestGonmap(t *testing.T) {
	Init(9)

	nmap := New()
	var text []string
	for _, value := range nmap.probeGroup {
		var row []string
		row = append(row, value.request.name)
		row = append(row, value.request.protocol)
		row = append(row, strconv.Quote(value.request.string))
		row = append(row, strconv.Itoa(len(value.matchGroup)))
		row = append(row, fmt.Sprint(value.ports.value))
		row = append(row, fmt.Sprint(value.sslports.value))
		row = append(row, fmt.Sprint(value.rarity))
		for _, match := range value.matchGroup {
			var mrow []string
			mrow = append(mrow, match.service)
			mrow = append(mrow, match.versioninfo.Hostname)
			mrow = append(mrow, match.versioninfo.DeviceType)
			mrow = append(mrow, match.versioninfo.OperatingSystem)
			mrow = append(mrow, match.versioninfo.ProductName)
			mrow = append(mrow, match.versioninfo.Version)
			mrow = append(mrow, match.patternRegexp.String())
			for index, value := range mrow {
				mrow[index] = strings.ReplaceAll(value, ",", "[douhao]")
			}
			line := fmt.Sprintf("%s,%s", strings.Join(row, ","), strings.Join(mrow, ","))
			text = append(text, line)
		}
	}
}
