package shttp

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"path"
	"testing"
)

func TestName(t *testing.T) {
	filepath := "C:\\Users\\Administrator\\Desktop\\user_agents"
	fileExt := path.Ext(filepath)
	fmt.Println(fileExt)
}

func TestHttps(t *testing.T) {
	request, err := http.NewRequest("GET", "http://192.168.3.158:80", nil)
	if err != nil {
		fmt.Println(err.Error(), "1")
		return
	}
	request.Header.Add("User-Agent", getUserAgent())
	request.Header.Add("Cookie", "rememberMe=b69375edcb2b3c5084c02bd9690b6625")
	request.Close = true
	tr := &http.Transport{}
	(*tr).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	(*tr).DisableKeepAlives = false
	client := &http.Client{}
	client.Transport = tr
	resp, err := client.Do(request)
	if err != nil {
		fmt.Println(err.Error(), "2")
		return
	}
	fmt.Println(resp, err)
}
