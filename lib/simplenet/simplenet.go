package simplenet

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

func tcpSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	conn, err := net.DialTimeout(protocol, netloc, duration)
	if err != nil {
		//fmt.Println(conn)
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	buf := make([]byte, size)
	_, err = conn.Write([]byte(data))
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	//设置读取超时Deadline
	_ = conn.SetReadDeadline(time.Now().Add(duration * 2))
	//等待回复时长
	time.Sleep(time.Second)
	//读取数据
	length, err := conn.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return "", errors.New(err.Error() + " STEP3:READ")
	}
	if length == 0 {
		return "", errors.New("STEP3:response is empty")
	}
	return string(buf[:length]), nil
}

func tlsSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	dial := &net.Dialer{
		Timeout:  duration,
		Deadline: time.Now().Add(duration * 2),
	}
	conn, err := tls.DialWithDialer(dial, protocol, netloc, config)
	if err != nil {
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	_, err = io.WriteString(conn, data)
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	buf := make([]byte, size)
	_ = conn.SetReadDeadline(time.Now().Add(duration * 2))
	//等待回复时长
	time.Sleep(time.Second)
	//读取数据
	length, err := conn.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return "", errors.New(err.Error() + " STEP3:READ")
	}
	if length == 0 {
		return "", errors.New("response is empty")
	}
	return string(buf[:length]), nil
}

func TcpConnectCheck(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	conn, err := net.DialTimeout(protocol, netloc, duration)
	if err != nil {
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	buf := make([]byte, size)
	_, err = conn.Write([]byte(data))
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	//设置读取超时Deadline
	_ = conn.SetReadDeadline(time.Now().Add(duration))
	//等待回复时长
	time.Sleep(time.Millisecond * 500)
	//读取数据
	length, err := conn.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return "", errors.New(err.Error() + " STEP3:READ")
	}
	if length == 0 {
		return "", errors.New("STEP3:response is empty")
	}
	return string(buf[:length]), nil
}

func Send(protocol string, tls bool, netloc string, data string, duration time.Duration, size int) (string, error) {
	if tls {
		return tlsSend(protocol, netloc, data, duration, size)
	} else {
		return tcpSend(protocol, netloc, data, duration, size)
	}
}
