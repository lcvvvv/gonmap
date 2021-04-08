package simplenet

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

func Send(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	conn, err := net.DialTimeout(protocol, netloc, duration)
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	_, err = io.WriteString(conn, data)
	if err != nil {
		_ = conn.Close()
		return "", err
	}
	length, err := conn.Read(buf)
	if err != nil && err.Error() != "EOF" {
		_ = conn.Close()
		return "", err
	}
	_ = conn.Close()
	if length == 0 {
		return "", errors.New("response is empty")
	}
	return string(buf[:length]), nil
}

func TLSSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
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
		return "", err
	}
	_, err = io.WriteString(conn, data)
	if err != nil {
		_ = conn.Close()
		return "", err
	}
	buf := make([]byte, size)
	length, err := conn.Read(buf)
	if err != nil && err.Error() != "EOF" {
		_ = conn.Close()
		return "", err
	}
	_ = conn.Close()
	if length == 0 {
		return "", errors.New("response is empty")
	}
	return string(buf[:length]), nil
}
