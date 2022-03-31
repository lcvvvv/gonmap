package gonmap

import "fmt"

type target struct {
	host string
	port int
}

func (t *target) URI() string {
	return fmt.Sprintf("%s:%d", t.host, t.port)
}

func (t *target) Port() int {
	return t.port
}

func (t *target) Addr() string {
	return t.host
}
