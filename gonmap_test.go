package gonmap

import (
	"testing"
)

func TestGonmap(t *testing.T) {
	Init()
	n := New()
	n.Scan("192.168.217.22", 22).Show()
}
