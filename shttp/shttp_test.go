package shttp

import (
	"fmt"
	"path"
	"testing"
)

func TestName(t *testing.T) {
	filepath := "C:\\Users\\Administrator\\Desktop\\user_agents"
	fileExt := path.Ext(filepath)
	fmt.Println(fileExt)
}
