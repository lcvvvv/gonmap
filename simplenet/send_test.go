package simplenet

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"
)

func TestName(t *testing.T) {
	response, err := Send("tcp", "125.253.123.22:3306", "", time.Second*3, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	responseBuf := []byte(response)
	printStr := ""
	for _, charBuf := range responseBuf {
		if strconv.IsPrint(rune(charBuf)) {
			if charBuf > 0x7f {
				printStr += "?"
			} else {
				printStr += string(charBuf)
			}
			continue
		}
		printStr += fmt.Sprintf("\\x%x", string(charBuf))
	}

	r := regexp.MustCompile(`.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00`)
	fmt.Println(printStr)
	fmt.Println(r.MatchString(response))

}

func convData(s string) string {
	b := []byte(s)
	var r []rune
	for _, i := range b {
		r = append(r, rune(i))
	}
	return string(r)
}

func TestRuneALl(t *testing.T) {
	for i := 0; i <= 0xffff; i++ {
		fmt.Println(string(rune(i)), " ", fmt.Sprintf("\\%x", i))
	}
}

func IsPrint(r rune) bool {
	if r < 20 {
		return false
	}
	if r > 0x7f {
		return false
	}
	return true
}
