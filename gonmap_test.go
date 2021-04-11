package gonmap

import (
	"fmt"
	"testing"
	"time"
)

func TestGonmap(t *testing.T) {
	status := Init(9)
	fmt.Printf("[INFO] 成功加载探针:[%d]个,指纹[%d]条\n", status["PROBE"], status["MATCH"])
	fmt.Printf("[INFO] 本次扫描将使用探针:[%d]个,指纹[%d]条\n", status["USED_PROBE"], status["USED_MATCH"])
	n := New()
	r := n.SafeScan("193.112.63.109", 80, 5*time.Second)
	fmt.Printf("%s\t%s\t%s\t%s\n", n.target.uri, r.status, r.Service(), r.finger.Information())

	//for i := 1; i <= 10000; i++ {
	//	fmt.Println("开始探测端口：",i)
	//	fmt.Println(n.Scan("192.168.217.1", 139))
	//if n.Scan("192.168.217.1", i) != nil {
	//	fmt.Println(i," is open")
	//}
	//}

	//var s = `00000073ff534d4272000000008803400000000000000000000000000000400600000100110600033200010004410000000001003c2e0000fdf38000332400a46829d70120fe082e0055c8fcbf5c32ccfd57004f0052004b00470052004f00550050000000440053003300360031003700580053000000`
	//b, _ := hex.DecodeString(s)
	//s = string(b)
	//
	//var ns = hex.EncodeToString([]byte(s))
	//fmt.Println(ns)
	//s1 := "\x00\x00\x00\x73\xff"
	//r1 := regexp.MustCompile(`\x00\x00\x00\x73\xff`)
	//fmt.Printf("%x\n",s1)
	//fmt.Println(r1.MatchString(s1))
	////00000073c3bf
	////false
	//s2 := "\x00\x00\x00\x73\xc3\xbf"
	//r2 := regexp.MustCompile(`\x00\x00\x00\x73\xff`)
	//fmt.Printf("%x\n",s2)
	//fmt.Println(r2.MatchString(s2))
	//00000073c3bf
	//true

	//s1 := "\x00\x00\x00\x73\xff"
	//b1 := []byte(s1)
	//r1 := []rune{}
	//for _,i := range b1 {
	//	r1 = append(r1,rune(i))
	//}
	//s2 := string(r1)
	//fmt.Printf("%x\n",s2)
	//

	//r := []rune{15*16 + 15}
	//rs := string(r)
	//
	//fmt.Printf("%x\n",r)
	//fmt.Printf("%x\n",rs)
	//fmt.Printf("%x\n",s)
	//fmt.Printf("%s\n",s)
	//for i:=0;i<=10;i++ {
	//	r := regexp.MustCompile(`\x00\x00\x00\x73\xff`)
	//	fmt.Println(r.MatchString(s))
	//}
	////r := regexp.MustCompile(`^(?s:\x00\x00\x00.\xffSMBr\x00\x00\x00\x00\x88..\x00\x00[-\w. ]*\x00+@\x06\x00\x00\x01\x00\x11\x06\x00.{42}(.*)\x00\x00(.*)\x00\x00)$`)

}
