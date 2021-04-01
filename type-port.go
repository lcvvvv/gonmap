package gonmap

type port struct {
	value  []int
	length int
}

func newPort() *port {
	return &port{
		value:  []int{},
		length: 0,
	}
}

func (i *port) Exist(v int) bool {
	if IsInIntArr(i.value, v) {
		return true
	} else {
		return false
	}
}

func (i *port) Push(v int) bool {
	if v > 65535 || v < 0 {
		return false
	}
	if i.Exist(v) {
		return false
	}
	i.value = append(i.value, v)
	i.length += 1
	return true
}

func (i *port) Pushs(iArr []int) int {
	var res int
	for _, v := range iArr {
		if i.Push(v) {
			res += 1
		}
	}
	return res
}

func (i *port) Len() int {
	return i.length
}
