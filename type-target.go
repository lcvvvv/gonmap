package gonmap

type target struct {
	port int
	host string
	uri  string
}

func newTarget() target {
	return target{0, "", ""}
}
