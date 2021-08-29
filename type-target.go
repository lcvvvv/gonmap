package gonmap

type target struct {
	port int
	host string
	uri  string
}

func newTarget() target {
	return target{0, "", ""}
}

func (t *target) URI() string {
	return t.uri
}
