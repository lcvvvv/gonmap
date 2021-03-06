package urlparse

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type URL struct {
	Scheme, Netloc, Path string
	Port                 int
	url                  *url.URL
}

func Load(s string) (*URL, error) {
	r, err := url.Parse(s)
	if err != nil {
		if strings.Contains(err.Error(), "first path segment in URL cannot contain colon") || strings.Contains(err.Error(), "missing protocol scheme") {
			r, err = url.Parse("http://" + s)
			if err != nil {
				return nil, err
			}
			r.Scheme = ""
		} else {
			return nil, err
		}
	}
	//fmt.Printf("%#v", r)
	if r.Path != "" && r.Host == "" {
		r.Host = r.Path + ":" + r.Port()
		r.Path = ""
	}
	if r.Scheme != "" && r.Host == "" {
		r.Host = r.Scheme + ":" + r.Port()
		r.Scheme = ""
	}
	return &URL{
		Scheme: func() string {
			if r.Scheme != "" {
				return r.Scheme
			}
			return ""
		}(),
		Netloc: r.Hostname(),
		Path: func() string {
			if r.Path != "" {
				if r.Path[:1] != "/" {
					return "/" + r.Path
				}
			}
			return r.Path
		}(),
		Port: func() int {
			if r.Opaque != "" {
				if p, err := strconv.Atoi(r.Opaque); err == nil {
					return p
				}
			}
			if r.Port() != "" {
				p, _ := strconv.Atoi(r.Port())
				return p
			}
			if r.Scheme == "https" {
				return 443
			}
			if r.Scheme == "http" {
				return 80
			}
			return 80
		}(),
	}, nil
}

func (i *URL) UnParse() string {
	if i.Scheme == "https" && i.Port == 443 {
		return fmt.Sprintf("https://%s%s", i.Netloc, i.Path)
	}
	if i.Scheme == "http" && i.Port == 80 {
		return fmt.Sprintf("http://%s%s", i.Netloc, i.Path)
	}
	if i.Scheme == "" && i.Port != 0 {
		return fmt.Sprintf("%s:%d%s", i.Netloc, i.Port, i.Path)
	}
	return fmt.Sprintf("%s://%s:%d%s", i.Scheme, i.Netloc, i.Port, i.Path)
}
