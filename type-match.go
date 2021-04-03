package gonmap

import (
	"regexp"
	"strings"
)

type match struct {
	//match <service> <pattern> <patternopt> [<versioninfo>]
	soft          bool
	service       string
	pattern       string
	patternRegexp *regexp.Regexp
	versioninfo   *finger
}

var MATCH_LOAD_REGEXPS = []*regexp.Regexp{
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m\\|([^|]+)\\|([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m=([^=]+)=([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m%([^%]+)%([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m@([^@]+)@([is]{0,2})(?: (.*))?$"),
}

var MATCH_VARSIONINFO_REGEXPS = map[string]*regexp.Regexp{
	"PRODUCTNAME": regexp.MustCompile("p/([^/]+)/"),
	"VERSION":     regexp.MustCompile("v/([^/]+)/"),
	"INFO":        regexp.MustCompile("i/([^/]+)/"),
	"HOSTNAME":    regexp.MustCompile("h/([^/]+)/"),
	"OS":          regexp.MustCompile("o/([^/]+)/"),
	"DEVICE":      regexp.MustCompile("d/([^/]+)/"),
}

func newMatch() *match {
	return &match{
		soft:        false,
		service:     "",
		pattern:     "",
		versioninfo: newFinger(),
	}
}

func (m *match) load(s string, soft bool) bool {
	var MATCH_LOAD_REGEXP *regexp.Regexp
	for _, r := range MATCH_LOAD_REGEXPS {
		if r.MatchString(s) {
			MATCH_LOAD_REGEXP = r
		}
	}
	if MATCH_LOAD_REGEXP == nil {
		return false
	}
	args := MATCH_LOAD_REGEXP.FindStringSubmatch(s)
	m.soft = soft
	m.service = args[1]
	m.pattern = args[2]
	m.versioninfo.service = m.service
	m.versioninfo.productname = m.getVersionInfo(s, "PRODUCTNAME")
	m.versioninfo.version = m.getVersionInfo(s, "VERSION")
	m.versioninfo.info = m.getVersionInfo(s, "INFO")
	m.versioninfo.hostname = m.getVersionInfo(s, "HOSTNAME")
	m.versioninfo.operatingsystem = m.getVersionInfo(s, "OS")
	m.versioninfo.devicetype = m.getVersionInfo(s, "INFO")
	m.patternRegexp = m.getPatternRegexp(m.pattern)
	return true
}

func (m *match) getPatternRegexp(pattern string) *regexp.Regexp {
	pattern = strings.ReplaceAll(pattern, `\0`, `\00`)
	return regexp.MustCompile(pattern)
}

func (m *match) getVersionInfo(s string, regID string) string {
	if MATCH_VARSIONINFO_REGEXPS[regID].MatchString(s) {
		return MATCH_VARSIONINFO_REGEXPS[regID].FindStringSubmatch(s)[1]
	} else {
		return ""
	}
}
