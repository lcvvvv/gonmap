package gonmap

import (
	"fmt"
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

var MATCH_VERSIONINFO_HELPER_P_REGEXP = regexp.MustCompile(`\$P\((\d)\)`)

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

	m.patternRegexp = m.getPatternRegexp(m.pattern, args[3])
	return true
}

func (m *match) getPatternRegexp(pattern string, opt string) *regexp.Regexp {
	pattern = strings.ReplaceAll(pattern, `\0`, `\x00`)
	if opt != "" {
		if pattern[:1] == "^" {
			pattern = fmt.Sprintf("^(?%s:%s", opt, pattern[1:])
		} else {
			pattern = fmt.Sprintf("(?%s:%s", opt, pattern)
		}
		if pattern[len(pattern)-1:] == "$" {
			pattern = fmt.Sprintf("%s)$", pattern[:len(pattern)-1])
		} else {
			pattern = fmt.Sprintf("%s)", pattern)
		}
	}
	//pattern = regexp.MustCompile(`\\x[89a-f][0-9a-f]`).ReplaceAllString(pattern,".")
	return regexp.MustCompile(pattern)
}

func (m *match) getVersionInfo(s string, regID string) string {
	if MATCH_VARSIONINFO_REGEXPS[regID].MatchString(s) {
		return MATCH_VARSIONINFO_REGEXPS[regID].FindStringSubmatch(s)[1]
	} else {
		return ""
	}
}

func (m *match) makeVersionInfo(s string) *finger {
	f := newFinger()
	//fmt.Println(s)
	f.info = m.makeVersionInfoSubHelper(s, m.versioninfo.info, m.patternRegexp)
	f.devicetype = m.makeVersionInfoSubHelper(s, m.versioninfo.devicetype, m.patternRegexp)
	f.hostname = m.makeVersionInfoSubHelper(s, m.versioninfo.hostname, m.patternRegexp)
	f.operatingsystem = m.makeVersionInfoSubHelper(s, m.versioninfo.operatingsystem, m.patternRegexp)
	f.productname = m.makeVersionInfoSubHelper(s, m.versioninfo.productname, m.patternRegexp)
	f.version = m.makeVersionInfoSubHelper(s, m.versioninfo.version, m.patternRegexp)
	f.service = m.makeVersionInfoSubHelper(s, m.versioninfo.service, m.patternRegexp)
	return f
}

func (m *match) makeVersionInfoSubHelper(s string, pattern string, matchPatternRegexp *regexp.Regexp) string {
	if MATCH_VERSIONINFO_HELPER_P_REGEXP.MatchString(pattern) {
		pattern = MATCH_VERSIONINFO_HELPER_P_REGEXP.ReplaceAllStringFunc(pattern, func(repl string) string {
			s := MATCH_VERSIONINFO_HELPER_P_REGEXP.FindStringSubmatch(repl)[1]
			return "$" + s
		})
	}
	pattern = strings.ReplaceAll(pattern, "\n", "")
	pattern = strings.ReplaceAll(pattern, "\r", "")
	return matchPatternRegexp.ReplaceAllString(s, pattern)
}
