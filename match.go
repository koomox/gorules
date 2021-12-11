package gorules

import (
	"net"
	"regexp"
	"strings"
)

const (
	typeIPv4 byte = 0x01 // type is ipv4 address
	typeDm   byte = 0x03 // type is domain address
	typeIPv6 byte = 0x04 // type is ipv6 address

	ActionAccept = "ACCEPT"
	ActionProxy  = "PROXY"
	ActionReject = "REJECT"
	ActionDirect = "DIRECT"
)

func (c *Filter) MatchBypass(host string) (match, action string) {
	r := c.matchBypass(host)
	if r != nil {
		return r.Match, r.Action
	}

	return
}

func (c *Filter) matchBypass(addr string) *Rule {
	if c.bypassDomains != nil {
		ip := net.ParseIP(addr)
		for _, h := range c.bypassDomains {
			var bypass = false
			var isIp = nil != ip
			switch h.(type) {
			case net.IP:
				if isIp {
					bypass = ip.Equal(h.(net.IP))
				}
			case *net.IPNet:
				if isIp {
					bypass = h.(*net.IPNet).Contains(ip)
				}
			case string:
				dm := h.(string)
				r := regexp.MustCompile("^" + dm + "$")
				bypass = r.MatchString(addr)
			}
			if bypass {
				return &Rule{Match: "bypass", Action: "DIRECT"}
			}
		}
	}

	return nil
}

func (c *Filter) MatchGit(host string) bool {
	s := domainSuffix(host)
	for _, suffix := range c.ruleGit {
		if s == suffix {
			return true
		}
	}

	return false
}

func (c *Filter) MatchHosts(host string) string {
	for _, rule := range c.ruleHosts {
		if strings.EqualFold(host, rule.Host) {
			return rule.Addr
		}
	}

	return ""
}

func (c *Filter) MatchPort(port string) bool {
	if _, ok := c.rulePort.Get(port); ok {
		return true
	}

	return false
}

func (c *Filter) MatchRule(host string, typeHost byte) (match, action string) {
	rule := c.matchRule(host, typeHost)
	if rule == nil {
		return
	}
	return strings.ToLower(rule.Match), strings.ToLower(rule.Action)
}

func (c *Filter) MatchExtension(host string) (match, action string) {
	if c.extDomains != nil {
		for _, rule := range c.extDomains { // "DOMAIN"
			if host == rule.Match {
				return rule.Match, rule.Action
			}
		}
	}
	if c.extSuffixDomains != nil {
		s := domainSuffix(host)
		for _, rule := range c.extSuffixDomains { // "DOMAIN-SUFFIX"
			if s == rule.Match {
				return rule.Match, rule.Action
			}
		}
	}

	return
}
