package gorules

import (
	"net"
	"strings"
)

func readArrayLine(source string) []string {
	out := strings.Split(source, ",")
	for i, str := range out {
		out[i] = strings.TrimSpace(str)
	}
	return out
}

func (c *Filter) FromRules(b []byte) {
	str := strings.ReplaceAll(string(b), "\r", "")
	lines := strings.Split(str, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "skip-proxy") || strings.HasPrefix(strings.ToLower(line), "bypass-tun") {
			items := strings.Split(line, "=")
			c.systemBypass = append(c.systemBypass, readArrayLine(items[1])...)
			continue
		}
		items := readArrayLine(line)
		ruleName := strings.ToLower(items[0])
		switch ruleName {
		case "user-agent":
			c.ruleUserAgent = append(c.ruleUserAgent, &Rule{Match: items[1], Action: strings.ToLower(items[2])})
		case "domain":
			key := items[1]
			c.ruleDomains[key] = strings.ToLower(items[2])
		case "domain-suffix":
			c.ruleSuffixDomains.Put(items[1], &Rule{Match: items[1], Action: strings.ToLower(items[2])})
		case "domain-country":
			c.ruleCountryDomains = append(c.ruleCountryDomains, &Rule{Match: items[1], Action: strings.ToLower(items[2])})
		case "domain-keyword":
			c.ruleKeywordDomains = append(c.ruleKeywordDomains, &Rule{Match: items[1], Action: strings.ToLower(items[2])})
		case "ip-cidr":
			_, cidr, err := net.ParseCIDR(items[1])
			if err != nil {
				continue
			}
			c.ruleIPCIDR = append(c.ruleIPCIDR, &RuleIPCIDR{Match: cidr, Action: strings.ToLower(items[2])})
		case "geoip":
			c.ruleGeoIP = append(c.ruleGeoIP, &Rule{Match: items[1], Action: strings.ToLower(items[2])})
		case "final":
			c.ruleFinal = &Rule{Match: "final", Action: strings.ToUpper(items[1])}
		}
	}

	c.bypassDomains = make([]interface{}, len(c.systemBypass))
	for i, v := range c.systemBypass {
		ip := net.ParseIP(v)
		if nil != ip {
			c.bypassDomains[i] = ip
		} else if _, n, err := net.ParseCIDR(v); err == nil {
			c.bypassDomains[i] = n
		} else {
			c.bypassDomains[i] = v
		}
	}

	return
}

func (c *Filter) matchRule(host string, typeHost byte) (rule *Rule) {
	rule = c.matchBypass(host)
	if nil == rule {
		switch typeHost {
		case typeIPv4, typeIPv6:
			rule = c.matchIpRule(host)
		case typeDm:
			rule = c.matchDomainRule(host)
		}
	}
	if nil == rule {
		if nil != c.ruleFinal {
			rule = c.ruleFinal
		} else {
			rule = &Rule{Match: "default", Action: "DIRECT"}
		}
	}

	return rule
}

func (c *Filter) matchDomainRule(domain string) (r *Rule) {
	//
	if v, ok := c.ruleDomains[domain]; ok { // DOMAIN
		return &Rule{Match: domain, Action: v}
	}
	d := domainSuffix(domain)
	if d == "" {
		return &Rule{Match: domain, Action: ActionDirect}
	}
	if c.ruleSuffixDomains != nil { // DOMAIN-SUFFIX
		if v, ok := c.ruleSuffixDomains.Get(d); ok {
			return v.(*Rule)
		}
	}
	if c.ruleCountryDomains != nil { // Country
		for _, rule := range c.ruleCountryDomains {
			if strings.HasSuffix(domain, rule.Match) {
				return rule
			}
		}
	}
	d = domainKeyword(domain)
	if c.ruleKeywordDomains != nil {
		for _, rule := range c.ruleKeywordDomains { // "DOMAIN-KEYWORD"
			if strings.EqualFold(d, rule.Match) {
				return rule
			}
		}
	}

	return nil
}

// addr = host/not port
func (c *Filter) matchIpRule(addr string) *Rule {
	ips := resolveRequestIPAddr(addr) //  convert []net.IP
	r := c.matchIPCIDR(ips)           // IP-CIDR rule
	if r != nil {
		return r
	}
	if nil != ips { // GEOIP rule
		country := strings.ToLower(c.GeoIPs(ips)) // return country
		if c.ruleGeoIP != nil {
			for _, rule := range c.ruleGeoIP {
				if strings.ToLower(rule.Match) == country {
					return rule
				}
			}
		}

		return &Rule{Match: "GEOIP", Action: country}
	}
	return nil
}

func (c *Filter) matchIPCIDR(ip []net.IP) *Rule {
	if c.ruleIPCIDR != nil {
		for _, addr := range ip {
			for _, h := range c.ruleIPCIDR {
				if h.Match.Contains(addr) {
					return &Rule{Match: "IPCIDR", Action: h.Action}
				}
			}
		}
	}

	return nil
}
