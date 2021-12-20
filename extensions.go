package gorules

import (
	"strings"
)

func (c *Filter) FromExtensions(b []byte) {
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		items := readArrayLine(line)
		ruleName := strings.ToLower(items[0])
		switch ruleName {
		case "domain-country":
			c.ruleCountryDomains = append(c.ruleCountryDomains, &Rule{Match: items[1], Action: strings.ToUpper(items[2])})
		case "domain":
			c.extDomains = append(c.extDomains, &Rule{Match: items[1], Action: strings.ToUpper(items[2])})
		case "domain-suffix":
			c.extSuffixDomains = append(c.extSuffixDomains, &Rule{Match: items[1], Action: strings.ToUpper(items[2])})
		case "dst-port": // port white list
			c.rulePort.Put(items[1], &Rule{Match: items[1], Action: strings.ToUpper(items[2])})
		}
	}
	return
}
