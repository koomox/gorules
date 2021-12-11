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
		case "domain":
			c.extDomains = append(c.extDomains, &Rule{Match: items[1], Action: strings.ToLower(items[2])})
		case "domain-suffix":
			c.extSuffixDomains = append(c.extSuffixDomains, &Rule{Match: items[1], Action: strings.ToLower(items[2])})
		case "port": // port white list
			c.rulePort.Put(items[2], &Rule{Match: items[2], Action: strings.ToLower(items[3])})
		}
	}
	return
}
