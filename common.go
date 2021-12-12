package gorules

import (
	"github.com/koomox/redblacktree"
	"github.com/oschwald/geoip2-golang"
	"net"
	"strings"
	"sync"
)

type Match interface {
	MatchBypass(host string) (match, action string)
	MatchGit(host string) bool
	MatchHosts(host string) string
	MatchPort(port string) bool
	MatchRule(host string, typeHost byte) (match, action string)
	MatchExtension(host string) (match, action string)
}

type Filter struct {
	sync.RWMutex
	useGeoIP bool
	useHosts bool

	geoDB *geoip2.Reader // GeoIP

	bypassDomains      []interface{}
	systemBypass       []string
	ruleHosts          []*RuleHost // local hosts
	rulePort           *redblacktree.Tree
	ruleDomains        map[string]string
	ruleSuffixDomains  *redblacktree.Tree
	ruleGit            []string
	ruleCountryDomains []*Rule
	ruleKeywordDomains []*Rule
	ruleUserAgent      []*Rule
	ruleIPCIDR         []*RuleIPCIDR
	ruleGeoIP          []*Rule
	ruleFinal          *Rule

	extDomains       []*Rule
	extSuffixDomains []*Rule
}

type Rule struct {
	Match  string `json:"match"`
	Action string `json:"action"`
}

type RuleIPCIDR struct {
	Match  *net.IPNet `json:"match"`
	Action string     `json:"action"`
}

type RuleHost struct {
	Addr string `json:"addr"`
	Host string `json:"domain"`
}

func New(rules []byte, useHosts bool) (element *Filter) {
	element = &Filter{
		useGeoIP:          false,
		useHosts:          false,
		ruleDomains:       make(map[string]string),
		rulePort:          redblacktree.NewWithStringComparator(),
		ruleSuffixDomains: redblacktree.NewWithStringComparator(),
	}

	if useHosts {
		element.FromHosts()
	}
	element.FromRules(rules)

	return
}

func (c *Filter) FromGeoIP(name string) (err error) {
	db, err := FromGeoIP(name)
	if err != nil {
		return
	}
	c.useGeoIP = true
	c.geoDB = db

	return
}

func (c *Filter) FromHosts() {
	hosts := FromHosts()
	if hosts != nil {
		c.useHosts = true
		c.ruleHosts = hosts
	}

	return
}

func (c *Filter) FromPort(elements ...string) {
	for _, v := range elements {
		c.rulePort.Put(v, &Rule{Match: v, Action: ActionAccept})
	}
}

func (c *Filter) FromGit(elements ...string) {
	for _, v := range elements {
		c.ruleGit = append(c.ruleGit, v)
	}
}

func (c *Filter) FromFinal(action string) {
	c.ruleFinal = &Rule{Match: strings.ToUpper("Final"), Action: strings.ToUpper(action)}
}
