# gorules
golang rules filter

> based on [flora-kit](https://github.com/huacnlee/flora-kit)

# Code Example        
```go
package main

import (
	"fmt"
	"github.com/koomox/goproxy/tunnel"
	"github.com/koomox/gorules"
)

const (
	typeIPv4 byte = 0x01 // type is ipv4 address
	typeDm   byte = 0x03 // type is domain address
	typeIPv6 byte = 0x04 // type is ipv6 address
)

var (
	config = []byte(`
[General]
loglevel = notify
replica = false
skip-Proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local

[Rule]
DOMAIN-KEYWORD,google,PROXY
DOMAIN-KEYWORD,facebook,PROXY
DOMAIN-KEYWORD,youtube,PROXY
DOMAIN-KEYWORD,twitter,PROXY
DOMAIN-SUFFIX,baidu.com,DIRECT
DOMAIN-SUFFIX,google.com,PROXY
DOMAIN-SUFFIX,google.co.jp,PROXY
IP-CIDR,91.108.4.0/22,PROXY
GEOIP,CN,DIRECT
FINAL,DIRECT
`)
	extensions = []byte(`
DOMAIN,scholar.google.com,US
DOMAIN-SUFFIX,.cn,DIRECT
DOMAIN-SUFFIX,.us,PROXY
DOMAIN-SUFFIX,.ca,PROXY
DOMAIN-SUFFIX,netflix.com,NETFLIX
DOMAIN-SUFFIX,nflxext.com,NETFLIX
DOMAIN-SUFFIX,nflxso.net,NETFLIX
DOMAIN-SUFFIX,nflxvideo.net,NETFLIX
DOMAIN-SUFFIX,nflximg.net,NETFLIX
DST-PORT,20,FTP
DST-PORT,21,FTP
DST-PORT,53,DNS
DST-PORT,123,NTP
DST-PORT,80,HTTP
DST-PORT,443,HTTPS
`)
)

func MatchRule(host string, rules gorules.Match) {
	addr, _ := tunnel.FromAddr("tcp", host+":443")
	r := rules.MatchRule(addr)
	fmt.Println(host, r.String(), r.Adapter())
}

func main() {
	rules := gorules.New(config)
	rules.FromHosts()
	// if err := rules.FromGeoIP("GeoLite2-Country.mmdb"); err != nil {
	// 	fmt.Println(err.Error())
	// 	return
	// }

	rules.FromPort("80", "443")
	rules.FromFinal(gorules.ActionDirect)
	rules.FromExtensions(extensions)

	fmt.Println(rules.MatchBypass("localhost"))
	fmt.Println(rules.MatchRule("google.com", typeDm))
	MatchRule("github.com", rules)
	MatchRule("china.com.cn", rules)
	MatchRule("netflix.com", rules)
	MatchRule("pinterest.ca", rules)

	rules.SetHosts("0.0.0.0", "activate.adobe.com")
	fmt.Println(rules.MatchHosts("activate.adobe.com"))
	fmt.Println(rules.MatchPort("443"))
}
```

## License

GPL v3.0
