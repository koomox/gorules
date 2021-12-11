# gorules
golang rules filter

> based on [flora-kit](https://github.com/huacnlee/flora-kit)

# Code Example        
```go
package main

import (
	"fmt"
	"github.com/koomox/gorules"
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
DOMAIN-COUNTRY,.cn,DIRECT
DOMAIN-COUNTRY,.jp,PROXY
DOMAIN-SUFFIX,baidu.com,DIRECT
DOMAIN-SUFFIX,google.com,PROXY
DOMAIN-SUFFIX,google.co.jp,PROXY
IP-CIDR,91.108.4.0/22,PROXY
GEOIP,CN,DIRECT
FINAL,DIRECT
`)
	extensions = []byte(`
DOMAIN,scholar.google.com,US
DOMAIN-SUFFIX,netflix.com,NETFLIX
DOMAIN-SUFFIX,nflxext.com,NETFLIX
DOMAIN-SUFFIX,nflxso.net,NETFLIX
DOMAIN-SUFFIX,nflxvideo.net,NETFLIX
DOMAIN-SUFFIX,nflximg.net,NETFLIX
PORT,FTP,20,ACCEPT
PORT,FTP,21,ACCEPT
PORT,DNS,53,ACCEPT
PORT,NTP,123,ACCEPT
PORT,HTTP,80,ACCEPT
PORT,HTTPS,443,ACCEPT
`)
)

func main() {
	rules := gorules.New(config, true)
	// if err := rules.FromGeoIP("GeoLite2-Country.mmdb"); err != nil {
	// 	fmt.Println(err.Error())
	// 	return
	// }

	rules.FromGit("github.com", "golang.org", "bitbucket.org", "gitlab.com")
	rules.FromPort("80", "443")
	rules.FromFinal(gorules.ActionDirect)
	rules.FromExtensions(extensions)

	match, action := rules.MatchBypass("localhost")
	fmt.Println(match, action)
	match, action = rules.MatchRule("google.com", 0x03)
	fmt.Println(match, action)

	fmt.Println(rules.MatchHosts("activate.adobe.com"))
	fmt.Println(rules.MatchGit("github.com"))
	fmt.Println(rules.MatchPort("443"))
}
```

## License

GPL v3.0
