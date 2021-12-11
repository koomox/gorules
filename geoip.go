package gorules

import (
	"errors"
	"github.com/oschwald/geoip2-golang"
	"net"
	"os"
	"strings"
)

func validPath(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func FromGeoIP(name string) (db *geoip2.Reader, err error) {
	if ok, err := validPath(name); !ok || err != nil {
		err = errors.New("load GeoIP file failed")
		return nil, err
	}
	return geoip2.Open(name)
}

func (c *Filter) GeoIPString(ipaddr string) string {
	if c.geoDB == nil {
		return ""
	}
	ip := net.ParseIP(ipaddr)
	return c.GeoIP(ip)
}

func (c *Filter) GeoIPs(ips []net.IP) string {
	if c.geoDB == nil {
		return ""
	}
	for _, ip := range ips {
		return c.GeoIP(ip)
	}
	return ""
}

// Return Country code
func (c *Filter) GeoIP(ip net.IP) string {
	// log.Println("Lookup GEO IP", ip)
	if c.geoDB == nil {
		return ""
	}
	country, err := c.geoDB.Country(ip)
	if err != nil {
		return ""
	}
	return strings.ToLower(country.Country.IsoCode)
}

func resolveRequestIPAddr(host string) []net.IP {
	var (
		ips []net.IP
		err error
	)
	ip := net.ParseIP(host)
	if nil == ip {
		ips, err = net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil
		}
	} else {
		ips = []net.IP{ip}
	}
	return ips
}
