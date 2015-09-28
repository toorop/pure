package main

import (
	"crypto/tls"
	"strings"

	"github.com/hashicorp/golang-lru"
	"github.com/toorop/goproxy"
)

// TLSConfigCache is a cache for TLS configuration
var TLSConfigCache *lru.Cache

// TLSGetConfig return TLS configuration
func TLSGetConfig(host string, ctx *goproxy.ProxyCtx, ca *tls.Certificate) (*tls.Config, error) {
	host = getWildcardHost(host)
	c, ok := TLSConfigCache.Get(host)
	if ok {
		return c.(*tls.Config), nil
	}
	// generate new cache
	cfg, err := goproxy.TLSConfigFromCA(ca)(host, ctx)
	if err == nil {
		TLSConfigCache.Add(host, cfg)
	} else {
		TLSConfigCache.Remove(host)
		ctx.Warnf("failed to sign %s: %s", host, err)
	}
	return cfg, err
}

// getWildcardHost return wildcarded host
// -> less cert
func getWildcardHost(host string) string {
	first := strings.Index(host, ".")
	if first <= 0 {
		return host
	}
	last := strings.LastIndex(host, ".")
	if last == first {
		// root domain, no wildcard
		return host
	}
	return "*" + host[first:]
}
