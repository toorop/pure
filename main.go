package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/toorop/goproxy"
	"github.com/toorop/goproxy/ext/auth"
	"github.com/toorop/yara"
)

// CA_CERT -> CA cert (amazing !)
var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIIB+jCCAWOgAwIBAgIJAO+gwjqaRNK+MA0GCSqGSIb3DQEBCwUAMBUxEzARBgNV
BAoMClB1cmUgcHJveHkwIBcNMTUwNzIyMTA1MDQ1WhgPMjA1MDA3MTMxMDUwNDVa
MBUxEzARBgNVBAoMClB1cmUgcHJveHkwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
AoGBAM6MHr+vpsT9oUs1gEoiiMUY9IT57tVOVPt71PJh6kTgOwA6u4Q2jUt37Us6
1IU5OHhXxM+Ky4kcElux+VhsSFvguCqSNyzFvYwH4/PMAHBv9R5QOcx7FicHb6ho
nCW83q6o8bku67SS5C0D9trJViEmyBYssmIv3x8jtH5b1KppAgMBAAGjUDBOMB0G
A1UdDgQWBBSFt2/5pKojMqhkHxEIp5p4wT4UWjAfBgNVHSMEGDAWgBSFt2/5pKoj
MqhkHxEIp5p4wT4UWjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBADMU
WM+QWtW+Yybia61B7Y8wY+C4A7gO3ag4TsKNOHB2XLHY/aCXOwxEhBvJYGmwECW2
hZLLzeuWbT6T+mikWoZZive18v81kY7Rf956Ai3YKNgh2WDHMEBRJ9VUdmq08TSI
ckDzupnnvj5B9Uhq3/xQ8egaCXhDYSmCq17wuZNx
-----END CERTIFICATE-----`)

// CA_KEY  key
var CA_KEY = []byte(`-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAM6MHr+vpsT9oUs1
gEoiiMUY9IT57tVOVPt71PJh6kTgOwA6u4Q2jUt37Us61IU5OHhXxM+Ky4kcElux
+VhsSFvguCqSNyzFvYwH4/PMAHBv9R5QOcx7FicHb6honCW83q6o8bku67SS5C0D
9trJViEmyBYssmIv3x8jtH5b1KppAgMBAAECgYEAnggJcsJTR/+CzEd4C8DWgm8w
jxmnid7wGKZLbNRL6TzjB67oUCVpACgXD+tINVJtiW4l8GGSjypCRZQrYmMfDIRg
uvHtQLUk3uWFvHQ8NPU/49irxZ95HwqMJlJzw2AzlpZR3BPT0QMwSyTH3kz1bgAu
i6mQxI42A4wSHgj52QECQQD3CEPz1+5k3JHTmpIV5C+Uzj/rAFQ1rF5JfeE5KEBB
Ta3vMr8ZxWzrk+YqHnz0fT5OrRD2lS7QmQbvtGOgJfrhAkEA1gueIPuBp8T5WtBZ
Hn9ASsmJVN0XWqcp6iqbX3QHsGRkl73ke7ewBKIzjqm7wFCOjlcHroxYNnve9gHc
MlZoiQJBALIjx7zkDgm19YL+iDI5JwbL5NP2nMNH1YZxvCSXnh55geBoW96du/n1
4Zil+73jQzdBHmZzFhte/t2E3AL04IECQANAwfJ2YA4QrEl5CSGxhWSdk3y6r3Qt
PjHU2++jb8p6fBziQeqva/lmDaqJYdUWZFQ9dlxsvZp2X3kVpicNsSECQFC2W9s1
7GySl8NLqgOaStq94uyK1rQpJxQlArqMZbi7COIlQZ0Q0r5m9aALNxXYeIs8HGJN
Ut0HOxyRVMZunh4=
-----END PRIVATE KEY-----`)

func handleErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	login := flag.String("login", "", "proxy login")
	password := flag.String("password", "", "proxy passwd")
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()

	// Yara
	c, err := yara.NewCompiler()
	handleErr(err)
	// Load & compile rules
	err = filepath.Walk("rules", func(path string, info os.FileInfo, err error) error {
		log.Println(path)
		if info.IsDir() {
			return nil
		}
		return c.AddFile("", "rules/"+info.Name())
	})
	handleErr(err)

	engine, err := c.Rules()
	if err != nil {
		log.Fatalln(err)
	}
	c.Destroy()

	// launch proxy
	goproxy.CertOrganisation = "Pure proxy"
	goproxy.GoproxyCa, err = tls.X509KeyPair(CA_CERT, CA_KEY)
	handleErr(err)
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).HandleConnect(goproxy.AlwaysMitm)
	proxy.Verbose = *verbose
	auth.ProxyBasic(proxy, "my_realm", func(user, passwd string) bool {
		return user == *login && passwd == *password
	})
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		log.Println(host)
		name := ""
		err = engine.ScanMemory([]byte(host), func(rule *yara.Rule) yara.CallbackStatus {
			name = rule.Identifier
			return yara.Abort
		})
		if name != "" {
			log.Println("REJECTED", name, host)
			return goproxy.RejectConnect, host
		}
		return goproxy.OkConnect, host
	})

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			log.Println("request: " + r.RequestURI)
			r.Header.Set("X-Pure", "0.0.1")
			name := ""
			err = engine.ScanMemory([]byte(r.RequestURI), func(rule *yara.Rule) yara.CallbackStatus {
				name = rule.Identifier
				return yara.Abort
			})
			if name != "" {
				log.Println("BLOCKED", name, r.Host)
				return r, goproxy.NewResponse(r,
					goproxy.ContentTypeText, http.StatusForbidden,
					"Fuck you")
			}
			log.Println(r.Method, r.Host, r.RequestURI)
			return r, nil
		})
	log.Fatal(http.ListenAndServe(*addr, proxy))
}
