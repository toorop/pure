package main

import (
	"bytes"
	//"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"crypto/tls"
	lru "github.com/hashicorp/golang-lru"
	"github.com/toorop/goproxy"
	"github.com/toorop/yara"
)

//
var TLSCacheSize = 200

// CaCert -> CA cert (amazing !)
var CaCert = []byte(`-----BEGIN CERTIFICATE-----
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

// CaKey key
var CaKey = []byte(`-----BEGIN PRIVATE KEY-----
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

func normalize(in string) string {
	t := bytes.Replace([]byte(in), []byte{13}, []byte{}, -1)
	t = bytes.Replace(t, []byte{10}, []byte{}, -1)
	t = regexp.MustCompile(`[ \t]+`).ReplaceAll(t, []byte(" "))
	return string(t)
}

func handleErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

var IsWebsocket goproxy.ReqConditionFunc = func(r *http.Request, ctx *goproxy.ProxyCtx) bool {
	return r.Header.Get("Connection") == "Upgrade" || r.Header.Get("Upgrade") == "websocket"
}

//  Main
func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	/*login := flag.String("login", "", "proxy login")
	password := flag.String("password", "", "proxy passwd")*/
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()

	// Yara
	c, err := yara.NewCompiler()
	handleErr(err)
	// Load & compile rules
	err = filepath.Walk("rules/yara", func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		return c.AddFile("", "rules/yara/"+info.Name())
	})
	handleErr(err)

	engine, err := c.Rules()
	handleErr(err)
	c.Destroy()

	// HTML cleaners
	htmlCleaner := NewHTMLCleaner()
	err = htmlCleaner.LoadRulesFromFile("rules/HTMLCleaner.txt")
	handleErr(err)

	// CSS injector
	cssInjector := NewCSSInjector()
	err = cssInjector.LoadRulesFromFile("rules/filters/css2inject.txt")
	handleErr(err)

	// launch proxy
	goproxy.CertOrganisation = "Pure proxy"
	// Cache for certs
	TLSConfigCache, err = lru.New(TLSCacheSize)
	//goproxy.GoproxyCa, err = tls.X509KeyPair(CaCert, CaKey)
	ca, err := tls.X509KeyPair(CaCert, CaKey)
	handleErr(err)
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	MitmConnect := &goproxy.ConnectAction{
		Action: goproxy.ConnectMitm,
		TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
			return TLSGetConfig(host, ctx, &ca)
		},
	}
	var AlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (
		*goproxy.ConnectAction, string) {
		return MitmConnect, host
	}

	proxy.OnRequest().HandleConnect(AlwaysMitm)

	/*auth.ProxyBasic(proxy, "my_realm", func(user, passwd string) bool {
		return user == *login && passwd == *password
	})*/

	/*
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
	*/

	// POC websocket
	/*proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		log.Println(host)
		if host == "live.toorop.fr:80" {
			msg := "---------------------------------------------------------\n"
			for k, v := range ctx.Req.Header {
				msg += string(k) + ":" + v[0] + "\n"
			}
			msg += "---------------------------------------------------------\n\n"
			log.Println(msg)
		}
		return goproxy.OkConnect, host
	})*/

	/*proxy.OnRequest(IsWebsocket).
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
		defer func() {
			if e := recover(); e != nil {
				ctx.Logf("error connecting to remote: %v", e)
				client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
			}
			client.Close()
		}()
		log.Println("Requete versTHE  websocket")
		clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
		remote, err := connectDial(proxy, "tcp", req.URL.Host)
		orPanic(err)
		remoteBuf := bufio.NewReadWriter(bufio.NewReader(remote), bufio.NewWriter(remote))
		for {
			req, err := http.ReadRequest(clientBuf.Reader)
			orPanic(err)
			orPanic(req.Write(remoteBuf))
			orPanic(remoteBuf.Flush())
			resp, err := http.ReadResponse(remoteBuf.Reader, req)
			orPanic(err)
			orPanic(resp.Write(clientBuf.Writer))
			orPanic(clientBuf.Flush())
		}
	})*/

	/*proxy.OnRequest(IsWebsocket).DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.Println("Requete vers websocket")
		return r, nil
	})*/

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			name := ""
			err = engine.ScanMemory([]byte(r.Host), func(rule *yara.Rule) yara.CallbackStatus {
				name = rule.Identifier
				return yara.Abort
			})
			if name == "" {
				err = engine.ScanMemory([]byte(r.RequestURI), func(rule *yara.Rule) yara.CallbackStatus {
					name = rule.Identifier
					return yara.Abort
				})
			}
			if name != "" {
				log.Println("BLOCKED", name, r.RequestURI)
				return r, goproxy.NewResponse(r,
					goproxy.ContentTypeText, http.StatusForbidden,
					"I'm sorry, Dave. I'm afraid I can't do that.")
			}
			return r, nil
		})

	// Scan response - POC
	// TODO: refactoring
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return nil
		}
		contentType := resp.Header.Get("content-type")

		// http
		if strings.HasPrefix(contentType, "text/html") {
			resp.Body = htmlCleaner.Clean(resp.Body, ctx.Req.Host)
		} else if strings.HasPrefix(contentType, "text/css") {
			resp.Body = cssInjector.Inject(resp.Body, ctx.Req.Host)
		} else if strings.HasPrefix(contentType, "application/json") {
			// POC remove google ads on search
			if ctx.Req.Host == "www.google.fr" {
				// read body
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					ctx.Warnf("Pure - ERROR while reading body: %s", err)
					return resp
				}
				bodyPart := strings.Split(string(body), `/*""*/`)
				t := ""
				for _, p := range bodyPart {
					if strings.Contains(p, "commercial-unit") || strings.Contains(p, "tadsb") {
						continue
					}
					t = t + p + `/*""*/`
				}
				body = []byte(t)
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
			}
		}

		return resp
	})
	log.Fatal(http.ListenAndServe(*addr, proxy))
}
