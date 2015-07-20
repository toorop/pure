package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/elazarl/goproxy"
	"github.com/toorop/yara"
)

func handleErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")

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

	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose
	/*proxy.OnRequest().HandleConnectFunc(f func(host string, ctx *goproxy.ProxyCtx){
	  log.Println("Host", host)
	})*/

	proxy.OnRequest(goproxy.ReqHostIs("www.zdnet.fr")).HandleConnect(goproxy.AlwaysMitm)

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
			//log.Println("On a une requete")
			//r.Header.Set("X-Pure", "0.0.1")
			name := ""
			err = engine.ScanMemory([]byte(r.Host), func(rule *yara.Rule) yara.CallbackStatus {
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
