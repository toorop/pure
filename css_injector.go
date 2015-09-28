package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
)

// CSSInjector represent an injector
type CSSInjector struct {
	*sync.Mutex
	cssToInject map[string][]string
}

// NewCSSIjector returns a new CSSIjector
func NewCSSIjector() *CSSInjector {
	return &CSSInjector{
		new(sync.Mutex), make(map[string][]string),
	}
}

// LoadRulesFromFile load rule (CSS to inject) from file file
func (i *CSSInjector) LoadRulesFromFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		hostCSS := strings.Split(line, "|")
		if len(hostCSS) != 2 {
			return fmt.Errorf("bad CSS injector rule found in %s : %s", file, line)
		}
		i.AddCSSForHost(hostCSS[0], hostCSS[1])
	}
	return nil
}

// AddCSSForHost add a CSS rule for host host
func (i *CSSInjector) AddCSSForHost(css, host string) {
	host = strings.ToLower(host)
	i.Lock()
	defer i.Unlock()
	if _, ok := i.cssToInject[host]; ok {
		i.cssToInject[host] = append(i.cssToInject[host], css)
	}
}

// Inject add CSS if needed
func (i *CSSInjector) Inject(body io.ReadCloser, host string) (io.ReadCloser, error) {
	i.Lock()
	defer i.Unlock()
	css, ok := i.cssToInject[host]
	if ok {
		// read body
		bodyStr, err := ioutil.ReadAll(body)
		if err != nil {
			return body, err
		}
		bodyStr = append(bodyStr, []byte(strings.Join(css, ";"))...)
		body = ioutil.NopCloser(bytes.NewBuffer(bodyStr))
		//body = &bodyR
	}
	return body, nil
}

/*
// TODO map[string][]string
type CSSByHost struct {
	Name       string
	CSS2Inject []string
}

type FilterCSSToInject struct {
	Hosts []*CSSByHost
}

func (f *FilterCSSToInject) GetHost(hostname string) *CSSByHost {
	for _, host := range f.Hosts {
		if host.Name == hostname {
			return host
		}
	}
	return nil
}

func (f *FilterCSSToInject) GetCSS2InjectForHost(hostname string) string {
	if h := f.GetHost(hostname); h != nil {
		return strings.Join(h.CSS2Inject, ";")
	}
	return ""
}

func (f *FilterCSSToInject) AddCSS(hostname, css string) {
	if h := f.GetHost(hostname); h != nil {
		h.CSS2Inject = append(h.CSS2Inject, css)
	} else {
		f.Hosts = append(f.Hosts, &CSSByHost{
			Name:       hostname,
			CSS2Inject: []string{css},
		})
	}
}
*/
