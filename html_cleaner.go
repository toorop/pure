package main

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Rule represents a HTMLCleaner rule
type Rule struct {
	Selector string
	Classes  []string
	White    bool
}

// HTMLCleaner represents the main cleaner
type HTMLCleaner struct {
	*sync.Mutex
	Rules map[string]map[string]map[string]bool
}

// NewHTMLCleaner returns a pointer to a new HTMLCleaner struct
func NewHTMLCleaner() *HTMLCleaner {
	return &HTMLCleaner{new(sync.Mutex), make(map[string]map[string]map[string]bool)}
}

// AddRule is used to add a rule
func (c *HTMLCleaner) AddRule(host, selector string, classes []string, white bool) {
	c.Lock()
	defer c.Unlock()
	if _, ok := c.Rules[host]; !ok {
		c.Rules[host] = make(map[string]map[string]bool)
	}
	if _, ok := c.Rules[host][selector]; !ok {
		c.Rules[host][selector] = make(map[string]bool)
	}
	for _, class := range classes {
		c.Rules[host][selector][class] = white
	}
}

// LoadRulesFromFile load rules form file
func (c *HTMLCleaner) LoadRulesFromFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()

		// comments
		if len(line) == 0 || line[0] == 35 {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			log.Fatalln("Bad HTMLCleaner rule: " + line)
		}
		white := false
		if parts[0][0] == 126 {
			white = true
			parts[0] = parts[0][1:]
		}
		c.AddRule(parts[0], strings.ToLower(parts[1]), strings.Split(parts[2], ","), white)
	}
	return nil
}

// Clean remove unwanted HTML nodes
func (c *HTMLCleaner) Clean(body io.ReadCloser, host string) io.ReadCloser {
	c.Lock()
	_, found := c.Rules[host]
	c.Unlock()
	if found {
		//log.Println("On remove des nodes pour cet host")
		doc, err := html.Parse(body)
		if err != nil {
			log.Println("ERROR - HTMLCleaner.Clean - ", err)
			return body
		}
		// we can't remove node during parsing because if we do it, we do not parse all doc
		//RemoveChild removes a node c that is a child of n. Afterwards, c will have no parent and no siblings.
		toRemove := []*html.Node{}
		wg := sync.WaitGroup{}
		var f func(*html.Node)
		f = func(n *html.Node) {

			if n.Type == html.ElementNode {
				selector := n.Data
			L:
				for _, a := range n.Attr {
					if a.Key == "class" {
						// clean no.Class
						a.Val = normalize(a.Val)
						attrClasses := strings.Split(a.Val, " ")
						for _, class := range attrClasses {
							if _, ok := c.Rules[host][selector][class]; ok {
								toRemove = append(toRemove, n)
								//log.Println("dans la boucle", toRemove)
								break L
							}
						}
					}
				}
			}

			//wg.Done()
			for node := n.FirstChild; node != nil; node = node.NextSibling {
				wg.Add(1)
				go f(node)
			}
			wg.Done()
		}

		//  Parse doc
		//start := time.Now()
		wg.Add(1)
		f(doc)
		// Really bad hack....
		time.Sleep(time.Duration(100) * time.Millisecond)

		//log.Println("START WAIT")
		wg.Wait()

		for _, n := range toRemove {
			n.Parent.RemoveChild(n)
		}
		buff := bytes.NewBuffer([]byte{})
		err = html.Render(buff, doc)
		if err != nil {
			log.Println("ERROR - HTMLCleaner.Clean - ", err)
			return body
		}
		body = ioutil.NopCloser(buff)
	}
	return body
}
