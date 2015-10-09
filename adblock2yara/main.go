package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

const yaraRuleTpl = `rule {{.Name}}
{
    meta:
        description = "{{.Description}}"
    strings:
        $match = "{{.Rule}}"
    condition:
        $match
}

`

var yaraRuleTemplate *template.Template

type yaraRule struct {
	Name        string
	Description string
	Rule        string
}

func handleErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func processFile(path string, info os.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	log.Println(info)

	inFile, err := os.Open("rules/" + info.Name())
	handleErr(err)
	defer inFile.Close()

	outFile, err := os.Create("../rules/yara/" + info.Name() + ".yar")
	handleErr(err)
	defer outFile.Close()

	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	i := 0
	for scanner.Scan() {
		abFilter := scanner.Text()
		//println(abFilter[0])
		if abFilter[0] == 33 || abFilter[0] == 91 {
			continue
		}
		if strings.HasPrefix(abFilter, "||") {
			continue
		}

		if strings.HasPrefix(abFilter, "@@") {
			continue
		}
		i++
		if i > 2000 {
			break
		}

		// Name
		name := fmt.Sprintf("%s_%d", info.Name(), i)
		name = strings.Replace(name, ".", "_", -1)

		rule := yaraRule{
			Name:        fmt.Sprintf(name),
			Description: abFilter,
			Rule:        abFilter,
		}
		err := yaraRuleTemplate.Execute(outFile, rule)
		handleErr(err)
	}
	outFile.Sync()

	return nil
}

func main() {
	yaraRuleTemplate = template.Must(template.New("rule").Parse(yaraRuleTpl))
	err := filepath.Walk("rules", processFile)
	handleErr(err)

	/*
	 */
}
