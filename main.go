/*
Copyright © 2022 John Harris

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package main

import (
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	collect "github.com/kong/kong-debug-tool/lib"
	log "github.com/sirupsen/logrus"
)

func main() {
	if os.Getenv("LOG_LEVEL") == "debug" {
		log.SetLevel(5)
	}

	webserverPort := os.Getenv("WEBSERVER_PORT")

	if os.Getenv("KONG_ADDR") == "" {
		log.Info("KONG_ADDR environment variable is not set, so output will not contain a deck dump")
	}

	if webserverPort == "" {
		log.Info("WEBSERVER_PORT environment variable not set, defaulting to 8080")
		webserverPort = "8080"
	}

	//cmd.Execute()

	log.Info("Starting webserver...")
	mux := http.NewServeMux()
	mux.HandleFunc("/", base)
	mux.HandleFunc("/collect", collectDiagnostics)

	log.Info("Webserver listening on port: ", webserverPort)
	err := http.ListenAndServe(":"+webserverPort, mux)

	log.Fatal(err)
}

func base(w http.ResponseWriter, r *http.Request) {

	p := path.Dir("/tmp/index.html")
	// set header
	w.Header().Set("Content-type", "text/html")
	http.ServeFile(w, r, p)
}

func collectDiagnostics(w http.ResponseWriter, r *http.Request) {

	cleanDirectory()

	log.Info("Generating new diagnostics")
	collect.Execute()

	diagFilename := getCurrentTarName()

	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(diagFilename))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, diagFilename)

}

func cleanDirectory() {
	files, err := os.Open(".")

	if err != nil {
		log.Debug(err)
	}

	defer files.Close()

	list, _ := files.Readdirnames(0) // 0 to read all files and folders

	for _, name := range list {
		if strings.Contains(name, "support.tar.gz") || strings.Contains(name, "log") || strings.Contains(name, "yaml") || strings.Contains(name, "Summary.txt") {
			os.Remove(name)
		}
	}
}

func getCurrentTarName() string {
	files, err := os.Open(".")

	if err != nil {
		log.Debug(err)
	}

	defer files.Close()

	diagFilename := ""

	list, _ := files.Readdirnames(0) // 0 to read all files and folders
	for _, name := range list {
		if strings.Contains(name, "support.tar.gz") {
			diagFilename = name
			break
		}
	}

	return diagFilename
}
