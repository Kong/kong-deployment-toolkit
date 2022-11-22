.SILENT: clean

build-docker:
	docker build --platform=linux/amd64 -t kdt:1.0 .

build-macos:
	env GOOS=darwin GOARCH=amd64 go build -o bin/kdt

build-linux:
	env GOOS=linux GOARCH=amd64 go build -o bin/kdt
	
clean:
	rm -f $(wildcard *.yaml)
	rm -f $(wildcard *.json)
	rm -f $(wildcard *.tar.gz)
	rm -f $(wildcard *.log)
	rm -rf bin/
	rm -f Summary.txt

clear:
	rm -f $(wildcard *.yaml)
	rm -f $(wildcard *.json)
	rm -f $(wildcard *.tar.gz)
	rm -f $(wildcard *.log)
	rm -f Summary.txt
