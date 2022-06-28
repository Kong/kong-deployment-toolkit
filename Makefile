.SILENT: clean

build:
	env GOOS=darwin GOARCH=amd64 go build -o bin/kdt
	#env GOOS=linux GOARCH=amd64 go build -o bin/kdt
	# docker build --platform=linux/amd64 -t kdt:1.0 .
clean:
	rm -f $(wildcard *.yaml)
	rm -f $(wildcard *.json)
	rm -f $(wildcard *.tar.gz)
	rm -f $(wildcard *.log)
	rm -rf bin/
	rm -f Summary.txt