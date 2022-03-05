.SILENT: clean

build:
	go build -o bin/mist

clean:
	rm -f $(wildcard *.yaml)
	rm -f $(wildcard *.json)
	rm -f $(wildcard *.tar.gz)
	rm -f $(wildcard *.log)
	rm -rf bin/
	rm -f Summary.txt