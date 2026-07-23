.SILENT: clean

build-docker:
	docker build --platform=linux/amd64 -t kdt:1.0 .

build-macos:
	env GOOS=darwin GOARCH=amd64 go build -o bin/kdt

build-macos-arm64:
	env GOOS=darwin GOARCH=arm64 go build -o bin/kdt

build-linux:
	env GOOS=linux GOARCH=amd64 go build -o bin/kdt

test:
	CGO_ENABLED=0 go test ./...

# Collected diagnostic output now lives under a per-run temp directory (see
# FUNC-12), not the repo/CWD, so clean no longer needs to sweep *.yaml/*.json/
# *.log/*.txt here - doing so previously risked deleting a user's own files
# of those names sitting in the working directory.
clean:
	rm -rf bin/
	rm -f *.tar.gz
