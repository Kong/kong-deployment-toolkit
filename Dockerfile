FROM golang:1.26.5 AS build
WORKDIR /kdt
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o kdt

# distroless: no shell, no package manager, no root user - kdt's own binary
# (built CGO_ENABLED=0 above) is the only thing that needs to run here. Neither
# deck nor kubectl are invoked by the Go code (both were previously installed
# via unverified curl-piped downloads and never used), so there's nothing else
# this stage needs.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /kdt/kdt /usr/local/bin/kdt
WORKDIR /kdt

ENTRYPOINT ["/usr/local/bin/kdt"]
