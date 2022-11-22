FROM golang:1.18.3 AS build
WORKDIR /kdt
COPY go.mod ./
COPY go.sum ./
RUN go mod download
ADD . .
RUN GOOS=linux GOARCH=amd64 go build -o kdt

FROM ubuntu:latest as base
RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

RUN apt-get update &&  apt install -y curl
RUN apt-get install -y gpg wget apt-transport-https ca-certificates curl gnupg2 software-properties-common lsb-release

RUN curl -sL https://github.com/kong/deck/releases/download/v1.8.1/deck_1.8.1_linux_amd64.tar.gz -o deck.tar.gz
RUN tar -xf deck.tar.gz -C /tmp
RUN cp /tmp/deck /usr/local/bin/

RUN curl -LO https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
RUN install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

COPY --from=build /kdt/kdt /usr/local/bin
WORKDIR /kdt

ENTRYPOINT ["kdt"]