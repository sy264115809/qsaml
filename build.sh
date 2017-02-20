#!/bin/sh
docker build -t qsaml-build - <<EOF
FROM golang:1.8.0
RUN apt-get update -yy && \
    apt-get install -yy --no-install-recommends git make curl libxml2-dev libxmlsec1-dev liblzma-dev pkg-config && \
    curl https://glide.sh/get | sh
EOF

docker run --rm -v $PWD/package:/package -it qsaml-build:latest bash -c " \
mkdir -p /go/src/github.com/gofly && \
    curl -L https://github.com/gofly/qsaml/archive/master.tar.gz | tar zx -C /go/src/github.com/gofly && \
    mv /go/src/github.com/gofly/qsaml-master /go/src/github.com/gofly/qsaml && \
    cd /go/src/github.com/gofly/qsaml && \
    glide install && \
    go install github.com/gofly/qsaml && \
    mv /go/bin/qsaml /package && \
    cp -r /go/src/github.com/gofly/qsaml/static /package && \
    cp -r /go/src/github.com/gofly/qsaml/templates /package"
docker build -t qsaml:latest .
docker rmi $(docker images -qf dangling=true)