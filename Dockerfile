FROM debian:jessie
RUN apt-get update -yy && \
    apt-get install -yy --no-install-recommends libxml2 libxmlsec1 libxmlsec1-openssl liblzma5 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ADD package /srv/qsaml
RUN chmod 755 /srv/qsaml && \
    mkdir /srv/qsaml/config
EXPOSE 8080
WORKDIR /srv/qsaml
VOLUME ["/srv/qsaml/config"]
CMD ["/srv/qsaml/qsaml"]