FROM debian:jessie
RUN apt-get update -yy && \
    apt-get install -yy --no-install-recommends libxml2 libxmlsec1 libxmlsec1-openssl liblzma5 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY package/qsaml /usr/local/bin/
COPY package/templates /usr/local/share/qsaml/templates
COPY package/static /usr/local/share/qsaml/static
RUN chmod 755 /usr/local/bin/qsaml && \
    mkdir /usr/local/etc/qsaml
EXPOSE 8080
WORKDIR /usr/local/share/qsaml
VOLUME ["/usr/local/etc/qsaml"]
CMD ["qsaml"]