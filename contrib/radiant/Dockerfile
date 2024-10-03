# The Radiant Blockchain Developers
# The purpose of this image is to be able to host ElectrumX for radiantd (RXD)
# Build with: `docker build -t electrumx .`
# Public images at: https://hub.docker.com/repository/docker/radiantblockchain

FROM python:3.11

LABEL maintainer="radiantblockchain@protonmail.com"
LABEL version="1.2.0"
LABEL description="Docker image for electrumx radiantd node"

ENV PACKAGES="libleveldb-dev htop net-tools"

RUN apt update && apt install --no-install-recommends -y $PACKAGES  && \
    rm -rf /var/lib/apt/lists/* && \
    apt clean

# Create directory for DB
RUN mkdir /root/electrumdb

WORKDIR /root

# ORIGINAL SOURCE
COPY . /root/electrumx

WORKDIR /root/electrumx

RUN python3 -m pip install -r requirements.txt
# Install py-spy
# Usage example: py-spy record -o profile.svg --pid 1
# Only supports up to Python 3.11
RUN pip install py-spy

# Create SSL
WORKDIR /root/electrumx
RUN openssl genrsa -out server.key 2048
RUN openssl req -new -key server.key -out server.csr -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=radiantblockchain.org"
RUN openssl x509 -req -days 1825 -in server.csr -signkey server.key -out server.crt

EXPOSE 50010 50012

ENTRYPOINT ["python3", "electrumx_server"]

##### DOCKER INFO
# build it with eg.: `docker build -t electrumx .`
# run it with eg.:
# `docker run -d --net=host -e DAEMON_URL="http://youruser:yourpass@localhost:7332" -e REPORT_SERVICES=tcp://example.com:50010 electrumx`
# for a proper clean shutdown, send TERM signal to the running container eg.: `docker kill --signal="TERM" CONTAINER_ID`

