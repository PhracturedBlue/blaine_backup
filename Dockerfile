FROM golang:1.16 as gocryptfs_builder
ARG GOCRYPTFS_VER=v2.2.0
RUN cd /tmp && \
    wget https://github.com/rfjakob/gocryptfs/releases/download/${GOCRYPTFS_VER}/gocryptfs_${GOCRYPTFS_VER}_src-deps.tar.gz
RUN cd /tmp && \
    tar -xf gocryptfs_${GOCRYPTFS_VER}_src-deps.tar.gz &&  \
    mv gocryptfs_${GOCRYPTFS_VER}_src-deps /work
WORKDIR /work
RUN ./build-without-openssl.bash

# We build par2cmdline from source due to needing a fix for
# https://github.com/Parchive/par2cmdline/issues/145
# Which is not included in v0.8.1
FROM debian:bullseye-slim as par2_builder
ARG PAR2CMDLINE_VER=29cab44c1f4139a385c1267dce9ea039802d2d36
RUN apt-get update -y && \
    apt-get install -y build-essential wget unzip automake && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /src

RUN cd /tmp && \
    wget https://github.com/Parchive/par2cmdline/archive/${PAR2CMDLINE_VER}.zip && \
    unzip ${PAR2CMDLINE_VER}.zip && \
    mv par2cmdline-${PAR2CMDLINE_VER}/ /src && \
    rm -rf /tmp/${PAR2CMDLINE_VER}.sip
    
WORKDIR /src

RUN ./automake.sh && \
    ./configure && \
    make && \
    make check

FROM node:bullseye-slim

ARG UID=1000
ARG GID=1000

RUN deluser node
RUN addgroup --gid $GID debian && adduser --system --uid $UID --gid 1000 debian

ARG TEST
RUN apt-get update -y && \
    apt-get install -y dc3dd sqlite3 fuse securefs python3 libgomp1\
    $(if false; then echo par2; fi) \
    $(if [ "$TEST" != "" ]; then echo python3-pip; fi) \
    build-essential && \
    npm install -g @animetosho/parpar && \
    apt-get purge -y build-essential && \
    apt-get autoremove -y && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /src


RUN if [ "$TEST" != "" ]; then pip install pytest pylint coverage pytest-cov; fi

COPY --from=par2_builder /src/par2 /usr/local/bin/par2
COPY --from=gocryptfs_builder /work/gocryptfs /work/gocryptfs-xray /usr/local/bin/
RUN mkdir /work && chown debian:debian /work

USER debian

WORKDIR /work
ENV PATH=/work:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CMD ["bash"]

