FROM ubuntu:16.04
MAINTAINER Brett Sheffield <brett@gladserv.com>
RUN apt-get update && apt-get install -y \
	build-essential \
	gdb \
	libncurses5-dev
ADD . /usr/local/src/librecast/
ADD tests/docker/librecastd/etc/ /etc/
ADD tests/docker/librecastd/bin/ /usr/local/bin/
RUN cd /usr/local/src/librecast/src && make clean && make && make install
RUN cd /usr/local/src/librecast/tests && make
