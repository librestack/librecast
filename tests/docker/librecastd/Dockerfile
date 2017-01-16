FROM ubuntu:16.04
MAINTAINER Brett Sheffield <brett@gladserv.com>
RUN apt-get update && apt-get install -y \
	build-essential \
	libncurses5
ADD . /usr/local/src/librecast/
RUN cd /usr/local/src/librecast/src && make install
RUN cd /usr/local/src/librecast/tests && make
