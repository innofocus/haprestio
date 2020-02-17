FROM alpine:latest
MAINTAINER Caius Crypt<caius.crypt<a/>gmail.com>

# dependencies requirements
RUN apk add python3 curl dumb-init
RUN apk add --no-cache python3-dev musl-dev openssl-dev libffi-dev g++

# installs pip
RUN curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
RUN python3 /tmp/get-pip.py

# installs haprestio
COPY requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt
COPY *.whl /tmp
RUN pip install /tmp/*whl

# installs haproxy and consul-template
RUN apk add haproxy
RUN cd /usr/local/bin && curl https://releases.hashicorp.com/consul-template/0.24.1/consul-template_0.24.1_linux_amd64.tgz | tar zxvf -

# sudo needed
RUN apk add sudo

# configure haprestio
ENV HAPRESTIO_CFG=/etc/haprestio/
ARG env="test"
ENV HAPRESTIO_ENV=$env
RUN haprestio

# cleanup files
RUN rm -rf /tmp/*

# container running
EXPOSE 5080
EXPOSE 80 443 8282

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["haprestio"]