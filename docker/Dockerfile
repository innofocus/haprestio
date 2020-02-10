FROM alpine:3.9
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

# configure haprestio
RUN haprestio -i -d /etc/haprestio
COPY haprestio.cfg  /etc/haprestio

# installs haproxy and consul-template
RUN apk add haproxy
RUN cd /usr/local/bin && curl https://releases.hashicorp.com/consul-template/0.24.1/consul-template_0.24.1_linux_amd64.tgz | tar zxvf -

# cleanup files
RUN rm /tmp/get-pip.py /tmp/*whl

# container running
EXPOSE 5080

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["haprestio"]