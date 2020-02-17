FROM innofocus/haprestio:latest
MAINTAINER Caius Crypt<caius.crypt<a/>gmail.com>
COPY ./ /root

COPY requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

COPY testing-entrypoint.sh /usr/local/bin/testing-entrypoint.sh
ENTRYPOINT ["testing-entrypoint.sh"]
WORKDIR /root
CMD ["./test.sh"]