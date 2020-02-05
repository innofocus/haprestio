from consul:latest
RUN apk add python3
RUN apk add --no-cache python3-dev musl-dev openssl-dev libffi-dev g++
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python3 get-pip.py
RUN pip install grpcio
COPY haprestio-0.1.80.Once.upon.a.time-py2.py3-none-any.whl /tmp
RUN pip install /tmp/*whl
RUN haprestio -i -d /etc/haprestio