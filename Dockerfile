FROM alpine:3.10
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apk update --no-cache && apk add --no-cache \
    build-base \
    jpeg-dev \
    python3-dev \
    py3-pip \
    zlib-dev && \
    rm -rf /var/cache/* && \
    rm -rf /root/.cache/*

COPY VERSION /pcapplot/VERSION
COPY requirements.txt /pcapplot/requirements.txt
RUN pip3 install -r /pcapplot/requirements.txt
COPY . /pcapplot
WORKDIR /pcapplot


ENV PYTHONUNBUFFERED 0
ENTRYPOINT ["python3", "pcapplot.py"]
CMD ["/pcaps"]
