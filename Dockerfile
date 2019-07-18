FROM ubuntu:19.10
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apt-get update && apt-get install -y \
    python3-dev \
    python3-pip

COPY requirements.txt /pcapplot/requirements.txt
RUN pip3 install -r /pcapplot/requirements.txt
COPY . /pcapplot
WORKDIR /pcapplot


ENV PYTHONUNBUFFERED 0
ENTRYPOINT ["python3", "pcapplot.py"]
CMD ["/pcaps"]
