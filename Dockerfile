FROM ubuntu:18.10
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apt-get update && apt-get install -y \
    libsdl-image1.2-dev \
    libsdl-mixer1.2-dev \
    libsdl-ttf2.0-dev \
    libsmpeg-dev \
    libsdl1.2-dev \
    libportmidi-dev \
    libswscale-dev \
    libavformat-dev \
    libavcodec-dev \
    libplib-dev \
    libopenal-dev \
    libalut-dev \
    libvorbis-dev \
    libxxf86vm-dev \
    libxmu-dev \
    libgl1-mesa-dev \
    python-dev \
    python-pip \
    python-pygame

COPY requirements.txt /pcapplot/requirements.txt
RUN pip install -r /pcapplot/requirements.txt
COPY . /pcapplot
WORKDIR /pcapplot

EXPOSE 8000
ENV PYTHONUNBUFFERED 0
ENTRYPOINT ["python", "pcapplot.py"]
CMD ["/pcaps"]
