# pcapplot

This is a tool to visualize PCAPs.  It makes a couple assumptions about your
PCAP files.  First they should have a naming scheme as follows:

```
<device-label>-<YY>-<MM>-<DD>.pcap
```

To get started, first ensure you have Docker and Git installed, then build the
image for this tool as follows:

```
git clone https://va-vsrv-github.a.internal/CyberReboot/pcapplot
cd pcapplot
docker build -t pcapplot .
```

Once the image is built, you can run the tool in a container and map in your
PCAPs via volumes as follows:

```
docker run -it -p 8000:8000 \
           -v ~/my_local_pcaps:/pcaps \
           -v $(pwd)/www:/pcapplot/www \
           pcapplot
```

This tool can take either a directory of PCAPs and process them all (like the
above), or you can specify a single PCAP file if you like. Here's an example to
do the later:

```
docker run -it -p 8000:8000 \
           -v ~/my_local_pcaps:/pcaps \
           -v $(pwd)/www:/pcapplot/www \
           pcapplot \
           /pcaps/iphone-16-09-23.pcap
```

Once the tool is finished processing, it will point you to the location of the
images it has created (note the volume for `www`, which lets you retain your
images after the container exits).  It will also point you to the where the
images are being served up and a link you can browse to see your results.  When
you're finished you can `ctrl-c` to stop the container.  If you want to add
more data to your visualization just run the container again with new PCAPs and
it will add it to the visualization (note the same filename will overwrite any
pre-existing results with that filename).

You can also run the tool for viewing without adding additional data by using
the following:

```
docker run -it -p 8000:8000 \
           -v $(pwd)/www:/pcapplot/www \
           pcapplot \
           []
```

# FAQ

If you see flashing in your terminal and error messages that start with this:

```
ALSA lib confmisc.c:768:(parse_card) cannot find card '0'
```

That is perfectly normal, it is the UI building the images in a terminal, and
is safe to ignore.
