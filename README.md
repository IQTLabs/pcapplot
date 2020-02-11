# pcapplot

This is a tool to visualize PCAPs.  It makes a couple assumptions about your
PCAP files.  First they should have a naming scheme as follows:

```
<device-label>-<YY>-<MM>-<DD>.pcap
```

Secondly it assumes your PCAPs have been carved such that all packets in the
capture revolve a particular IP address, naming the one the PCAP has as the
device label in the filename.

To get started, first ensure you have Docker and Git installed, then build the
image for this tool as follows:

```
git clone https://github.com/CyberReboot/pcapplot
cd pcapplot
docker build -t pcapplot .
```

Once the image is built, you can run the tool in a container and map in your
PCAPs via volumes as follows:

```
docker run -it \
           -v ~/my_local_pcaps:/pcaps \
           -v $(pwd)/www:/pcapplot/www \
           pcapplot \
           /pcaps
```

This tool can take either a directory of PCAPs and process them all (like the
above), or you can specify a single PCAP file if you like. Here's an example to
do the later:

```
docker run -it \
           -v ~/my_local_pcaps:/pcaps \
           -v $(pwd)/www:/pcapplot/www \
           pcapplot \
           iphone-16-09-23.pcap
```

Once the tool is finished processing, it will point you to the location of the
images it has created (note the volume for `www`, which lets you retain your
images after the container exits). If you want to add more data to your
visualization just run the container again with new PCAPs and it will add it to
the visualization (note the same filename will overwrite any pre-existing
results with that filename).
